/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! Minimal STUN application layer detector and parser.

use crate::applayer::{self, *};
use crate::core::{
    self, sc_app_layer_parser_trigger_raw_stream_inspection, ALPROTO_UNKNOWN, IPPROTO_UDP,
};
use crate::direction::Direction;
use crate::flow::Flow;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

const STUN_HEADER_LEN: usize = 20;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_TX_PROGRESS_DONE: i32 = 1;

static mut ALPROTO_STUN: AppProto = ALPROTO_UNKNOWN;

#[derive(Default)]
pub struct StunTransaction {
    tx_data: AppLayerTxData,
    tx_id: u64,
}

impl Transaction for StunTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct StunState {
    #[allow(dead_code)]
    state_data: AppLayerStateData,
    transactions: Vec<StunTransaction>,
    tx_id: u64,
}

impl State<StunTransaction> for StunState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&StunTransaction> {
        self.transactions.get(index)
    }
}

impl StunState {
    fn new() -> Self {
        Self::default()
    }

    fn new_tx(&mut self, direction: Direction) -> StunTransaction {
        self.tx_id += 1;
        StunTransaction {
            tx_data: AppLayerTxData::for_direction(direction),
            tx_id: self.tx_id,
        }
    }

    fn add_tx(&mut self, direction: Direction) {
        let mut tx = self.new_tx(direction);
        match direction {
            Direction::ToServer => tx.tx_data.updated_ts = true,
            Direction::ToClient => tx.tx_data.updated_tc = true,
        }
        self.transactions.push(tx);
    }

    fn free(&mut self) {
        for mut tx in self.transactions.drain(..) {
            tx.tx_data.cleanup();
        }
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(idx) = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1)
        {
            let mut tx = self.transactions.remove(idx);
            tx.tx_data.cleanup();
        }
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&StunTransaction> {
        self.transactions.iter().find(|&tx| tx.tx_id == tx_id + 1)
    }
}

extern "C" fn stun_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = StunState::new();
    Box::into_raw(Box::new(state)) as *mut c_void
}

unsafe extern "C" fn stun_state_free(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let mut state = Box::from_raw(state as *mut StunState);
    state.free();
}

unsafe extern "C" fn stun_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, StunState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn stun_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, StunState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => tx as *const _ as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn stun_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, StunState);
    state.transactions.len() as u64
}

unsafe extern "C" fn stun_tx_get_alstate_progress(_tx: *mut c_void, _direction: u8) -> i32 {
    STUN_TX_PROGRESS_DONE
}

unsafe extern "C" fn stun_parse_request(
    _flow: *mut Flow, state: *mut c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        return AppLayerResult::ok();
    }
    sc_app_layer_parser_trigger_raw_stream_inspection(_flow, Direction::ToServer as i32);
    let state = cast_pointer!(state, StunState);
    state.add_tx(Direction::ToServer);
    AppLayerResult::ok()
}

unsafe extern "C" fn stun_parse_response(
    _flow: *mut Flow, state: *mut c_void, _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        return AppLayerResult::ok();
    }
    sc_app_layer_parser_trigger_raw_stream_inspection(_flow, Direction::ToClient as i32);
    let state = cast_pointer!(state, StunState);
    state.add_tx(Direction::ToClient);
    AppLayerResult::ok()
}

fn is_stun_header(slice: &[u8]) -> bool {
    if slice.len() < STUN_HEADER_LEN {
        return false;
    }
    if (slice[0] & 0xC0) != 0 {
        return false;
    }
    let magic = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
    magic == STUN_MAGIC_COOKIE
}

unsafe extern "C" fn stun_probing_parser(
    _flow: *const Flow, _flags: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input.is_null() {
        return ALPROTO_UNKNOWN;
    }
    let slice = std::slice::from_raw_parts(input, input_len as usize);
    if is_stun_header(slice) {
        return ALPROTO_STUN;
    }
    ALPROTO_UNKNOWN
}

export_tx_data_get!(stun_get_tx_data, StunTransaction);
export_state_data_get!(stun_get_state_data, StunState);

const PARSER_NAME: &[u8] = b"stun\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterStunParser() {
    let ip_proto_str = CString::new("udp").unwrap();
    if SCAppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        PARSER_NAME.as_ptr() as *const c_char,
    ) == 0
    {
        SCLogDebug!("Protocol detector and parser disabled for STUN.");
        return;
    }

    let default_port = CString::new("3478,3479").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: core::IPPROTO_UDP,
        probe_ts: Some(stun_probing_parser),
        probe_tc: Some(stun_probing_parser),
        min_depth: STUN_HEADER_LEN as u16,
        max_depth: 256,
        state_new: stun_state_new,
        state_free: stun_state_free,
        tx_free: stun_state_tx_free,
        parse_ts: stun_parse_request,
        parse_tc: stun_parse_response,
        get_tx_count: stun_state_get_tx_count,
        get_tx: stun_state_get_tx,
        tx_comp_st_ts: STUN_TX_PROGRESS_DONE,
        tx_comp_st_tc: STUN_TX_PROGRESS_DONE,
        tx_get_progress: stun_tx_get_alstate_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<StunState, StunTransaction>),
        get_tx_data: stun_get_tx_data,
        get_state_data: stun_get_state_data,
        apply_tx_config: None,
        flags: 0,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
    ALPROTO_STUN = alproto;
    if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let _ = AppLayerRegisterParser(&parser, alproto);
    }
    SCAppLayerParserRegisterLogger(IPPROTO_UDP, alproto);
    SCLogDebug!("Rust STUN parser registered.");
}
