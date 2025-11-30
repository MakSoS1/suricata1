/* Copyright (C) 2025 Open Information Security Foundation
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

use crate::applayer::{self, *};
use crate::core::*;
use crate::direction::Direction;
use crate::flow::Flow;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(super) static mut ALPROTO_STUN: AppProto = ALPROTO_UNKNOWN;

#[derive(Default)]
pub struct StunTransaction {
    tx_id: u64,
    tx_data: AppLayerTxData,
}

impl StunTransaction {
    fn new(id: u64, direction: Direction) -> Self {
        let tx_data = AppLayerTxData::for_direction(direction);
        Self { tx_id: id, tx_data }
    }
}

impl Transaction for StunTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct StunState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: Vec<StunTransaction>,
}

impl StunState {
    fn new() -> Self {
        Default::default()
    }

    fn alloc_tx(&mut self, direction: Direction) -> &mut StunTransaction {
        self.tx_id += 1;
        self.transactions
            .push(StunTransaction::new(self.tx_id, direction));
        self.transactions
            .last_mut()
            .expect("just pushed transaction should exist")
    }

    fn ensure_tx(&mut self, direction: Direction) -> &mut StunTransaction {
        if self.transactions.is_empty() {
            return self.alloc_tx(direction);
        }
        self.transactions
            .last_mut()
            .expect("transactions must contain at least one entry")
    }

    fn get_tx(&mut self, tx_id: u64) -> Option<&mut StunTransaction> {
        self.transactions.iter_mut().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1)
        {
            self.transactions.remove(index);
        }
    }
}

impl State<StunTransaction> for StunState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&StunTransaction> {
        self.transactions.get(index)
    }
}

export_tx_data_get!(stun_get_tx_data, StunTransaction);
export_state_data_get!(stun_get_state_data, StunState);

extern "C" fn stun_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = StunState::new();
    let boxed = Box::new(state);
    Box::into_raw(boxed) as *mut _
}

unsafe extern "C" fn stun_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut StunState));
}

unsafe extern "C" fn stun_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, StunState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn stun_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, StunState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *mut _ as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn stun_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, StunState);
    state.transactions.len() as u64
}

unsafe extern "C" fn stun_tx_get_alstate_progress(_tx: *mut c_void, _direction: u8) -> c_int {
    1
}

unsafe extern "C" fn stun_probe(
    _flow: *const Flow, _flags: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input.is_null() || input_len < 20 {
        return ALPROTO_UNKNOWN;
    }

    let data = std::slice::from_raw_parts(input, input_len as usize);
    if (data[0] & 0xC0) != 0 {
        return ALPROTO_UNKNOWN;
    }

    if data.len() < 8 {
        return ALPROTO_UNKNOWN;
    }

    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != 0x2112A442 {
        return ALPROTO_UNKNOWN;
    }

    unsafe { ALPROTO_STUN }
}

unsafe extern "C" fn stun_parse_common(
    _flow: *mut Flow,
    state: *mut c_void,
    _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
    direction: Direction,
) -> AppLayerResult {
    if stream_slice.is_gap() || stream_slice.is_empty() {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, StunState);
    let tx = state.ensure_tx(direction);
    match direction {
        Direction::ToServer => tx.tx_data.updated_ts = true,
        Direction::ToClient => tx.tx_data.updated_tc = true,
    }

    AppLayerResult::ok()
}

unsafe extern "C" fn stun_parse_ts(
    flow: *mut Flow,
    state: *mut c_void,
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    data: *const c_void,
) -> AppLayerResult {
    stun_parse_common(flow, state, pstate, stream_slice, data, Direction::ToServer)
}

unsafe extern "C" fn stun_parse_tc(
    flow: *mut Flow,
    state: *mut c_void,
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    data: *const c_void,
) -> AppLayerResult {
    stun_parse_common(flow, state, pstate, stream_slice, data, Direction::ToClient)
}

const PARSER_NAME: &[u8] = b"stun\0";

fn build_parser(default_port: &CString, ipproto: u8) -> RustParser {
    RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto,
        probe_ts: Some(stun_probe),
        probe_tc: Some(stun_probe),
        min_depth: 20,
        max_depth: 256,
        state_new: stun_state_new,
        state_free: stun_state_free,
        tx_free: stun_state_tx_free,
        parse_ts: stun_parse_ts,
        parse_tc: stun_parse_tc,
        get_tx_count: stun_state_get_tx_count,
        get_tx: stun_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
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
    }
}

unsafe fn register_parser(ipproto: u8, proto_label: &str) {
    let ports = CString::new("[3478, 3479]").unwrap();
    let parser = build_parser(&ports, ipproto);
    let proto = CString::new(proto_label).unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(proto.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_STUN = alproto;
        if SCAppLayerParserConfParserEnabled(proto.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detection and parser disabled for STUN/{proto_label}.");
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterStunUdpParser() {
    register_parser(IPPROTO_UDP, "udp");
}

#[no_mangle]
pub unsafe extern "C" fn SCRegisterStunTcpParser() {
    register_parser(IPPROTO_TCP, "tcp");
}
