#!/usr/bin/env python3
from scapy.all import IP, UDP, wrpcap
import os

MAGIC_COOKIE = b"\x21\x12\xa4\x42"
STUN_HEADER_LEN = 20

# Adjust IPs if you want to match different HOME_NET / EXTERNAL_NET
HOME_IP = "192.168.1.10"
EXTERNAL_IP = "198.51.100.10"

STD_PORT = 3478      # standard STUN port
NONSTD_PORT = 40000  # non-standard port for rule #2


def stun_header(msg_type: int, body: bytes = b"") -> bytes:
    """
    Build a minimal STUN header:
    - msg_type (2 bytes)
    - message length (2 bytes, length of body)
    - magic cookie (4 bytes)
    - transaction ID (12 random bytes)
    + body (if provided)
    """
    if len(body) % 4 != 0:
        # STUN attributes are 32-bit aligned; pad with zeros for simplicity
        pad_len = 4 - (len(body) % 4)
        body += b"\x00" * pad_len

    msg_type_bytes = msg_type.to_bytes(2, byteorder="big")
    msg_len_bytes = len(body).to_bytes(2, byteorder="big")
    tx_id = os.urandom(12)

    return msg_type_bytes + msg_len_bytes + MAGIC_COOKIE + tx_id + body


def generate_pcap(filename: str = "qa/pcaps/stun_3rules_60pkts.pcap"):
    dirname = os.path.dirname(filename)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    pkts = []

    # ---------- Rule 1 ----------
    # alert stun $HOME_NET any -> $EXTERNAL_NET any
    #  msg:"STUN Binding Request from internal host";
    #  flow:to_server;
    #  content:"|00 01|"; offset:0; depth:2;
    #  content:"|21 12 a4 42|"; offset:4; depth:4;

    for i in range(20):
        payload = stun_header(0x0001)  # Binding Request (0x0001)
        pkt = (
            IP(src=HOME_IP, dst=EXTERNAL_IP)
            / UDP(sport=50000 + i, dport=STD_PORT)
            / payload
        )
        pkts.append(pkt)

    # ---------- Rule 2 ----------
    # alert stun $HOME_NET any -> $EXTERNAL_NET ![3478,3479]
    #  msg:"Suspicious STUN traffic on non-standard port";
    #  flow:to_server;
    #  content:"|00 01|"; offset:0; depth:2;
    #  content:"|21 12 a4 42|"; offset:4; depth:4;

    for i in range(20):
        payload = stun_header(0x0001)  # Binding Request
        pkt = (
            IP(src=HOME_IP, dst=EXTERNAL_IP)
            / UDP(sport=51000 + i, dport=NONSTD_PORT)
            / payload
        )
        pkts.append(pkt)

    # ---------- Rule 3 ----------
    # alert stun $EXTERNAL_NET any -> $HOME_NET any
    #  msg:"STUN Binding Success Response to internal host";
    #  flow:stateless;
    #  content:"|01 01|"; offset:0; depth:2;
    #  content:"|21 12 a4 42|"; offset:4; depth:4;

    for i in range(20):
        payload = stun_header(0x0101)  # Binding Success Response (0x0101)
        pkt = (
            IP(src=EXTERNAL_IP, dst=HOME_IP)
            / UDP(sport=STD_PORT, dport=52000 + i)
            / payload
        )
        pkts.append(pkt)

    wrpcap(filename, pkts)
    print(f"[+] PCAP saved to: {filename}")
    print(f"    Total packets: {len(pkts)} (20 + 20 + 20)")


if __name__ == "__main__":
    generate_pcap()
