"""手工构造 Ethernet/IPv4/TCP 报文并写出经典 pcap（供样本与测试使用）。"""
from __future__ import annotations

import socket
import struct

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def tcp_frame(src_ip: str, dst_ip: str, sport: int, dport: int,
              seq: int, ack: int, flags: int, payload: bytes = b"",
              src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
              dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02") -> bytes:
    off_flags = (5 << 12) | flags
    tcp_head = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 65535, 0, 0)
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_head) + len(payload)))
    tcp_sum = checksum(pseudo + tcp_head + payload)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 65535, tcp_sum, 0) + payload
    total = 20 + len(tcp)
    ip_head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64,
                          socket.IPPROTO_TCP, 0,
                          socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_sum = checksum(ip_head)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64,
                     socket.IPPROTO_TCP, ip_sum,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp


class PcapBuilder:
    """按 (ts, frame) 累积并序列化为经典 pcap（little-endian，DLT_EN10MB）。"""

    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []

    def add(self, ts: float, frame: bytes) -> None:
        self.frames.append((ts, frame))

    def tcp(self, ts: float, src_ip: str, sport: int, dst_ip: str, dport: int,
            seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
        self.add(ts, tcp_frame(src_ip, dst_ip, sport, dport, seq, ack, flags, payload))

    def build(self) -> bytes:
        out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for ts, frame in self.frames:
            sec = int(ts)
            usec = round((ts - sec) * 1_000_000)
            out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            out.append(frame)
        return b"".join(out)


def handshake(b: PcapBuilder, ts: float, cip: str, sport: int, sip: str, dport: int,
              isn_c: int, isn_s: int, syn_retrans: bool = False) -> None:
    b.tcp(ts, cip, sport, sip, dport, isn_c, 0, SYN)
    if syn_retrans:
        b.tcp(ts + 0.005, cip, sport, sip, dport, isn_c, 0, SYN)  # 同 ISN 的 SYN 重传
    b.tcp(ts + 0.010, sip, dport, cip, sport, isn_s, isn_c + 1, SYN | ACK)
    b.tcp(ts + 0.020, cip, sport, sip, dport, isn_c + 1, isn_s + 1, ACK)


class Flow:
    """一条已握手连接的收发助手；seq 显式给出时不自动推进，便于构造乱序/重传。"""

    def __init__(self, b: PcapBuilder, ts: float, cip: str, sport: int,
                 sip: str, dport: int, isn_c: int, isn_s: int,
                 syn_retrans: bool = False) -> None:
        self.b, self.cip, self.sport, self.sip, self.dport = b, cip, sport, sip, dport
        handshake(b, ts, cip, sport, sip, dport, isn_c, isn_s, syn_retrans)
        self.cseq = isn_c + 1
        self.sseq = isn_s + 1

    def csend(self, ts: float, payload: bytes, seq: int | None = None) -> None:
        s = self.cseq if seq is None else seq
        self.b.tcp(ts, self.cip, self.sport, self.sip, self.dport, s, self.sseq, PSH | ACK, payload)
        if seq is None:
            self.cseq += len(payload)

    def ssend(self, ts: float, payload: bytes, seq: int | None = None) -> None:
        s = self.sseq if seq is None else seq
        self.b.tcp(ts, self.sip, self.dport, self.cip, self.sport, s, self.cseq, PSH | ACK, payload)
        if seq is None:
            self.sseq += len(payload)


def req_head(body: bytes, extra: tuple[str, ...] | list[str] = ()) -> bytes:
    lines = ["POST /reports HTTP/1.1", "Host: gateway.lab:8000", "Content-Type: text/csv",
             f"Content-Length: {len(body)}", *extra, "", ""]
    return "\r\n".join(lines).encode()


def http_request(body: bytes, extra: tuple[str, ...] | list[str] = ()) -> bytes:
    return req_head(body, extra) + body


def http_response(status: int, reason: str, body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}", "Server: lab-gateway/1.0",
             f"Content-Length: {len(body)}", "", ""]
    return "\r\n".join(lines).encode() + body
