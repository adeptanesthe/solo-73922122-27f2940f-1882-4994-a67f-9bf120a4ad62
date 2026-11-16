"""pcap → 连接跟踪 → 流重组 → HTTP 配对 → 投递清单。

约束与判定规则：
- 仅处理 Ethernet / IPv4 / TCP；IP 分片包跳过（由此造成的流缺口会把连接转待核）；
- 仅分析完整三次握手的连接；同四元组重新握手（新 ISN 的 SYN）视为新连接；
- 流内缺口或重叠字节冲突 → 整连接待核，不解析、不开放原件；
- 请求按顺序与最终响应配对（1xx 中间响应不参与配对）；
- 最终响应未完整捕获 → 状态标“未知”，不推断成败；
- 仅完整请求且连接正常时才允许下载原 CSV。
"""
from __future__ import annotations

import hashlib
import io
import socket
import uuid
from dataclasses import dataclass, field

import dpkt

from .http_parse import parse_requests, parse_responses, target_path
from .reassembly import StreamReassembler

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapError(Exception):
    """输入文件不符合约束。"""


@dataclass
class Delivery:
    index: int
    method: str
    target: str
    is_delivery: bool           # POST /reports
    req_complete: bool
    body: bytes | None          # 完整请求正文（供下载）
    body_len: int | None
    sha256: str | None
    final_status: int | None    # None → 未知
    response_complete: bool
    interims: list[int] = field(default_factory=list)  # 1xx 中间响应
    downloadable: bool = False


@dataclass
class ConnResult:
    index: int
    client: str
    server: str
    state: str                  # "ok" | "review"
    reasons: list[str]
    notes: list[str]
    cli_bytes: int
    srv_bytes: int
    deliveries: list[Delivery]
    first_ts: float
    last_ts: float


@dataclass
class Analysis:
    id: str
    filename: str
    size: int
    stats: dict
    connections: list[ConnResult]
    skipped_incomplete_handshake: int


class _Conn:
    """一条进行中的连接（按客户端→服务器四元组跟踪）。"""

    __slots__ = ("client", "server", "isn_c", "isn_s", "synack", "acked",
                 "cli", "srv", "first_ts", "last_ts")

    def __init__(self, client, server, isn_c, ts):
        self.client = client
        self.server = server
        self.isn_c = isn_c
        self.isn_s = None
        self.synack = False
        self.acked = False
        self.cli = StreamReassembler(isn_c)
        self.srv: StreamReassembler | None = None
        self.first_ts = ts
        self.last_ts = ts

    @property
    def handshake_done(self) -> bool:
        return self.synack and self.acked


def _fmt_ep(ep) -> str:
    return f"{ep[0]}:{ep[1]}"


def _pair(reqs, resps) -> list[Delivery]:
    """请求按顺序与最终响应配对；1xx 归入对应投递的中间响应。"""
    finals, groups, cur = [], [], []
    for r in resps:
        if r.interim:
            cur.append(r.status)
        else:
            finals.append(r)
            groups.append(cur)
            cur = []
    deliveries = []
    for i, req in enumerate(reqs):
        resp = finals[i] if i < len(finals) else None
        body = req.body if req.complete else None
        deliveries.append(Delivery(
            index=i + 1,
            method=req.method,
            target=req.target,
            is_delivery=req.method == "POST" and target_path(req.target) == "/reports",
            req_complete=req.complete,
            body=body,
            body_len=len(body) if body is not None else None,
            sha256=hashlib.sha256(body).hexdigest() if body is not None else None,
            # 最终响应未完整捕获 → 状态未知，不推断成败
            final_status=resp.status if (resp is not None and resp.complete) else None,
            response_complete=resp is not None and resp.complete,
            interims=groups[i] if i < len(groups) else [],
        ))
    return deliveries


def analyze_pcap(data: bytes, filename: str = "upload.pcap") -> Analysis:
    if len(data) < 4:
        raise PcapError("文件太小，不是有效的 pcap")
    magic = data[:4]
    if magic == PCAPNG_MAGIC:
        raise PcapError("暂不支持 pcapng，请提供经典 pcap 格式")
    if magic not in PCAP_MAGICS:
        raise PcapError("无法识别的文件格式（非 pcap）")
    try:
        reader = dpkt.pcap.Reader(io.BytesIO(data))
    except Exception as exc:
        raise PcapError(f"pcap 解析失败：{exc}") from exc
    if reader.datalink() != dpkt.pcap.DLT_EN10MB:
        raise PcapError("仅支持 Ethernet（DLT_EN10MB）链路类型的 pcap")

    stats = {"total": 0, "tcp": 0, "non_ipv4": 0, "fragmented": 0, "non_tcp": 0, "orphan": 0}
    packets = []
    for ts, buf in reader:
        stats["total"] += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            stats["non_ipv4"] += 1
            continue
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            stats["non_ipv4"] += 1
            continue
        if ip.mf or ip.offset:
            stats["fragmented"] += 1  # 约束：不处理 IP 分片
            continue
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            stats["non_tcp"] += 1
            continue
        stats["tcp"] += 1
        packets.append((
            ts,
            (socket.inet_ntoa(ip.src), tcp.sport),
            (socket.inet_ntoa(ip.dst), tcp.dport),
            tcp.flags, tcp.seq, bytes(tcp.data),
        ))
    packets.sort(key=lambda p: p[0])

    active: dict[tuple, _Conn] = {}
    conns: list[_Conn] = []
    for ts, src, dst, flags, seq, payload in packets:
        syn = bool(flags & dpkt.tcp.TH_SYN)
        ackf = bool(flags & dpkt.tcp.TH_ACK)
        if syn and not ackf:
            key = (src, dst)
            old = active.get(key)
            if old is not None and old.isn_c == seq:
                continue  # SYN 重传，忽略
            if old is not None:
                conns.append(old)  # 同四元组重新握手 → 旧化身封存
            conn = _Conn(src, dst, seq, ts)
            active[key] = conn
            if payload:  # SYN 携带数据（TFO，极少见）
                conn.cli.add(seq + 1, payload)
            continue
        conn = active.get((src, dst)) or active.get((dst, src))
        if conn is None:
            stats["orphan"] += 1  # 无对应握手的报文（如抓包从连接中途开始）
            continue
        conn.last_ts = ts
        forward = src == conn.client
        if syn and ackf and not forward:
            if conn.isn_s is None:
                conn.isn_s = seq
                conn.srv = StreamReassembler(seq)
                conn.synack = True
            continue
        if forward and ackf and conn.synack and not conn.acked:
            conn.acked = True
        if payload:
            if forward:
                conn.cli.add(seq, payload)
            elif conn.srv is not None:
                conn.srv.add(seq, payload)
    conns.extend(active.values())
    conns.sort(key=lambda c: c.first_ts)

    results: list[ConnResult] = []
    skipped = 0
    for conn in conns:
        if not conn.handshake_done:
            skipped += 1  # 约束：仅分析完整握手的连接
            continue
        cli_bytes, gaps_c, conf_c = conn.cli.assemble()
        srv_bytes, gaps_s, conf_s = conn.srv.assemble() if conn.srv else (b"", [], [])
        reasons: list[str] = []
        notes: list[str] = []
        deliveries: list[Delivery] = []
        if gaps_c:
            reasons.append(f"客户端→服务器流存在 {len(gaps_c)} 处缺口")
        if gaps_s:
            reasons.append(f"服务器→客户端流存在 {len(gaps_s)} 处缺口")
        if conf_c:
            reasons.append(f"客户端→服务器流存在 {len(conf_c)} 处重叠字节冲突")
        if conf_s:
            reasons.append(f"服务器→客户端流存在 {len(conf_s)} 处重叠字节冲突")
        state = "review" if reasons else "ok"
        if state == "ok":
            reqs, tail_r = parse_requests(cli_bytes)
            resps, tail_s = parse_responses(srv_bytes)
            for tail, side in ((tail_r, "请求"), (tail_s, "响应")):
                if tail.startswith("error"):
                    reasons.append(f"{side}解析失败：{tail[len('error: '):]}")
                elif tail == "truncated":
                    notes.append(f"{side}侧捕获在报文中途结束（截断）")
            if reasons:
                state = "review"
            else:
                deliveries = _pair(reqs, resps)
                n_final = sum(1 for r in resps if not r.interim)
                if n_final > len(reqs):
                    notes.append("存在无法配对的多余响应")
        results.append(ConnResult(
            index=len(results) + 1,
            client=_fmt_ep(conn.client),
            server=_fmt_ep(conn.server),
            state=state,
            reasons=reasons,
            notes=notes,
            cli_bytes=len(cli_bytes),
            srv_bytes=len(srv_bytes),
            deliveries=deliveries,
            first_ts=conn.first_ts,
            last_ts=conn.last_ts,
        ))
    for c in results:
        for d in c.deliveries:
            d.downloadable = c.state == "ok" and d.is_delivery and d.req_complete
    return Analysis(
        id=uuid.uuid4().hex[:12],
        filename=filename,
        size=len(data),
        stats=stats,
        connections=results,
        skipped_incomplete_handshake=skipped,
    )
