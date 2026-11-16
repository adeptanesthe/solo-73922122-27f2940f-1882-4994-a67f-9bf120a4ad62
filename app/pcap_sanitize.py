"""pcap 脱敏重写：遮盖抓包内所有 ``POST /reports`` 的 CSV 指定列。

受理条件（任一不满足即整份拒绝，不产出部分结果）：
- 经典 pcap、Ethernet / IPv4 / TCP，无 IP 分片，无链路层非 IPv4 报文；
- 恰好一条连接且完成完整三次握手（同四元组重新握手视为多条 → 拒绝）；
- 双向字节流无缺口、无重叠字节冲突（重传与一致重叠允许，按重传处理）；
- HTTP/1.1 报文双向完整（请求与最终响应均以 Content-Length 定界、无截断、
  无 Transfer-Encoding、无解析尾部残留），且至少含一条 POST /reports 投递；
- 每份投递正文为合法 UTF-8 CSV，表头列名唯一、目标列存在、记录字段数一致。

重写保证：
- 包序、时间戳、每包捕获长度（incl_len）、TCP 序号/确认号、响应报文原样保留；
- 被遮盖字节落在哪些包（含分段、重传、一致重叠的全部副本）就逐字节替换那些包；
- 仅重算受影响包的 IPv4 / TCP 校验和，其余包头字节不动。
"""
from __future__ import annotations

import io
import socket
import struct
import uuid
from dataclasses import dataclass, field

import dpkt

from .csv_mask import CsvError, mask_csv
from .http_parse import parse_requests, parse_responses, target_path
from .reassembly import StreamReassembler

WRAP = 1 << 32
PCAP_NS_MAGICS = {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"} | PCAP_NS_MAGICS
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class SanitizeError(Exception):
    """抓包不满足脱敏受理条件。"""


@dataclass
class DeliveryMask:
    index: int
    target: str
    body_len: int
    masked_len: int
    final_status: int | None
    interims: list[int] = field(default_factory=list)


@dataclass
class SanitizeResult:
    id: str
    filename: str
    size: int
    output: bytes
    packet_count: int
    rewritten_packets: list[int]      # 1 起始的包序号（含全部重传副本）
    deliveries: list[DeliveryMask]
    column: str
    isn_client: int
    isn_server: int
    masked_bytes: int = 0             # 实际替换为 * 的字节数（0 表示目标列全为空值）


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _reject(cond: bool, msg: str) -> None:
    if cond:
        raise SanitizeError(msg)


def _parse_pcap(data: bytes):
    _reject(len(data) < 4, "文件太小，不是有效的 pcap")
    magic = data[:4]
    _reject(magic == PCAPNG_MAGIC, "暂不支持 pcapng，请提供经典 pcap 格式")
    _reject(magic not in PCAP_MAGICS, "无法识别的文件格式（非 pcap）")
    try:
        reader = dpkt.pcap.Reader(io.BytesIO(data))
    except Exception as exc:  # pragma: no cover - 魔数已校验
        raise SanitizeError(f"pcap 解析失败：{exc}") from exc
    _reject(reader.datalink() != dpkt.pcap.DLT_EN10MB,
            "仅支持 Ethernet（DLT_EN10MB）链路类型的 pcap")
    return reader, magic in PCAP_NS_MAGICS


def sanitize_pcap(data: bytes, column: str, filename: str = "upload.pcap") -> SanitizeResult:
    if not isinstance(column, str) or column.strip() == "":
        raise SanitizeError("请指定需要遮盖的列名")
    reader, nanos = _parse_pcap(data)

    # ---- 1. 逐包解析并按四元组收集（保留原始帧与逐包元数据）----
    packets: list[dict] = []
    for pkt_index, (ts, frame) in enumerate(reader, start=1):
        try:
            eth = dpkt.ethernet.Ethernet(frame)
        except Exception as exc:
            raise SanitizeError(f"第 {pkt_index} 包链路层解析失败：{exc}") from exc
        ip = eth.data
        _reject(not isinstance(ip, dpkt.ip.IP),
                f"第 {pkt_index} 包不是 IPv4（受理范围仅 Ethernet/IPv4/TCP）")
        _reject(bool(ip.mf or ip.offset),
                f"第 {pkt_index} 包为 IP 分片，存在分片的抓包不予受理")
        tcp = ip.data
        _reject(not isinstance(tcp, dpkt.tcp.TCP),
                f"第 {pkt_index} 包不是 TCP（受理范围仅 Ethernet/IPv4/TCP）")
        packets.append({
            "index": pkt_index, "ts": ts, "frame": frame,
            "eth": eth, "ip": ip, "tcp": tcp,
            "src": (socket.inet_ntoa(ip.src), tcp.sport),
            "dst": (socket.inet_ntoa(ip.dst), tcp.dport),
            "payload": bytes(tcp.data),
        })
    _reject(not packets, "pcap 中没有任何报文")
    pure_syns = [p for p in packets
                 if (p["tcp"].flags & dpkt.tcp.TH_SYN)
                 and not (p["tcp"].flags & dpkt.tcp.TH_ACK)]
    _reject(not pure_syns, "抓包不含 SYN，缺少完整三次握手")
    distinct_isns = {p["tcp"].seq for p in pure_syns}
    _reject(len(distinct_isns) > 1,
            "检测到重新握手或多条连接（多个不同 ISN 的 SYN），仅受理单条连接")

    # ---- 2. 单条连接 + 完整握手校验（同 ISN 的 SYN 重传视为同一握手）----
    first_syn = pure_syns[0]
    client, server = first_syn["src"], first_syn["dst"]
    isn_c = first_syn["tcp"].seq
    for p in packets:
        _reject({p["src"], p["dst"]} != {client, server},
                f"第 {p['index']} 包不属于唯一连接的四元组，存在多连接流量")
    isn_s = None
    acked = False
    for p in packets:
        tcp = p["tcp"]
        if (p["src"] == server and (tcp.flags & dpkt.tcp.TH_SYN)
                and (tcp.flags & dpkt.tcp.TH_ACK)):
            _reject(isn_s is not None, "检测到多个 SYN-ACK，握手异常")
            isn_s = tcp.seq
        if (p["src"] == client and not (tcp.flags & dpkt.tcp.TH_SYN)
                and (tcp.flags & dpkt.tcp.TH_ACK) and isn_s is not None):
            acked = True
    _reject(isn_s is None, "缺少 SYN-ACK，三次握手不完整")
    _reject(not acked, "缺少握手第三 ACK，三次握手不完整")

    # ---- 3. 双向流重组（乱序 / 重传 / 一致重叠 / 缺口 / 冲突）----
    cli = StreamReassembler(isn_c)
    srv = StreamReassembler(isn_s)
    for p in packets:
        if not p["payload"]:
            continue
        (cli if p["src"] == client else srv).add(p["tcp"].seq, p["payload"])
    cli_stream, gaps_c, conf_c = cli.assemble()
    srv_stream, gaps_s, conf_s = srv.assemble()
    _reject(bool(gaps_c), f"客户端→服务器流存在 {len(gaps_c)} 处序号缺口，流不完整")
    _reject(bool(gaps_s), f"服务器→客户端流存在 {len(gaps_s)} 处序号缺口，流不完整")
    _reject(bool(conf_c), "客户端→服务器流存在重叠字节冲突，不予受理")
    _reject(bool(conf_s), "服务器→客户端流存在重叠字节冲突，不予受理")

    # ---- 4. 双向 HTTP 报文完整性 ----
    reqs, tail_r = parse_requests(cli_stream)
    resps, tail_s = parse_responses(srv_stream)
    _reject(tail_r != "clean", f"请求流解析未干净收尾（{tail_r}），报文不完整")
    _reject(tail_s != "clean", f"响应流解析未干净收尾（{tail_s}），报文不完整")
    n_final = sum(1 for r in resps if not r.interim)
    _reject(n_final != len(reqs),
            f"请求 {len(reqs)} 条与最终响应 {n_final} 条数量不一致，报文配对不完整")
    _reject(not reqs, "抓包中没有任何 HTTP 请求")
    for r in reqs:
        _reject(not r.complete, "存在未完整捕获的请求")
    for r in resps:
        _reject(not r.complete, "存在未完整捕获的响应")

    # ---- 5. 逐份定位 POST /reports，校验并遮盖 CSV ----
    finals = [r for r in resps if not r.interim]
    interim_groups: list[list[int]] = []
    cur_interims: list[int] = []
    for r in resps:
        if r.interim:
            cur_interims.append(r.status)
        else:
            interim_groups.append(cur_interims)
            cur_interims = []
    deliveries: list[DeliveryMask] = []
    # 流内偏移映射：请求按顺序首尾相接，逐个定位正文区间
    req_ranges: list[tuple[int, int, object]] = []
    cursor = 0
    for req in reqs:
        head_end = cli_stream.find(b"\r\n\r\n", cursor)
        _reject(head_end < 0, "内部错误：请求头定界失败")
        body_at = head_end + 4
        body_end = body_at + (req.announced_len or 0)
        req_ranges.append((body_at, body_end, req))
        cursor = body_end
    _reject(cli_stream[cursor:].strip(), "内部错误：请求流存在未归属字节")

    masked_stream = bytearray(cli_stream)
    for idx, (body_at, body_end, req) in enumerate(req_ranges, start=1):
        if not (req.method == "POST" and target_path(req.target) == "/reports"):
            continue
        body = cli_stream[body_at:body_end]
        try:
            masked = mask_csv(body, column)
        except CsvError as exc:
            raise SanitizeError(f"第 {idx} 条 POST /reports 投递{exc}") from exc
        assert len(masked) == len(body), "遮盖必须保持正文等长"
        if masked != body:
            masked_stream[body_at:body_end] = masked
        matched = finals[idx - 1]
        deliveries.append(DeliveryMask(
            index=idx, target=req.target, body_len=len(body),
            masked_len=len(masked), final_status=matched.status,
            interims=interim_groups[idx - 1],
        ))
    _reject(not deliveries, "抓包中没有 POST /reports 投递，无需脱敏")
    # 目标列在各投递中全为空值时不重写任何包（空字段遮盖后仍为空），结果照常交付

    # ---- 6. 把流内遮盖映射回原始包（分段 / 重传 / 一致重叠全覆盖）----
    changed_stream = bytes(masked_stream)
    rewritten: list[int] = []
    new_frames: list[bytes] = []
    for p in packets:
        if p["src"] != client or not p["payload"]:
            new_frames.append(p["frame"])
            continue
        off = (p["tcp"].seq - (isn_c + 1)) % WRAP
        end = off + len(p["payload"])
        new_payload = changed_stream[off:end]
        if new_payload == p["payload"]:
            new_frames.append(p["frame"])
            continue
        eth = dpkt.ethernet.Ethernet(p["frame"])
        ip, tcp = eth.data, eth.data.data
        tcp.data = new_payload
        # 先算 TCP 校验和（依赖伪首部与最终 TCP 段），再 pack IP（会重算 IP 头校验和）；
        # 顺序不能反：ip.pack() 会重新打包 TCP，覆盖之后的 tcp.sum 赋值。
        tcp.sum = 0
        pseudo = bytes(ip.src) + bytes(ip.dst) + struct.pack(
            "!BBH", 0, socket.IPPROTO_TCP, len(tcp))
        tcp.sum = _checksum(pseudo + bytes(tcp))
        ip.sum = 0
        ip.pack()
        new_frames.append(bytes(eth))
        rewritten.append(p["index"])

    # ---- 7. 按原包序、原时间戳写出新 pcap（同字节序/链路类型）----
    _reject(len(new_frames) != len(packets), "内部错误：重写后包数变化")
    masked_bytes = sum(x != y for x, y in zip(cli_stream, changed_stream))
    out = io.BytesIO()
    writer = dpkt.pcap.Writer(out, snaplen=reader.snaplen, linktype=reader.datalink(),
                              nano=nanos)
    for p, frame in zip(packets, new_frames):
        writer.writepkt(frame, ts=p["ts"])
    output = out.getvalue()
    writer.close()  # dpkt 会同时关闭底层 BytesIO，故先取字节再关闭
    return SanitizeResult(
        id=uuid.uuid4().hex[:12],
        filename=filename, size=len(data), output=output,
        packet_count=len(packets), rewritten_packets=rewritten,
        deliveries=deliveries, column=column, isn_client=isn_c, isn_server=isn_s,
        masked_bytes=masked_bytes,
    )
