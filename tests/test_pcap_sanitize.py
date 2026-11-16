"""pcap 脱敏重写：包级不变量、跨包重传覆盖、回执不变与整份拒绝规则。"""
import io
import socket
import struct

import dpkt
import pytest

from app.pcap_ingest import analyze_pcap
from app.pcap_sanitize import SanitizeError, sanitize_pcap
from tools import make_samples as ms
from tools.pcapcraft import (ACK, FIN, PSH, SYN, Flow, PcapBuilder,
                             http_request, http_response, req_head)

SAMPLE = (ms.OUT / "mask-demo.pcap").read_bytes()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _frames(blob):
    return list(dpkt.pcap.Reader(io.BytesIO(blob)))


def _tcp_pairs(blob):
    out = []
    for ts, frame in _frames(blob):
        eth = dpkt.ethernet.Ethernet(frame)
        tcp = eth.data.data
        out.append((ts, len(frame), tcp.seq, tcp.ack, tcp.flags,
                    socket.inet_ntoa(eth.data.src), tcp.sport, bytes(tcp.data)))
    return out


def test_demo_sample_sanitized_end_to_end():
    res = sanitize_pcap(SAMPLE, "sample_id", "mask-demo.pcap")
    # 跨包重传 + 一致重叠的全部副本都被重写
    assert res.rewritten_packets == [7, 8, 9, 10, 11]
    assert res.packet_count == len(_frames(SAMPLE))
    assert len(res.deliveries) == 1
    d = res.deliveries[0]
    assert d.body_len == d.masked_len == len(ms.CSV_MASK_DEMO)
    assert d.final_status == 200 and d.interims == [100]
    assert len(res.output) > 0


def test_packet_order_ts_len_seqack_preserved():
    res = sanitize_pcap(SAMPLE, "sample_id")
    before, after = _tcp_pairs(SAMPLE), _tcp_pairs(res.output)
    assert len(before) == len(after)
    for b, a in zip(before, after):
        assert b[:7] == a[:7]  # 时间戳、帧长、seq/ack/flags/端点全部不变
    # 未改动的包整帧字节一致
    for (_, f1), (_, f2) in zip(_frames(SAMPLE), _frames(res.output)):
        eth1, eth2 = dpkt.ethernet.Ethernet(f1), dpkt.ethernet.Ethernet(f2)
        if bytes(eth1.data.data.data) == bytes(eth2.data.data.data):
            assert f1 == f2


def test_checksums_valid_after_rewrite():
    res = sanitize_pcap(SAMPLE, "sample_id")
    for _, frame in _frames(res.output):
        eth = dpkt.ethernet.Ethernet(frame)
        ip, tcp = eth.data, eth.data.data
        ihl = ip.hl * 4
        hdr = bytes(ip)[:10] + b"\x00\x00" + bytes(ip)[12:ihl]
        assert _checksum(hdr) == ip.sum
        seg = bytes(tcp)
        seg0 = seg[:16] + b"\x00\x00" + seg[18:]
        pseudo = bytes(ip.src) + bytes(ip.dst) + struct.pack(
            "!BBH", 0, socket.IPPROTO_TCP, len(seg))
        assert _checksum(pseudo + seg0) == tcp.sum


def test_reupload_delivery_count_and_receipts_unchanged_csv_masked():
    import csv as _csv
    res = sanitize_pcap(SAMPLE, "sample_id")
    a_before = analyze_pcap(SAMPLE, "before.pcap")
    a_after = analyze_pcap(res.output, "after.pcap")
    cb, ca = a_before.connections[0], a_after.connections[0]
    assert len(cb.deliveries) == len(ca.deliveries) == 1
    db, da = cb.deliveries[0], ca.deliveries[0]
    assert db.final_status == da.final_status == 200
    assert db.interims == da.interims == [100]
    assert db.body_len == da.body_len
    assert da.body != ms.CSV_MASK_DEMO
    rows = list(_csv.reader(io.StringIO(da.body.decode("utf-8"))))
    assert rows[0] == ["sample_id", "site", "analyte", "note", "result"]
    idx = rows[0].index("sample_id")
    for row in rows[1:]:
        assert set(row[idx]) == {"*"}
    # 其他列保持原样（含引号转义与引号内换行）
    flat = da.body.decode("utf-8")
    assert '站点""X""' in flat and "引号内换行\n第二行" in flat and "上海" in flat


def test_response_bytes_fully_preserved():
    res = sanitize_pcap(SAMPLE, "sample_id")
    before = b"".join(p[7] for p in _tcp_pairs(SAMPLE) if p[5] == ms.SIP)
    after = b"".join(p[7] for p in _tcp_pairs(res.output) if p[5] == ms.SIP)
    assert before == after  # 服务器→客户端方向一个字节都不改


def test_mask_other_column_leaves_sample_id_intact():
    import csv as _csv
    res = sanitize_pcap(SAMPLE, "result")
    a = analyze_pcap(res.output, "m.pcap")
    body = a.connections[0].deliveries[0].body.decode()
    assert "S-001" in body and "S-002" in body and "S-003" in body
    rows = list(_csv.reader(io.StringIO(body)))
    ridx = rows[0].index("result")
    for row in rows[1:]:
        assert set(row[ridx]) == {"*"}


def test_multiple_deliveries_all_masked():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.1", 41000, ms.SIP, 8000, 1000, 2000)
    csv1 = b"id,v\n1,a\n2,b\n"
    csv2 = b"id,v\n3,c\n"
    f.csend(1.01, http_request(csv1))
    f.ssend(1.02, http_response(200, "OK", b"ok\n"))
    f.csend(1.03, http_request(csv2))
    f.ssend(1.04, http_response(201, "Created"))
    res = sanitize_pcap(b.build(), "id")
    a = analyze_pcap(res.output, "m.pcap")
    ds = a.connections[0].deliveries
    assert len(ds) == 2 and [d.final_status for d in ds] == [200, 201]
    assert ds[0].body == b"id,v\n*,a\n*,b\n"
    assert ds[1].body == b"id,v\n*,c\n"


def test_segmented_request_each_copy_rewritten():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.2", 41001, ms.SIP, 8000, 500, 600)
    req = http_request(b"id,v\nabcde,zzzzz\n")
    c0 = f.cseq
    p1, p2 = req[:30], req[30:]
    f.csend(1.01, p1, seq=c0)
    f.csend(1.02, p2, seq=c0 + 30)
    f.csend(1.03, p2, seq=c0 + 30)           # 第二段重传
    f.cseq = c0 + len(req)
    f.ssend(1.04, http_response(200, "OK", b"ok\n"))
    res = sanitize_pcap(b.build(), "id")
    a = analyze_pcap(res.output, "m.pcap")
    assert a.connections[0].deliveries[0].body == b"id,v\n*****,zzzzz\n"
    # 原始三个数据包中后两个承载 id 字节，均须重写
    assert len(res.rewritten_packets) >= 2


def test_byte_at_a_time_segmentation():
    """遮盖列字段被逐字节切分到大量小包，重组后仍能正确逐字节映射回每个包。"""
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.12", 41011, ms.SIP, 8000, 6000, 6100)
    req = http_request(b"id,v\nabcdef,yy\n")
    c0 = f.cseq
    for k in range(0, len(req), 1):
        f.csend(1.01 + k * 0.001, req[k:k + 1], seq=c0 + k)
    f.cseq = c0 + len(req)
    f.ssend(1.9, http_response(200, "OK", b"ok\n"))
    res = sanitize_pcap(b.build(), "id")
    a = analyze_pcap(res.output, "m.pcap")
    assert a.connections[0].deliveries[0].body == b"id,v\n******,yy\n"
    # 每个承载遮盖字节的单字节包都必须重写（id 数据行 6 个字段字节）
    assert len(res.rewritten_packets) == 6


def test_invalid_csv_in_second_delivery_rejects_whole_file():
    """多份投递中任一份 CSV 非法 → 整份拒绝，不开放部分结果。"""
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.13", 41012, ms.SIP, 8000, 7000, 7100)
    f.csend(1.01, http_request(b"id,v\n1,a\n"))
    f.ssend(1.02, http_response(200, "OK"))
    bad = b"id,v\n1,a,b\n"  # 字段数与表头不一致
    f.csend(1.03, http_request(bad))
    f.ssend(1.04, http_response(200, "OK"))
    with pytest.raises(SanitizeError, match="不一致"):
        sanitize_pcap(b.build(), "id")


def test_invalid_csv_rejected_entirely_no_output():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.3", 41002, ms.SIP, 8000, 700, 800)
    bad = b"id,id\n1,2\n"  # 表头列名不唯一
    f.csend(1.01, http_request(bad))
    f.ssend(1.02, http_response(200, "OK"))
    with pytest.raises(SanitizeError, match="不唯一"):
        sanitize_pcap(b.build(), "id")


def test_missing_column_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.4", 41003, ms.SIP, 8000, 701, 801)
    f.csend(1.01, http_request(b"id,v\n1,x\n"))
    f.ssend(1.02, http_response(200, "OK"))
    with pytest.raises(SanitizeError, match="缺少指定列"):
        sanitize_pcap(b.build(), "nope")


def test_ragged_csv_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.5", 41004, ms.SIP, 8000, 702, 802)
    f.csend(1.01, http_request(b"id,a,b\n1,x,y\n2,z\n"))
    f.ssend(1.02, http_response(200, "OK"))
    with pytest.raises(SanitizeError, match="不一致"):
        sanitize_pcap(b.build(), "id")


def test_gap_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.6", 41005, ms.SIP, 8000, 900, 950)
    req = http_request(b"id,v\n1,x\n")
    c0 = f.cseq
    f.csend(1.01, req[:10], seq=c0)
    f.csend(1.02, req[20:], seq=c0 + 20)   # 缺口
    f.cseq = c0 + len(req)
    f.ssend(1.03, http_response(200, "OK"))
    with pytest.raises(SanitizeError, match="缺口"):
        sanitize_pcap(b.build(), "id")


def test_overlap_conflict_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.7", 41006, ms.SIP, 8000, 1100, 1200)
    req = http_request(b"id,v\n1,x\n")
    c0 = f.cseq
    f.csend(1.01, req[:20], seq=c0)
    clash = bytearray(req[10:])
    clash[0] = ord("Z")
    f.csend(1.02, bytes(clash), seq=c0 + 10)  # 重叠且字节冲突
    f.cseq = c0 + len(req)
    f.ssend(1.03, http_response(200, "OK"))
    with pytest.raises(SanitizeError, match="冲突"):
        sanitize_pcap(b.build(), "id")


def test_two_connections_rejected():
    # 复用现成样本：normal.pcap 含两条连接
    blob = (ms.OUT / "normal.pcap").read_bytes()
    with pytest.raises(SanitizeError, match="四元组|连接"):
        sanitize_pcap(blob, "sample_id")


def test_rehandshake_rejected():
    blob = (ms.OUT / "retrans.pcap").read_bytes()
    with pytest.raises(SanitizeError, match="ISN|连接"):
        sanitize_pcap(blob, "sample_id")


def test_incomplete_handshake_rejected():
    b = PcapBuilder()
    b.tcp(1.0, "10.1.1.8", 41007, ms.SIP, 8000, 1, 0, SYN)
    b.tcp(1.01, ms.SIP, 8000, "10.1.1.8", 41007, 9, 2, SYN | ACK)
    with pytest.raises(SanitizeError, match="握手"):
        sanitize_pcap(b.build(), "id")


def test_truncated_response_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.9", 41008, ms.SIP, 8000, 3000, 3100)
    f.csend(1.01, http_request(b"id,v\n1,x\n"))
    f.ssend(1.02, b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort")
    with pytest.raises(SanitizeError, match="完整|配对"):
        sanitize_pcap(b.build(), "id")


def test_non_reports_only_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.10", 41009, ms.SIP, 8000, 4000, 4100)
    f.csend(1.01, b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
    f.ssend(1.02, http_response(200, "OK", b"ok\n"))
    with pytest.raises(SanitizeError, match="POST /reports"):
        sanitize_pcap(b.build(), "id")


def test_empty_column_name_rejected():
    with pytest.raises(SanitizeError, match="列名"):
        sanitize_pcap(SAMPLE, "  ")


def test_all_empty_target_values_accepted_without_rewrite():
    # 目标列全为空值不属于 CSV 非法：接受，且不重写任何包、输出与原件等价
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.14", 41013, ms.SIP, 8000, 8000, 8100)
    f.csend(1.01, http_request(b"id,v\n,x\n,y\n"))
    f.ssend(1.02, http_response(200, "OK"))
    res = sanitize_pcap(b.build(), "id")
    assert res.masked_bytes == 0 and res.rewritten_packets == []
    a = analyze_pcap(res.output, "m.pcap")
    assert a.connections[0].deliveries[0].body == b"id,v\n,x\n,y\n"


def test_pcapng_rejected():
    with pytest.raises(SanitizeError, match="pcapng"):
        sanitize_pcap(b"\x0a\x0d\x0d\x0a" + b"\x00" * 64, "id")


def test_fragmented_packet_rejected():
    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.1.11", 41010, ms.SIP, 8000, 5000, 5100)
    req = http_request(b"id,v\n1,x\n")
    c0 = f.cseq
    f.csend(1.01, req[:8], seq=c0)
    # 手工 MF 分片包
    payload = req[8:20]
    tcp_head = struct.pack("!HHIIHHHH", 41010, 8000, c0 + 8, f.sseq, (5 << 12) | 0x18,
                           65535, 0, 0)
    pseudo = (socket.inet_aton("10.1.1.11") + socket.inet_aton(ms.SIP)
              + struct.pack("!BBH", 0, 6, len(tcp_head) + len(payload)))
    tsum = _checksum(pseudo + tcp_head + payload)
    tcp = struct.pack("!HHIIHHHH", 41010, 8000, c0 + 8, f.sseq, (5 << 12) | 0x18,
                      65535, tsum, 0) + payload
    total = 20 + len(tcp)
    ipw = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x2000, 64, 6, 0,
                      socket.inet_aton("10.1.1.11"), socket.inet_aton(ms.SIP))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x2000, 64, 6,
                     _checksum(ipw), socket.inet_aton("10.1.1.11"),
                     socket.inet_aton(ms.SIP))
    b.add(1.02, b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip + tcp)
    with pytest.raises(SanitizeError, match="分片"):
        sanitize_pcap(b.build(), "id")
