"""端到端：对随附样本抓包运行完整分析流水线。"""
import hashlib
from pathlib import Path

import pytest

from app.pcap_ingest import analyze_pcap
from tools import make_samples as ms

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def load(name):
    return analyze_pcap((SAMPLES / name).read_bytes(), name)


def test_normal_reuse_pipeline_continue():
    a = load("normal.pcap")
    assert a.skipped_incomplete_handshake == 0
    assert len(a.connections) == 2

    c1, c2 = a.connections
    assert c1.state == "ok" and c2.state == "ok"

    # 连接 1：100 Continue + 连接复用
    assert len(c1.deliveries) == 2
    d1, d2 = c1.deliveries
    assert d1.is_delivery and d1.interims == [100]
    assert d1.final_status == 200
    assert d1.sha256 == hashlib.sha256(ms.CSV_CONTINUE).hexdigest()
    assert d1.body == ms.CSV_CONTINUE and d1.downloadable
    assert d2.final_status == 201
    assert d2.sha256 == hashlib.sha256(ms.CSV_REUSE).hexdigest()
    assert d2.downloadable

    # 连接 2：流水线 + 同文新投递 + 非投递请求
    assert len(c2.deliveries) == 4
    p1, p2, p1_again, health = c2.deliveries
    assert p1.sha256 == hashlib.sha256(ms.CSV_PIPE1).hexdigest()
    assert p2.sha256 == hashlib.sha256(ms.CSV_PIPE2).hexdigest()
    assert p1_again.sha256 == p1.sha256          # 同文
    assert p1_again.index != p1.index            # 分别保留
    assert p1_again.body == p1.body
    assert all(d.final_status == 200 for d in (p1, p2, p1_again))
    assert not health.is_delivery and health.method == "GET"
    assert health.final_status == 200 and not health.downloadable


def test_retrans_reorder_and_rehandshake():
    a = load("retrans.pcap")
    # 同四元组重新握手 → 两条连接
    assert len(a.connections) == 2
    c1, c2 = a.connections
    assert c1.client == c2.client and c1.server == c2.server

    assert c1.state == "ok"
    assert len(c1.deliveries) == 1               # 重传不重复提取
    d = c1.deliveries[0]
    assert d.body == ms.CSV_RETRANS
    assert d.sha256 == hashlib.sha256(ms.CSV_RETRANS).hexdigest()
    assert d.final_status == 200 and d.downloadable

    assert c2.state == "ok" and len(c2.deliveries) == 1
    d2 = c2.deliveries[0]
    assert d2.body == ms.CSV_REHANDSHAKE
    assert d2.final_status == 200 and d2.downloadable


def test_truncated_capture():
    a = load("truncated.pcap")
    assert len(a.connections) == 2
    c1, c2 = a.connections
    assert c1.state == "ok" and c2.state == "ok"

    # 响应未完整捕获 → 状态未知，但完整请求仍可下载
    d1 = c1.deliveries[0]
    assert d1.req_complete and d1.downloadable
    assert d1.body == ms.CSV_TRUNC_REQ
    assert d1.final_status is None and not d1.response_complete

    # 请求未完整捕获 → 不可下载，状态未知
    d2 = c2.deliveries[0]
    assert not d2.req_complete and not d2.downloadable
    assert d2.body is None and d2.sha256 is None
    assert d2.final_status is None


def test_anomaly_gap_and_conflict():
    a = load("anomaly.pcap")
    assert a.skipped_incomplete_handshake == 1
    assert a.stats["orphan"] == 1
    assert len(a.connections) == 2
    for c in a.connections:
        assert c.state == "review"
        assert c.reasons                        # 有待核原因
        assert c.deliveries == []               # 待核连接不解析、不开放原件
    joined = " ".join(r for c in a.connections for r in c.reasons)
    assert "缺口" in joined and "冲突" in joined


def test_fragmented_packets_skipped():
    """IP 分片包被跳过，其承载的字节形成流内缺口 → 整连接待核。"""
    import socket
    import struct

    from tools.pcapcraft import Flow, PcapBuilder, checksum, http_request, http_response

    b = PcapBuilder()
    f = Flow(b, 1.0, "10.1.0.1", 5000, "10.1.0.2", 80, 100, 200)
    req = http_request(b"a,b\n1,2\n")
    c0 = f.cseq
    f.csend(1.05, req[:8], seq=c0)          # 正常段
    # 手工构造带 MF 标志的 IP 分片（承载 req[8:20]）→ 应被跳过
    payload = req[8:20]
    tcp_head = struct.pack("!HHIIHHHH", 5000, 80, c0 + 8, f.sseq, (5 << 12) | 0x18, 65535, 0, 0)
    pseudo = (socket.inet_aton("10.1.0.1") + socket.inet_aton("10.1.0.2")
              + struct.pack("!BBH", 0, 6, len(tcp_head) + len(payload)))
    tsum = checksum(pseudo + tcp_head + payload)
    tcp = struct.pack("!HHIIHHHH", 5000, 80, c0 + 8, f.sseq, (5 << 12) | 0x18, 65535, tsum, 0) + payload
    total = 20 + len(tcp)
    ip_wo = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x2000, 64, 6, 0,
                        socket.inet_aton("10.1.0.1"), socket.inet_aton("10.1.0.2"))
    isum = checksum(ip_wo)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x2000, 64, 6, isum,
                     socket.inet_aton("10.1.0.1"), socket.inet_aton("10.1.0.2"))
    b.add(1.06, b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip + tcp)
    f.csend(1.07, req[20:], seq=c0 + 20)    # 后续正常段 → [8,20) 成缺口
    f.cseq = c0 + len(req)
    f.ssend(1.08, http_response(200, "OK", b"ok\n"))

    from app.pcap_ingest import analyze_pcap
    a = analyze_pcap(b.build(), "frag.pcap")
    assert a.stats["fragmented"] == 1
    assert len(a.connections) == 1
    conn = a.connections[0]
    assert conn.state == "review"           # 分片被跳过 → 流内缺口 → 待核
    assert any("缺口" in r for r in conn.reasons)
    assert conn.deliveries == []
