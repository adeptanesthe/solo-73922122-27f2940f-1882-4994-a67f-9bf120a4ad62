from app.reassembly import StreamReassembler


def test_in_order():
    r = StreamReassembler(isn=100)
    r.add(101, b"hello ")
    r.add(107, b"world")
    data, gaps, conf = r.assemble()
    assert data == b"hello world" and not gaps and not conf


def test_out_of_order():
    r = StreamReassembler(100)
    r.add(107, b"world")
    r.add(101, b"hello ")
    data, gaps, conf = r.assemble()
    assert data == b"hello world" and not gaps and not conf


def test_retransmission_dedup():
    r = StreamReassembler(100)
    r.add(101, b"hello ")
    r.add(101, b"hello ")  # 重传
    r.add(107, b"world")
    r.add(107, b"world")
    data, gaps, conf = r.assemble()
    assert data == b"hello world" and not gaps and not conf


def test_overlap_consistent():
    r = StreamReassembler(100)
    r.add(101, b"hello world")
    r.add(105, b"o world!")  # 重叠一致且多一字节
    data, gaps, conf = r.assemble()
    assert data == b"hello world!" and not gaps and not conf


def test_overlap_conflict():
    r = StreamReassembler(100)
    r.add(101, b"hello")
    r.add(103, b"XX")  # 与已放置字节冲突
    _, _, conf = r.assemble()
    assert conf


def test_conflicting_retransmission():
    r = StreamReassembler(100)
    r.add(101, b"hello")
    r.add(101, b"hallo")  # 同偏移不同字节
    _, _, conf = r.assemble()
    assert conf == [(0, 5)]


def test_gap_detected():
    r = StreamReassembler(100)
    r.add(101, b"ab")
    r.add(105, b"cd")  # 缺 [103,105)
    _, gaps, _ = r.assemble()
    assert gaps == [(2, 4)]


def test_stale_segment_ignored():
    r = StreamReassembler(1000)
    r.add(500, b"old")  # 上一化身连接的迟到段
    r.add(1001, b"new")
    data, gaps, conf = r.assemble()
    assert data == b"new" and not gaps and not conf
