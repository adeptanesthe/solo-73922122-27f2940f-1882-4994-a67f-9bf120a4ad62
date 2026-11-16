"""生成演示用样本抓包：正常 / 重传 / 截断 / 异常（缺口与重叠冲突）。

用法：python3 -m tools.make_samples
CSV 常量同时被测试引用，用于校验还原结果。
"""
from __future__ import annotations

from pathlib import Path

from tools.pcapcraft import (ACK, FIN, PSH, SYN, Flow, PcapBuilder,
                             http_request, http_response, req_head)

OUT = Path(__file__).resolve().parent.parent / "samples"
SIP, DPORT = "10.0.0.20", 8000


def csv_rows(tag: str, n: int) -> bytes:
    lines = ["sample_id,analyte,result,unit,qc_flag"]
    for i in range(n):
        lines.append(f"{tag}-{i:03d},Pb,{0.002 * (i + 1):.3f},mg/L,N")
    return ("\n".join(lines) + "\n").encode()


CSV_CONTINUE = csv_rows("C100", 12)   # normal 连接1 投递1（Expect: 100-continue）
CSV_REUSE = csv_rows("C200", 8)       # normal 连接1 投递2（连接复用）
CSV_PIPE1 = csv_rows("P100", 10)      # normal 连接2 流水线投递1（稍后同文重投）
CSV_PIPE2 = csv_rows("P200", 6)       # normal 连接2 流水线投递2
CSV_RETRANS = csv_rows("R100", 15)    # retrans 乱序 + 重传
CSV_REHANDSHAKE = csv_rows("R200", 5)  # retrans 同四元组重新握手
CSV_TRUNC_REQ = csv_rows("T100", 9)   # truncated 连接1（响应截断）
CSV_TRUNC_HALF = csv_rows("T200", 20)  # truncated 连接2（请求截断）
CSV_GAP = csv_rows("G100", 10)        # anomaly 流内缺口
CSV_CONFLICT = csv_rows("X100", 10)   # anomaly 重叠字节冲突

# 脱敏演示：含引号转义、引号内换行、逗号与多字节 UTF-8；遮盖列为 sample_id
CSV_MASK_DEMO = (
    "sample_id,site,analyte,note,result\n"
    "S-001,北京-01,Pb,\"含,逗号\",0.002\n"
    "S-002,\"站点\"\"X\"\"\",Cd,\"引号内换行\n第二行\",0.005\n"
    "S-003,上海,Hg,普通备注,0.009\n"
).encode("utf-8")
MASK_COLUMN = "sample_id"


def build_normal() -> bytes:
    b = PcapBuilder()
    # 连接 1：Expect: 100-continue → 100 → 正文 → 200；随后同连接复用再投一次
    f = Flow(b, 1.000, "10.0.0.10", 40001, SIP, DPORT, isn_c=100_000, isn_s=900_000)
    f.csend(1.010, req_head(CSV_CONTINUE, extra=["Expect: 100-continue"]))
    f.ssend(1.020, b"HTTP/1.1 100 Continue\r\n\r\n")
    f.csend(1.030, CSV_CONTINUE)
    f.ssend(1.040, http_response(200, "OK", b"ok\n"))
    f.csend(1.050, http_request(CSV_REUSE))
    f.ssend(1.060, http_response(201, "Created"))
    # 连接 2：流水线两连发 → 顺序两响应；同文新投递；一个非投递请求
    g = Flow(b, 2.000, "10.0.0.11", 40002, SIP, DPORT, isn_c=2_000, isn_s=8_000)
    g.csend(2.010, http_request(CSV_PIPE1))
    g.csend(2.011, http_request(CSV_PIPE2))  # 流水线：不等响应连续发送
    g.ssend(2.020, http_response(200, "OK", b"ok\n"))
    g.ssend(2.021, http_response(200, "OK", b"ok\n"))
    g.csend(2.030, http_request(CSV_PIPE1))  # 同文新投递，须单独保留
    g.ssend(2.040, http_response(200, "OK", b"ok\n"))
    g.csend(2.050, b"GET /health HTTP/1.1\r\nHost: gateway.lab:8000\r\n\r\n")
    g.ssend(2.060, http_response(200, "OK", b"ok\n"))
    return b.build()


def build_retrans() -> bytes:
    b = PcapBuilder()
    # 连接 1：SYN 重传 + 请求分段乱序到达 + 数据重传 + 响应整段重传
    f = Flow(b, 1.000, "10.0.0.12", 40003, SIP, DPORT, 7_000, 33_000, syn_retrans=True)
    req = http_request(CSV_RETRANS)
    c0 = f.cseq
    p1, p2, p3 = req[:120], req[120:260], req[260:]
    f.csend(1.030, p2, seq=c0 + 120)   # 乱序：第二段先到
    f.csend(1.040, p1, seq=c0)
    f.csend(1.050, p2, seq=c0 + 120)   # 重传（相同字节，不得重复提取）
    f.csend(1.060, p3, seq=c0 + 260)
    f.csend(1.065, p3, seq=c0 + 260)   # 重传
    f.cseq = c0 + len(req)
    s0 = f.sseq
    resp = http_response(200, "OK", b"ok\n")
    f.ssend(1.070, resp)
    f.ssend(1.080, resp, seq=s0)       # 响应整段重传
    # 正常关闭（FIN 不影响分析）
    b.tcp(1.090, "10.0.0.12", 40003, SIP, DPORT, f.cseq, f.sseq, FIN | ACK)
    b.tcp(1.095, SIP, DPORT, "10.0.0.12", 40003, f.sseq, f.cseq + 1, FIN | ACK)
    # 同四元组重新握手（新 ISN）→ 必须识别为新连接
    g = Flow(b, 2.000, "10.0.0.12", 40003, SIP, DPORT, 444_000, 777_000)
    g.csend(2.010, http_request(CSV_REHANDSHAKE))
    g.ssend(2.020, http_response(200, "OK", b"ok\n"))
    return b.build()


def build_truncated() -> bytes:
    b = PcapBuilder()
    # 连接 1：请求完整，响应声明了 Content-Length 但正文未完整捕获
    f = Flow(b, 1.000, "10.0.0.13", 40004, SIP, DPORT, 5_000, 6_000)
    f.csend(1.010, http_request(CSV_TRUNC_REQ))
    body = b'{"status":"ok","received":' + str(len(CSV_TRUNC_REQ)).encode() + b"}"
    body = body + b" " * (120 - len(body))
    head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    f.ssend(1.020, head + body[:40])   # 捕获到此为止 → 最终状态未知
    # 连接 2：请求正文未完整捕获
    g = Flow(b, 2.000, "10.0.0.14", 40005, SIP, DPORT, 7_100, 8_200)
    g.csend(2.010, req_head(CSV_TRUNC_HALF) + CSV_TRUNC_HALF[:80])
    return b.build()


def build_anomaly() -> bytes:
    b = PcapBuilder()
    # 连接 1：客户端→服务器流内缺口（[100,200) 未捕获）
    f = Flow(b, 1.000, "10.0.0.15", 40006, SIP, DPORT, 1_111, 2_222)
    req = http_request(CSV_GAP)
    c0 = f.cseq
    f.csend(1.010, req[:100], seq=c0)
    f.csend(1.020, req[200:], seq=c0 + 200)
    f.cseq = c0 + len(req)
    f.ssend(1.030, http_response(200, "OK", b"ok\n"))
    # 连接 2：重叠字节冲突（[100,150) 两次到达内容不一致）
    g = Flow(b, 2.000, "10.0.0.16", 40007, SIP, DPORT, 3_333, 4_444)
    req2 = http_request(CSV_CONFLICT)
    g0 = g.cseq
    g.csend(2.010, req2[:150], seq=g0)
    clash = bytearray(req2[100:260])
    clash[:50] = b"X" * 50
    g.csend(2.020, bytes(clash), seq=g0 + 100)
    g.cseq = g0 + 260
    g.ssend(2.030, http_response(200, "OK", b"ok\n"))
    # 未完整握手（SYN + SYN-ACK，无第三 ACK）→ 应被跳过
    b.tcp(3.000, "10.0.0.17", 40008, SIP, DPORT, 9_000, 0, SYN)
    b.tcp(3.010, SIP, DPORT, "10.0.0.17", 40008, 9_999, 9_001, SYN | ACK)
    # 无连接的孤儿包
    b.tcp(4.000, "10.0.0.99", 9999, SIP, DPORT, 1, 1, PSH | ACK, b"garbage")
    return b.build()


def build_mask_demo() -> bytes:
    """脱敏演示：单连接完整握手；POST /reports 分段跨包，含跨包重传与一致重叠。

    遮盖列 sample_id 的字段字节跨越多个 TCP 段边界，且：
    - 第二段整段重传（含其承载的 sample_id 字节）；
    - 一致重叠段覆盖第一段尾部与第二段全部；末段另有一次整段重传；
    - 响应侧 100 Continue 与 200 OK 均有重传，响应须原样保留。
    """
    b = PcapBuilder()
    f = Flow(b, 1.000, "10.0.0.21", 40010, SIP, DPORT, isn_c=80_000, isn_s=88_000)
    req = http_request(CSV_MASK_DEMO)
    c0 = f.cseq
    p1, p2, p3 = req[:90], req[90:200], req[200:]
    cont = b"HTTP/1.1 100 Continue\r\n\r\n"
    s0 = f.sseq
    f.ssend(1.010, cont)
    f.ssend(1.011, cont, seq=s0)                  # 100 重传（同 seq/ack，字节一致）
    f.csend(1.020, p1, seq=c0)
    f.csend(1.035, p3, seq=c0 + 200)                 # 乱序：末段先到
    f.csend(1.040, p2, seq=c0 + 90)
    f.csend(1.050, p2, seq=c0 + 90)                  # 整段重传（分段副本）
    f.csend(1.060, p1[60:] + p2, seq=c0 + 60)        # 一致重叠重传（覆盖 p1 尾 + p2 全部）
    f.csend(1.062, p3, seq=c0 + 200)                 # 末段重传（同样承载遮盖列字节）
    f.cseq = c0 + len(req)
    resp = http_response(200, "OK", b"accepted\n")
    r0 = f.sseq
    f.ssend(1.070, resp)
    f.ssend(1.080, resp, seq=r0)                     # 最终响应整段重传（同 seq/ack）
    b.tcp(1.090, "10.0.0.21", 40010, SIP, DPORT, f.cseq, f.sseq, FIN | ACK)
    b.tcp(1.095, SIP, DPORT, "10.0.0.21", 40010, f.sseq, f.cseq + 1, FIN | ACK)
    return b.build()


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, builder in [
        ("normal.pcap", build_normal),
        ("retrans.pcap", build_retrans),
        ("truncated.pcap", build_truncated),
        ("anomaly.pcap", build_anomaly),
        ("mask-demo.pcap", build_mask_demo),
    ]:
        data = builder()
        (OUT / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
