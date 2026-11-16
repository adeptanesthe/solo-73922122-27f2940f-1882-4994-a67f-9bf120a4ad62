# 检测报告恢复核对台

实验室数据接入工程师丢失网关原件后，从抓包（pcap）还原 `POST /reports` 的 CSV 投递，
核对每次投递的最终回执，据此决定是否需要补采。

## 快速启动

### Docker Compose（推荐）

```bash
docker compose up --build
# 打开 http://localhost:8000
```

### 本地运行

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 自测

```bash
python3 -m pytest tests -q        # 32 项测试
python3 -m tools.make_samples     # 重新生成 samples/ 下的样本抓包
```

## 使用说明

1. 打开首页，上传 pcap（≤ 10 MiB），或先下载页面上的样本抓包试用。
2. 报告页按连接列出每次投递：正文 SHA-256、正文字节数、中间响应（如 100 Continue）、最终状态。
3. 连接状态为「正常」且请求完整的投递，可点击「下载 CSV」取回原件。
4. 另提供 JSON API：`POST /api/analyze`（multipart 上传，字段名 `file`）。

## 约束与判定规则

| 约束 | 实现 |
| --- | --- |
| pcap ≤ 10 MiB | 超限返回 413 |
| Ethernet / IPv4 / TCP | 其余报文跳过并计数；非 Ethernet 链路类型直接报错 |
| 无 IP 分片 | 分片包跳过；由此造成的流缺口使整连接待核 |
| 完整三次握手 | 未完整握手的连接跳过并计数 |
| 明文 HTTP/1.1，Content-Length 定界 | Transfer-Encoding 或缺失 Content-Length → 连接待核 |

- **乱序 / 重传**：按 TCP 序号重组；重传（含重叠一致）只提取一次，不重复计数。
- **重叠字节冲突**：同一序号区间两次到达且字节不一致 → 整连接待核。
- **流内缺口**：序号空洞 → 整连接待核；待核连接不解析报文、不开放原件下载。
- **同四元组重新握手**：新 ISN 的 SYN 开启新连接，旧化身封存；旧化身的迟到报文
  （序号落在新区间之前）被忽略，不污染新连接。SYN 重传（同 ISN）不会误判为新连接。
- **连接复用 / 流水线**：请求流、响应流顺序解析，按顺序一一配对。
- **100 Continue**：1xx 记为中间响应，最终响应取第一个非 1xx。
- **最终状态**：最终响应完整捕获才显示状态码；未完整捕获（含抓包截断）标「未知」，
  不推断成败。
- **同文新投递**：每次投递单独成行，即使 SHA-256 相同也分别保留。
- **下载**：仅「连接正常 + 请求完整 + POST /reports」的投递可下载原 CSV。

## 样本抓包（samples/）

| 文件 | 内容 |
| --- | --- |
| `normal.pcap` | 连接复用、流水线、100 Continue、同文重复投递、非投递请求（GET /health） |
| `retrans.pcap` | SYN 重传、数据乱序到达、数据/响应重传、同四元组重新握手 |
| `truncated.pcap` | 响应正文截断（状态未知、请求可下载）；请求正文截断（不可下载） |
| `anomaly.pcap` | 流内缺口、重叠字节冲突（均整连接待核）、未完整握手、孤儿包 |

## 架构

```
app/
  pcap_ingest.py   pcap → 连接跟踪（握手/重握手）→ 流重组 → HTTP 配对 → 投递清单
  reassembly.py    TCP 单向流重组（乱序/重传/缺口/冲突）
  http_parse.py    HTTP/1.1 解析（Content-Length、1xx）
  main.py          FastAPI：网页、JSON API、CSV 下载
tools/
  pcapcraft.py     手工构造 Ethernet/IPv4/TCP 报文与 pcap
  make_samples.py  生成 samples/ 样本抓包
tests/             pytest：重组 / 解析 / 端到端 / 网页 四层测试
```

## 已知限制

- 分析结果保存在进程内存中，重启即失效；未做容量淘汰（单文件 ≤ 10 MiB，演示规模可控）。
- 仅支持经典 pcap（不支持 pcapng）；仅 Ethernet 链路类型。
- SYN 携带数据（TCP Fast Open）按数据入流处理，但未做专门验证。
- 响应体内容不做解析，仅按 Content-Length 定界以定位报文边界。
- 多 worker 部署时各进程内存独立，下载可能 404（演示按单进程运行）。
