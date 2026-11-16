# 检测报告恢复核对台

实验室数据接入工程师丢失网关原件后，从抓包（pcap）还原 `POST /reports` 的 CSV 投递，
核对每次投递的最终回执，据此决定是否需要补采。

另提供**抓包脱敏页**：向厂商排查重传前，上传抓包并指定一个 CSV 列名，系统重写抓包，
把每份 `POST /reports` 正文中该列的数据遮盖为 `*`，其余一切保持不变，生成可直接外发的新 pcap。

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
python3 -m pytest tests -q        # 82 项测试
python3 -m tools.make_samples     # 重新生成 samples/ 下的样本抓包
```

## 使用说明

1. 打开首页，上传 pcap（≤ 10 MiB），或先下载页面上的样本抓包试用。
2. 报告页按连接列出每次投递：正文 SHA-256、正文字节数、中间响应（如 100 Continue）、最终状态。
3. 连接状态为「正常」且请求完整的投递，可点击「下载 CSV」取回原件。
4. 另提供 JSON API：`POST /api/analyze`（multipart 上传，字段名 `file`）。

## 抓包脱敏（CSV 列遮盖）

首页「抓包脱敏」表单上传 pcap 并填写列名（如 `sample_id`），也可调用
`POST /api/sanitize`（multipart：字段 `file` + `column`）。成功后在结果页下载新 pcap
（`GET /sanitized/{id}`），并可把它重新上传做「还原分析」核对。

### 遮盖规则

- 仅处理每份 `POST /reports` 的 UTF-8 逗号 CSV：**保留表头、其他字段及字段原始字节长度**，
  目标字段的每个原始字节（含引号框、转义双引号、引号内换行）替换为 `*`，遮盖后正文总长度不变。
- 支持双引号转义（`""`）与引号字段内的逗号、CR/LF 换行。
- 同一份 CSV 中表头列名必须唯一；记录字段数必须与表头一致，否则整份拒绝。
- CSV 非法、列名缺失、列名重复、非法 UTF-8、引号未闭合等情况**整份拒绝，不产出部分结果**。
- 目标列在所有投递中均为空值时不算非法：照常交付，输出与原件逐包一致（页面/JSON 会提示未遮盖任何字节）。

### 受理条件（不满足即拒绝）

- 经典 pcap（非 pcapng）、Ethernet / IPv4 / TCP、无 IP 分片、无非 IPv4/TCP 报文；
- **恰好一条连接**且完成完整三次握手（同 ISN 的 SYN 重传允许；重新握手或多连接拒绝）；
- 双向字节流**无序号缺口、无重叠字节冲突**（重传与一致重叠允许）；
- 双向 HTTP/1.1 报文完整：请求与最终响应均以 Content-Length 定界、无截断、
  无 Transfer-Encoding、无尾部残留，请求与最终响应数量一一配对；
- 抓包中至少含一条完整的 `POST /reports` 投递，且所有投递 CSV 通过上述校验。

### 重写保证

- **包序、时间戳、每包捕获长度（incl_len）、TCP SEQ/ACK、响应报文一字节不改**；
- 遮盖字节按流内偏移映射回原始包：覆盖**分段、重传和一致重叠的全部副本**，
  每个承载遮盖字节的包都被重写，未承载的包整帧保持原样；
- 仅重算受影响包的 IPv4 头校验和与 TCP 校验和（含伪首部），校验和保持有效；
- 新 pcap 重新上传后投递数、中间响应与最终回执不变，下载到的 CSV 为遮盖版；
- 原件与原 CSV 的分析/下载入口完全不受影响。

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
| `mask-demo.pcap` | 脱敏演示：单连接完整握手，POST /reports 跨包分段、乱序、整段重传、一致重叠、末段重传，100 Continue 与 200 响应重传（遮盖列 `sample_id`） |
| `normal.pcap` | 连接复用、流水线、100 Continue、同文重复投递、非投递请求（GET /health） |
| `retrans.pcap` | SYN 重传、数据乱序到达、数据/响应重传、同四元组重新握手 |
| `truncated.pcap` | 响应正文截断（状态未知、请求可下载）；请求正文截断（不可下载） |
| `anomaly.pcap` | 流内缺口、重叠字节冲突（均整连接待核）、未完整握手、孤儿包 |

## 架构

```
app/
  pcap_ingest.py    pcap → 连接跟踪（握手/重握手）→ 流重组 → HTTP 配对 → 投递清单
  pcap_sanitize.py  脱敏受理校验 → CSV 遮盖 → 偏移映射回原始包（含重传副本）→ 重算校验和 → 新 pcap
  csv_mask.py       严格 UTF-8 CSV 字节级扫描与列遮盖（引号转义/引号内换行，整份拒绝）
  reassembly.py     TCP 单向流重组（乱序/重传/缺口/冲突）
  http_parse.py     HTTP/1.1 解析（Content-Length、1xx）
  main.py           FastAPI：网页、JSON API、原 CSV 与脱敏 pcap 下载
tools/
  pcapcraft.py      手工构造 Ethernet/IPv4/TCP 报文与 pcap
  make_samples.py   生成 samples/ 样本抓包
tests/              pytest：CSV / 重组 / 解析 / 脱敏 / 端到端 / 网页 六层测试
```

## 已知限制

- 分析结果保存在进程内存中，重启即失效；未做容量淘汰（单文件 ≤ 10 MiB，演示规模可控）。
- 仅支持经典 pcap（不支持 pcapng）；仅 Ethernet 链路类型。
- SYN 携带数据（TCP Fast Open）按数据入流处理，但未做专门验证。
- 响应体内容不做解析，仅按 Content-Length 定界以定位报文边界。
- 多 worker 部署时各进程内存独立，下载可能 404（演示按单进程运行）。
