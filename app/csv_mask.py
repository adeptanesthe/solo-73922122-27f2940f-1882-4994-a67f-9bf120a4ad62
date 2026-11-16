"""严格 RFC 4180 风格的 UTF-8 CSV 解析与列遮盖。

设计要点：
- 字节级状态机扫描，支持双引号转义（``""``）与引号字段内的逗号、CR/LF 换行；
- 整份校验：UTF-8 合法、表头列名唯一、目标列存在、每条记录字段数与表头一致，
  任一不满足即抛 :class:`CsvError`，不产生部分结果；
- 遮盖在原始字节上进行：目标字段的整段线长字节（含引号框、转义引号、
  引号内换行）逐字节替换为 ``*``，因此遮盖前后正文总字节数完全一致，
  字段原始字节长度保持不变，其余字节一律不动。
"""
from __future__ import annotations

BOM = b"\xef\xbb\xbf"
QUOTE = 0x22   # "
COMMA = 0x2C   # ,
CR = 0x0D
LF = 0x0A
FIELD_TERMINATORS = (COMMA, CR, LF)


class CsvError(ValueError):
    """CSV 非法或列名不满足约束（缺列 / 列名重复）。"""


def _decode_value(span: tuple[int, int, bool], data: bytes) -> str:
    """把字段线字节解码为字段值（去引号框、还原双引号转义），并校验 UTF-8。"""
    start, end, quoted = span
    raw = data[start:end]
    if quoted:
        inner = raw[1:-1].replace(b'""', b'"')
    else:
        inner = raw
    try:
        return inner.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CsvError(f"CSV 含非法 UTF-8 字节（{exc}）") from exc


def parse_structure(data: bytes) -> list[list[tuple[int, int, bool]]]:
    """扫描 CSV 字节，返回记录列表；每条记录为 (start, end, quoted) 字段跨度。

    跨度覆盖字段在线上的全部字节：引号字段含首尾引号与内部转义/换行。
    """
    if not data:
        raise CsvError("CSV 正文为空")
    records: list[list[tuple[int, int, bool]]] = []
    cur: list[tuple[int, int, bool]] = []
    n = len(data)
    i = 0
    while i < n:
        fstart = i
        if data[i] == QUOTE:
            i += 1
            while True:
                if i >= n:
                    raise CsvError("引号字段未闭合（缺少收尾双引号）")
                if data[i] == QUOTE:
                    if i + 1 < n and data[i + 1] == QUOTE:
                        i += 2  # 转义的双引号 ""
                        continue
                    i += 1  # 收尾引号
                    break
                i += 1
            cur.append((fstart, i, True))
            if i < n and data[i] not in FIELD_TERMINATORS:
                raise CsvError("引号字段收尾后出现非法字符（仅允许逗号或换行）")
        else:
            j = i
            while j < n and data[j] not in FIELD_TERMINATORS:
                if data[j] == QUOTE:
                    raise CsvError("未加引号的字段中出现双引号")
                j += 1
            cur.append((i, j, False))  # 空字段 j == i
            i = j
        if i >= n:
            break
        c = data[i]
        if c == COMMA:
            i += 1
            if i == n:
                cur.append((n, n, False))  # 行尾逗号后的空字段
            continue
        # 记录结束（CR / LF），CRLF 整体消费；尾部换行不产生多余空记录
        records.append(cur)
        cur = []
        if c == CR and i + 1 < n and data[i + 1] == LF:
            i += 2
        else:
            i += 1
    if cur:
        records.append(cur)
    if not records:
        raise CsvError("CSV 正文为空")
    return records


def mask_csv(data: bytes, column: str) -> bytes:
    """遮盖 ``data`` 中每条数据行的 ``column`` 列，返回等长的新字节串。

    表头、其他字段及所有分隔字节保持原样；目标字段的每个原始字节（含引号框、
    转义双引号、引号内换行）替换为 ``*``，字段线长与正文总长度不变。
    """
    if not isinstance(column, str) or column == "":
        raise CsvError("列名不能为空")
    # 用户显式带 BOM 书写列名时同样受理（BOM 不属于列名语义）
    column = column[1:] if column.startswith("﻿") else column
    prefix = b""
    body = data
    if body.startswith(BOM):
        prefix, body = BOM, body[len(BOM):]
    records = parse_structure(body)
    # 整份 UTF-8 合法性：逐字段解码（同时还原引号语义），非法即整份拒绝
    decoded = [[_decode_value(span, body) for span in rec] for rec in records]
    names = decoded[0]
    # 首列名带 UTF-8 BOM 时，匹配用名去掉 BOM（BOM 字节仍保留在输出中）
    effective = [n[1:] if i == 0 and n.startswith("﻿") else n
                 for i, n in enumerate(names)]
    if any(name == "" for name in effective):
        raise CsvError("表头存在空列名")
    seen: set[str] = set()
    dup = sorted({name for name in effective if name in seen or seen.add(name)})
    if dup:
        raise CsvError(f"表头列名不唯一，重复列名：{', '.join(dup)}")
    if column not in effective:
        raise CsvError(f"CSV 缺少指定列：{column}")
    if len(records) < 2:
        raise CsvError("CSV 仅含表头，没有可遮盖的数据行")
    width = len(effective)
    target = effective.index(column)
    out = bytearray(body)
    for rec in records[1:]:
        if len(rec) != width:
            raise CsvError(f"存在字段数（{len(rec)}）与表头（{width}）不一致的记录，整份拒绝")
        start, end, _ = rec[target]
        for pos in range(start, end):
            out[pos] = 0x2A  # '*'
    return prefix + bytes(out)
