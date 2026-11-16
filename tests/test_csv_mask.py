"""CSV 遮盖：严格解析、引号转义、引号内换行、UTF-8 与整份拒绝规则。"""
import csv
import io

import pytest

from app.csv_mask import CsvError, mask_csv, parse_structure


def masked_rows(blob: bytes, column: str):
    out = mask_csv(blob, column)
    assert len(out) == len(blob)  # 遮盖前后总字节数严格相等
    return list(csv.reader(io.StringIO(out.decode("utf-8"))))


def test_basic_mask_preserves_header_and_other_fields():
    blob = "sample_id,analyte,result\nS-001,Pb,0.002\nS-002,Cd,0.005\n".encode()
    rows = masked_rows(blob, "sample_id")
    assert rows[0] == ["sample_id", "analyte", "result"]
    assert rows[1][0] == "*****" and rows[1][1:] == ["Pb", "0.002"]
    assert rows[2][0] == "*****" and rows[2][1:] == ["Cd", "0.005"]


def test_field_wire_length_preserved():
    # 字段原始字节长度（含引号框）必须逐字节保留，只允许出现 *
    blob = 'id,note\n"AB",plain\n'.encode()
    out = mask_csv(blob, "id")
    assert out == b'id,note\n****,plain\n'  # "AB" 四个字节 → 四个 *
    assert len(out) == len(blob)


def test_quoted_escaped_quote_and_embedded_newline():
    blob = ('id,note\n'
            'S1,"line1\nline2"\n'
            '"S""2",普通\n').encode("utf-8")
    rows = masked_rows(blob, "id")
    assert rows[0] == ["id", "note"]
    assert rows[1] == ["**", "line1\nline2"]          # S1 两字节 → **
    assert rows[2] == ["******", "普通"]              # "S""2" 六字节 → ******
    # 遮盖 note 列：引号字段（含引号框与内部换行）整体逐字节变 *，id 列原样
    out = mask_csv(blob, "note")
    assert len(out) == len(blob)
    assert out.startswith(b'id,note\nS1,') and out.split(b"\n", 2)[2].startswith(b'"S""2",')
    assert b'"S""2"' in out and b"S1," in out   # id 列两个值均原样
    assert b"line" not in out and "普通".encode() not in out  # note 全部遮盖


def test_embedded_comma_and_multibyte_utf8():
    blob = "id,note\n1,\"含,逗号\"\n2,日本語\n".encode("utf-8")
    out = mask_csv(blob, "id")
    rows = list(csv.reader(io.StringIO(out.decode())))
    assert rows[1] == ["*", "含,逗号"]
    assert rows[2] == ["*", "日本語"]
    assert len(out) == len(blob)


def test_crlf_and_empty_fields():
    blob = b"id,a,b\r\n1,,x\r\n,yy,\r\n"
    rows = masked_rows(blob, "id")
    assert rows[1] == ["*", "", "x"]
    assert rows[2] == ["", "yy", ""]  # 空 id 保持空
    assert mask_csv(blob, "id") == b"id,a,b\r\n*,,x\r\n,yy,\r\n"


def test_ragged_record_rejected_entirely():
    blob = b"id,a,b\n1,x,y\n2,z\n"
    with pytest.raises(CsvError, match="不一致"):
        mask_csv(blob, "id")


def test_missing_column_rejected():
    with pytest.raises(CsvError, match="缺少指定列"):
        mask_csv(b"id,a\n1,x\n", "nope")


def test_duplicate_header_rejected():
    with pytest.raises(CsvError, match="不唯一"):
        mask_csv(b"id,id,a\n1,2,x\n", "id")


def test_invalid_utf8_rejected():
    # 构造引号字段内含非法 UTF-8 续字节
    blob = b'id,a\n"\xff\xfe",x\n'
    with pytest.raises(CsvError, match="UTF-8"):
        mask_csv(blob, "id")


def test_unterminated_quote_rejected():
    with pytest.raises(CsvError, match="未闭合"):
        mask_csv(b'id,a\n"abc,x\n', "id")


def test_quote_inside_unquoted_field_rejected():
    with pytest.raises(CsvError, match="双引号"):
        mask_csv(b'id,a\nab"c,x\n', "id")


def test_quote_followed_by_garbage_rejected():
    with pytest.raises(CsvError, match="非法字符"):
        mask_csv(b'id,a\n"ab"c,x\n', "id")


def test_empty_and_header_only_rejected():
    with pytest.raises(CsvError):
        mask_csv(b"", "id")
    with pytest.raises(CsvError):
        mask_csv(b"id,a\n", "id")


def test_blank_column_name_rejected():
    with pytest.raises(CsvError):
        mask_csv(b"id,a\n1,x\n", "")


def test_bom_tolerated_and_preserved():
    bom_name = "﻿" + "id"
    blob = b"\xef\xbb\xbfid,a\n1,x\n"
    out = mask_csv(blob, "id")
    assert out.startswith(b"\xef\xbb\xbf") and out == b"\xef\xbb\xbfid,a\n*,x\n"
    # 不带 BOM 的列名也能匹配带 BOM 的首列；显式带 BOM 的列名同样可匹配
    assert mask_csv(blob, "id") == mask_csv(blob, bom_name)


def test_parse_structure_spans_cover_all_bytes():
    blob = b'a,b\n"x""y",z,\n'
    recs = parse_structure(blob)
    flat = sorted((s, e) for rec in recs for s, e, _ in rec)
    # 字段跨度覆盖除逗号/换行外的全部位置
    separators = {i for i, c in enumerate(blob) if c in (0x2C, 0x0A, 0x0D)}
    covered = {i for s, e in flat for i in range(s, e)}
    assert covered | separators == set(range(len(blob)))
    assert recs[0] == [(0, 1, False), (2, 3, False)]
    assert recs[1][0] == (4, 10, True)  # "x""y"


def test_empty_target_value_remains_empty():
    # 目标列空值不产生 *，空字段宽度（0 字节）保持
    blob = b"id,a\n,x\n1,\n"
    out = mask_csv(blob, "id")
    assert out == b"id,a\n,x\n*,\n"


def test_trailing_crlf_after_last_record_preserved():
    blob = b"id,a\r\n1,x\r\n"
    assert mask_csv(blob, "id") == b"id,a\r\n*,x\r\n"


def test_only_newline_line_endings_and_no_final_newline():
    blob = b"id,a\n1,x"
    out = mask_csv(blob, "id")
    assert out == b"id,a\n*,x" and len(out) == len(blob)
