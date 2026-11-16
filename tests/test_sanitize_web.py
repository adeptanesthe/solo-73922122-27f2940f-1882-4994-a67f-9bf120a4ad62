"""脱敏网页 / JSON API：表单、结果页、pcap 下载、拒绝与上限处理。"""
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from tools import make_samples as ms

client = TestClient(app)
SAMPLE = (ms.OUT / "mask-demo.pcap").read_bytes()


def test_index_links_sanitize_form_and_demo():
    r = client.get("/")
    assert r.status_code == 200
    assert "/sanitize" in r.text and "mask-demo.pcap" in r.text and "sample_id" in r.text


def test_sanitize_html_flow_and_download():
    r = client.post("/sanitize",
                    files={"file": ("mask-demo.pcap", SAMPLE, "application/octet-stream")},
                    data={"column": "sample_id"})
    assert r.status_code == 200
    assert "抓包脱敏完成" in r.text and "sample_id" in r.text
    import re
    url = re.search(r'href="(/sanitized/[0-9a-f]+)"', r.text).group(1)
    d = client.get(url)
    assert d.status_code == 200
    assert d.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert "attachment" in d.headers["content-disposition"]
    # 下载产物可再次分析
    import csv as _csv
    import io as _io
    from app.pcap_ingest import analyze_pcap
    a = analyze_pcap(d.content, "re.pcap")
    rows = list(_csv.reader(_io.StringIO(a.connections[0].deliveries[0].body.decode())))
    assert rows[0][0] == "sample_id"
    idx = rows[0].index("sample_id")
    assert all(set(r[idx]) == {"*"} for r in rows[1:])


def test_sanitize_json_api():
    r = client.post("/api/sanitize",
                    files={"file": ("mask-demo.pcap", SAMPLE)},
                    data={"column": "sample_id"})
    assert r.status_code == 200
    j = r.json()
    assert j["column"] == "sample_id"
    assert j["packet_count"] >= j["rewritten_count"] > 0
    assert j["rewritten_packets"] == [7, 8, 9, 10, 11]
    assert j["masked_bytes"] > 0 and j["all_target_values_empty"] is False
    assert all(d["length_preserved"] and d["final_status"] == 200 for d in j["deliveries"])
    d = client.get(j["download_url"])
    assert d.status_code == 200 and d.content[:4] == b"\xd4\xc3\xb2\xa1"


def test_sanitize_rejected_renders_index_error():
    bad = (ms.OUT / "anomaly.pcap").read_bytes()
    r = client.post("/sanitize", files={"file": ("anomaly.pcap", bad)},
                    data={"column": "sample_id"})
    assert r.status_code == 400 and "脱敏被拒绝" in r.text


def test_sanitize_json_rejection_400():
    r = client.post("/api/sanitize",
                    files={"file": ("mask-demo.pcap", SAMPLE)},
                    data={"column": "no-such-column"})
    assert r.status_code == 400 and "缺少指定列" in r.json()["detail"]


def test_sanitize_oversize_413():
    big = b"\x00" * (10 * 1024 * 1024 + 1)
    r = client.post("/api/sanitize", files={"file": ("big.pcap", big)},
                    data={"column": "id"})
    assert r.status_code == 413


def test_sanitized_download_404_after_unknown_id():
    r = client.get("/sanitized/deadbeef")
    assert r.status_code == 404


def test_original_analysis_and_download_still_work():
    """原件及原 CSV 下载入口不受脱敏功能影响。"""
    r = client.post("/api/analyze",
                    files={"file": ("mask-demo.pcap", SAMPLE)})
    j = r.json()
    d = j["connections"][0]["deliveries"][0]
    assert d["downloadable"]
    csv1 = client.get(d["download_url"]).content
    assert csv1 == ms.CSV_MASK_DEMO  # 原件未被任何脱敏改动影响
