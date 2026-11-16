"""网页层：上传、报告页、JSON API、CSV 下载、限制与错误处理。"""
import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from tools import make_samples as ms

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
client = TestClient(app)


def sample(name):
    return (SAMPLES / name).read_bytes()


def test_index_page():
    r = client.get("/")
    assert r.status_code == 200 and "检测报告恢复核对台" in r.text


def test_api_analyze_and_download():
    r = client.post("/api/analyze", files={"file": ("normal.pcap", sample("normal.pcap"))})
    assert r.status_code == 200
    j = r.json()
    assert len(j["connections"]) == 2
    d = j["connections"][0]["deliveries"][0]
    assert d["downloadable"] and d["download_url"]
    r2 = client.get(d["download_url"])
    assert r2.status_code == 200
    assert r2.headers["content-type"].startswith("text/csv")
    assert "attachment" in r2.headers["content-disposition"]
    assert r2.content == ms.CSV_CONTINUE
    assert hashlib.sha256(r2.content).hexdigest() == d["sha256"]


def test_html_report_shows_sha_and_status():
    r = client.post("/analyze", files={"file": ("normal.pcap", sample("normal.pcap"))})
    assert r.status_code == 200
    sha = hashlib.sha256(ms.CSV_CONTINUE).hexdigest()
    assert sha in r.text and "下载 CSV" in r.text and "正常" in r.text


def test_html_report_shows_unknown_status():
    r = client.post("/analyze", files={"file": ("truncated.pcap", sample("truncated.pcap"))})
    assert r.status_code == 200 and "未知" in r.text


def test_download_forbidden_when_request_incomplete():
    r = client.post("/api/analyze", files={"file": ("truncated.pcap", sample("truncated.pcap"))})
    j = r.json()
    aid = j["id"]
    # 连接 2 投递 1：请求不完整 → 403
    r2 = client.get(f"/download/{aid}/2/1")
    assert r2.status_code == 403


def test_download_not_found_when_connection_under_review():
    r = client.post("/api/analyze", files={"file": ("anomaly.pcap", sample("anomaly.pcap"))})
    j = r.json()
    aid = j["id"]
    assert all(c["state"] == "review" for c in j["connections"])
    assert all(c["deliveries"] == [] for c in j["connections"])
    r2 = client.get(f"/download/{aid}/1/1")
    assert r2.status_code == 404


def test_oversize_upload_rejected():
    big = b"\x00" * (10 * 1024 * 1024 + 1)
    r = client.post("/api/analyze", files={"file": ("big.pcap", big)})
    assert r.status_code == 413
    r2 = client.post("/analyze", files={"file": ("big.pcap", big)})
    assert r2.status_code == 413


def test_invalid_pcap_rejected():
    r = client.post("/api/analyze", files={"file": ("x.pcap", b"this is not a pcap file at all")})
    assert r.status_code == 400


def test_pcapng_rejected():
    pcapng = b"\x0a\x0d\x0d\x0a" + b"\x00" * 64
    r = client.post("/api/analyze", files={"file": ("x.pcapng", pcapng)})
    assert r.status_code == 400 and "pcapng" in r.json()["detail"]


def test_samples_served():
    r = client.get("/samples/normal.pcap")
    assert r.status_code == 200
    assert r.content == sample("normal.pcap")
