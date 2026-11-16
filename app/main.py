"""FastAPI 入口：上传 pcap → 报告页 / JSON API / 原 CSV 下载。"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .pcap_ingest import Analysis, PcapError, analyze_pcap

MAX_BYTES = 10 * 1024 * 1024  # 10 MiB 上传上限

BASE = Path(__file__).resolve().parent
SAMPLES = BASE.parent / "samples"

app = FastAPI(title="检测报告恢复核对台")
templates = Jinja2Templates(directory=str(BASE / "templates"))

if SAMPLES.is_dir():
    app.mount("/samples", StaticFiles(directory=str(SAMPLES)), name="samples")

# 分析结果保存在内存中（单进程演示用途，重启即失效）
ANALYSES: dict[str, Analysis] = {}


def _index_ctx(request: Request, error: str | None = None) -> dict:
    return {
        "request": request,
        "error": error,
        "max_mib": MAX_BYTES // (1024 * 1024),
        "samples_ready": SAMPLES.is_dir(),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context=_index_ctx(request))


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        return templates.TemplateResponse(
            request=request, name="index.html",
            context=_index_ctx(request, "文件超过 10 MiB 上限"), status_code=413)
    try:
        result = analyze_pcap(data, file.filename or "upload.pcap")
    except PcapError as exc:
        return templates.TemplateResponse(
            request=request, name="index.html",
            context=_index_ctx(request, str(exc)), status_code=400)
    ANALYSES[result.id] = result
    return templates.TemplateResponse(request=request, name="report.html",
                                      context={"request": request, "a": result})


@app.post("/api/analyze")
async def api_analyze(file: UploadFile = File(...)):
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="文件超过 10 MiB 上限")
    try:
        result = analyze_pcap(data, file.filename or "upload.pcap")
    except PcapError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    ANALYSES[result.id] = result
    return _analysis_json(result)


@app.get("/download/{analysis_id}/{conn_index}/{delivery_index}")
async def download(analysis_id: str, conn_index: int, delivery_index: int):
    a = ANALYSES.get(analysis_id)
    if a is None:
        raise HTTPException(status_code=404, detail="分析不存在或已过期（结果仅存于内存）")
    conn = next((c for c in a.connections if c.index == conn_index), None)
    d = next((x for x in (conn.deliveries if conn else []) if x.index == delivery_index), None)
    if conn is None or d is None:
        raise HTTPException(status_code=404, detail="投递不存在")
    if not d.downloadable or d.body is None:
        raise HTTPException(status_code=403, detail="该投递不满足下载条件（连接待核或请求不完整）")
    fname = f"report_c{conn_index}_d{delivery_index}_{(d.sha256 or '')[:8]}.csv"
    return Response(
        content=d.body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


def _analysis_json(a: Analysis) -> dict:
    return {
        "id": a.id,
        "filename": a.filename,
        "size": a.size,
        "stats": a.stats,
        "skipped_incomplete_handshake": a.skipped_incomplete_handshake,
        "connections": [
            {
                "index": c.index,
                "client": c.client,
                "server": c.server,
                "state": c.state,
                "reasons": c.reasons,
                "notes": c.notes,
                "cli_bytes": c.cli_bytes,
                "srv_bytes": c.srv_bytes,
                "deliveries": [
                    {
                        "index": d.index,
                        "method": d.method,
                        "target": d.target,
                        "is_delivery": d.is_delivery,
                        "req_complete": d.req_complete,
                        "body_len": d.body_len,
                        "sha256": d.sha256,
                        "interims": d.interims,
                        "final_status": d.final_status,
                        "response_complete": d.response_complete,
                        "downloadable": d.downloadable,
                        "download_url": (f"/download/{a.id}/{c.index}/{d.index}"
                                         if d.downloadable else None),
                    }
                    for d in c.deliveries
                ],
            }
            for c in a.connections
        ],
    }
