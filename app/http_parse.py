"""极简 HTTP/1.1 报文解析。

环境约束：请求与最终响应均以 Content-Length 定界；支持 1xx（如
100 Continue）中间响应；不支持 Transfer-Encoding（出现即视为违反约束，
连接转待核）。解析只依赖字节流本身，不做任何猜测性补全。
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

HEAD_END = b"\r\n\r\n"


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: dict
    body: bytes | None  # None 表示正文未完整捕获
    complete: bool
    announced_len: int | None  # 声明的 Content-Length


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: dict
    body: bytes | None
    complete: bool
    interim: bool  # 1xx 中间响应


def _parse_headers(lines: list[str]) -> dict:
    headers: dict[str, str] = {}
    for ln in lines:
        if not ln:
            continue
        if ":" not in ln:
            raise ValueError(f"头部行缺少冒号: {ln!r}")
        k, v = ln.split(":", 1)
        k = k.strip().lower()
        if k in headers:
            raise ValueError(f"重复头部: {k}")
        headers[k] = v.strip()
    return headers


def _content_length(headers: dict) -> int | None:
    cl = headers.get("content-length")
    if cl is None:
        return None
    n = int(cl)
    if n < 0:
        raise ValueError("Content-Length 为负")
    return n


def parse_requests(data: bytes) -> tuple[list[HttpRequest], str]:
    """顺序解析请求流（连接复用 / 流水线即多个请求首尾相接）。

    返回 (请求列表, 尾部状态)；尾部状态为 "clean" / "truncated" / "error: ..."。
    """
    reqs: list[HttpRequest] = []
    pos = 0
    tail = "clean"
    while pos < len(data):
        idx = data.find(HEAD_END, pos)
        if idx < 0:
            tail = "truncated" if data[pos:].strip() else "clean"
            break
        try:
            lines = data[pos:idx].decode("iso-8859-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                raise ValueError(f"请求行异常: {lines[0]!r}")
            method, target, version = parts
            headers = _parse_headers(lines[1:])
            if "transfer-encoding" in headers:
                tail = "error: 不支持的 Transfer-Encoding（约束仅允许 Content-Length）"
                break
            n = _content_length(headers)
        except (ValueError, UnicodeDecodeError) as exc:
            tail = f"error: 请求头解析失败（{exc}）"
            break
        body_at = idx + len(HEAD_END)
        if n is None:
            reqs.append(HttpRequest(method, target, version, headers, b"", True, 0))
            pos = body_at
            continue
        body = data[body_at : body_at + n]
        if len(body) < n:
            reqs.append(HttpRequest(method, target, version, headers, None, False, n))
            tail = "truncated"
            break
        reqs.append(HttpRequest(method, target, version, headers, body, True, n))
        pos = body_at + n
    return reqs, tail


def parse_responses(data: bytes) -> tuple[list[HttpResponse], str]:
    """顺序解析响应流；1xx 记为中间响应，最终响应需 Content-Length 定界。"""
    resps: list[HttpResponse] = []
    pos = 0
    tail = "clean"
    while pos < len(data):
        idx = data.find(HEAD_END, pos)
        if idx < 0:
            tail = "truncated" if data[pos:].strip() else "clean"
            break
        try:
            lines = data[pos:idx].decode("iso-8859-1").split("\r\n")
            parts = lines[0].split(" ", 2)
            if len(parts) < 2 or not parts[0].startswith("HTTP/1."):
                raise ValueError(f"状态行异常: {lines[0]!r}")
            status = int(parts[1])
            reason = parts[2] if len(parts) > 2 else ""
            headers = _parse_headers(lines[1:])
        except (ValueError, UnicodeDecodeError) as exc:
            tail = f"error: 响应头解析失败（{exc}）"
            break
        if 100 <= status < 200:
            resps.append(HttpResponse(status, reason, headers, b"", True, True))
            pos = idx + len(HEAD_END)
            continue
        if "transfer-encoding" in headers:
            tail = "error: 不支持的 Transfer-Encoding（约束仅允许 Content-Length）"
            break
        try:
            n = _content_length(headers)
        except ValueError as exc:
            tail = f"error: 响应 Content-Length 非法（{exc}）"
            break
        if n is None:
            tail = "error: 最终响应缺少 Content-Length"
            break
        body_at = idx + len(HEAD_END)
        body = data[body_at : body_at + n]
        if len(body) < n:
            resps.append(HttpResponse(status, reason, headers, None, False, False))
            tail = "truncated"
            break
        resps.append(HttpResponse(status, reason, headers, body, True, False))
        pos = body_at + n
    return resps, tail


def target_path(target: str) -> str:
    """兼容 origin-form 与 absolute-form 的请求目标，取路径部分。"""
    try:
        return urlsplit(target).path or "/"
    except ValueError:
        return target
