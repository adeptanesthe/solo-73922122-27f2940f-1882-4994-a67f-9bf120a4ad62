from app.http_parse import parse_requests, parse_responses, target_path


def test_simple_request():
    data = b"POST /reports HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
    reqs, tail = parse_requests(data)
    assert tail == "clean" and len(reqs) == 1
    assert reqs[0].method == "POST" and reqs[0].body == b"hello" and reqs[0].complete


def test_keepalive_and_pipeline():
    one = b"POST /reports HTTP/1.1\r\nContent-Length: 3\r\n\r\naaa"
    two = b"POST /reports HTTP/1.1\r\nContent-Length: 3\r\n\r\nbbb"
    reqs, tail = parse_requests(one + two)
    assert tail == "clean"
    assert [r.body for r in reqs] == [b"aaa", b"bbb"]


def test_100_continue_is_interim():
    data = (b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    resps, tail = parse_responses(data)
    assert tail == "clean"
    assert [r.status for r in resps] == [100, 200]
    assert resps[0].interim and not resps[1].interim
    assert resps[1].body == b"ok"


def test_truncated_request_body():
    reqs, tail = parse_requests(b"POST /reports HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc")
    assert tail == "truncated"
    assert len(reqs) == 1 and not reqs[0].complete and reqs[0].body is None


def test_truncated_response_body():
    resps, tail = parse_responses(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
    assert tail == "truncated"
    assert len(resps) == 1 and not resps[0].complete


def test_missing_content_length_final_response():
    _, tail = parse_responses(b"HTTP/1.1 200 OK\r\n\r\n")
    assert tail.startswith("error")


def test_chunked_unsupported():
    _, tail = parse_requests(
        b"POST /reports HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n")
    assert tail.startswith("error")


def test_trailing_crlf_is_clean():
    reqs, tail = parse_requests(
        b"POST /reports HTTP/1.1\r\nContent-Length: 1\r\n\r\nx\r\n")
    assert tail == "clean" and len(reqs) == 1


def test_target_path():
    assert target_path("/reports") == "/reports"
    assert target_path("/reports?x=1") == "/reports"
    assert target_path("http://gw.lab/reports") == "/reports"
