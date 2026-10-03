"""Interface / HTTP smoke tests run against the real stdlib server."""

import base64
import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, os.path.dirname(__file__))

import server as srv  # noqa: E402
from venc import MAGIC, stream, vint, WindowBuilder  # noqa: E402


@pytest.fixture(scope="module")
def httpd():
    srv.serve  # import sanity
    daemon = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = daemon.server_address[1]
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % port
    daemon.shutdown()
    daemon.server_close()


def _post(httpd, payload):
    req = urllib.request.Request(
        httpd + "/api/decode",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(httpd, path):
    with urllib.request.urlopen(httpd + path, timeout=5) as resp:
        return resp.status, resp.headers.get("Content-Type"), resp.read()


def _rfc_sample():
    src = b"abcdefghijklmnop"
    tgt = b"abcdwxyz" + b"efgh" * 4 + b"zzzz"
    inst = bytes([20, 5, 20, 19]) + vint(12) + bytes([0]) + vint(4)
    data = b"wxyz" + b"z"
    addr = vint(0) + vint(4) + vint(24)
    body = vint(len(tgt)) + b"\x00" + vint(len(data)) + vint(len(inst)) + vint(len(addr))
    body += data + inst + addr
    win = b"\x01" + vint(len(src)) + vint(0) + vint(len(body)) + body
    return src, tgt, MAGIC + win


class TestHttpSmoke:
    def test_healthz(self, httpd):
        status, ctype, body = _get(httpd, "/healthz")
        assert status == 200
        assert "application/json" in ctype
        assert json.loads(body)["status"] == "ok"

    def test_index_page(self, httpd):
        status, ctype, body = _get(httpd, "/")
        assert status == 200
        assert "text/html" in ctype
        assert b"VCDIFF" in body

    def test_unknown_route_404_json(self, httpd):
        status, _, _ = (404, None, None)
        try:
            _get(httpd, "/nope")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404

    def test_decode_success_through_real_endpoint(self, httpd):
        src, tgt, delta = _rfc_sample()
        status, body = _post(httpd, {
            "delta": base64.b64encode(delta).decode(),
            "dictionary": base64.b64encode(src).decode(),
        })
        assert status == 200, body
        assert body["ok"] is True
        assert body["target_length"] == len(tgt)
        assert body["sha256"] == hashlib.sha256(tgt).hexdigest()
        assert body["window_count"] == 1
        seg = body["windows"][0]["source"]
        assert seg["kind"] == "SOURCE" and seg["segment_size"] == 16
        kinds = [i["kind"] for i in body["instructions"]]
        assert kinds == ["COPY", "ADD", "COPY", "COPY", "RUN"]
        orders = [i["order"] for i in body["instructions"]]
        assert orders == list(range(5))
        assert body["instructions"][3]["overlap"] is True
        assert body["instructions"][3]["origin"] == "CURRENT_TARGET"

    def test_decode_error_reports_offset_and_window(self, httpd):
        src, _, delta = _rfc_sample()
        bad = bytearray(delta)
        bad[-1] = 0x7F                      # corrupt RUN size -> overproduces/...
        status, body = _post(httpd, {
            "delta": base64.b64encode(bytes(bad)).decode(),
            "dictionary": base64.b64encode(src).decode(),
        })
        assert status == 422
        assert body["ok"] is False
        assert isinstance(body["raw_offset"], int)
        assert body["raw_offset"] == len(delta) - 1
        assert body["window"] == 0
        assert not body.get("target_length")

    def test_invalid_base64_is_400(self, httpd):
        status, body = _post(httpd, {"delta": "not@base64!!", "dictionary": ""})
        assert status == 400
        assert "Base64" in body["error"]

    def test_non_json_body_is_400(self, httpd):
        req = urllib.request.Request(httpd + "/api/decode", data=b"hello",
                                     method="POST")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=5)
        assert ei.value.code == 400

    def test_oversize_delta_is_413(self, httpd):
        status, body = _post(httpd, {"delta": "A" * (128 * 1024 + 4),
                                     "dictionary": ""})
        assert status == 413
        assert body["ok"] is False

    def test_empty_dictionary_allowed(self, httpd):
        wb = WindowBuilder(0)
        wb.add(b"hi")
        delta = stream(wb.window_bytes(0))
        status, body = _post(httpd, {"delta": base64.b64encode(delta).decode()})
        assert status == 200
        assert body["target_length"] == 2
