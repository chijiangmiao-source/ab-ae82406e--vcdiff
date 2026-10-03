"""HTTP front-end for the VCDIFF archive checker.

Endpoints
---------
GET  /            single-page UI
GET  /healthz     liveness probe ("健康响应")
POST /api/decode  request body: {"delta": "<base64>", "dictionary": "<base64>"}

Only the Python standard library is required.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vcdiff import MAX_TARGET_BYTES, MAX_WINDOWS, VcdiffError, decode  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "web")

# Pasted payload limits (Base64 text lengths, as entered by the engineer).
MAX_DELTA_B64_BYTES = 128 * 1024
MAX_DICT_B64_BYTES = 64 * 1024
MAX_BODY_BYTES = MAX_DELTA_B64_BYTES + MAX_DICT_B64_BYTES + 4096


def _strict_b64(value: str, what: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("%s must be a Base64 string" % what)
    if value == "":
        return b""
    # Only standard padded Base64 alphabet; no whitespace or URL-safe chars.
    if (len(value) % 4 != 0 or value.count("=") > 2 or
            ("=" in value and not value.endswith("=" * value.count("=")))):
        raise ValueError("%s is not correctly padded standard Base64" % what)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ValueError("%s is not valid standard Base64" % what)
    return raw


def _evidence_payload(result) -> dict:
    return {
        "ok": True,
        "raw_delta_length": result.raw_length,
        "target_length": len(result.target),
        "target_limit": MAX_TARGET_BYTES,
        "sha256": result.sha256_hex,
        "window_count": len(result.windows),
        "window_limit": MAX_WINDOWS,
        "windows": [w.to_json() for w in result.windows],
        "instructions": [i.to_json() for i in result.instructions],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "VcdiffChecker/1.0"

    def log_message(self, fmt, *args):  # quiet, structured stderr
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok",
                                            "service": "vcdiff-checker"})
            return
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR,
                                {"ok": False, "error": "UI asset missing"})
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/decode":
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST,
                            {"ok": False, "error": "bad Content-Length"})
            return
        if length > MAX_BODY_BYTES:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {
                "ok": False,
                "error": "request body too large; at most %d bytes of "
                         "Base64 delta and %d bytes of Base64 dictionary "
                         "are accepted" % (MAX_DELTA_B64_BYTES,
                                           MAX_DICT_B64_BYTES),
            })
            return
        raw_body = self.rfile.read(length)
        try:
            req = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST,
                            {"ok": False, "error": "request body must be JSON"})
            return
        if not isinstance(req, dict):
            self._send_json(HTTPStatus.BAD_REQUEST,
                            {"ok": False, "error": "request body must be a JSON object"})
            return

        delta_b64 = req.get("delta", "")
        dict_b64 = req.get("dictionary", "")
        if not isinstance(delta_b64, str) or not isinstance(dict_b64, str):
            self._send_json(HTTPStatus.BAD_REQUEST,
                            {"ok": False, "error": "delta and dictionary must be strings"})
            return
        if len(delta_b64.encode("utf-8")) > MAX_DELTA_B64_BYTES:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {
                "ok": False,
                "error": "Base64 VCDIFF payload exceeds the 128 KiB paste limit"})
            return
        if len(dict_b64.encode("utf-8")) > MAX_DICT_B64_BYTES:
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {
                "ok": False,
                "error": "Base64 dictionary exceeds the 64 KiB paste limit"})
            return

        try:
            delta = _strict_b64(delta_b64, "delta")
            dictionary = _strict_b64(dict_b64, "dictionary")
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False,
                                                     "error": str(exc)})
            return

        try:
            result = decode(delta, dictionary)
        except VcdiffError as exc:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {
                "ok": False,
                "error": exc.message,
                "raw_offset": exc.offset,
                "window": exc.window_index,
            })
            return
        except Exception:  # pragma: no cover - defensive
            traceback.print_exc()
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR,
                            {"ok": False, "error": "internal decoder failure"})
            return

        self._send_json(HTTPStatus.OK, _evidence_payload(result))


def serve(host: str, port: int) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("vcdiff-checker listening on http://%s:%d\n" % (host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    serve(host, port)
