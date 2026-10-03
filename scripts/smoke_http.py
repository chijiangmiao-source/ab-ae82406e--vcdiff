"""Black-box HTTP smoke test for a running vcdiff-checker instance.

Usage: python3 scripts/smoke_http.py --base-url http://127.0.0.1:8080

Exits 0 only if every check passes.  Used by the one-shot ``verify`` service.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tests"))
sys.path.insert(0, os.path.join(HERE, "..", "app"))

from venc import MAGIC, vint, WindowBuilder, stream  # noqa: E402

failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print("[%s] %s%s" % (status, name, (" -- " + detail) if detail and not cond else ""))
    if not cond:
        failures.append(name)


def wait_ready(base_url, timeout=20.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/healthz", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.5)
    print("service never became ready: %r" % last)
    return False


def get(base_url, path):
    with urllib.request.urlopen(base_url + path, timeout=5) as r:
        return r.status, r.headers.get("Content-Type", ""), r.read()


def post_json(base_url, payload):
    req = urllib.request.Request(
        base_url + "/api/decode",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def rfc_sample():
    src = b"abcdefghijklmnop"
    tgt = b"abcdwxyz" + b"efgh" * 4 + b"zzzz"
    inst = bytes([20, 5, 20, 19]) + vint(12) + bytes([0]) + vint(4)
    data = b"wxyz" + b"z"
    addr = vint(0) + vint(4) + vint(24)
    body = vint(len(tgt)) + b"\x00" + vint(len(data)) + vint(len(inst)) + vint(len(addr))
    body += data + inst + addr
    win = b"\x01" + vint(len(src)) + vint(0) + vint(len(body)) + body
    return src, tgt, MAGIC + win


def feature_sample():
    """Two windows: a TARGET overlap copy, prior-window TARGET sourcing,
    near-cache addressing, plus a one-byte-corrupted variant that must fail
    at a precise raw offset."""
    w0 = WindowBuilder(0)
    w0.add(b"abc")
    w0.do_copy(13, 0, b"", mode=0)           # overlapping TARGET copy
    prefix = bytes(w0.target)               # "abc" + "abc"*4 + "a" (16 B)
    w1 = WindowBuilder(len(prefix))
    w1.do_copy(4, 1, prefix, mode=0)        # seeds near cache slot
    w1.do_copy(4, 1, prefix, mode=2)        # NEAR0 delta 0
    w1.do_copy(4, 5, prefix, mode=2)        # NEAR0 delta 4
    good = stream(w0.window_bytes(0),
                  w1.window_bytes(2, len(prefix), 0))
    expected = prefix + prefix[1:5] + prefix[1:5] + prefix[5:9]
    bad = bytearray(good)
    bad[-1] = 0x60                          # near delta -> ungrown address
    return good, expected, bytes(bad)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=os.environ.get("BASE_URL", "http://127.0.0.1:8080"))
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    if not wait_ready(base):
        return 1

    status, ctype, body = get(base, "/healthz")
    check("GET /healthz -> 200 json ok",
          status == 200 and "json" in ctype and json.loads(body)["status"] == "ok")

    status, ctype, body = get(base, "/")
    check("GET / serves the HTML page",
          status == 200 and "html" in ctype and b"VCDIFF" in body)

    src, tgt, delta = rfc_sample()
    status, p = post_json(base, {
        "delta": base64.b64encode(delta).decode(),
        "dictionary": base64.b64encode(src).decode(),
    })
    check("POST valid sample -> 200", status == 200, str(p.get("error", "")))
    check("target length matches", p.get("target_length") == len(tgt))
    check("sha256 matches",
          p.get("sha256") == hashlib.sha256(tgt).hexdigest())
    check("window source segment exposed",
          p.get("windows", [{}])[0].get("source", {}).get("kind") == "SOURCE")
    kinds = [i["kind"] for i in p.get("instructions", [])]
    check("instructions listed in order",
          kinds == ["COPY", "ADD", "COPY", "COPY", "RUN"], str(kinds))
    check("overlapping TARGET copy flagged",
          p["instructions"][3].get("overlap") is True
          and p["instructions"][3].get("origin") == "CURRENT_TARGET")

    bad = bytearray(delta)
    bad[-1] = 0x7F
    status, p = post_json(base, {
        "delta": base64.b64encode(bytes(bad)).decode(),
        "dictionary": base64.b64encode(src).decode(),
    })
    check("corrupt delta -> 422 with raw offset and window",
          status == 422 and isinstance(p.get("raw_offset"), int)
          and p.get("window") == 0 and p.get("ok") is False,
          str(p))

    # Feature sample: prior-window TARGET COPY + near address cache.
    good, expected, corrupt = feature_sample()
    status, p = post_json(base, {"delta": base64.b64encode(good).decode()})
    check("feature sample -> 200, two windows",
          status == 200 and p.get("window_count") == 2, str(p.get("error", "")))
    check("feature sample target bytes", p.get("target_length") == len(expected))
    check("feature sample sha256",
          p.get("sha256") == hashlib.sha256(expected).hexdigest())
    win1_src = p["windows"][1]["source"]
    check("window 1 sourced from prior TARGET",
          win1_src["kind"] == "TARGET" and win1_src["segment_size"] == 16)
    modes = [i.get("mode") for i in p["instructions"]
             if i["window"] == 1]
    check("window 1 uses SELF then near cache",
          modes == ["SELF", "NEAR0", "NEAR0"], str(modes))
    check("window 1 COPY origins are PRIOR_TARGET",
          all(i.get("origin") == "PRIOR_TARGET"
              for i in p["instructions"] if i["window"] == 1))
    status, p = post_json(base, {"delta": base64.b64encode(corrupt).decode()})
    check("corrupt feature sample -> 422 at last raw byte in window 1",
          status == 422 and p.get("window") == 1
          and p.get("raw_offset") == len(corrupt) - 1
          and "has not been generated" in p.get("error", ""), str(p))

    status, p = post_json(base, {"delta": "@@bad@@", "dictionary": ""})
    check("invalid Base64 -> 400", status == 400 and "Base64" in p.get("error", ""))

    if failures:
        print("\n%d smoke check(s) FAILED: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("\nall HTTP smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
