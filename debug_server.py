"""Local, no-store host for the isolated 14.02 debug.bin experiment.

The launcher is manual and permits one attempt after a cold boot. This
server only responds to the configured PS4 peer; it never contacts a PS4.
"""

import argparse
import hashlib
import json
import mimetypes
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT.parent / "debug-captures"
DEBUG_HASHES = {
    "debug.bin": "19939e83d0dc57c1172a156503461a333129ebd3f9db704f0dbc3f249ecfcbd5",
    "debug-1402-fixed.bin": "5862bf202a7c5f146820fd6354330dd07b1c6bdbe6e7f939ba71692b5410d083",
}
DEBUG_SIZE = 498720
FILES = frozenset({
    "index.html", "launch.html", "style.css", "launch.js", "jb-g.js",
    "core.js", "mem.js", "int64.js", "ps4_offsets.js", "afterglow-g.js",
    "kernel-format-1402.js", "sha256.js", "debug.bin", "debug-1402-fixed.bin",
})
RUN_RE = re.compile(r"^[0-9]{8,16}-[0-9]{6,20}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
LOG_LOCK = threading.Lock()


def verified_debug_bytes(name):
    content = (ROOT / name).read_bytes()
    if len(content) != DEBUG_SIZE or hashlib.sha256(content).hexdigest() != DEBUG_HASHES[name]:
        raise RuntimeError(name + " differs from the audited file")
    return content


class Handler(BaseHTTPRequestHandler):
    peer = "192.168.1.104"

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def reply(self, code, body=b"", content_type="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.serve()

    def do_GET(self):
        self.serve()

    def serve(self):
        if self.client_address[0] != self.peer:
            self.reply(403, b"PS4 IP address not allowed")
            return
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        if path == "/beacon":
            self.beacon(parsed.query)
            return
        if path == "/":
            path = "/index.html"
        name = path[1:]
        if name not in FILES:
            self.reply(404, b"Not found")
            return
        try:
            content = verified_debug_bytes(name) if name in DEBUG_HASHES else (ROOT / name).read_bytes()
        except (OSError, RuntimeError) as error:
            self.reply(503, str(error).encode("utf-8"))
            return
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if name.endswith(".js"):
            content_type = "text/javascript"
        elif name.endswith(".html"):
            content_type = "text/html"
        elif name.endswith(".css"):
            content_type = "text/css"
        if content_type.startswith("text/"):
            content_type += "; charset=utf-8"
        self.reply(200, content, content_type)

    def beacon(self, query):
        args = parse_qs(query, keep_blank_values=True)
        run = args.get("run", [""])[0]
        tag = args.get("tag", [""])[0]
        detail = args.get("detail", [""])[0]
        if not RUN_RE.fullmatch(run) or not TAG_RE.fullmatch(tag) or len(detail) > 512:
            self.reply(400, b"Invalid checkpoint")
            return
        record = {"time": time.time(), "run": run, "tag": tag, "detail": detail}
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_LOCK:
            with (LOG_DIR / (run + ".jsonl")).open("a", encoding="utf-8") as output:
                output.write(json.dumps(record, ensure_ascii=True) + "\n")
        self.reply(204)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="192.168.1.99")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--peer", default="192.168.1.104")
    args = parser.parse_args()
    for name in DEBUG_HASHES:
        verified_debug_bytes(name)
    Handler.peer = args.peer
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print("Local one-shot host on http://%s:%d/ for %s; manual launch is ENABLED" %
          (args.bind, args.port, args.peer), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
