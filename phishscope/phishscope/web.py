"""Tiny local web UI:  python -m phishscope.web   then open http://127.0.0.1:8080

Binds to localhost only. Uploaded emails are analysed in memory and never saved.
"""
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

from .analyzer import analyze
from .report import CSS, build_report

MAX_BYTES = 10 * 1024 * 1024


def extract_upload(content_type, body, field="eml"):
    """Cut the uploaded file out of a multipart/form-data body.

    Done by hand on purpose: browsers label .eml uploads as message/rfc822, and
    Python's email parser would treat that part as a nested email instead of
    returning the file's raw bytes.
    Returns (file_bytes, filename) or (None, None).
    """
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        return None, None
    delimiter = b"--" + m.group(1).encode()
    for chunk in body.split(delimiter):
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep or f'name="{field}"'.encode() not in head:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        fn = re.search(rb'filename="([^"]*)"', head)
        return data, (fn.group(1).decode("utf-8", "replace") if fn else "upload.eml")
    return None, None

FORM = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PhishScope</title>
<style>{CSS}
.drop{{background:var(--panel);border:2px dashed var(--line);border-radius:6px;padding:40px;text-align:center}}
button{{background:var(--accent);color:#fff;border:0;border-radius:4px;padding:10px 22px;font:inherit;cursor:pointer}}
button:focus-visible,input:focus-visible{{outline:3px solid var(--accent);outline-offset:2px}}
</style></head><body><main><h1>PhishScope</h1>
<p class="sub">Upload a suspicious email saved as .eml. It is analysed in memory and never stored.</p>
<form class="drop" method="post" enctype="multipart/form-data">
<p><input type="file" name="eml" accept=".eml,message/rfc822" required></p>
<button type="submit">Analyze email</button></form>{{msg}}</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, code=200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(FORM.replace("{msg}", ""))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BYTES:
            return self._send(FORM.replace("{msg}", "<p class='high'>File is empty or larger than 10 MB.</p>"), 400)
        body = self.rfile.read(length)
        raw, name = extract_upload(self.headers.get("Content-Type", ""), body)
        if raw:
            return self._send(build_report(analyze(raw, name)))
        self._send(FORM.replace("{msg}", "<p class='high'>No file received.</p>"), 400)

    def log_message(self, *a):  # keep the console quiet
        pass


def main(port=8080):
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print(f"PhishScope running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
