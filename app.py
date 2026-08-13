"""Small deployable web app for DOCX PII redaction.

It uses only the Python standard library plus the redaction package dependencies,
which keeps free-tier deployment simple.
"""

from __future__ import annotations

import cgi
import html
import os
from pathlib import Path
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from pii_redaction import redact_docx
from pii_redaction.evaluation import write_docx_report, write_markdown_report
from pii_redaction.gold_fixture import run_gold_fixture


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs" / "web"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


class RedactionHandler(BaseHTTPRequestHandler):
    server_version = "PIIRedactor/1.0"

    def do_HEAD(self) -> None:
        if self.path in {"/", "/index.html"}:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self._send_html(render_index())
            return
        if self.path.startswith("/download/"):
            self._serve_download()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if self.path != "/redact":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0 or content_length > MAX_UPLOAD_BYTES:
            self._send_html(render_index("Please upload a DOCX file under 10 MB."), HTTPStatus.BAD_REQUEST)
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": str(content_length),
            },
        )
        file_item = form["file"] if "file" in form else None
        if file_item is None or not getattr(file_item, "filename", ""):
            self._send_html(render_index("Please choose a DOCX file."), HTTPStatus.BAD_REQUEST)
            return

        filename = Path(file_item.filename).name
        if not filename.lower().endswith(".docx"):
            self._send_html(render_index("Only .docx files are supported."), HTTPStatus.BAD_REQUEST)
            return

        job_id = uuid.uuid4().hex
        job_dir = OUTPUT_DIR / job_id
        upload_dir = UPLOAD_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        upload_dir.mkdir(parents=True, exist_ok=True)

        input_path = upload_dir / filename
        data = file_item.file.read()
        input_path.write_bytes(data)

        output_path = job_dir / f"{Path(filename).stem}_redacted.docx"
        report_json = job_dir / "redaction_run.json"
        report_md = job_dir / "evaluation_report.md"
        report_docx = job_dir / "evaluation_report.docx"

        try:
            gold_score, _ = run_gold_fixture(job_dir / "fixture")
            run_report = redact_docx(input_path, output_path, report_json)
            write_markdown_report(run_report, report_md, gold_score)
            write_docx_report(report_md, report_docx)
        except Exception as exc:  # pragma: no cover - defensive for web runtime
            self._send_html(render_index(f"Processing failed: {html.escape(str(exc))}"), HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self._send_html(render_result(job_id, run_report, output_path.name, report_docx.name, report_json.name))

    def _serve_download(self) -> None:
        parts = [unquote(part) for part in self.path.split("/") if part]
        if len(parts) != 3:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        _, job_id, filename = parts
        if not job_id.replace("-", "").isalnum():
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid job")
            return
        safe_name = Path(filename).name
        path = OUTPUT_DIR / job_id / safe_name
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        content_type = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            if safe_name.endswith(".docx")
            else "application/json"
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        print("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))


def render_index(error: str | None = None) -> str:
    error_html = f'<p class="alert">{error}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PII Redaction Tool</title>
  <style>{CSS}</style>
</head>
<body>
  <main class="shell">
    <section class="panel">
      <div>
        <p class="eyebrow">DOCX privacy workflow</p>
        <h1>PII Redaction Tool</h1>
      </div>
      {error_html}
      <form class="upload" action="/redact" method="post" enctype="multipart/form-data">
        <label for="file">DOCX file</label>
        <input id="file" name="file" type="file" accept=".docx" required>
        <button type="submit">Redact document</button>
      </form>
    </section>
  </main>
</body>
</html>"""


def render_result(
    job_id: str,
    run_report: dict,
    output_name: str,
    report_name: str,
    json_name: str,
) -> str:
    counts = run_report.get("counts_by_type", {})
    rows = "\n".join(
        f"<tr><td>{html.escape(entity_type)}</td><td>{count}</td></tr>"
        for entity_type, count in sorted(counts.items())
    )
    rows = rows or "<tr><td>No PII found</td><td>0</td></tr>"
    total = run_report.get("total_replacements", 0)
    residual_count = len(run_report.get("residual_original_values", []))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PII Redaction Results</title>
  <style>{CSS}</style>
</head>
<body>
  <main class="shell">
    <section class="panel">
      <p class="eyebrow">Run complete</p>
      <h1>{total} replacements</h1>
      <div class="summary">
        <span>Residual originals: {residual_count}</span>
        <span>Replacement rate: {run_report.get("detected_candidate_replacement_rate", 1.0):.2%}</span>
      </div>
      <div class="actions">
        <a class="button" href="/download/{job_id}/{html.escape(output_name)}">Download redacted DOCX</a>
        <a class="button secondary" href="/download/{job_id}/{html.escape(report_name)}">Download evaluation DOCX</a>
        <a class="button quiet" href="/download/{job_id}/{html.escape(json_name)}">Download JSON</a>
      </div>
      <table>
        <thead><tr><th>PII type</th><th>Count</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p><a class="textlink" href="/">Process another file</a></p>
    </section>
  </main>
</body>
</html>"""


CSS = """
:root {
  --ink: #17201b;
  --muted: #5e6a63;
  --line: #d6ddd7;
  --paper: #f7f8f5;
  --panel: #ffffff;
  --accent: #2f6f4e;
  --accent-ink: #ffffff;
  --amber: #b87917;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  font-family: Arial, Helvetica, sans-serif;
  color: var(--ink);
  background: var(--paper);
}
.shell {
  width: min(920px, calc(100% - 32px));
  margin: 0 auto;
  padding: 48px 0;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 28px;
  box-shadow: 0 16px 44px rgba(23, 32, 27, 0.08);
}
.eyebrow {
  margin: 0 0 8px;
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}
h1 {
  margin: 0 0 22px;
  font-size: clamp(2rem, 4vw, 3.4rem);
  line-height: 1.02;
  letter-spacing: 0;
}
.upload {
  display: grid;
  gap: 14px;
  max-width: 560px;
}
label {
  font-weight: 700;
}
input[type=file] {
  width: 100%;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 12px;
  background: #fbfcfa;
}
button,
.button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: fit-content;
  min-height: 42px;
  border: 0;
  border-radius: 6px;
  padding: 10px 16px;
  color: var(--accent-ink);
  background: var(--accent);
  font-weight: 700;
  text-decoration: none;
  cursor: pointer;
}
.button.secondary { background: var(--amber); }
.button.quiet {
  color: var(--ink);
  background: #e9eee9;
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin: 18px 0 22px;
}
.summary {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  color: var(--muted);
  font-weight: 700;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 10px;
}
th,
td {
  padding: 12px;
  border-bottom: 1px solid var(--line);
  text-align: left;
}
th {
  color: var(--muted);
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0;
}
.alert {
  max-width: 560px;
  margin: 0 0 16px;
  border-left: 4px solid #b42318;
  background: #fff1ef;
  padding: 12px;
}
.textlink {
  color: var(--accent);
  font-weight: 700;
}
@media (max-width: 560px) {
  .shell { width: min(100% - 20px, 920px); padding: 24px 0; }
  .panel { padding: 20px; }
  .button, button { width: 100%; }
}
"""


def main() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), RedactionHandler)
    print(f"PII Redaction Tool running on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
