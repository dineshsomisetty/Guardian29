"""`make serve-runs`: static server for runs/ with CORS (§4.2). Owner: Dev1.

  GET /<run_id>/<file>   files of one run
  GET /latest/<file>     newest run (runs/LATEST), works on Windows without symlinks
  GET /index.json        list of run ids, newest first
"""

from __future__ import annotations

import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from guardian.tools.file_read import is_denied


class RunsHandler(SimpleHTTPRequestHandler):
    runs_dir: Path

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _runs(self) -> list[str]:
        return sorted((p.name for p in self.runs_dir.iterdir() if p.is_dir() and p.name.startswith("run_")),
                      reverse=True)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] == "/index.json":
            body = json.dumps({"runs": self._runs()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def denied(self, fs_path: str) -> bool:
        """G1.1, decided on the resolved file path (after URL decoding, `.`/`..`, case and symlinks), not on
        the raw URL: refuse anything outside runs/, any run's `work/` copy, and sensitive file names."""
        root = Path(self.directory).resolve()
        target = Path(fs_path).resolve()
        if not target.is_relative_to(root):
            return True
        rel = target.relative_to(root)
        if len(rel.parts) >= 2 and rel.parts[1].casefold() == "work":
            return True
        return is_denied(rel)

    def send_head(self):  # shared by GET and HEAD
        if self.path.startswith("/latest/") or self.path == "/latest":
            latest_file = self.runs_dir / "LATEST"
            latest = latest_file.read_text().strip() if latest_file.exists() else (self._runs() or [""])[0]
            self.path = "/" + latest + self.path[len("/latest"):]
        if self.denied(self.translate_path(self.path)):
            self.send_error(403, "not served (work copy or sensitive file)")
            return None
        return super().send_head()


def serve_runs(runs_dir: Path, port: int = 8001) -> None:
    runs_dir.mkdir(parents=True, exist_ok=True)
    handler = partial(RunsHandler, directory=str(runs_dir))
    RunsHandler.runs_dir = runs_dir
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"Serving {runs_dir} on http://localhost:{port}/  (latest run: /latest/run_summary.json)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
