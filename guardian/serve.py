"""`make serve-runs`: static server for runs/ with CORS (§4.2). Owner: Dev1.

  GET /<run_id>/<file>   files of one run
  GET /latest/<file>     newest run (runs/LATEST), works on Windows without symlinks
  GET /index.json        list of run ids, newest first

Called by `python -m guardian serve-runs` (guardian/cli.py) for the UI's file-based mode: the UI fetches the JSON
artefacts of a run (run_summary.json, findings.json, ...) straight from runs/ with no API process. Read-only,
bound to 127.0.0.1, CORS open to any origin because it serves nothing secret (see `denied` for what is withheld).
Unlike guardian/api/app.py it has no authentication and cannot start runs or record decisions.
"""

from __future__ import annotations

import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from guardian.tools.file_read import is_denied


class RunsHandler(SimpleHTTPRequestHandler):
    """Static handler for runs/: adds CORS and no-cache headers, a run index, "latest", and the G1.1 deny rules."""

    runs_dir: Path  # set by `serve_runs` before the server starts (needed for /latest and /index.json)

    def end_headers(self) -> None:
        """Add CORS and no-store to every response (run files change while a run is in progress)."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        """CORS preflight: answer 204 with the allowed methods."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _runs(self) -> list[str]:
        """Run folder names, newest first (run ids start with "run_" and sort chronologically)."""
        return sorted((p.name for p in self.runs_dir.iterdir() if p.is_dir() and p.name.startswith("run_")),
                      reverse=True)

    def do_GET(self) -> None:  # noqa: N802
        """Serve the synthetic /index.json itself; everything else goes to the stock file handler."""
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
        the raw URL: refuse anything outside runs/, any run's `work/` or `attempts/` copy, and sensitive file names."""
        root = Path(self.directory).resolve()
        target = Path(fs_path).resolve()
        if not target.is_relative_to(root):
            return True
        rel = target.relative_to(root)
        # the work copy and every patched attempt copy (attempts/<id>/work) hold the target's files
        if any(part.casefold() in {"work", "attempts"} for part in rel.parts[1:]):
            return True
        return is_denied(rel)

    def send_head(self):  # shared by GET and HEAD
        # Rewrite /latest/... to the newest run's folder. runs/LATEST is a plain text file, not a symlink,
        # because symlinks need extra privileges on Windows.
        if self.path.startswith("/latest/") or self.path == "/latest":
            latest_file = self.runs_dir / "LATEST"
            latest = latest_file.read_text().strip() if latest_file.exists() else (self._runs() or [""])[0]
            self.path = "/" + latest + self.path[len("/latest"):]
        if self.denied(self.translate_path(self.path)):
            self.send_error(403, "not served (work copy or sensitive file)")
            return None
        return super().send_head()


def serve_runs(runs_dir: Path, port: int = 8001) -> None:
    """Serve `runs_dir` (created if missing) on 127.0.0.1:`port` until Ctrl+C. Blocking."""
    runs_dir.mkdir(parents=True, exist_ok=True)
    handler = partial(RunsHandler, directory=str(runs_dir))
    RunsHandler.runs_dir = runs_dir
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"Serving {runs_dir} on http://localhost:{port}/  (latest run: /latest/run_summary.json)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
