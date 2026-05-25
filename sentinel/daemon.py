"""Sentinel daemon: local HTTP + SSE service backing the Electron UI.

Endpoints
---------
POST   /scan                       Body: {"file_path": "...", "options": {...}}
                                   Returns: {"scan_id": "..."}
GET    /scan/<scan_id>/events      Server-Sent Events stream
                                       data: {"type": "scan.started", "data": {...}, "ts": ...}
                                       data: {"type": "stage.started", ...}
                                       data: {"type": "stage.finished", ...}
                                       data: {"type": "verdict.final", ...}
                                       data: {"type": "end", ...}
DELETE /scan/<scan_id>             Best-effort cancel (between-stages granularity)
GET    /scan/<scan_id>             Full report for a completed scan
GET    /history                    Last 100 scans from reports/
GET    /health                     {"status": "ok", "version": "..."}

Bind: 127.0.0.1 by default, never bind public. CORS open for localhost UI.
"""
import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request, stream_with_context
from flask_cors import CORS

from sentinel import __version__
from sentinel.scanner import CancelledError, ScanOptions, scan_file

REPORTS_DIR = Path("./reports")
MAX_HISTORY = 100
MAX_IN_MEMORY_SCANS = 100
SSE_KEEPALIVE_SECONDS = 25

log = logging.getLogger("sentinel.daemon")


@dataclass
class ScanContext:
    id: str
    file_name: str
    file_path: str
    status: str = "queued"  # queued | running | completed | failed | cancelled
    events: queue.Queue = field(default_factory=queue.Queue)
    cancel: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    report: dict | None = None
    error: str | None = None
    started_at: float = field(default_factory=time.time)


class Scans:
    """Thread-safe in-memory registry of recent scans (live + completed)."""

    def __init__(self, cap: int = MAX_IN_MEMORY_SCANS):
        self._d: dict[str, ScanContext] = {}
        self._lock = threading.Lock()
        self._cap = cap

    def add(self, ctx: ScanContext) -> None:
        with self._lock:
            self._d[ctx.id] = ctx
            # evict oldest completed if over cap
            if len(self._d) > self._cap:
                to_drop = sorted(
                    (k for k, v in self._d.items()
                     if v.status in ("completed", "failed", "cancelled")),
                    key=lambda k: self._d[k].started_at,
                )[: len(self._d) - self._cap]
                for k in to_drop:
                    self._d.pop(k, None)

    def get(self, scan_id: str) -> ScanContext | None:
        with self._lock:
            return self._d.get(scan_id)


SCANS = Scans()


def _run_scan(ctx: ScanContext, opts: ScanOptions) -> None:
    def on_event(ev_type: str, data: dict) -> None:
        ctx.events.put({"type": ev_type, "data": data, "ts": time.time()})

    try:
        ctx.status = "running"
        report = scan_file(
            Path(ctx.file_path),
            opts,
            on_event=on_event,
            cancel_event=ctx.cancel,
        )
        ctx.report = report.model_dump(mode="json")
        ctx.status = "completed"
        from sentinel.report import write_report
        try:
            write_report(report, REPORTS_DIR)
        except Exception as e:
            log.warning("failed to write report file: %s", e)
    except CancelledError:
        ctx.status = "cancelled"
        ctx.events.put({"type": "cancelled", "data": {}, "ts": time.time()})
    except Exception as e:
        ctx.status = "failed"
        ctx.error = str(e)
        ctx.events.put({"type": "error", "data": {"message": str(e)}, "ts": time.time()})
    finally:
        ctx.events.put({"type": "end", "data": {"status": ctx.status}, "ts": time.time()})


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "version": __version__})

    @app.get("/settings")
    def get_settings():
        import os
        from sentinel.verdict import BLOCK_THRESHOLD
        from sentinel.llm.claude_cli import get_ghidra_mode
        from sentinel.ghidra_headless import find_analyze_headless

        def masked(name: str) -> str | None:
            v = os.environ.get(name) or ""
            if not v:
                return None
            if len(v) <= 8:
                return "••••"
            return v[:4] + "•" * 12 + v[-4:]

        env_file = Path(".env").resolve()
        return jsonify({
            "version": __version__,
            "ai_mode": get_ghidra_mode(),
            "block_threshold": BLOCK_THRESHOLD,
            "env_file": str(env_file),
            "env_file_exists": env_file.is_file(),
            "keys": {
                "VT_API_KEY": masked("VT_API_KEY"),
                "TRIAGE_API_KEY": masked("TRIAGE_API_KEY"),
                "MALWAREBAZAAR_API_KEY": masked("MALWAREBAZAAR_API_KEY"),
            },
            "engine": {
                "claude_bin": os.environ.get("SENTINEL_CLAUDE_BIN") or "claude",
                "claude_model": os.environ.get("SENTINEL_CLAUDE_MODEL") or None,
                "ghidra_home": os.environ.get("GHIDRA_HOME"),
                "analyze_headless_path": find_analyze_headless(),
            },
        })

    @app.post("/scan")
    def post_scan():
        data = request.get_json(silent=True) or {}
        file_path = data.get("file_path")
        if not file_path:
            return jsonify({"error": "file_path is required"}), 400
        p = Path(file_path).expanduser()
        if not p.is_file():
            return jsonify({"error": f"{file_path} is not a file"}), 400

        opts_dict = data.get("options") or {}
        opts = ScanOptions(
            upload=bool(opts_dict.get("upload", False)),
            skip_triage=bool(opts_dict.get("skip_triage", False)),
            skip_ai=bool(opts_dict.get("skip_ai", False)),
        )

        scan_id = uuid.uuid4().hex
        ctx = ScanContext(id=scan_id, file_name=p.name, file_path=str(p.resolve()))
        SCANS.add(ctx)
        t = threading.Thread(target=_run_scan, args=(ctx, opts), daemon=True, name=f"scan-{scan_id[:8]}")
        ctx.thread = t
        t.start()
        return jsonify({"scan_id": scan_id, "status": "queued"}), 202

    @app.get("/scan/<scan_id>/events")
    def scan_events(scan_id):
        ctx = SCANS.get(scan_id)
        if ctx is None:
            abort(404)

        def gen():
            while True:
                try:
                    ev = ctx.events.get(timeout=SSE_KEEPALIVE_SECONDS)
                    yield f"data: {json.dumps(ev)}\n\n"
                    if ev["type"] == "end":
                        break
                except queue.Empty:
                    yield ": keepalive\n\n"

        headers = {
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
        return Response(stream_with_context(gen()),
                        mimetype="text/event-stream",
                        headers=headers)

    @app.delete("/scan/<scan_id>")
    def cancel_scan(scan_id):
        ctx = SCANS.get(scan_id)
        if ctx is None:
            abort(404)
        ctx.cancel.set()
        return jsonify({"scan_id": scan_id, "status": "cancelling"})

    @app.get("/scan/<scan_id>")
    def get_scan(scan_id):
        ctx = SCANS.get(scan_id)
        if ctx is not None and ctx.report is not None:
            return jsonify({"status": ctx.status, "report": ctx.report})
        if ctx is not None:
            return jsonify({"status": ctx.status, "error": ctx.error}), 202
        # fall through: look on disk
        path = _find_report_on_disk(scan_id)
        if path is not None:
            try:
                return jsonify({"status": "completed", "report": json.loads(path.read_text())})
            except Exception:
                pass
        abort(404)

    @app.get("/history")
    def history():
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        out = []
        for f in files[:MAX_HISTORY]:
            try:
                r = json.loads(f.read_text())
                out.append({
                    "report_file": f.name,
                    "file_name": r.get("file_name"),
                    "sha256": r.get("sha256"),
                    "size_bytes": r.get("size_bytes"),
                    "final_verdict": r.get("final_verdict"),
                    "started_at": r.get("started_at"),
                    "completed_at": r.get("completed_at"),
                })
            except Exception:
                continue
        return jsonify({"history": out})

    return app


def _find_report_on_disk(scan_id_or_sha_prefix: str) -> Path | None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    prefix = scan_id_or_sha_prefix[:12]
    for f in REPORTS_DIR.glob("*.json"):
        if prefix in f.name:
            return f
    return None


def serve(host: str = "127.0.0.1", port: int = 7331) -> None:
    app = create_app()
    print(f"Sentinel daemon listening on http://{host}:{port}")
    print("  POST   /scan")
    print("  GET    /scan/<id>/events  (SSE)")
    print("  DELETE /scan/<id>")
    print("  GET    /scan/<id>")
    print("  GET    /history")
    print("  GET    /health")
    app.run(host=host, port=port, debug=False, threaded=True)
