"""
ULPF API — satisfies:
  (f) unified visibility  — /events lets you query across every source in one place
  (g) SIEM/data lake integration — /events/export gives NDJSON any downstream tool can ingest
  (h) AI/ML-ready — the normalized JSON is already a clean feature set for ML pipelines

Run:
    uvicorn api.main:app --reload --port 8000
Then visit http://localhost:8000/docs for interactive API docs (auto-generated).
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
from typing import Optional
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.registry import ParserRegistry
from core.storage import init_db, get_conn, insert_event, query_events, get_by_id, stats

app = FastAPI(
    title="Universal Log Pre-processing Framework (ULPF)",
    description="SIH26156 — NTRO. Ingests logs of any format, normalizes to a "
                "common schema, preserves raw bytes with SHA-256 traceability.",
    version="0.1.0",
)

init_db()


@app.on_event("startup")
def startup():
    init_db()


from fastapi.responses import HTMLResponse, StreamingResponse

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(dashboard_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/status")
def root_api():
    return {
        "name": "ULPF",
        "status": "running",
        "registered_parsers": ParserRegistry().parser_names(),
    }



@app.get("/stats")
def get_stats():
    conn = get_conn()
    result = stats(conn)
    conn.close()
    return result


@app.get("/events")
def list_events(severity: Optional[str] = None, format: Optional[str] = None, limit: int = 100):
    conn = get_conn()
    events = query_events(conn, severity=severity, original_format=format, limit=limit)
    conn.close()
    return {"count": len(events), "events": events}


@app.get("/events/{event_id}")
def get_event(event_id: str):
    conn = get_conn()
    event = get_by_id(conn, event_id)
    conn.close()
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


from fastapi.responses import StreamingResponse

@app.get("/events/export/ndjson")
def export_ndjson(limit: int = 1000):
    """NDJSON chunked streaming export — standard format for SIEM / Data Lake ingestion (requirement g)."""
    def event_generator():
        conn = get_conn()
        events = query_events(conn, limit=limit)
        conn.close()
        for e in events:
            yield json.dumps(e, default=str) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")



@app.post("/ingest/line")
def ingest_single_line(raw_line: str):
    """Ingest one raw log line directly — useful for the live demo:
    paste any log line and watch it get classified and normalized."""
    registry = ParserRegistry()
    event = registry.parse_line(raw_line)
    if event is None:
        raise HTTPException(status_code=400, detail="Empty line")
    conn = get_conn()
    insert_event(conn, event)
    conn.commit()
    conn.close()
    return event.to_dict()


@app.post("/ingest/file")
async def ingest_file_upload(file: UploadFile = File(...)):
    """Upload a log file and ingest every line — demonstrates plug-and-play
    handling of a new source file without any code changes (requirement e)."""
    registry = ParserRegistry()
    raw_content = await file.read()
    lines = [line for line in raw_content.splitlines(keepends=True) if line.strip()]

    is_csv = file.filename.lower().endswith(".csv")
    if is_csv and lines:
        header_str = lines[0].decode("utf-8", errors="replace").strip()
        registry.csv_parser.set_header(header_str)
        lines = lines[1:]

    conn = get_conn()
    counts = {}
    for raw_bytes in lines:
        event = registry.parse_bytes(raw_bytes)
        if event is None:
            continue
        insert_event(conn, event)
        counts[event.parse_status] = counts.get(event.parse_status, 0) + 1
    conn.commit()
    conn.close()

    return {"filename": file.filename, "ingested": sum(counts.values()), "by_status": counts}

