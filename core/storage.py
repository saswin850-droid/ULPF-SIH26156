"""
Storage layer — SQLite for the hackathon build.

Stores the FULL normalized event as JSON (so we never lose a field,
even ones only present in `extra`), plus indexed columns for the
fields you'd actually query/filter on. At real scale this table's
JSON blob is exactly the shape you'd hand to Elasticsearch/OpenSearch
or a data lake — swapping storage backend later is a translation of
this module, not a redesign.
"""

import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "ulpf.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ingest_timestamp TEXT,
    event_timestamp TEXT,
    original_format TEXT,
    parser_name TEXT,
    parse_status TEXT,
    raw_hash TEXT,
    hostname TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    user TEXT,
    action TEXT,
    outcome TEXT,
    severity TEXT,
    category TEXT,
    full_event_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_format ON events(original_format);
CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def reset_db():
    conn = get_conn()
    conn.execute("DROP TABLE IF EXISTS events")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()



def insert_event(conn, event):
    d = event.to_dict()
    conn.execute(
        """INSERT OR REPLACE INTO events
           (event_id, ingest_timestamp, event_timestamp, original_format,
            parser_name, parse_status, raw_hash, hostname, src_ip, dst_ip,
            user, action, outcome, severity, category, full_event_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            d["event_id"], d["ingest_timestamp"], d["event_timestamp"],
            d["original_format"], d["parser_name"], d["parse_status"],
            d["raw_hash"], d["hostname"], d["src_ip"], d["dst_ip"],
            d["user"], d["action"], d["outcome"], d["severity"],
            d["category"], json.dumps(d, default=str),
        ),
    )


def query_events(conn, severity=None, original_format=None, limit=100):
    q = "SELECT full_event_json FROM events WHERE 1=1"
    params = []
    if severity:
        q += " AND severity = ?"
        params.append(severity)
    if original_format:
        q += " AND original_format = ?"
        params.append(original_format)
    q += " ORDER BY ingest_timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    return [json.loads(r["full_event_json"]) for r in rows]


def get_by_id(conn, event_id):
    row = conn.execute(
        "SELECT full_event_json FROM events WHERE event_id = ?", (event_id,)
    ).fetchone()
    return json.loads(row["full_event_json"]) if row else None


def stats(conn):
    total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    by_format = conn.execute(
        "SELECT original_format, COUNT(*) c FROM events GROUP BY original_format"
    ).fetchall()
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) c FROM events GROUP BY severity"
    ).fetchall()
    return {
        "total_events": total,
        "by_format": {r["original_format"]: r["c"] for r in by_format},
        "by_severity": {r["severity"]: r["c"] for r in by_severity},
    }
