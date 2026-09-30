"""
Ingestion CLI with true raw-byte retention.

Usage:
    python -m core.ingest sample_logs/syslog_sample.log
    python -m core.ingest sample_logs/firewall_sample.csv --format csv
"""

import argparse
import sys
from .registry import ParserRegistry
from .storage import init_db, get_conn, insert_event


def ingest_file(path: str, is_csv: bool = False):
    registry = ParserRegistry()
    init_db()
    conn = get_conn()

    counts = {}
    total = 0

    with open(path, "rb") as f:
        raw_content = f.read()

    lines = [line for line in raw_content.splitlines(keepends=True) if line.strip()]

    if is_csv and lines:
        header_str = lines[0].decode("utf-8", errors="replace").strip()
        registry.csv_parser.set_header(header_str)
        lines = lines[1:]  # header consumed, don't parse it as a row

    for raw_bytes in lines:
        event = registry.parse_bytes(raw_bytes)
        if event is None:
            continue
        insert_event(conn, event)
        total += 1
        counts[event.parse_status] = counts.get(event.parse_status, 0) + 1

    conn.commit()
    conn.close()

    print(f"Ingested {total} events from {path}")
    for status, count in counts.items():
        print(f"  {status}: {count}")


def main():
    ap = argparse.ArgumentParser(description="ULPF ingestion CLI")
    ap.add_argument("path", help="Path to a log file to ingest")
    ap.add_argument("--format", choices=["auto", "csv"], default="auto",
                     help="Force CSV header handling; default auto-detects by extension")
    args = ap.parse_args()

    is_csv = args.format == "csv" or args.path.lower().endswith(".csv")
    ingest_file(args.path, is_csv=is_csv)


if __name__ == "__main__":
    sys.exit(main())
