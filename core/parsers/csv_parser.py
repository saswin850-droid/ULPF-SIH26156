"""
CSV parser — common for exported firewall/proxy logs, e.g.:

timestamp,src_ip,dst_ip,src_port,dst_port,action,user
2026-09-19T10:00:01Z,10.0.0.5,142.250.4.10,51422,443,ALLOW,admin

Because CSV has no self-describing structure, this parser needs a
header. In this framework, the FIRST line of a CSV source is consumed
by the ingest layer as the header and handed to every subsequent
parse() call via `set_header()`. This mirrors how a real streaming
ingest pipeline would treat a CSV file: header once, rows many times.
"""

import csv
import io
from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso


class CSVParser(BaseParser):
    name = "csv_generic"
    version = "1.0"

    def __init__(self):
        self.header = None

    def set_header(self, header_line: str):
        self.header = next(csv.reader(io.StringIO(header_line)))

    def can_parse(self, raw_line: str) -> bool:
        if self.header is None:
            return False
        try:
            row = next(csv.reader(io.StringIO(raw_line)))
        except Exception:
            return False
        return len(row) == len(self.header) and "," in raw_line

    def parse(self, raw_line: str) -> NormalizedEvent:
        raw_bytes = raw_line.encode("utf-8", errors="replace")
        row = next(csv.reader(io.StringIO(raw_line)))
        data = dict(zip([h.lower() for h in self.header], row))

        return NormalizedEvent(
            event_id=make_event_id(),
            ingest_timestamp=now_iso(),
            raw_hash=hash_raw(raw_bytes),
            raw_payload=raw_line,
            original_format="csv",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            event_timestamp=data.get("timestamp"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=int(data["src_port"]) if data.get("src_port", "").isdigit() else None,
            dst_port=int(data["dst_port"]) if data.get("dst_port", "").isdigit() else None,
            action=data.get("action"),
            user=data.get("user"),
            source_type="firewall",
            category="network",
            outcome="success" if str(data.get("action", "")).upper() == "ALLOW" else (
                "failure" if str(data.get("action", "")).upper() in ("DENY", "BLOCK", "DROP") else "unknown"
            ),
            extra={k: v for k, v in data.items()
                   if k not in ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "action", "user")},
        )
