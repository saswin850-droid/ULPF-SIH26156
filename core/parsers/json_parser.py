"""
JSON structured log parser — handles app/cloud logs like:
{"timestamp": "...", "level": "ERROR", "user": "admin", "src_ip": "1.2.3.4",
 "action": "login", "result": "failure", "host": "app01"}

Field names vary a lot between vendors, so this maps a small set of
common aliases into the universal schema rather than requiring an
exact shape — that flexibility is most of what "vendor-agnostic"
means in practice for JSON sources.
"""

import json
from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso

FIELD_ALIASES = {
    "hostname": ["host", "hostname", "server", "source_host"],
    "user": ["user", "username", "actor", "account"],
    "src_ip": ["src_ip", "source_ip", "client_ip", "ip"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip"],
    "action": ["action", "event_type", "operation"],
    "outcome": ["result", "outcome", "status"],
    "severity": ["level", "severity", "priority"],
    "event_timestamp": ["timestamp", "time", "@timestamp", "ts"],
    "message": ["message", "msg", "description"],
}

SEVERITY_NORMALIZE = {
    "error": "high", "err": "high", "critical": "critical", "fatal": "critical",
    "warning": "medium", "warn": "medium",
    "info": "low", "debug": "low", "information": "low",
}

OUTCOME_NORMALIZE = {
    "fail": "failure", "failed": "failure", "failure": "failure", "error": "failure",
    "success": "success", "ok": "success", "allowed": "success",
}


def _first_present(d: dict, keys: list):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


class JSONParser(BaseParser):
    name = "json_generic"
    version = "1.0"

    def can_parse(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if not (s.startswith("{") and s.endswith("}")):
            return False
        try:
            json.loads(s)
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    def parse(self, raw_line: str) -> NormalizedEvent:
        raw_bytes = raw_line.encode("utf-8", errors="replace")
        data = json.loads(raw_line.strip())
        # lowercase keys for case-insensitive matching, keep original in `extra`
        lower_data = {k.lower(): v for k, v in data.items()}

        mapped = {}
        used_keys = set()
        for schema_field, aliases in FIELD_ALIASES.items():
            val = _first_present(lower_data, aliases)
            if val is not None:
                mapped[schema_field] = val
                used_keys.update(a for a in aliases if a in lower_data)

        severity = str(mapped.get("severity", "")).lower()
        outcome = str(mapped.get("outcome", "")).lower()

        # anything not consumed by the mapping stays in `extra` — lossless (requirement a)
        leftover = {k: v for k, v in lower_data.items() if k not in used_keys}

        return NormalizedEvent(
            event_id=make_event_id(),
            ingest_timestamp=now_iso(),
            raw_hash=hash_raw(raw_bytes),
            raw_payload=raw_line,
            original_format="json",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            event_timestamp=str(mapped.get("event_timestamp")) if mapped.get("event_timestamp") else None,
            hostname=mapped.get("hostname"),
            user=mapped.get("user"),
            src_ip=mapped.get("src_ip"),
            dst_ip=mapped.get("dst_ip"),
            action=mapped.get("action"),
            outcome=OUTCOME_NORMALIZE.get(outcome, outcome or "unknown"),
            severity=SEVERITY_NORMALIZE.get(severity, severity or "unknown"),
            category="application",
            message=mapped.get("message"),
            extra=leftover,
        )
