"""
Generic fallback parser.

If no registered parser claims a line, this one always does — it's
the last thing checked in the registry. It guarantees requirement (a),
"preserve complete raw event data without information loss," even for
a vendor format we've never seen: the raw bytes and hash are still
captured, just with parse_status="fallback" instead of "full".

This is a deliberately small, honest piece of the system — it does not
try to guess field meaning (see ULPF reference project's note: "wrong
evidence in an investigation is the failure this exists to prevent").
"""

from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso


class FallbackParser(BaseParser):
    name = "generic_fallback"
    version = "1.0"

    def can_parse(self, raw_line: str) -> bool:
        return True  # always claims — must be registered LAST

    def parse(self, raw_line: str) -> NormalizedEvent:
        raw_bytes = raw_line.encode("utf-8", errors="replace")
        return NormalizedEvent(
            event_id=make_event_id(),
            ingest_timestamp=now_iso(),
            raw_hash=hash_raw(raw_bytes),
            raw_payload=raw_line,
            original_format="unknown",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="fallback",
            message=raw_line[:500],
        )
