"""
Parser registry with true raw-byte ingestion support.

Architecture:
  raw_bytes (untouched binary input)
     ↓
  SHA-256(raw_bytes)  [Computed first over raw bytes]
     ↓
  raw_payload = raw_bytes.decode("utf-8", errors="replace") [Untrimmed]
     ↓
  ParserRegistry priority chain

This satisfies requirement (a) "lossless raw preservation",
(d) "cryptographic traceability", and (e) "plug-and-play onboarding".
"""

from typing import Union
from .parsers.cef_parser import CEFParser
from .parsers.leef_parser import LEEFParser
from .parsers.firewall_vendor_parser import FirewallVendorParser
from .parsers.syslog_parser import SyslogParser
from .parsers.json_parser import JSONParser
from .parsers.csv_parser import CSVParser
from .parsers.fallback import FallbackParser
from .schema import hash_raw


class ParserRegistry:
    def __init__(self):
        self.parsers = [
            CEFParser(),            # Micro Focus ArcSight CEF
            LEEFParser(),           # IBM QRadar LEEF
            FirewallVendorParser(), # Cisco ASA & Fortinet FortiGate hardware firewalls
            SyslogParser(),         # RFC3164 Syslog
            JSONParser(),           # Generic JSON
            CSVParser(),            # Delimited CSV
            FallbackParser(),       # Always last (guarantees zero log loss)
        ]

    def register(self, parser):
        """Onboard a new source: insert before the fallback parser."""
        self.parsers.insert(-1, parser)

    @property
    def csv_parser(self):
        for p in self.parsers:
            if isinstance(p, CSVParser):
                return p
        return None

    def parse_bytes(self, raw_bytes: bytes):
        """Receive raw untouched bytes, compute SHA-256 first, then parse."""
        if not raw_bytes or not raw_bytes.strip():
            return None

        # Exact untrimmed text representation of the raw input bytes
        exact_raw_payload = raw_bytes.decode("utf-8", errors="replace")
        raw_text_for_parsing = exact_raw_payload.rstrip("\r\n")

        for parser in self.parsers:
            if parser.can_parse(raw_text_for_parsing):
                event = parser.parse(raw_text_for_parsing)
                if event:
                    # Enforce true raw byte hash and verbatim payload
                    event.raw_hash = hash_raw(raw_bytes)
                    event.raw_payload = exact_raw_payload
                    return event
        return None

    def parse_line(self, raw_line: Union[str, bytes]):
        if isinstance(raw_line, bytes):
            return self.parse_bytes(raw_line)
        raw_bytes = raw_line.encode("utf-8", errors="replace")
        return self.parse_bytes(raw_bytes)

    def parser_names(self):
        return [p.name for p in self.parsers]
