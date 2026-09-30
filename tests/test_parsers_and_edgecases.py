"""
Robustness & Edge-Case Unit Tests for ULPF.

Tests:
  1. Malformed/Corrupted CEF, LEEF, and Firewall logs (No crashes, proper fallback).
  2. Byte-for-byte SHA-256 raw payload preservation.
  3. Dynamic runtime onboarding ("unknown log -> fallback -> register parser -> full parse").
"""

import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.registry import ParserRegistry
from core.base_parser import BaseParser
from core.schema import NormalizedEvent, make_event_id, hash_raw, now_iso


def test_malformed_inputs():
    print("[*] Running Malformed Input Edge-Case Tests...")
    registry = ParserRegistry()

    malformed_lines = [
        b"CEF:BROKEN_HEADER_NO_PIPES",
        b"CEF:0|Vendor|Product|Only4Fields",
        b"LEEF:1.0|Only|Three|Fields",
        b"%ASA-INVALID-SEVERITY-STRING: Teardown TCP connection",
        b"date=2026-09-20 time=12:00:00 BROKEN_KEY_VALUE_NO_EQUALS",
        b"{\"broken_json\": true, missing_quote: 123",
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", # Binary garbage
    ]

    for raw in malformed_lines:
        event = registry.parse_bytes(raw)
        assert event is not None, f"Registry failed to process line: {raw}"
        # Cryptographic check: hash must be exact SHA-256 of input bytes
        expected_hash = hashlib.sha256(raw).hexdigest()
        assert event.raw_hash == expected_hash, f"Hash mismatch for malformed input: {raw}"
        assert event.parse_status in ["full", "fallback"], f"Unexpected parse_status: {event.parse_status}"

    print("    -> All 7 malformed/corrupted log lines safely handled without exceptions!")


def test_dynamic_onboarding():
    print("\n[*] Running Dynamic Runtime Onboarding Test...")
    registry = ParserRegistry()

    unknown_log = b"SIEM_ALERT_V9: APP=AUTHENTICATION ACTION=LOGIN_FAILURE USER=HACKER IP=192.168.10.99"

    # Step 1: Initial parse — unknown format goes to FallbackParser
    event_1 = registry.parse_bytes(unknown_log)
    assert event_1 is not None
    assert event_1.parse_status == "fallback"
    assert event_1.parser_name == "generic_fallback"
    print("    -> Step 1: Unknown log successfully caught by FallbackParser (parse_status='fallback')")

    # Step 2: Dynamically define and register a new parser at runtime
    class SIEMAlertV9Parser(BaseParser):
        name = "siem_alert_v9"
        version = "1.0"

        def can_parse(self, raw_line: str) -> bool:
            return raw_line.startswith("SIEM_ALERT_V9:")

        def parse(self, raw_line: str) -> NormalizedEvent:
            kv = {}
            for token in raw_line.replace("SIEM_ALERT_V9:", "").strip().split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    kv[k] = v

            return NormalizedEvent(
                event_id=make_event_id(),
                ingest_timestamp=now_iso(),
                raw_hash=hash_raw(raw_line.encode("utf-8")),
                raw_payload=raw_line,
                original_format="siem_v9",
                parser_name=self.name,
                parser_version=self.version,
                parse_status="full",
                source_type="security_appliance",
                vendor="CustomSIEM",
                src_ip=kv.get("IP"),
                user=kv.get("USER"),
                action=kv.get("ACTION"),
                outcome="failure",
                severity="high",
                category="security",
                extra=kv,
            )

    registry.register(SIEMAlertV9Parser())
    print("    -> Step 2: Registered SIEMAlertV9Parser into ParserRegistry at runtime (0 pipeline restarts)")

    # Step 3: Reparse same log line — now claimed by new parser!
    event_2 = registry.parse_bytes(unknown_log)
    assert event_2 is not None
    assert event_2.parse_status == "full"
    assert event_2.parser_name == "siem_alert_v9"
    assert event_2.src_ip == "192.168.10.99"
    assert event_2.user == "HACKER"
    print("    -> Step 3: Reparsed log line: Now status='full' (Parser: siem_alert_v9, src_ip=192.168.10.99)!")


if __name__ == "__main__":
    print("======================================================================")
    print("  ULPF: Edge-Case Robustness & Dynamic Onboarding Test Suite")
    print("======================================================================")
    test_malformed_inputs()
    test_dynamic_onboarding()
    print("\n======================================================================")
    print("  ALL EDGE-CASE & ONBOARDING TESTS PASSED (100% SUCCESS)")
    print("======================================================================")
