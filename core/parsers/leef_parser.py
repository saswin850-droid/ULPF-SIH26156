"""
LEEF (Log Event Extended Format - IBM QRadar) Parser.

Format:
  LEEF:1.0|Vendor|Product|Version|EventID|Extension
  LEEF:2.0|Vendor|Product|Version|EventID|DelimiterCharacter|Extension

Example:
  LEEF:1.0|Microsoft|MSExchange|2016|1002|src=10.0.0.15 dst=172.16.0.4 usr=jdoe act=LOGIN outcome=success
"""

import re
from typing import Optional
from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso


class LEEFParser(BaseParser):
    name = "leef_qradar"
    version = "1.0"

    def can_parse(self, raw_line: str) -> bool:
        return raw_line.startswith("LEEF:") or " LEEF:" in raw_line

    def parse(self, raw_line: str) -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if " LEEF:" in line:
            line = line[line.find("LEEF:"):]

        parts = line.split("|")
        if len(parts) < 6:
            return None

        hdr_prefix = parts[0]  # LEEF:1.0 or LEEF:2.0
        vendor = parts[1].strip() or None
        product = parts[2].strip() or None
        event_id_str = parts[4].strip()

        delimiter = "\t"
        ext_index = 5

        if hdr_prefix == "LEEF:2.0" and len(parts) >= 7:
            delimiter = parts[5] if parts[5] else "\t"
            ext_index = 6

        ext_str = "|".join(parts[ext_index:])

        extensions = {}
        if delimiter in ext_str:
            kv_tokens = ext_str.split(delimiter)
        else:
            # Fallback to key=value space splitting
            kv_tokens = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', ext_str)
            for k, val_q, val_uq in kv_tokens:
                extensions[k] = val_q if val_q else val_uq
            kv_tokens = []

        for token in kv_tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                extensions[k.strip()] = v.strip()

        src_ip = extensions.pop("src", None) or extensions.pop("sourceAddress", None)
        dst_ip = extensions.pop("dst", None) or extensions.pop("destinationAddress", None)
        src_port = extensions.pop("spt", None) or extensions.pop("sourcePort", None)
        dst_port = extensions.pop("dpt", None) or extensions.pop("destinationPort", None)
        user = extensions.pop("usr", None) or extensions.pop("username", None) or extensions.pop("user", None)
        action = extensions.pop("act", None) or event_id_str

        outcome = extensions.pop("outcome", None) or "unknown"
        if outcome == "unknown" and action:
            act_upper = action.upper()
            if any(term in act_upper for term in ["ALLOW", "PERMIT", "ACCEPT", "PASS", "SUCCESS", "LOGIN"]):
                outcome = "success"
            elif any(term in act_upper for term in ["DENY", "BLOCK", "DROP", "FAIL", "REJECT"]):
                outcome = "failure"

        try:
            src_port = int(src_port) if src_port else None
        except ValueError:
            src_port = None

        try:
            dst_port = int(dst_port) if dst_port else None
        except ValueError:
            dst_port = None

        raw_bytes = raw_line.encode("utf-8", errors="replace")

        return NormalizedEvent(
            event_id=make_event_id(),
            ingest_timestamp=now_iso(),
            raw_hash=hash_raw(raw_bytes),
            raw_payload=raw_line,
            original_format="leef",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            source_type="security_appliance",
            vendor=vendor,
            hostname=extensions.pop("devname", None) or extensions.pop("identHostName", None),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            user=user,
            action=action,
            outcome=outcome,
            severity=extensions.pop("sev", None) or extensions.pop("cat", None),
            category="security",
            message=f"{product} event {event_id_str}",
            extra=extensions,
        )
