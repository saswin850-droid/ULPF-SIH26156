"""
CEF (Common Event Format - Micro Focus ArcSight) Parser.

Format:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Example:
  CEF:0|Cisco|ASA|9.1|106023|Inbound Deny|6|src=192.168.1.50 dst=10.0.0.10 spt=54321 dpt=80 act=DENY
"""

import re
from typing import Optional
from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso


class CEFParser(BaseParser):
    name = "cef_arcsight"
    version = "1.0"

    CEF_HEADER_REGEX = re.compile(
        r"^CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dev_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?:(?P<extension>.*))?$"
    )

    SEVERITY_MAP = {
        "0": "low", "1": "low", "2": "low", "3": "low",
        "4": "medium", "5": "medium", "6": "medium",
        "7": "high", "8": "high", "9": "critical", "10": "critical"
    }

    def can_parse(self, raw_line: str) -> bool:
        return raw_line.startswith("CEF:") or " CEF:" in raw_line

    def parse(self, raw_line: str) -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if " CEF:" in line:
            line = line[line.find("CEF:"):]

        match = self.CEF_HEADER_REGEX.match(line)
        if not match:
            return None

        gd = match.groupdict()
        vendor = gd["vendor"].strip() or None
        product = gd["product"].strip() or None
        signature_id = gd["signature_id"].strip()
        event_name = gd["name"].strip()
        raw_sev = gd["severity"].strip()

        severity = self.SEVERITY_MAP.get(raw_sev, "medium" if raw_sev else None)

        extensions = {}
        ext_str = gd.get("extension") or ""
        if ext_str:
            # Parse k1=v1 k2=v2 extension pairs
            kv_pairs = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', ext_str)
            for k, val_quoted, val_unquoted in kv_pairs:
                extensions[k] = val_quoted if val_quoted else val_unquoted

        src_ip = extensions.pop("src", None) or extensions.pop("sourceAddress", None)
        dst_ip = extensions.pop("dst", None) or extensions.pop("destinationAddress", None)
        src_port = extensions.pop("spt", None) or extensions.pop("sourcePort", None)
        dst_port = extensions.pop("dpt", None) or extensions.pop("destinationPort", None)
        user = extensions.pop("suser", None) or extensions.pop("duser", None) or extensions.pop("user", None)
        action = extensions.pop("act", None) or event_name

        outcome = "unknown"
        if action:
            act_upper = action.upper()
            if any(term in act_upper for term in ["ALLOW", "PERMIT", "ACCEPT", "PASS", "SUCCESS"]):
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
            original_format="cef",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            source_type="security_appliance",
            vendor=vendor,
            hostname=extensions.pop("dvchost", None) or extensions.pop("dvc", None),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            user=user,
            action=action,
            outcome=outcome,
            severity=severity,
            category="security",
            message=event_name,
            extra=extensions,
        )
