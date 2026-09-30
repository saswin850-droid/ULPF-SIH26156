"""
Dedicated Firewall Vendor Parser for Cisco ASA and Fortinet FortiGate logs.

Examples:
  Cisco ASA:
    %ASA-6-302014: Teardown TCP connection 12345 for outside:192.168.1.100/54321 to inside:10.0.0.5/80 duration 0:00:10 bytes 1024 (user1)

  Fortinet FortiGate:
    date=2026-09-20 time=12:00:00 devname="FGT100D" devid="FGT100D12345" type="traffic" subtype="forward" srcip=192.168.1.20 srcport=51234 dstip=10.0.0.1 dstport=443 action="deny" msg="Traffic denied"
"""

import re
from typing import Optional
from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso


class FirewallVendorParser(BaseParser):
    name = "firewall_vendor_cisco_fortinet"
    version = "1.0"

    CISCO_ASA_REGEX = re.compile(
        r"^(?:<(?P<pri>\d+)>)?(?:[A-Za-z]{3}\s+\d+\s+[\d:]+\s+)?(?:(?P<host>\S+)\s+)?%ASA-(?P<severity_num>\d)-(?P<msg_id>\d+):\s+(?P<message>.*)$"
    )

    CISCO_IP_PORT_REGEX = re.compile(
        r"(?:from|for)\s+(?:\w+:)?(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<src_port>\d+)\s+to\s+(?:\w+:)?(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<dst_port>\d+)"
    )

    CISCO_SEVERITY_MAP = {
        "0": "critical", "1": "critical", "2": "critical",
        "3": "high", "4": "medium", "5": "medium",
        "6": "low", "7": "low"
    }

    def can_parse(self, raw_line: str) -> bool:
        line = raw_line.strip()
        return "%ASA-" in line or "devname=" in line or ("type=\"traffic\"" in line and "srcip=" in line)

    def parse(self, raw_line: str) -> Optional[NormalizedEvent]:
        line = raw_line.strip()

        # Check FortiGate key=value style first
        if "devname=" in line or "srcip=" in line:
            return self._parse_fortigate(raw_line, line)

        # Check Cisco ASA format
        if "%ASA-" in line:
            return self._parse_cisco_asa(raw_line, line)

        return None

    def _parse_cisco_asa(self, raw_line: str, line: str) -> Optional[NormalizedEvent]:
        match = self.CISCO_ASA_REGEX.search(line)
        if not match:
            return None

        gd = match.groupdict()
        msg_id = gd["msg_id"]
        sev_num = gd["severity_num"]
        msg_text = gd["message"]
        hostname = gd.get("host") or "cisco_asa"

        severity = self.CISCO_SEVERITY_MAP.get(sev_num, "medium")

        src_ip, dst_ip = None, None
        src_port, dst_port = None, None

        ip_match = self.CISCO_IP_PORT_REGEX.search(msg_text)
        if ip_match:
            ip_gd = ip_match.groupdict()
            src_ip = ip_gd["src_ip"]
            dst_ip = ip_gd["dst_ip"]
            try:
                src_port = int(ip_gd["src_port"])
            except ValueError:
                src_port = None
            try:
                dst_port = int(ip_gd["dst_port"])
            except ValueError:
                dst_port = None

        action = f"ASA-{msg_id}"
        outcome = "unknown"
        msg_upper = msg_text.upper()
        if any(term in msg_upper for term in ["DENY", "DROP", "DISCARD", "BLOCK", "FAILED"]):
            outcome = "failure"
        elif any(term in msg_upper for term in ["BUILT", "PERMIT", "ALLOWED", "ACCEPTED", "SUCCESS"]):
            outcome = "success"

        raw_bytes = raw_line.encode("utf-8", errors="replace")

        return NormalizedEvent(
            event_id=make_event_id(),
            ingest_timestamp=now_iso(),
            raw_hash=hash_raw(raw_bytes),
            raw_payload=raw_line,
            original_format="cisco_asa",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            source_type="firewall",
            vendor="Cisco",
            hostname=hostname,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            user=None,
            action=action,
            outcome=outcome,
            severity=severity,
            category="network",
            message=msg_text,
            extra={"cisco_msg_id": msg_id},
        )

    def _parse_fortigate(self, raw_line: str, line: str) -> Optional[NormalizedEvent]:
        kv_pairs = re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line)
        kv = {}
        for k, val_q, val_uq in kv_pairs:
            kv[k] = val_q if val_q else val_uq

        src_ip = kv.pop("srcip", None)
        dst_ip = kv.pop("dstip", None)
        src_port = kv.pop("srcport", None)
        dst_port = kv.pop("dstport", None)
        user = kv.pop("user", None) or kv.pop("srcuser", None)
        action = kv.pop("action", None) or "traffic"
        devname = kv.pop("devname", None) or "fortigate"
        msg = kv.pop("msg", None) or f"FortiGate log {kv.get('logid', '')}"
        level = kv.pop("level", None)

        severity = "low"
        if level in ["critical", "alert", "emergency"]:
            severity = "critical"
        elif level in ["error", "high"]:
            severity = "high"
        elif level in ["warning", "notice"]:
            severity = "medium"

        outcome = "unknown"
        if action:
            act_upper = action.upper()
            if any(term in act_upper for term in ["ACCEPT", "ALLOW", "PASS", "PERMIT"]):
                outcome = "success"
            elif any(term in act_upper for term in ["DENY", "DROP", "BLOCK", "REJECT"]):
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
            original_format="fortigate",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            source_type="firewall",
            vendor="Fortinet",
            hostname=devname,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            user=user,
            action=action,
            outcome=outcome,
            severity=severity,
            category="network",
            message=msg,
            extra=kv,
        )
