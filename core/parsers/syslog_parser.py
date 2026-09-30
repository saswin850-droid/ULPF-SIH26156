"""
Syslog parser (RFC 3164 style — the common BSD/Cisco/firewall variant).

Example line it handles:
<134>Oct 11 22:14:15 fw01 sshd[1234]: Failed password for admin from 10.0.0.5 port 51422 ssh2
"""

import re
from ..base_parser import BaseParser
from ..schema import NormalizedEvent, make_event_id, hash_raw, now_iso

# <PRI>Mon DD HH:MM:SS host process[pid]: message
SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s"
    r"(?P<process>[^\[:]+)(\[(?P<pid>\d+)\])?:\s"
    r"(?P<message>.*)$"
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SEVERITY_MAP = {
    0: "critical", 1: "critical", 2: "critical",  # emerg, alert, crit
    3: "high",                                     # err
    4: "medium",                                   # warning
    5: "low", 6: "low", 7: "low",                  # notice, info, debug
}


class SyslogParser(BaseParser):
    name = "syslog_rfc3164"
    version = "1.0"

    def can_parse(self, raw_line: str) -> bool:
        return bool(SYSLOG_RE.match(raw_line.strip()))

    def parse(self, raw_line: str) -> NormalizedEvent:
        raw_bytes = raw_line.encode("utf-8", errors="replace")
        m = SYSLOG_RE.match(raw_line.strip())
        pri = int(m.group("pri"))
        severity_code = pri % 8  # low 3 bits of PRI = severity per RFC 3164
        message = m.group("message")

        ips = IP_RE.findall(message)
        outcome = "failure" if re.search(r"\bfail(ed|ure)?\b", message, re.I) else (
            "success" if re.search(r"\baccept(ed)?\b|\bsuccess", message, re.I) else "unknown"
        )

        return NormalizedEvent(
            event_id=make_event_id(),
            ingest_timestamp=now_iso(),
            raw_hash=hash_raw(raw_bytes),
            raw_payload=raw_line,
            original_format="syslog",
            parser_name=self.name,
            parser_version=self.version,
            parse_status="full",
            hostname=m.group("host"),
            source_type="network_device",
            action=m.group("process"),
            outcome=outcome,
            severity=SEVERITY_MAP.get(severity_code, "unknown"),
            category="security" if "sshd" in m.group("process") or "fail" in message.lower() else "system",
            src_ip=ips[0] if len(ips) > 0 else None,
            dst_ip=ips[1] if len(ips) > 1 else None,
            message=message,
        )
