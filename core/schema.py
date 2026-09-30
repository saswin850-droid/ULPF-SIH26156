"""
Universal Event Schema for ULPF (SIH26156).

Every parser, regardless of source format, produces one of these.
Field names are kept close to OCSF / ECS naming conventions so a
future export to those standards is a straight mapping, not a rewrite.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import hashlib
import uuid
import json
import time


@dataclass
class NormalizedEvent:
    # --- identity & traceability (satisfies requirement d) ---
    event_id: str
    ingest_timestamp: str
    raw_hash: str              # SHA-256 of the exact raw bytes — independently recomputable
    raw_payload: str           # the original event, byte-for-byte, untouched (requirement a)
    original_format: str       # "syslog" | "json" | "csv" | "cef" | "unknown"

    # --- parser metadata ---
    parser_name: str
    parser_version: str
    parse_status: str          # "full" | "partial" | "fallback"

    # --- normalized fields (requirement c: common taxonomy) ---
    event_timestamp: Optional[str] = None
    source_type: Optional[str] = None      # firewall | server | app | idam | iot | unknown
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None          # success | failure | unknown
    severity: Optional[str] = None         # low | medium | high | critical
    category: Optional[str] = None         # authentication | network | system | security
    message: Optional[str] = None          # human-readable summary if the format has one

    # --- catch-all for fields a specific parser extracts but the
    #     common schema doesn't have a named slot for yet.
    #     Keeps us lossless (requirement a) even for weird vendor fields. ---
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), default=str)


def make_event_id() -> str:
    return str(uuid.uuid4())


def hash_raw(raw_bytes: bytes) -> str:
    """SHA-256 of the raw payload — independently recomputable by an
    investigator who only has the original log file. This is what makes
    traceability (requirement d) real rather than just a foreign key."""
    return hashlib.sha256(raw_bytes).hexdigest()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
