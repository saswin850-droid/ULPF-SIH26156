# ULPF — Universal Log Pre-processing Framework
### SIH26156 · NTRO · Blockchain & Cybersecurity

Ingests logs from heterogeneous formats (**Syslog RFC3164, JSON, CSV, CEF ArcSight, LEEF QRadar, Cisco ASA, Fortinet FortiGate** — with guaranteed fallback for unknown formats), normalizes them into an OCSF-aligned common taxonomy with a zero-loss extension bucket, and preserves raw log payloads with SHA-256 cryptographic hashes computed directly over binary input bytes. Deployable in a container, including fully offline / air-gapped environments.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run automated test suite (verifies 32 events, 7 files, malformed inputs, dynamic onboarding)
python demo_runner.py

# 3. Start the Web API
python -m uvicorn api.main:app --reload --port 8000

# 4. Open http://localhost:8000/docs for interactive API documentation
```

## Demo Flow

1. `python demo_runner.py` — clean database initialization + live verification of 32 multi-source events across 6 native parsers, 7 sample files, 7 malformed edge-cases, and dynamic runtime onboarding
2. `GET /stats` — see cross-vendor event counts grouped by format and severity
3. `GET /events?format=cisco_asa` — filter normalized events across security firewalls
4. `GET /events/{event_id}` — inspect forensic trace: `raw_payload`, `raw_hash`, and normalized fields side-by-side
5. `GET /events/export/ndjson` — true HTTP chunked streaming NDJSON export for SIEM / Data Lake loaders
6. `POST /ingest/line` — paste any raw log line live and watch it parse and hash instantly

## Docker (Air-Gapped Deployment)

```bash
# Build container image (requires internet for pip dependencies)
docker build -t ulpf:latest .

# Run completely offline — 100% air-gapped test
docker run --rm --network none ulpf:latest python demo_runner.py
```

## Architecture

```
Raw log bytes (Syslog / JSON / CSV / CEF / LEEF / Cisco ASA / FortiGate / Unknown)
   │
SHA-256(raw_bytes) computed over exact input bytes
   │
Parser Registry (Priority-chain execution of can_parse())
   │
[CEFParser] [LEEFParser] [FirewallVendorParser] [SyslogParser] [JSONParser] [CSVParser] [FallbackParser -- always last]
   │
NormalizedEvent (raw_payload + raw_hash SHA-256 + OCSF-aligned taxonomy + extra bucket)
   │
SQLite storage layer (indexed columns + full canonical JSON)
   │
FastAPI query & chunked streaming export layer
```

## Adding a New Log Source (Plug-and-Play, Requirement e)

1. Create a new module in `core/parsers/`, subclassing `BaseParser`
2. Implement `can_parse(raw_line) -> bool` and `parse(raw_line) -> NormalizedEvent`
3. Register it in `core/registry.py` before `FallbackParser` (can be executed dynamically at runtime with `registry.register(new_parser)`)

No other file needs to change.

## What's Implemented vs. Production Roadmap (Honest Scope)

**Implemented Core (MVP):**
- 6 native format parsers (Syslog RFC3164, JSON, CSV, CEF ArcSight, LEEF QRadar, Cisco ASA / FortiGate) + generic FallbackParser
- True byte-preserving raw payload retention with independently-recomputable SHA-256 cryptographic hash (`parse_bytes`)
- Common OCSF-aligned normalized taxonomy with `extra` overflow dictionary
- Robust edge-case handling (passed 7/7 malformed input corruption tests)
- FastAPI REST interface with filtering, single-event forensic lookup, and chunked NDJSON streaming
- Docker packaging, verified under `--network none` air-gapped mode

**Production Roadmap:**
- XML, NetFlow/IPFIX, Windows EVTX parsers
- Billions-of-events/day scale — swapping SQLite storage for an Apache Kafka ingestion buffer + horizontally scaled worker pods feeding OpenSearch and Apache Iceberg
- Batch Merkle Tree cryptographic sealing over hourly log blocks
- Real-time ML anomaly detection pipeline feeding directly from NDJSON streams

## Tech Stack

Python 3.11 · FastAPI · SQLite · Docker
