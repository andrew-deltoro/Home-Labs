# PySIEM — Lightweight SIEM/EDR in Python

A minimal, readable, and fully customizable Security Information and Event Management (SIEM) system built from scratch in Python. Designed as a portfolio project and practical learning tool — not a replacement for enterprise solutions, but a working system you can understand end-to-end.

---

## Design Philosophy

Most open-source SIEMs (Wazuh, ELK, Splunk) are powerful but heavy. Standing them up takes hours, the config is XML or proprietary DSL, and you need a cluster just to try them. PySIEM takes the opposite approach:

- **No bloat** — every module does one thing. Ingest logs. Match rules. Store alerts. Show a dashboard.
- **Plain YAML rules** — detection logic lives in human-readable YAML files, not XML or a compiled rule format.
- **Minimal dependencies** — `pip install` and you're running in under 10 minutes.
- **Readable code** — the source is meant to be read and modified, not just deployed.

---

## Architecture

```
Endpoint (Windows)          Server
┌─────────────────┐         ┌──────────────────────────────────────┐
│  agent/         │  HTTP   │  server/                             │
│  ┌───────────┐  │ ──────► │  ┌────────────┐  ┌───────────────┐  │
│  │log_reader │  │         │  │ ingestion/ │  │   rules/      │  │
│  │forwarder  │  │         │  │  receiver  │─►│  rule_engine  │  │
│  └───────────┘  │         │  └────────────┘  └──────┬────────┘  │
└─────────────────┘         │                         │           │
                            │                  ┌──────▼────────┐  │
                            │                  │  database/    │  │
                            │                  │  alerts.db    │  │
                            │                  └──────┬────────┘  │
                            │                         │           │
                            │                  ┌──────▼────────┐  │
                            │                  │  dashboard/   │  │
                            │                  │  Flask UI     │  │
                            │                  └───────────────┘  │
                            └──────────────────────────────────────┘
```

### Components

| Path | Role |
|---|---|
| `agent/` | Runs on the monitored Windows endpoint. Reads Windows Event Logs and Sysmon events, then forwards them to the server over HTTP. |
| `server/ingestion/` | Receives log events from agents via a REST API endpoint. |
| `server/rules/` | Loads YAML rule files and evaluates each incoming log event against them. |
| `server/database/` | Stores triggered alerts in a local SQLite database. |
| `server/dashboard/` | Flask web app that displays alerts in real time. |
| `rules/` | Your detection rules, written in plain YAML. |
| `config/` | Server and agent configuration files. |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Windows endpoint (for the agent; server runs anywhere)

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
python server/main.py
```

The server starts on `http://localhost:5000`. The dashboard is at `http://localhost:5000/`.

### 3. Start the agent (on the monitored machine)

Edit `config/agent.yaml` to point at your server, then:

```bash
python agent/main.py
```

The agent begins reading Windows Event Logs and forwarding them every 5 seconds.

### 4. Write a detection rule

Drop a `.yaml` file in `rules/`. Rules are reloaded automatically. Example:

```yaml
id: suspicious_powershell
name: Suspicious PowerShell Execution
description: Detects PowerShell launched with encoded command flag
severity: high
source: windows_event_log
conditions:
  - field: EventID
    operator: equals
    value: 4104
  - field: Message
    operator: contains
    value: "-EncodedCommand"
```

---

## Writing Detection Rules

Rules live in `rules/*.yaml`. Each rule has:

| Field | Description |
|---|---|
| `id` | Unique rule identifier (snake_case) |
| `name` | Human-readable name shown in the dashboard |
| `description` | What this rule detects and why it matters |
| `severity` | `low`, `medium`, `high`, or `critical` |
| `source` | Log source: `windows_event_log` or `sysmon` |
| `conditions` | List of field checks. All conditions must match (AND logic). |

### Condition operators

| Operator | Behavior |
|---|---|
| `equals` | Exact match |
| `contains` | Substring match |
| `startswith` | Prefix match |
| `regex` | Full Python regex match |
| `greater_than` | Numeric comparison |

### Rule example — failed logon spike

```yaml
id: failed_logon
name: Failed Logon Attempt
description: Windows logon failure (wrong password, locked account, etc.)
severity: medium
source: windows_event_log
conditions:
  - field: EventID
    operator: equals
    value: 4625
```

---

## Project Structure

```
my-siem/
├── agent/
│   ├── __init__.py
│   ├── main.py            # Entry point — starts the agent loop
│   ├── log_reader.py      # Reads Windows Event Log and Sysmon events
│   └── forwarder.py       # Sends log events to the server via HTTP
│
├── server/
│   ├── main.py            # Entry point — starts Flask + ingestion
│   ├── ingestion/
│   │   ├── __init__.py
│   │   └── receiver.py    # REST endpoint that accepts log events
│   ├── rules/
│   │   ├── __init__.py
│   │   └── engine.py      # Loads YAML rules and matches events
│   ├── database/
│   │   ├── __init__.py
│   │   └── store.py       # SQLite read/write for alerts
│   └── dashboard/
│       ├── __init__.py
│       ├── app.py         # Flask routes for the web UI
│       ├── templates/
│       │   └── index.html # Dashboard template
│       └── static/
│           └── style.css  # Minimal styles
│
├── rules/                 # Your YAML detection rules go here
│   ├── failed_logon.yaml
│   ├── suspicious_powershell.yaml
│   └── new_service_installed.yaml
│
├── config/
│   ├── server.yaml        # Server host, port, DB path
│   └── agent.yaml         # Server URL, poll interval, log sources
│
├── tests/
│   ├── test_rule_engine.py
│   └── test_database.py
│
├── requirements.txt
└── README.md
```

---

## Dependencies

Kept deliberately minimal:

| Package | Why |
|---|---|
| `flask` | Web dashboard and REST API receiver |
| `pyyaml` | Parse YAML rule files and config |
| `pywin32` | Read Windows Event Logs from the agent |
| `requests` | Agent HTTP forwarding |

No message queues, no Elasticsearch, no Docker required.

---

## Extending PySIEM

The codebase is designed to be forked and extended. Common additions:

- **Email/Slack alerting** — add a notifier module that subscribes to new alerts from the database
- **IP enrichment** — call a threat intel API (AbuseIPDB, VirusTotal) on each alert's source IP
- **Correlation rules** — add a `window` field to rules to count events over time
- **Agent encryption** — wrap the HTTP transport in TLS with a pre-shared key
- **Linux agent** — swap `log_reader.py` for a journald/syslog reader; the rest is identical

---

## Learning Goals

Building and running this project teaches:

1. How Windows Event Log works and which Event IDs matter
2. What Sysmon is and why defenders use it
3. How a detection rule engine evaluates log events
4. How SIEM alert pipelines are structured (ingest → enrich → match → store → visualize)
5. How to build a minimal REST API + web dashboard with Flask

---

## License

MIT — use it, fork it, and put it on your resume.
