# PySIEM Development Log

A running journal of every build decision made in this project — what was built, why, what was considered, and what it teaches about SIEM architecture.

---

## 2026-06-14 — Bugfix: `/static/` 404s caused by Flask app-level route shadowing blueprint

### What changed
- `server/main.py`: `Flask(__name__)` → `Flask(__name__, static_folder=None)`

### What was wrong
When `Flask(__name__)` creates an application instance it automatically registers a `/static/<path:filename>` route pointing to a `static/` folder relative to the application's root (which for `server/main.py` is `server/static/` — a directory that doesn't exist). The dashboard blueprint also registers its own `/static/<path:filename>` route, pointing to `server/dashboard/static/` where the actual files live.

Flask resolves URL conflicts by using the first matching route. Because the app-level endpoint is registered before any blueprints, every request to `/static/style.css` hit the app's missing folder and returned 404. The blueprint's correct handler was never reached.

```
Before:  /static/<filename>  →  static       (app-level, no folder) ← matched first → 404
         /static/<filename>  →  dashboard.static  (blueprint, has files) ← never reached

After:   /static/<filename>  →  dashboard.static  (blueprint, has files) ← only endpoint → 200
```

### What to understand about this as a SIEM learner

This is a general Flask lesson worth knowing: `Flask(__name__)` always sets up a `/static` route unless you explicitly opt out with `static_folder=None`. When you register a blueprint that also serves `/static`, the app-level route wins silently. The fix is one parameter, but the symptom (404 in browser, files obviously present on disk) looks like a file path problem, not a routing problem — which makes it easy to misdiagnose.

The broader principle: **two routes with identical URL patterns are a conflict, not a fallback chain**. Flask doesn't try the second one if the first returns 404. If you ever see static files present on disk but returning 404 from Flask, check for duplicate endpoint registrations with `app.url_map.iter_rules()` before checking file paths.

---

## 2026-06-14 — Server entry point and agent (`server/main.py`, `agent/`)

### What was built
- `server/main.py` — `load_config()`, `create_app()`, `main()`: reads YAML config, wires Flask blueprints, starts server
- `agent/log_reader.py` — `EventReader` class: reads Windows Event Log via pywin32, tracks a high-water RecordNumber to avoid re-sending events
- `agent/forwarder.py` — `forward_events()`: POSTs a batch of events to `/ingest`, raises on network failure
- `agent/main.py` — main loop: one `EventReader` per channel, collect → forward → sleep
- `tests/test_main.py` — 11 tests on `create_app` and `load_config` (route registration, DB init, rule loading)
- `tests/test_forwarder.py` — 11 tests on `forward_events` using `unittest.mock` (no real HTTP)
- Updated `config/agent.yaml` to include `source` field on each log source entry

### Why built this way

**`create_app(db_path, rules_dir)` is separated from `main()`.** `main()` reads config and calls `app.run()`, which blocks forever. If `create_app` were merged into `main()`, there would be no way to test the app construction without starting a real server. Separating them makes the construction logic fully testable: `test_main.py` calls `create_app()` directly, gets back a Flask app, and inspects it with a test client. The same pattern is used across all four modules in this project.

**`EventReader` uses a `_high_water` mark instead of timestamps.** Windows Event Log records each have a `RecordNumber` — a monotonically increasing integer assigned by the OS when the event is written. Tracking the highest RecordNumber seen is more reliable than tracking timestamps: two events written in the same second will have different RecordNumbers but identical timestamps. High-water marks are also how Kafka consumer offsets work — you don't re-process messages you've already consumed.

**Reading backwards, returning forwards.** `win32evtlog.ReadEventLog` with `EVENTLOG_BACKWARDS_READ` returns the newest event first. We stop reading as soon as we hit an event we've already seen, then reverse the collected list before returning it. This means: (a) we don't read the entire channel on every cycle — we stop early once we reach the high-water mark, and (b) events arrive at the server in chronological order, which is what you'd expect when inserting into a time-ordered table.

**`EventID & 0xFFFF` strips Windows severity/facility bits.** The raw `EventID` field in a Windows event record isn't just the event number. Microsoft packs facility codes and severity flags into the upper 16 bits. Event 4625 is stored as `0xC0040011` or similar, not `0x1191`. Masking with `0xFFFF` extracts the bottom 16 bits — the actual Event ID number that matches what's in Microsoft documentation and your YAML rules.

**`forward_events` raises on failure instead of swallowing exceptions.** The agent's main loop catches exceptions from `forward_events` and logs them, but the forwarder itself raises. This keeps the forwarder simple and honest — it doesn't know whether a failure is retryable or fatal. The caller (the main loop) decides what to do: in this case, log and move on so the agent doesn't die if the server is temporarily unreachable. A production agent would also buffer unsent events and retry them.

**`unittest.mock` for forwarder tests instead of a real server.** The forwarder is a thin wrapper around `requests.post`. Its logic lives entirely in three lines: construct URL, post JSON, raise on error. Testing this with a real running server would be testing `requests` (already tested by its own maintainers) rather than our logic. Mocking `requests.post` lets us verify exactly what URL and JSON we're calling with, and simulate both success and failure paths with zero network overhead.

### Alternatives considered

| Decision | Alternative | Why rejected |
|---|---|---|
| `create_app` separate from `main()` | Single monolithic `main()` | Untestable — `app.run()` blocks; can't construct app without starting a server |
| High-water RecordNumber | Timestamp-based deduplication | Two events in the same second would both match a timestamp cursor; RecordNumber is unique |
| Backwards read + reverse | Forwards read from offset | `EVENTLOG_SEEK_READ` with an offset requires knowing the right offset up front; backwards read with an early-stop is simpler |
| `EventID & 0xFFFF` | Pass raw EventID | Raw IDs don't match Microsoft documentation or what analysts know (4625, 4688, etc.) |
| Raise on network failure | Return None / log and continue inside forwarder | Hides failures from the caller; makes the forwarder dishonest about its result |
| `unittest.mock` for forwarder tests | `responses` library | Another dependency for a test concern; standard library mock is sufficient |

### What to understand about this as a SIEM learner

**The agent is a sensor, not a brain.** `agent/` contains no detection logic at all — no rules, no pattern matching, no database. Its only job is to read events and forward them. All intelligence lives on the server. This is the *dumb sensor, smart backend* architecture used by every real EDR: CrowdStrike Falcon Sensor, Carbon Black's CBC sensor, and Microsoft Defender for Endpoint all operate this way. The advantage is that you can update detection logic (rules) on the server without touching the endpoint at all — no re-deployment, no endpoint downtime.

**`RecordNumber` as a cursor is how all streaming systems work.** Kafka calls it an *offset*. PostgreSQL WAL replication calls it an *LSN (Log Sequence Number)*. AWS Kinesis calls it a *shard iterator*. Redis Streams calls it a *stream ID*. The concept is universal: you maintain a pointer into an ordered sequence of events and advance it as you consume. You never re-process events before the pointer (that's a duplicate), and you never skip events after it (that's a gap). The Windows Event Log high-water mark in `EventReader._high_water` is the same pattern.

**Why `pywin32` and not WMI or the Windows Event Forwarding API?** Windows has several ways to read event logs: `pywin32` (direct API), `python-evtx` (parse exported `.evtx` files), WMI, the Windows Event Forwarding (WEF) service, and PowerShell `Get-WinEvent`. `pywin32` is the lowest-level and most direct — it calls the Windows API functions that everything else is built on. WEF is the enterprise solution (it lets one machine subscribe to another's logs over the network) but requires Group Policy and domain membership. For a local agent, direct API access is the simplest path.

**The agent's error handling design choice.** When `forward_events` raises, the agent logs the error and continues to the next sleep cycle. This means events collected during that cycle are *lost* — they won't be re-sent. A production agent would maintain a local queue (a SQLite database or a memory buffer) of unsent events and retry them. We deliberately skip this because it doubles the complexity and, for a learning project running on a single machine, a dropped batch once in a while is acceptable. Understanding that this trade-off exists — and knowing how to add a retry queue if you needed it — is the important lesson.

---

## 2026-06-14 — Flask dashboard (`server/dashboard/`)

### What was built
- `server/dashboard/app.py` — Flask blueprint with four routes: `GET /`, `GET /api/alerts`, `GET /api/stats`, `GET /api/alerts/count`
- `server/dashboard/templates/index.html` — single-page dashboard: severity stat cards, filter buttons, alert table
- `server/dashboard/static/style.css` — dark theme, severity color palette, no external dependencies
- `server/dashboard/static/dashboard.js` — auto-refresh via polling, vanilla `fetch()` + `setInterval`, XSS escaping
- `tests/test_dashboard.py` — 15 tests covering all four API endpoints, filtering, field presence, and edge cases

### Why built this way

**Four routes, not one.** The dashboard exposes its data through three separate API endpoints rather than one big "give me everything" endpoint. `GET /api/alerts` returns the alert list. `GET /api/stats` returns severity counts. `GET /api/alerts/count` returns just a number. This separation lets the UI be smart: every 5 seconds it calls the cheap `/count` endpoint first — one integer over the wire — and only triggers the heavier `/alerts` fetch if something actually changed. The alternative (re-fetching all 200 alerts every 5 seconds) is wasteful when most cycles produce zero new alerts.

**Polling, not WebSockets.** A WebSocket connection would push new alerts to the browser instantly without any polling delay. That's the right choice for a production SIEM where sub-second latency matters. For a home lab setup receiving tens of events per minute, polling every 5 seconds is completely adequate and far simpler — no `flask-socketio`, no connection state management, no reconnect logic. You can reduce the interval in `dashboard.js` if you need faster updates.

**Vanilla JS, no framework.** React or Vue would give you component re-rendering, state management, and a nice developer experience. They would also require a build step (Node.js, npm, Webpack/Vite) which breaks the "pip install and go" promise. The dashboard is a single-page app with one table and a handful of counters — that's 80 lines of `fetch()` and `innerHTML`. A framework would add more complexity than it removes.

**XSS escaping in `escHtml()`.** Alert content comes directly from Windows Event Log messages — attacker-controlled strings that could contain `<script>` tags or other HTML. If we used `innerHTML` without escaping, a crafted log message could execute JavaScript in the analyst's browser. `escHtml()` converts `<`, `>`, `&`, and `"` to their HTML entity equivalents before injecting any alert data into the DOM. This is standard output encoding — one of the OWASP Top 10 defenses.

**Blueprint factory (`create_dashboard(db_path)`) for the same reason as the receiver.** No global state, no import-time side effects, easy to test by instantiating fresh Flask apps per test.

### Alternatives considered

| Decision | Alternative | Why rejected |
|---|---|---|
| Polling every 5s with cheap count check | WebSockets (`flask-socketio`) | Adds a dependency and complexity not justified by home lab event rates |
| Polling every 5s with cheap count check | Re-fetch full alert list every 5s | Wastes bandwidth when nothing changed (most cycles) |
| Vanilla JS `fetch()` | React / Vue | Requires Node.js build tooling, breaking the "pip install" setup story |
| Vanilla JS `fetch()` | HTMX | A viable middle ground, but still an external dependency; raw fetch is dependency-free |
| Dark theme CSS from scratch | Bootstrap or Tailwind CDN | External CDN means the dashboard breaks without internet; a 150-line CSS file has no such dependency |
| `escHtml()` string escaping | `textContent` instead of `innerHTML` | `textContent` is actually safer for plain-text fields, but doesn't allow the `<span class="badge">` severity pills — escaping lets us mix markup and data safely |

### What to understand about this as a SIEM learner

**The dashboard is a read-only view, and that's the right architecture.** The dashboard talks only to `GET /api/*` endpoints — it never writes to the database directly. Writes come exclusively from `POST /ingest` via the agent. This separation means you could run the dashboard as a completely separate process from the ingestion server, or give read-only dashboard access to a junior analyst without risking them modifying alert data. In enterprise SIEMs this separation is enforced by role-based access control (RBAC); here it's enforced by the route structure.

**The "cheap poll then fetch" pattern is a cursor.** `lastCheck` is a timestamp that acts as a cursor into the alerts table: "give me everything after this point." Every full refresh advances the cursor. This is identical to how log shippers, database change-data-capture systems, and message queue consumers track their position — they maintain a pointer into a stream and only process what's new. Kafka calls this the "consumer offset."

**Why four severity levels and not more?** `low / medium / high / critical` maps to the CVSS (Common Vulnerability Scoring System) and is the industry standard. Security tools that invent their own scales (info / notice / warning / alert / emergency) force analysts to mentally translate between systems. Sticking to four well-understood levels means a rule author and an analyst share the same vocabulary without ambiguity. CVSS itself uses a numeric 0–10 score, but for human-facing UIs four buckets are easier to scan at a glance than ten.

---

## 2026-06-14 — Ingestion receiver (`server/ingestion/receiver.py`)

### What was built
- `server/ingestion/receiver.py` — a 40-line Flask blueprint with one route: `POST /ingest`
- `tests/test_receiver.py` — 13 tests covering input validation, matching, alert persistence, batch edge cases, and hot reload

### Why built this way

**Blueprint factory (`create_receiver(engine, db_path)`) instead of a bare route.** If the route function were defined at module level, it would have to reach for global variables to find the engine and database path. That creates hidden coupling — the module only works if a specific global is set up first, which makes it hard to test and hard to reason about. The factory pattern injects both dependencies as closure variables. The route function becomes a pure function of its inputs: it receives an HTTP request, uses the injected engine and db_path, and returns a response. No globals, no side-channel state.

**Accept batches, not individual events.** The agent collects events over a poll interval (default 5 seconds) and sends them all in one request. Accepting a `{"events": [...]}` array means one round-trip per poll cycle regardless of how many events arrived — compare that to one round-trip per event, which would saturate a home lab server instantly if a noisy Windows Security log fires 200 events in 5 seconds.

**`force=True, silent=True` on `get_json`.** `force=True` parses the body as JSON even if the agent forgets to set `Content-Type: application/json`. `silent=True` returns `None` instead of raising an exception on malformed JSON. Together they produce a well-behaved API that doesn't crash on bad input but still returns 400 for anything unacceptable.

**Skip non-dict items silently, don't reject the whole batch.** If the agent sends a batch of 100 events and one is malformed, rejecting the whole batch means 99 valid events go unprocessed and the agent has to re-send them (or lose them). Skipping the bad item and processing the rest is the more resilient choice. The agent is our own code, so malformed items are rare and non-malicious — no need for strict all-or-nothing validation here.

**`reload_if_changed()` at the top of every ingest call.** This is the moment where live rule editing takes effect. The engine checks file modification times (a cheap `stat()` call per file) and only re-reads files that actually changed. Putting it here means an operator can drop a new YAML file into `rules/` and see it take effect on the very next batch — no server restart, no reload endpoint, no `kill -HUP`.

### Alternatives considered

| Decision | Alternative | Why rejected |
|---|---|---|
| Blueprint factory with injected deps | `flask.g` or `current_app.config` for shared state | Both require Flask application context to be active; harder to test and less obvious to read |
| Blueprint factory with injected deps | Module-level globals set before `import` | Hidden coupling; the module becomes order-of-import sensitive |
| Batch endpoint | One event per request | One request per event would cause 10–200 HTTP round-trips per poll cycle; wasteful and slow |
| Skip bad batch items | Reject whole batch on first bad item | Causes event loss if a transient agent bug produces one bad event |
| `reload_if_changed()` per request | Background thread watching the rules dir | A background thread needs locking around the `_rules` dict; polling is simpler and safe |
| `reload_if_changed()` per request | Dedicated reload API endpoint (`POST /reload`) | Requires the operator to remember to call it; automatic polling is zero-friction |

### What to understand about this as a SIEM learner

**This endpoint is the pipeline junction.** Everything flows through here: the agent produces events, this endpoint consumes them, the engine filters them, the database stores the survivors. Every SIEM has an equivalent component — Logstash in the ELK stack, the Wazuh manager's analysis engine, Splunk's HTTP Event Collector. The pattern is always the same: receive a stream of events, evaluate rules, emit alerts. The implementation details differ (protocol, serialization format, rule language) but the shape doesn't.

**Why HTTP and not a message queue?** Production SIEMs like Splunk and Elastic use message queues (Kafka, RabbitMQ) between the collector and the analysis engine. Queues decouple the two sides: the collector can write events even if the analysis engine is temporarily down, and the analysis engine can process at its own pace. For a single-endpoint setup that handles one or a few machines, HTTP is simpler, has no extra infrastructure, and the "queue" failure mode (analysis engine is down → agent can't deliver events) is acceptable. Knowing this trade-off helps you understand why enterprise SIEMs are more complex: they're buying durability and throughput at the cost of operational complexity.

**The `received` vs `alerts_triggered` response is a primitive health signal.** In production you'd track this ratio in a dashboard. If `received` climbs but `alerts_triggered` stays at zero, either your rules are wrong or the events aren't matching what you expected. If `alerts_triggered` suddenly spikes, something is happening on the endpoint. Real SIEMs call this the *signal-to-noise ratio* and tuning it — reducing false positives without missing true positives — is a core SOC engineering discipline.

---

## 2026-06-14 — Rule engine (`server/rules/engine.py`)

### What was built
- `server/rules/engine.py` — `RuleEngine` class plus two module-level functions (`_validate_rule`, `_condition_matches`) kept public enough for direct testing
- `tests/test_rule_engine.py` — 35 tests covering loading, validation, all five operators, AND logic, multi-rule matches, and hot-reload (new file / modified file / deleted file)

### Why built this way

**A class, not a set of functions.** The rule engine is stateful: it holds a dictionary of loaded rules and a cache of file modification times between calls. A class is the natural container for that state. The database layer is stateless (it opens a new connection on every call), so it used plain functions. The rule engine is called hundreds of times per second (once per incoming event), so it keeps state in memory and avoids re-reading YAML files unless they actually changed.

**Two tracking dicts: `_path_to_id` and `_mtimes`.** The engine needs to answer two questions efficiently: "has this file changed since last load?" and "if I delete this file, which rule ID do I remove?" A single dict can't answer both. `_mtimes` maps path → mtime for change detection; `_path_to_id` maps path → rule_id for deletion. This separation also handles the edge case where a file is rewritten with a *different* rule ID — the old rule is removed and the new one registered.

**`_validate_rule` and `_condition_matches` as module-level functions, not private methods.** Keeping them at module scope (with underscore prefix as a naming convention for "internal but testable") lets the test file import and call them directly with simple dict inputs. If they were class methods, every validation test would need to construct a full `RuleEngine` with a temp directory. Flat functions are easier to test and easier to reason about in isolation.

**`str(actual) == str(expected)` for the `equals` operator.** YAML parses `value: 4625` as a Python `int`. The event dict forwarded by the agent may store `EventID` as either an `int` or a `str` depending on how the Windows API returns it. Converting both sides to strings before comparing makes the rule work regardless of how the field was typed. The alternative — strict type checking — would force rule authors to write `value: "4625"` (with quotes) to match a string field, which is confusing.

**`reload_if_changed()` uses mtime comparison, not file hashing.** Hashing the file content would catch changes even if the mtime was somehow identical, but it requires reading every rule file on every poll cycle. Mtime comparison is a single `stat()` call per file — nearly free. The failure mode (mtime unchanged but content changed) requires adversarial effort and is not worth guarding against in this context.

### Alternatives considered

| Decision | Alternative | Why rejected |
|---|---|---|
| Class with `_mtimes` cache | Re-read all YAML files on every event | Disk reads on every event would dominate latency at any real volume |
| Class with `_mtimes` cache | `watchdog` file watcher library | Another dependency; polling is simpler and sufficient for this event rate |
| `str()` coercion for `equals` | Type-aware comparison | Forces rule authors to know the field's Python type; error-prone |
| Module-level `_validate_rule` | Private `RuleEngine` method | Harder to test without a full class fixture; the function has no natural need for `self` |
| Five explicit `if` branches in `_condition_matches` | Dict of `{operator: lambda}` | The lambda dict is clever but harder to read; `if/elif` is self-documenting |

### What to understand about this as a SIEM learner

**This is how real rule engines work, just simpler.** Suricata (network IDS), YARA (malware scanner), and Sigma (log detection) all follow the same structure: load a set of rules into memory, then run each incoming event through every loaded rule. The differences are in the operators (Suricata does byte-level packet inspection; YARA does PE file structure matching), not the architecture. Understanding this loop — load rules once, match events many times — is the mental model for all signature-based detection.

**AND vs. OR logic matters enormously for false positive rates.** This engine uses AND logic: all conditions must pass. That's a precision-first approach — it's harder to trigger, so you get fewer alerts, but the ones you get are more specific. OR logic (any condition fires the rule) is easier to write but produces far more false positives. Some rule formats support both: Sigma has `condition: all of them` (AND) and `condition: 1 of them` (OR). Most real detection rules use AND for high-severity alerts, because a single-field match (e.g. "process name contains 'powershell'") is far too broad.

**Hot reload is a SOC quality-of-life feature.** In a real incident, analysts tune rules in real time as an attack unfolds. If reloading rules required restarting the SIEM server, you'd lose queued events and introduce gaps in coverage during the restart. Hot reload means you drop an edited YAML file into the directory and the next event cycle picks it up. This is why the engine tracks mtimes rather than loading rules once at startup.

**The `source` field is the first filter.** Before evaluating any conditions, the engine checks `event["source"] != rule["source"]` and exits early if they don't match. This means a Sysmon rule is never evaluated against a Windows Security log event and vice versa, even if they share the same Event IDs. In real SIEMs this is called *index routing* or *log source binding* — it prevents rules written for one data source from generating noise (or worse, false positives) when applied to a structurally similar but semantically different source.

---

## 2026-06-14 — Database layer (`server/database/store.py`)

### What was built
- `server/database/store.py` — five functions: `init_db`, `insert_alert`, `get_alerts`, `get_counts_by_severity`, `get_alert_count_since`
- `server/__init__.py` — package marker so the test runner can import `server.database.store`
- `tests/test_database.py` — 10 tests covering insert, ordering, filtering, truncation, and time-range counting

### Why built this way

**One module, five functions, no classes.** The database layer is a thin wrapper around `sqlite3`. There's no ORM, no session object, no repository class — just plain functions that take a `db_path` string and return plain Python dicts. This keeps every call site readable: you see exactly what SQL runs and what data comes back.

**Pass `db_path` to every function rather than a global connection.** A global `conn` object seems convenient but creates hidden state: it breaks under multi-threading (Flask runs threaded by default), makes tests hard to isolate (tests would share state), and makes it unclear where the DB file lives. Passing the path explicitly means each call opens its own connection, which SQLite handles efficiently with WAL mode if needed later.

**`sqlite3.Row` as the row factory.** By default sqlite3 returns tuples — `row[0]`, `row[1]`. Setting `row_factory = sqlite3.Row` lets you write `row["timestamp"]` instead, which is self-documenting and doesn't break if columns are reordered. Converting to `dict` at the return boundary means callers (Flask routes, the rule engine) work with plain Python dicts and have no sqlite3 dependency.

**Truncate `message` at 500 chars, store full payload in `raw_event`.** The `message` column is what the dashboard shows in a table row — 500 chars is plenty for a preview. The full event JSON lives in `raw_event` for forensic queries. Storing both avoids re-parsing JSON just to display a summary.

**Timezone-aware UTC timestamps.** `datetime.utcnow()` is deprecated in Python 3.12+ because it returns a naive datetime that looks like UTC but isn't labeled as such, which causes bugs when mixing with timezone-aware objects. `datetime.now(timezone.utc)` is explicit: the string stored in the DB (e.g. `2026-06-14T18:42:01.123456+00:00`) is unambiguous no matter what timezone the server runs in.

### Alternatives considered

| Decision | Alternative | Why rejected |
|---|---|---|
| Raw `sqlite3` | SQLAlchemy ORM | ORM adds a dependency and hides the SQL; explicit queries are more readable and educational |
| Raw `sqlite3` | SQLAlchemy Core | Still a dependency; `sqlite3` is in the standard library — zero install cost |
| Functions with `db_path` | Singleton connection object | Global state breaks thread safety and test isolation |
| `sqlite3.Row` → `dict` | Return `Row` objects directly | Callers would take a hidden dependency on sqlite3's Row type |
| UTC ISO string | Unix timestamp integer | ISO strings are human-readable in `sqlite3` browser tools and sort correctly as strings |

### What to understand about this as a SIEM learner

**Alerts are append-only by design.** Notice there's no `update_alert` or `delete_alert` function. Real SIEMs treat alerts as immutable records — once an event is logged, the log doesn't change. You add context (tickets, analyst notes) as new rows or separate tables, but you never alter the original record. This is a forensic integrity principle: the alert should reflect exactly what the system saw at the moment it fired.

**Why SQLite and not a "real" database?** SQLite can handle millions of rows and is used in production by major applications (Firefox, WhatsApp, Airbus). The reason enterprise SIEMs use PostgreSQL, Cassandra, or Elasticsearch isn't that SQLite is too slow — it's that they need *distributed* writes from hundreds of collectors simultaneously. For a single-server SIEM handling one or several endpoints, SQLite is the right tool. Choosing Postgres here would be premature complexity.

**The schema is the contract between components.** Every other module (the rule engine, the ingestion receiver, the dashboard) depends on what `insert_alert` stores and what `get_alerts` returns. If you change the schema, you change the contract. This is why the schema is defined once in `store.py` and nothing else touches the DB file. In larger systems this contract is enforced by migrations (Alembic, Flyway) — we don't need migrations yet, but `init_db` is the hook where they'd live.

**`get_alert_count_since` exists for the dashboard's live refresh.** The dashboard will poll `/api/alerts` every few seconds. Instead of re-fetching all 200 alerts each time, it can first call a cheap count endpoint to check if anything new arrived. Only if the count increased does it fetch the full list. This pattern — a cheap "did anything change?" check before an expensive "give me everything" fetch — is called *polling with a cursor* and appears everywhere in event-driven systems.

---

## 2026-06-14 — Project scaffold, README, and detection rules

### What was built
- Full project directory structure (`agent/`, `server/ingestion/`, `server/rules/`, `server/database/`, `server/dashboard/`, `rules/`, `config/`, `tests/`)
- `README.md` with architecture diagram, quick-start guide, and rule-writing reference
- `requirements.txt` (4 dependencies)
- `config/server.yaml` and `config/agent.yaml` with commented defaults
- Three starter YAML detection rules: `failed_logon.yaml`, `suspicious_powershell.yaml`, `new_service_installed.yaml`
- `__init__.py` stubs in each Python package directory

### Why built this way

**Monorepo layout with agent and server co-located.** Keeping both in one repo makes the project portable and easy to understand as a whole. In production SIEMs these would be separate deployable artifacts, but for a portfolio/learning project the overhead of multiple repos adds no value.

**Separate `rules/` directory at the project root, not inside `server/`.** Rules are the user-facing, editable part of the system. Putting them at the root (not buried inside `server/rules/`) signals that they are configuration, not code. An operator should be able to add a rule without touching source files.

**YAML for rules, not Python or JSON.** YAML was chosen because it reads like English, supports multi-line strings for descriptions without escaping, and is the de facto standard for security rule formats (Sigma rules, Ansible, Kubernetes all use YAML). It also means non-developers can write rules.

**SQLite for storage, not PostgreSQL or Elasticsearch.** The entire point of this project is zero-infrastructure setup. SQLite is a single file, ships with Python's standard library (no install), and handles tens of thousands of alerts with no configuration. Real SIEMs use distributed stores because they ingest millions of events per second — we don't need that, and adding it would obscure the architecture.

**Flask for the web layer, not FastAPI or Django.** Flask has the smallest surface area of any Python web framework. A beginner can read a Flask route and understand exactly what it does. FastAPI adds async complexity; Django adds ORM, admin, migrations — all overkill for a dashboard that serves one page and one JSON endpoint.

### Alternatives considered

| Decision | Alternative | Why rejected |
|---|---|---|
| YAML rules | Sigma rule format | Sigma has a complex transformer layer; YAML-native keeps the engine simple and teachable |
| YAML rules | Python functions | Requires code changes to add rules; breaks the "operator vs. developer" separation |
| SQLite | PostgreSQL | Requires a running DB server; violates the "pip install and go" goal |
| SQLite | Flat JSON files | No query capability; makes the dashboard filter/sort logic painful |
| Flask | FastAPI | Async adds complexity that isn't needed when ingestion volume is low |
| Flask | Django | Too much magic; the ORM and admin scaffold hide what's actually happening |
| Monorepo | Separate agent/server repos | Unnecessary friction for a learning project |

### What to understand about this as a SIEM learner

**The pipeline is always the same.** Every SIEM — open source or enterprise — has the same four stages: *collect → parse → detect → visualize*. The folder structure maps directly to this pipeline: `agent/` collects, `ingestion/` parses, `rules/` detects, `dashboard/` visualizes. When you read about Splunk or Elastic Security, mentally map their components to these same four stages.

**Rules are the product of a SOC.** The code of a SIEM is relatively stable; the rules are what security teams spend their time on. Rule quality — what you detect, how precisely you detect it, how you reduce false positives — is the actual job of a Security Operations Center. Starting with three rules based on specific Event IDs (4625, 4104, 7045) is realistic: real SOC rule libraries start with known-bad Event IDs from Microsoft's documentation and frameworks like MITRE ATT&CK.

**Windows Event IDs are the vocabulary.** Windows logs everything as numbered events. The numbers that matter most to defenders:
- `4625` — failed logon (brute force, password spray)
- `4688` — process creation (what ran and who launched it)
- `4698/4702` — scheduled task created/modified (persistence)
- `7045` — new service installed (persistence)
- `4104` — PowerShell script block (what a script actually executed)

Sysmon extends this vocabulary with events Windows doesn't log by default (network connections, DLL loads, file hashes). A Sysmon + Windows Event Log combination is the baseline telemetry for most endpoint detection work.

**Agent/server separation mirrors real EDR architecture.** The `agent/` runs on every monitored machine and is intentionally lightweight — it just reads and forwards. All the intelligence (rules, alerting, storage) lives on the server. This is how CrowdStrike, Carbon Black, and open-source tools like Velociraptor work: a thin sensor on the endpoint, a smart backend. It means you can update detection logic without touching every endpoint.

---
