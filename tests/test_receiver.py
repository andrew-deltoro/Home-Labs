"""
Tests for server/ingestion/receiver.py.

Covers: input validation, event-to-rule matching via the live engine,
alert persistence, batch counts, graceful skipping of bad items,
and hot-reload during an ingest call.
"""

import time
from pathlib import Path

import pytest
import yaml
from flask import Flask

from server.database.store import get_alerts, init_db
from server.ingestion.receiver import create_receiver
from server.rules.engine import RuleEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_rule(directory: Path, filename: str, rule: dict) -> Path:
    path = directory / filename
    path.write_text(yaml.dump(rule), encoding="utf-8")
    return path


def make_client(rules_dir: Path, db_path: str):
    """Wire up a Flask test client with a fresh engine. Returns (client, engine)."""
    engine = RuleEngine(str(rules_dir))
    app = Flask(__name__)
    app.register_blueprint(create_receiver(engine, db_path))
    app.config["TESTING"] = True
    return app.test_client(), engine


BASE_RULE = {
    "id": "failed_logon",
    "name": "Failed Logon Attempt",
    "severity": "medium",
    "source": "windows_event_log",
    "conditions": [{"field": "EventID", "operator": "equals", "value": 4625}],
}

MATCHING_EVENT = {
    "source": "windows_event_log",
    "hostname": "DESKTOP-TEST",
    "EventID": 4625,
    "Message": "An account failed to log on.",
}

NON_MATCHING_EVENT = {
    "source": "windows_event_log",
    "hostname": "DESKTOP-TEST",
    "EventID": 4624,  # successful logon — doesn't match the failed-logon rule
    "Message": "An account was successfully logged on.",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    return d


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "alerts.db")
    init_db(path)
    return path


@pytest.fixture
def client_no_rules(rules_dir, db_path):
    """Test client whose engine has no rules loaded."""
    client, _ = make_client(rules_dir, db_path)
    return client, db_path


@pytest.fixture
def client_with_rule(rules_dir, db_path):
    """Test client whose engine has BASE_RULE pre-loaded."""
    write_rule(rules_dir, "failed_logon.yaml", BASE_RULE)
    client, engine = make_client(rules_dir, db_path)
    return client, engine, rules_dir, db_path


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_non_json_body_returns_400(client_no_rules):
    client, _ = client_no_rules
    r = client.post("/ingest", data="not json", content_type="text/plain")
    assert r.status_code == 400
    assert "events" in r.get_json()["error"]


def test_missing_events_key_returns_400(client_no_rules):
    client, _ = client_no_rules
    r = client.post("/ingest", json={"host": "x"})
    assert r.status_code == 400


def test_events_not_a_list_returns_400(client_no_rules):
    client, _ = client_no_rules
    r = client.post("/ingest", json={"events": "just a string"})
    assert r.status_code == 400


def test_empty_events_list_returns_200(client_no_rules):
    client, _ = client_no_rules
    r = client.post("/ingest", json={"events": []})
    assert r.status_code == 200
    body = r.get_json()
    assert body["received"] == 0
    assert body["alerts_triggered"] == 0


# ---------------------------------------------------------------------------
# Matching and alert persistence
# ---------------------------------------------------------------------------

def test_matching_event_triggers_alert(client_with_rule):
    client, _, _, db_path = client_with_rule
    r = client.post("/ingest", json={"events": [MATCHING_EVENT]})

    assert r.status_code == 200
    assert r.get_json()["alerts_triggered"] == 1
    assert len(get_alerts(db_path)) == 1


def test_non_matching_event_triggers_no_alert(client_with_rule):
    client, _, _, db_path = client_with_rule
    r = client.post("/ingest", json={"events": [NON_MATCHING_EVENT]})

    assert r.status_code == 200
    assert r.get_json()["alerts_triggered"] == 0
    assert get_alerts(db_path) == []


def test_response_counts_match_batch(client_with_rule):
    client, _, _, db_path = client_with_rule
    events = [MATCHING_EVENT, NON_MATCHING_EVENT, MATCHING_EVENT]
    r = client.post("/ingest", json={"events": events})

    body = r.get_json()
    assert body["received"] == 3
    assert body["alerts_triggered"] == 2


def test_alert_stored_with_correct_fields(client_with_rule):
    client, _, _, db_path = client_with_rule
    client.post("/ingest", json={"events": [MATCHING_EVENT]})

    alert = get_alerts(db_path)[0]
    assert alert["rule_id"]   == "failed_logon"
    assert alert["severity"]  == "medium"
    assert alert["hostname"]  == "DESKTOP-TEST"
    assert alert["event_id"]  == 4625


def test_multiple_rules_matching_same_event_create_multiple_alerts(rules_dir, db_path):
    write_rule(rules_dir, "rule_a.yaml", BASE_RULE)
    write_rule(rules_dir, "rule_b.yaml", {**BASE_RULE, "id": "rule_b", "name": "Rule B"})
    client, _ = make_client(rules_dir, db_path)

    client.post("/ingest", json={"events": [MATCHING_EVENT]})
    assert len(get_alerts(db_path)) == 2


# ---------------------------------------------------------------------------
# Batch edge cases
# ---------------------------------------------------------------------------

def test_non_dict_items_in_batch_are_skipped(client_with_rule):
    client, _, _, db_path = client_with_rule
    events = ["not a dict", 42, None, MATCHING_EVENT]
    r = client.post("/ingest", json={"events": events})

    assert r.status_code == 200
    # Only the one valid dict event is processed.
    assert r.get_json()["received"] == 4
    assert r.get_json()["alerts_triggered"] == 1
    assert len(get_alerts(db_path)) == 1


def test_large_batch_is_processed(client_with_rule):
    client, _, _, db_path = client_with_rule
    events = [MATCHING_EVENT] * 50 + [NON_MATCHING_EVENT] * 50
    r = client.post("/ingest", json={"events": events})

    body = r.get_json()
    assert body["received"] == 100
    assert body["alerts_triggered"] == 50


# ---------------------------------------------------------------------------
# Hot reload
# ---------------------------------------------------------------------------

def test_ingest_picks_up_rule_added_after_startup(rules_dir, db_path):
    # Start with no rules.
    client, _ = make_client(rules_dir, db_path)

    # Confirm the event doesn't match (no rules yet).
    r = client.post("/ingest", json={"events": [MATCHING_EVENT]})
    assert r.get_json()["alerts_triggered"] == 0

    # Drop a rule file into the directory.
    write_rule(rules_dir, "failed_logon.yaml", BASE_RULE)

    # Next ingest call calls reload_if_changed() and picks up the new rule.
    r = client.post("/ingest", json={"events": [MATCHING_EVENT]})
    assert r.get_json()["alerts_triggered"] == 1
    assert len(get_alerts(db_path)) == 1


def test_ingest_picks_up_modified_rule(client_with_rule):
    client, engine, rules_dir, db_path = client_with_rule

    # Confirm it fires at medium severity.
    client.post("/ingest", json={"events": [MATCHING_EVENT]})
    assert get_alerts(db_path)[0]["severity"] == "medium"

    # Rewrite the rule with a higher severity.
    time.sleep(0.05)
    write_rule(rules_dir, "failed_logon.yaml", {**BASE_RULE, "severity": "high"})

    client.post("/ingest", json={"events": [MATCHING_EVENT]})
    alerts = get_alerts(db_path)
    assert alerts[0]["severity"] == "high"   # newest alert is highest
