"""
Tests for server/dashboard/app.py.

Covers: HTML page render, all four API endpoints, filtering,
limit parameter, and graceful handling of bad query params.
"""

from datetime import datetime, timedelta, timezone

import pytest
from flask import Flask

from server.dashboard.app import create_dashboard
from server.database.store import init_db, insert_alert


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

RULE_MED = {
    "id": "failed_logon",
    "name": "Failed Logon Attempt",
    "severity": "medium",
    "source": "windows_event_log",
}

RULE_HIGH = {
    "id": "suspicious_ps",
    "name": "Suspicious PowerShell",
    "severity": "high",
    "source": "windows_event_log",
}

EVENT = {
    "source": "windows_event_log",
    "EventID": 4625,
    "hostname": "DESKTOP-TEST",
    "Message": "An account failed to log on.",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture
def client(db_path):
    """Bare test client — empty database, dashboard blueprint registered."""
    app = Flask(__name__)
    app.register_blueprint(create_dashboard(db_path))
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def seeded_client(db_path):
    """Test client pre-seeded with two medium alerts and one high alert."""
    insert_alert(db_path, RULE_MED,  EVENT)
    insert_alert(db_path, RULE_MED,  EVENT)
    insert_alert(db_path, RULE_HIGH, EVENT)

    app = Flask(__name__)
    app.register_blueprint(create_dashboard(db_path))
    app.config["TESTING"] = True
    return app.test_client(), db_path


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

def test_index_returns_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"PySIEM" in r.data
    assert b"<table" in r.data


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------

def test_api_alerts_empty(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert r.get_json() == []


def test_api_alerts_returns_all(seeded_client):
    client, _ = seeded_client
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert len(r.get_json()) == 3


def test_api_alerts_newest_first(seeded_client):
    client, _ = seeded_client
    alerts = client.get("/api/alerts").get_json()
    timestamps = [a["timestamp"] for a in alerts]
    assert timestamps == sorted(timestamps, reverse=True)


def test_api_alerts_filter_by_severity(seeded_client):
    client, _ = seeded_client
    medium = client.get("/api/alerts?severity=medium").get_json()
    high   = client.get("/api/alerts?severity=high").get_json()

    assert len(medium) == 2
    assert all(a["severity"] == "medium" for a in medium)
    assert len(high) == 1
    assert high[0]["severity"] == "high"


def test_api_alerts_filter_by_rule_id(seeded_client):
    client, _ = seeded_client
    results = client.get("/api/alerts?rule_id=failed_logon").get_json()
    assert len(results) == 2
    assert all(a["rule_id"] == "failed_logon" for a in results)


def test_api_alerts_limit(seeded_client):
    client, _ = seeded_client
    results = client.get("/api/alerts?limit=2").get_json()
    assert len(results) == 2


def test_api_alerts_invalid_limit_falls_back_to_200(seeded_client):
    client, _ = seeded_client
    # Should not 400 — should silently use 200.
    r = client.get("/api/alerts?limit=notanumber")
    assert r.status_code == 200


def test_api_alerts_unknown_severity_returns_empty(seeded_client):
    client, _ = seeded_client
    results = client.get("/api/alerts?severity=extreme").get_json()
    assert results == []


# ---------------------------------------------------------------------------
# GET /api/stats
# ---------------------------------------------------------------------------

def test_api_stats_empty_db(client):
    stats = client.get("/api/stats").get_json()
    assert stats == {}


def test_api_stats_correct_counts(seeded_client):
    client, _ = seeded_client
    stats = client.get("/api/stats").get_json()
    assert stats["medium"] == 2
    assert stats["high"]   == 1
    assert "low"      not in stats
    assert "critical" not in stats


# ---------------------------------------------------------------------------
# GET /api/alerts/count
# ---------------------------------------------------------------------------

def test_api_count_since_past(seeded_client):
    client, _ = seeded_client
    since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    body  = client.get(f"/api/alerts/count?since={since}").get_json()
    assert body["count"] == 3


def test_api_count_since_future(seeded_client):
    client, _ = seeded_client
    since = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    body  = client.get(f"/api/alerts/count?since={since}").get_json()
    assert body["count"] == 0


def test_api_count_since_missing_returns_zero(client):
    # Missing `since` defaults to empty string; count should still be valid.
    body = client.get("/api/alerts/count").get_json()
    assert "count" in body


# ---------------------------------------------------------------------------
# Alert fields present in API response
# ---------------------------------------------------------------------------

def test_api_alerts_response_fields(seeded_client):
    client, _ = seeded_client
    alert = client.get("/api/alerts").get_json()[0]

    for field in ("id", "timestamp", "rule_id", "rule_name",
                  "severity", "hostname", "event_id", "message"):
        assert field in alert, f"missing field: {field}"
