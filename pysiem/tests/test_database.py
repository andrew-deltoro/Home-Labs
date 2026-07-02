"""
Tests for server/database/store.py.

Each test gets a fresh SQLite file in a temp directory via the `db` fixture,
so tests are fully isolated and leave no state behind.
"""

from datetime import datetime, timedelta, timezone

import pytest

from server.database.store import (
    get_alert_count_since,
    get_alerts,
    get_counts_by_severity,
    init_db,
    insert_alert,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    """Initialised database in a temp directory. Deleted after each test."""
    path = str(tmp_path / "test_alerts.db")
    init_db(path)
    return path


# Minimal rule and event dicts that mirror what the rule engine will produce.
RULE = {
    "id": "failed_logon",
    "name": "Failed Logon Attempt",
    "severity": "medium",
    "source": "windows_event_log",
}

EVENT = {
    "EventID": 4625,
    "hostname": "DESKTOP-TEST",
    "Message": "An account failed to log on.",
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_empty_on_init(db):
    assert get_alerts(db) == []


def test_insert_stores_all_fields(db):
    row_id = insert_alert(db, RULE, EVENT)
    assert row_id == 1

    alerts = get_alerts(db)
    assert len(alerts) == 1

    a = alerts[0]
    assert a["rule_id"] == "failed_logon"
    assert a["rule_name"] == "Failed Logon Attempt"
    assert a["severity"] == "medium"
    assert a["event_id"] == 4625
    assert a["hostname"] == "DESKTOP-TEST"
    assert "An account failed" in a["message"]
    assert a["raw_event"]  # JSON blob present


def test_newest_first_ordering(db):
    insert_alert(db, RULE, EVENT)
    insert_alert(db, {**RULE, "id": "second_rule", "name": "Second"}, EVENT)

    alerts = get_alerts(db)
    # Second insert should appear first (newest first).
    assert alerts[0]["rule_id"] == "second_rule"
    assert alerts[1]["rule_id"] == "failed_logon"


def test_filter_by_severity(db):
    insert_alert(db, RULE, EVENT)                               # medium
    insert_alert(db, {**RULE, "severity": "high"}, EVENT)      # high

    medium = get_alerts(db, severity="medium")
    high   = get_alerts(db, severity="high")

    assert len(medium) == 1 and medium[0]["severity"] == "medium"
    assert len(high)   == 1 and high[0]["severity"]   == "high"


def test_filter_by_rule_id(db):
    insert_alert(db, RULE, EVENT)
    insert_alert(db, {**RULE, "id": "other_rule", "name": "Other"}, EVENT)

    results = get_alerts(db, rule_id="failed_logon")
    assert len(results) == 1
    assert results[0]["rule_id"] == "failed_logon"


def test_limit_is_respected(db):
    for _ in range(10):
        insert_alert(db, RULE, EVENT)

    assert len(get_alerts(db, limit=3)) == 3


def test_counts_by_severity(db):
    insert_alert(db, RULE, EVENT)                                   # medium
    insert_alert(db, {**RULE, "severity": "high"}, EVENT)          # high
    insert_alert(db, {**RULE, "severity": "high"}, EVENT)          # high
    insert_alert(db, {**RULE, "severity": "critical"}, EVENT)      # critical

    counts = get_counts_by_severity(db)
    assert counts["medium"]   == 1
    assert counts["high"]     == 2
    assert counts["critical"] == 1
    assert "low" not in counts  # no low-severity alerts inserted


def test_alert_count_since(db):
    before = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    insert_alert(db, RULE, EVENT)
    assert get_alert_count_since(db, before) == 1


def test_alert_count_since_excludes_older(db):
    insert_alert(db, RULE, EVENT)
    # Set 'since' to now — the alert above was inserted before this moment.
    after = datetime.now(timezone.utc).isoformat()
    assert get_alert_count_since(db, after) == 0


def test_message_truncated_at_500_chars(db):
    long_event = {**EVENT, "Message": "A" * 1000}
    insert_alert(db, RULE, long_event)
    alert = get_alerts(db)[0]
    assert len(alert["message"]) == 500
