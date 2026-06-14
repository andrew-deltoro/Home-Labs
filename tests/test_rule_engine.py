"""
Tests for server/rules/engine.py.

Covers: loading, validation, all five operators, source filtering,
multi-condition AND logic, multi-rule matches, and hot-reload.
"""

import time
from pathlib import Path

import pytest
import yaml

from server.rules.engine import (
    RuleEngine,
    _condition_matches,
    _validate_rule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_rule(directory: Path, filename: str, rule: dict) -> Path:
    """Dump a rule dict to YAML and write it to directory/filename."""
    path = directory / filename
    path.write_text(yaml.dump(rule), encoding="utf-8")
    return path


# Minimal valid rule used across many tests.
BASE_RULE = {
    "id": "test_rule",
    "name": "Test Rule",
    "severity": "medium",
    "source": "windows_event_log",
    "conditions": [
        {"field": "EventID", "operator": "equals", "value": 4625}
    ],
}

# Event that satisfies BASE_RULE exactly.
MATCHING_EVENT = {
    "source": "windows_event_log",
    "EventID": 4625,
    "hostname": "DESKTOP-TEST",
    "Message": "An account failed to log on.",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rules_dir(tmp_path):
    """Empty temporary directory for rule YAML files."""
    return tmp_path


@pytest.fixture
def engine(rules_dir):
    """Engine pre-loaded with BASE_RULE."""
    write_rule(rules_dir, "test_rule.yaml", BASE_RULE)
    return RuleEngine(str(rules_dir))


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_loads_valid_rule(engine):
    assert engine.rule_count == 1


def test_empty_dir_loads_zero_rules(rules_dir):
    assert RuleEngine(str(rules_dir)).rule_count == 0


def test_loads_multiple_rules(rules_dir):
    write_rule(rules_dir, "rule_a.yaml", BASE_RULE)
    write_rule(rules_dir, "rule_b.yaml", {**BASE_RULE, "id": "rule_b", "name": "Rule B"})
    assert RuleEngine(str(rules_dir)).rule_count == 2


def test_skips_invalid_but_loads_valid(rules_dir):
    write_rule(rules_dir, "bad.yaml", {"id": "incomplete"})  # missing required fields
    write_rule(rules_dir, "good.yaml", BASE_RULE)
    eng = RuleEngine(str(rules_dir))
    assert eng.rule_count == 1
    assert eng.match(MATCHING_EVENT) != []


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_validate_passes_for_valid_rule():
    assert _validate_rule(BASE_RULE) == []


def test_validate_rejects_non_mapping():
    assert _validate_rule("just a string") != []
    assert _validate_rule(42) != []


def test_validate_rejects_missing_required_fields():
    errors = _validate_rule({"id": "x", "name": "X"})
    assert any("missing" in e for e in errors)


def test_validate_rejects_bad_severity():
    errors = _validate_rule({**BASE_RULE, "severity": "extreme"})
    assert any("severity" in e for e in errors)


def test_validate_accepts_all_valid_severities():
    for sev in ("low", "medium", "high", "critical"):
        assert _validate_rule({**BASE_RULE, "severity": sev}) == []


def test_validate_rejects_empty_conditions():
    errors = _validate_rule({**BASE_RULE, "conditions": []})
    assert errors


def test_validate_rejects_non_list_conditions():
    errors = _validate_rule({**BASE_RULE, "conditions": "EventID == 4625"})
    assert errors


def test_validate_rejects_condition_missing_value():
    rule = {
        **BASE_RULE,
        "conditions": [{"field": "EventID", "operator": "equals"}],
    }
    errors = _validate_rule(rule)
    assert any("value" in e for e in errors)


def test_validate_rejects_unknown_operator():
    rule = {
        **BASE_RULE,
        "conditions": [{"field": "EventID", "operator": "like", "value": 4625}],
    }
    errors = _validate_rule(rule)
    assert any("operator" in e for e in errors)


# ---------------------------------------------------------------------------
# Condition operators — match cases
# ---------------------------------------------------------------------------

def test_equals_int_match():
    cond = {"field": "EventID", "operator": "equals", "value": 4625}
    assert _condition_matches(cond, {"EventID": 4625})


def test_equals_coerces_int_to_string():
    # YAML parses value as int; event may store it as string. Both should match.
    cond = {"field": "EventID", "operator": "equals", "value": 4625}
    assert _condition_matches(cond, {"EventID": "4625"})


def test_equals_no_match():
    cond = {"field": "EventID", "operator": "equals", "value": 4625}
    assert not _condition_matches(cond, {"EventID": 4624})


def test_contains_match():
    cond = {"field": "Message", "operator": "contains", "value": "-EncodedCommand"}
    assert _condition_matches(cond, {"Message": "powershell -EncodedCommand abc123"})


def test_contains_no_match():
    cond = {"field": "Message", "operator": "contains", "value": "-EncodedCommand"}
    assert not _condition_matches(cond, {"Message": "powershell -Command 'ls'"})


def test_startswith_match():
    cond = {"field": "Path", "operator": "startswith", "value": "C:\\Windows\\Temp\\"}
    assert _condition_matches(cond, {"Path": "C:\\Windows\\Temp\\dropper.exe"})


def test_startswith_no_match():
    cond = {"field": "Path", "operator": "startswith", "value": "C:\\Windows\\Temp\\"}
    assert not _condition_matches(cond, {"Path": "C:\\Program Files\\legit.exe"})


def test_regex_match():
    cond = {"field": "Message", "operator": "regex", "value": r"cmd\.exe.*/c"}
    assert _condition_matches(cond, {"Message": "cmd.exe /c whoami"})


def test_regex_no_match():
    cond = {"field": "Message", "operator": "regex", "value": r"cmd\.exe.*/c"}
    assert not _condition_matches(cond, {"Message": "powershell.exe Get-Process"})


def test_greater_than_match():
    cond = {"field": "FailCount", "operator": "greater_than", "value": 5}
    assert _condition_matches(cond, {"FailCount": 10})


def test_greater_than_boundary_is_exclusive():
    cond = {"field": "FailCount", "operator": "greater_than", "value": 5}
    assert not _condition_matches(cond, {"FailCount": 5})


def test_greater_than_non_numeric_returns_false():
    cond = {"field": "FailCount", "operator": "greater_than", "value": 5}
    assert not _condition_matches(cond, {"FailCount": "many"})


def test_missing_field_never_matches():
    cond = {"field": "NonExistent", "operator": "equals", "value": "x"}
    assert not _condition_matches(cond, {"EventID": 4625})


# ---------------------------------------------------------------------------
# Rule-level matching
# ---------------------------------------------------------------------------

def test_match_returns_rule_on_hit(engine):
    matched = engine.match(MATCHING_EVENT)
    assert len(matched) == 1
    assert matched[0]["id"] == "test_rule"


def test_match_wrong_source_returns_empty(engine):
    event = {**MATCHING_EVENT, "source": "sysmon"}
    assert engine.match(event) == []


def test_match_failed_condition_returns_empty(engine):
    event = {**MATCHING_EVENT, "EventID": 9999}
    assert engine.match(event) == []


def test_all_conditions_must_pass(rules_dir):
    rule = {
        **BASE_RULE,
        "id": "multi",
        "conditions": [
            {"field": "EventID",  "operator": "equals",   "value": 4104},
            {"field": "Message",  "operator": "contains", "value": "-EncodedCommand"},
        ],
    }
    write_rule(rules_dir, "multi.yaml", rule)
    eng = RuleEngine(str(rules_dir))

    full_match = {
        "source": "windows_event_log",
        "EventID": 4104,
        "Message": "powershell -EncodedCommand abc",
    }
    assert len(eng.match(full_match)) == 1

    # First condition matches, second does not — should not fire.
    partial = {**full_match, "Message": "powershell -Command 'Get-Process'"}
    assert eng.match(partial) == []


def test_multiple_rules_can_fire_on_same_event(rules_dir):
    write_rule(rules_dir, "rule_a.yaml", BASE_RULE)
    rule_b = {**BASE_RULE, "id": "rule_b", "name": "Rule B"}
    write_rule(rules_dir, "rule_b.yaml", rule_b)
    eng = RuleEngine(str(rules_dir))
    assert len(eng.match(MATCHING_EVENT)) == 2


# ---------------------------------------------------------------------------
# Hot reload
# ---------------------------------------------------------------------------

def test_reload_picks_up_new_file(rules_dir):
    eng = RuleEngine(str(rules_dir))
    assert eng.rule_count == 0

    write_rule(rules_dir, "test_rule.yaml", BASE_RULE)
    changed = eng.reload_if_changed()

    assert "test_rule" in changed
    assert eng.rule_count == 1


def test_reload_picks_up_modified_severity(rules_dir):
    write_rule(rules_dir, "test_rule.yaml", BASE_RULE)
    eng = RuleEngine(str(rules_dir))

    time.sleep(0.05)  # ensure the OS records a different mtime on next write
    write_rule(rules_dir, "test_rule.yaml", {**BASE_RULE, "severity": "high"})
    eng.reload_if_changed()

    matched = eng.match(MATCHING_EVENT)
    assert matched[0]["severity"] == "high"


def test_reload_removes_deleted_file(rules_dir):
    path = write_rule(rules_dir, "test_rule.yaml", BASE_RULE)
    eng = RuleEngine(str(rules_dir))
    assert eng.rule_count == 1

    path.unlink()
    eng.reload_if_changed()
    assert eng.rule_count == 0


def test_reload_returns_empty_when_nothing_changed(rules_dir):
    write_rule(rules_dir, "test_rule.yaml", BASE_RULE)
    eng = RuleEngine(str(rules_dir))
    assert eng.reload_if_changed() == []
