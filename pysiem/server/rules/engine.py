"""
Rule engine: loads YAML detection rules from disk and matches log events against them.

A rule file looks like this:

    id: failed_logon
    name: Failed Logon Attempt
    severity: medium
    source: windows_event_log
    conditions:
      - field: EventID
        operator: equals
        value: 4625

All conditions in a rule must pass for the rule to fire (AND logic).
Multiple rules can fire on the same event.
"""

import re
from pathlib import Path

import yaml


VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_OPERATORS  = {"equals", "contains", "startswith", "regex", "greater_than"}
REQUIRED_FIELDS  = {"id", "name", "severity", "source", "conditions"}


class RuleEngine:
    """
    Holds all loaded detection rules in memory and matches events against them.

    Usage:
        engine = RuleEngine("rules/")
        matched = engine.match(event_dict)
        engine.reload_if_changed()  # call periodically to hot-reload edited files
    """

    def __init__(self, rules_dir: str) -> None:
        self.rules_dir = Path(rules_dir)
        self._rules: dict[str, dict] = {}       # rule_id   -> rule dict
        self._path_to_id: dict[str, str] = {}   # file path -> rule_id
        self._mtimes: dict[str, float] = {}     # file path -> last mtime
        self.load_all()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_all(self) -> None:
        """Load every *.yaml file found in the rules directory."""
        for path in sorted(self.rules_dir.glob("*.yaml")):
            self._load_file(path)

    def reload_if_changed(self) -> list[str]:
        """
        Detect new, modified, or deleted rule files and reload as needed.
        Returns the list of rule IDs that were added, updated, or removed.

        Designed to be called on every ingestion cycle so operators can edit
        rules and see them take effect without restarting the server.
        """
        changed: list[str] = []

        current_paths = set(self.rules_dir.glob("*.yaml"))
        known_paths   = {Path(p) for p in self._mtimes}

        # New or modified files.
        for path in current_paths:
            key = str(path)
            if key not in self._mtimes or self._mtimes[key] != path.stat().st_mtime:
                rule = self._load_file(path)
                if rule:
                    changed.append(rule["id"])

        # Files that were deleted since last check.
        for path in known_paths - current_paths:
            rule_id = self._unload_file(path)
            if rule_id:
                changed.append(rule_id)

        return changed

    def match(self, event: dict) -> list[dict]:
        """
        Return every rule that matches this event.
        Returns an empty list when nothing fires. Usually 0 or 1 rules match;
        multiple matches are possible (e.g. a process creation event that
        triggers both a suspicious binary rule and a temp-path rule).
        """
        return [r for r in self._rules.values() if _rule_matches(r, event)]

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_file(self, path: Path) -> dict | None:
        """Parse and validate one rule file. Registers it on success, returns it."""
        try:
            with open(path, encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
        except Exception as exc:
            print(f"[rules] Cannot parse {path.name}: {exc}")
            return None

        errors = _validate_rule(rule)
        if errors:
            print(f"[rules] Skipping {path.name}: {'; '.join(errors)}")
            return None

        key = str(path)

        # If this file previously held a different rule ID, remove the old entry.
        old_id = self._path_to_id.get(key)
        if old_id and old_id != rule["id"]:
            self._rules.pop(old_id, None)

        self._rules[rule["id"]]  = rule
        self._path_to_id[key]    = rule["id"]
        self._mtimes[key]        = path.stat().st_mtime
        return rule

    def _unload_file(self, path: Path) -> str | None:
        """Remove a rule whose file was deleted. Returns the rule ID, or None."""
        key = str(path)
        rule_id = self._path_to_id.pop(key, None)
        self._mtimes.pop(key, None)
        if rule_id:
            self._rules.pop(rule_id, None)
        return rule_id


# ------------------------------------------------------------------
# Validation (module-level so tests can call it directly)
# ------------------------------------------------------------------

def _validate_rule(rule: object) -> list[str]:
    """
    Return a list of error strings describing why the rule is invalid.
    An empty list means the rule is valid and ready to load.
    """
    if not isinstance(rule, dict):
        return [f"rule must be a YAML mapping, got {type(rule).__name__}"]

    errors: list[str] = []

    missing = REQUIRED_FIELDS - rule.keys()
    if missing:
        # Return early — can't validate sub-fields if top-level keys are absent.
        return [f"missing required field(s): {', '.join(sorted(missing))}"]

    if rule["severity"] not in VALID_SEVERITIES:
        errors.append(
            f"severity '{rule['severity']}' must be one of {sorted(VALID_SEVERITIES)}"
        )

    conditions = rule["conditions"]
    if not isinstance(conditions, list) or len(conditions) == 0:
        errors.append("conditions must be a non-empty list")
        return errors

    for i, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            errors.append(f"condition[{i}] must be a mapping")
            continue
        for key in ("field", "operator", "value"):
            if key not in cond:
                errors.append(f"condition[{i}] missing '{key}'")
        op = cond.get("operator")
        if op and op not in VALID_OPERATORS:
            errors.append(
                f"condition[{i}] unknown operator '{op}'; "
                f"valid: {sorted(VALID_OPERATORS)}"
            )

    return errors


# ------------------------------------------------------------------
# Matching (module-level so tests can call them directly)
# ------------------------------------------------------------------

def _rule_matches(rule: dict, event: dict) -> bool:
    """True if the event's source matches the rule and every condition passes."""
    if event.get("source") != rule["source"]:
        return False
    return all(_condition_matches(c, event) for c in rule["conditions"])


def _condition_matches(condition: dict, event: dict) -> bool:
    """
    Evaluate one condition against an event field.
    Returns False if the field is absent — a missing field never matches.
    """
    actual = event.get(condition["field"])
    if actual is None:
        return False

    op       = condition["operator"]
    expected = condition["value"]

    if op == "equals":
        # Compare as strings so YAML integers match event string values.
        return str(actual) == str(expected)

    if op == "contains":
        return str(expected) in str(actual)

    if op == "startswith":
        return str(actual).startswith(str(expected))

    if op == "regex":
        return bool(re.search(str(expected), str(actual)))

    if op == "greater_than":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False

    return False
