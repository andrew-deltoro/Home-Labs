"""
Tests for server/main.py.

Focuses on create_app() — the testable core — and load_config().
The main() function itself just calls these two then runs app.run(),
which blocks, so it isn't unit-tested here.
"""

from pathlib import Path

import pytest
import yaml
from flask import Flask

from server.main import create_app, load_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config_and_paths(tmp_path):
    """Return a (config_dict, db_path, rules_dir) tuple with dirs on disk."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    db_path = str(tmp_path / "test.db")
    cfg = {
        "host": "0.0.0.0",
        "port": 5000,
        "database_path": db_path,
        "rules_dir": str(rules_dir),
        "dashboard_refresh_interval": 5,
    }
    return cfg, db_path, str(rules_dir)


@pytest.fixture
def config_file(tmp_path, config_and_paths):
    """Write the config dict to a temp YAML file and return the path."""
    cfg, _, _ = config_and_paths
    path = tmp_path / "server.yaml"
    path.write_text(yaml.dump(cfg), encoding="utf-8")
    return str(path), cfg


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

def test_load_config_returns_dict(config_file):
    path, expected = config_file
    cfg = load_config(path)
    assert cfg["port"] == 5000
    assert cfg["host"] == "0.0.0.0"
    assert "database_path" in cfg
    assert "rules_dir" in cfg


def test_load_config_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/server.yaml")


# ---------------------------------------------------------------------------
# create_app
# ---------------------------------------------------------------------------

def test_create_app_returns_flask_instance(config_and_paths):
    cfg, db_path, rules_dir = config_and_paths
    app, engine = create_app(db_path, rules_dir)
    assert isinstance(app, Flask)


def test_create_app_returns_rule_engine(config_and_paths):
    from server.rules.engine import RuleEngine
    cfg, db_path, rules_dir = config_and_paths
    _, engine = create_app(db_path, rules_dir)
    assert isinstance(engine, RuleEngine)


def test_create_app_initialises_database(config_and_paths):
    cfg, db_path, rules_dir = config_and_paths
    create_app(db_path, rules_dir)
    assert Path(db_path).exists()


def test_create_app_loads_rules_from_dir(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule = {
        "id": "test_rule", "name": "Test", "severity": "low",
        "source": "windows_event_log",
        "conditions": [{"field": "EventID", "operator": "equals", "value": 1}],
    }
    (rules_dir / "test_rule.yaml").write_text(yaml.dump(rule), encoding="utf-8")

    _, engine = create_app(str(tmp_path / "test.db"), str(rules_dir))
    assert engine.rule_count == 1


# ---------------------------------------------------------------------------
# Route registration (both blueprints must be wired up)
# ---------------------------------------------------------------------------

@pytest.fixture
def app_client(config_and_paths):
    cfg, db_path, rules_dir = config_and_paths
    app, _ = create_app(db_path, rules_dir)
    app.config["TESTING"] = True
    return app.test_client()


def test_dashboard_route_registered(app_client):
    assert app_client.get("/").status_code == 200


def test_api_alerts_route_registered(app_client):
    assert app_client.get("/api/alerts").status_code == 200


def test_api_stats_route_registered(app_client):
    assert app_client.get("/api/stats").status_code == 200


def test_ingest_route_registered(app_client):
    # GET is not allowed — 405 proves the route exists (404 would mean it doesn't).
    assert app_client.get("/ingest").status_code == 405


def test_ingest_accepts_post(app_client):
    r = app_client.post("/ingest", json={"events": []})
    assert r.status_code == 200
