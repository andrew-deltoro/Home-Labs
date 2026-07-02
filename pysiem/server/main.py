"""
Server entry point.

Reads config/server.yaml, wires the Flask app together, and starts listening.

Run from the project root:
    python -m server.main
"""

from pathlib import Path

import yaml
from flask import Flask

from server.dashboard.app import create_dashboard
from server.database.store import init_db
from server.ingestion.receiver import create_receiver
from server.rules.engine import RuleEngine


def load_config(config_path: str) -> dict:
    with open(config_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def create_app(db_path: str, rules_dir: str) -> tuple[Flask, RuleEngine]:
    """
    Build and return the configured Flask app and the rule engine.

    Separated from main() so tests can call it without starting a live server.
    Returns both objects so callers can inspect engine.rule_count at startup.
    """
    init_db(db_path)
    engine = RuleEngine(rules_dir)

    # static_folder=None prevents Flask from registering its own /static route,
    # which would shadow the dashboard blueprint's /static endpoint.
    app = Flask(__name__, static_folder=None)
    app.register_blueprint(create_receiver(engine, db_path))
    app.register_blueprint(create_dashboard(db_path))

    return app, engine


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    config       = load_config(str(project_root / "config" / "server.yaml"))

    db_path   = config["database_path"]
    rules_dir = str(project_root / config["rules_dir"])
    host      = config["host"]
    port      = config["port"]

    app, engine = create_app(db_path, rules_dir)

    print("[server] PySIEM starting")
    print(f"[server] Dashboard  → http://{host}:{port}/")
    print(f"[server] Ingest     → http://{host}:{port}/ingest")
    print(f"[server] Database   : {db_path}")
    print(f"[server] Rules      : {rules_dir} ({engine.rule_count} loaded)")

    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
