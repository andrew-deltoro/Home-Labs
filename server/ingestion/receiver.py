"""
Ingestion receiver: a Flask blueprint that accepts batched log events from agents.

Agents POST a JSON body shaped like:
    {
        "events": [
            {
                "source":    "windows_event_log",
                "hostname":  "DESKTOP-TEST",
                "EventID":   4625,
                "Message":   "An account failed to log on.",
                "TimeCreated": "2026-06-14T18:00:00"
            },
            ...
        ]
    }

For each event the engine is asked to match it against all loaded rules.
Every match becomes a stored alert. The response reports how many events
were received and how many alerts were triggered.
"""

from flask import Blueprint, jsonify, request

from server.database.store import insert_alert
from server.rules.engine import RuleEngine


def create_receiver(engine: RuleEngine, db_path: str) -> Blueprint:
    """
    Blueprint factory — injects the shared engine and db_path at creation time
    so the route closure doesn't rely on any global state.

    Register with:
        app.register_blueprint(create_receiver(engine, db_path))
    """
    bp = Blueprint("receiver", __name__)

    @bp.post("/ingest")
    def ingest():
        body = request.get_json(force=True, silent=True)

        if not isinstance(body, dict) or "events" not in body:
            return jsonify({"error": "body must be JSON with an 'events' list"}), 400

        events = body["events"]
        if not isinstance(events, list):
            return jsonify({"error": "'events' must be a list"}), 400

        # Pick up any rule files the operator added or edited since last cycle.
        engine.reload_if_changed()

        alerts_triggered = 0
        for event in events:
            if not isinstance(event, dict):
                continue  # silently skip malformed items in the batch
            for rule in engine.match(event):
                insert_alert(db_path, rule, event)
                alerts_triggered += 1

        return jsonify({"received": len(events), "alerts_triggered": alerts_triggered})

    return bp
