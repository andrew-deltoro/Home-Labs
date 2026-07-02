"""
Dashboard blueprint: serves the web UI and the JSON API the UI polls.

Routes
------
GET /                        — HTML dashboard page
GET /api/alerts              — alert list as JSON  (?severity=&rule_id=&limit=)
GET /api/stats               — {severity: count} summary for the stat cards
GET /api/alerts/count        — {"count": N} of alerts newer than ?since=<ISO>
"""

from flask import Blueprint, jsonify, render_template, request

from server.database.store import (
    get_alert_count_since,
    get_alerts,
    get_counts_by_severity,
)


def create_dashboard(db_path: str) -> Blueprint:
    """
    Blueprint factory — db_path is injected at creation so routes need no globals.
    Register with: app.register_blueprint(create_dashboard(db_path))
    """
    bp = Blueprint(
        "dashboard",
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/static",
    )

    @bp.get("/")
    def index():
        return render_template("index.html")

    @bp.get("/api/alerts")
    def api_alerts():
        severity = request.args.get("severity") or None
        rule_id  = request.args.get("rule_id")  or None
        try:
            limit = int(request.args.get("limit", 200))
        except ValueError:
            limit = 200
        return jsonify(get_alerts(db_path, limit=limit, severity=severity, rule_id=rule_id))

    @bp.get("/api/stats")
    def api_stats():
        return jsonify(get_counts_by_severity(db_path))

    @bp.get("/api/alerts/count")
    def api_alert_count():
        since = request.args.get("since", "")
        return jsonify({"count": get_alert_count_since(db_path, since)})

    return bp
