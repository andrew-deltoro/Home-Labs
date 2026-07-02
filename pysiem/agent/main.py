"""
Agent entry point.

Reads Windows Event Log channels on a configurable interval and forwards
batched events to the PySIEM server.

Run from the project root:
    python -m agent.main
"""

import socket
import time
from pathlib import Path

import yaml

from agent.forwarder import forward_events
from agent.log_reader import EventReader


def load_config(config_path: str) -> dict:
    with open(config_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def main() -> None:
    project_root  = Path(__file__).resolve().parent.parent
    config        = load_config(str(project_root / "config" / "agent.yaml"))

    hostname      = socket.gethostname()
    server_url    = config["server_url"]
    poll_interval = config["poll_interval"]
    max_events    = config["max_events_per_poll"]

    readers = [
        EventReader(
            channel=src["channel"],
            source=src["source"],
            hostname=hostname,
            max_events=max_events,
        )
        for src in config["log_sources"]
    ]

    print(f"[agent] Starting on {hostname}")
    print(f"[agent] Server   : {server_url}")
    print(f"[agent] Interval : {poll_interval}s")
    print(f"[agent] Sources  : {[r.channel for r in readers]}")

    while True:
        events: list[dict] = []
        for reader in readers:
            events.extend(reader.read_new())

        if events:
            try:
                result    = forward_events(server_url, events)
                triggered = result.get("alerts_triggered", 0)
                suffix    = f" — {triggered} alert(s) triggered" if triggered else ""
                print(f"[agent] Forwarded {len(events)} event(s){suffix}")
            except Exception as exc:
                print(f"[agent] Could not reach server: {exc}")

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
