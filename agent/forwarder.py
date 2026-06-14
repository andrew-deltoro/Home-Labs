"""
Event forwarder: sends a batch of log events to the server's /ingest endpoint.
"""

import requests


def forward_events(
    server_url: str,
    events: list[dict],
    timeout: int = 10,
) -> dict:
    """
    POST a batch of events to POST /ingest on the server.

    Returns the server's response JSON: {"received": N, "alerts_triggered": M}.
    Raises requests.RequestException on network failure or a non-2xx response.

    timeout controls how long to wait for the server before giving up (seconds).
    """
    response = requests.post(
        f"{server_url}/ingest",
        json={"events": events},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()
