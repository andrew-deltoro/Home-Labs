"""
Tests for agent/forwarder.py.

Uses unittest.mock to intercept requests.post — no real HTTP calls are made.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.forwarder import forward_events


SERVER = "http://localhost:5000"

EVENTS = [
    {
        "source": "windows_event_log",
        "hostname": "DESKTOP-TEST",
        "EventID": 4625,
        "Message": "An account failed to log on.",
    }
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    """Build a mock requests.Response with the given JSON payload."""
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data
    m.raise_for_status.return_value = None  # no-op — simulates 2xx
    return m


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

@patch("agent.forwarder.requests.post")
def test_posts_to_correct_url(mock_post):
    mock_post.return_value = mock_response({"received": 1, "alerts_triggered": 0})
    forward_events(SERVER, EVENTS)
    mock_post.assert_called_once()
    called_url = mock_post.call_args.args[0]
    assert called_url == f"{SERVER}/ingest"


@patch("agent.forwarder.requests.post")
def test_sends_events_in_json_body(mock_post):
    mock_post.return_value = mock_response({"received": 1, "alerts_triggered": 0})
    forward_events(SERVER, EVENTS)
    sent_body = mock_post.call_args.kwargs["json"]
    assert sent_body == {"events": EVENTS}


@patch("agent.forwarder.requests.post")
def test_returns_server_response_dict(mock_post):
    payload = {"received": 1, "alerts_triggered": 1}
    mock_post.return_value = mock_response(payload)
    result = forward_events(SERVER, EVENTS)
    assert result == payload


@patch("agent.forwarder.requests.post")
def test_default_timeout_is_ten_seconds(mock_post):
    mock_post.return_value = mock_response({"received": 1, "alerts_triggered": 0})
    forward_events(SERVER, EVENTS)
    assert mock_post.call_args.kwargs["timeout"] == 10


@patch("agent.forwarder.requests.post")
def test_custom_timeout_is_passed_through(mock_post):
    mock_post.return_value = mock_response({"received": 1, "alerts_triggered": 0})
    forward_events(SERVER, EVENTS, timeout=30)
    assert mock_post.call_args.kwargs["timeout"] == 30


@patch("agent.forwarder.requests.post")
def test_large_batch_sent_intact(mock_post):
    many = EVENTS * 100
    mock_post.return_value = mock_response({"received": 100, "alerts_triggered": 0})
    forward_events(SERVER, many)
    sent = mock_post.call_args.kwargs["json"]["events"]
    assert len(sent) == 100


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

@patch("agent.forwarder.requests.post")
def test_raises_on_connection_refused(mock_post):
    mock_post.side_effect = requests.ConnectionError("Connection refused")
    with pytest.raises(requests.ConnectionError):
        forward_events(SERVER, EVENTS)


@patch("agent.forwarder.requests.post")
def test_raises_on_timeout(mock_post):
    mock_post.side_effect = requests.Timeout("timed out")
    with pytest.raises(requests.Timeout):
        forward_events(SERVER, EVENTS)


@patch("agent.forwarder.requests.post")
def test_raises_on_server_500(mock_post):
    bad = mock_response({}, status_code=500)
    bad.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
    mock_post.return_value = bad
    with pytest.raises(requests.HTTPError):
        forward_events(SERVER, EVENTS)


@patch("agent.forwarder.requests.post")
def test_raises_on_server_401(mock_post):
    bad = mock_response({}, status_code=401)
    bad.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
    mock_post.return_value = bad
    with pytest.raises(requests.HTTPError):
        forward_events(SERVER, EVENTS)
