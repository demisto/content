"""Unit tests for the Proofpoint Cloud Threat Response integration."""

import json
from pathlib import Path
from typing import Any

import pytest

from ProofpointCloudThreatResponse import (
    Client,
    ProofpointCTRAuthHandler,
    build_filters_body,
    fetch_incidents,
    format_ctr_date,
    parse_ctr_date,
    proofpoint_ctr_incident_get_command,
    proofpoint_ctr_incidents_list_command,
    run_test_module,
)

TEST_DATA = Path(__file__).parent / "test_data"
BASE_URL = "https://threatprotection-api.proofpoint.com"


def _load(name: str) -> dict:
    with (TEST_DATA / name).open() as fp:
        return json.load(fp)


@pytest.fixture()
def _patch_context(mocker):
    """Patch context-store I/O so the auth handler never hits the runtime."""
    mocker.patch.object(ProofpointCTRAuthHandler, "_load_token_from_context")
    mocker.patch.object(ProofpointCTRAuthHandler, "_save_token_to_context")


@pytest.fixture()
def client(_patch_context, mocker) -> Client:
    """Return a Client whose ``_http_request`` is mock-able per test."""
    # Avoid initializing the underlying ContentClient (httpx etc.) - we mock the
    # I/O surface exposed by Client.list_incidents / Client.get_incident.
    mocker.patch("ProofpointCloudThreatResponse.ContentClient.__init__", return_value=None)
    instance = Client.__new__(Client)
    # Provide just enough state for the test:
    instance.timeout = 60.0  # type: ignore[attr-defined]
    return instance


# --------------------------------------------------------------------------- helpers


def test_format_ctr_date_strips_timezone():
    from datetime import datetime

    formatted = format_ctr_date(datetime(2024, 11, 26, 16, 18, 7))
    assert formatted == "2024-11-26 16:18:07"


def test_parse_ctr_date_handles_freetext():
    parsed = parse_ctr_date("2024-11-26 16:18:07")
    assert parsed is not None
    assert parsed.year == 2024
    assert parsed.month == 11


def test_build_filters_body_omits_empty_filters():
    from datetime import datetime

    body = build_filters_body(
        start_time=datetime(2024, 11, 26, 16, 18, 7),
        end_time=datetime(2024, 11, 26, 16, 19, 7),
        end_row=10,
    )
    assert body == {
        "filters": {
            "time_range_filter": {
                "start": "2024-11-26 16:18:07",
                "end": "2024-11-26 16:19:07",
            },
        },
        "startRow": 0,
        "endRow": 10,
        "sortParams": [{"sort": "desc", "colId": "createdAt"}],
    }


def test_build_filters_body_validates_allowed_values():
    with pytest.raises(Exception, match="source_filters"):
        build_filters_body(source_filters=["bogus"])


# --------------------------------------------------------------------------- auth


def test_auth_handler_rejects_empty_credentials():
    from ProofpointCloudThreatResponse import ProofpointCTRAuthHandler

    with pytest.raises(Exception, match="Client ID"):
        ProofpointCTRAuthHandler(client_id="", client_secret="x")
    with pytest.raises(Exception, match="Client Secret"):
        ProofpointCTRAuthHandler(client_id="x", client_secret="")


def test_auth_handler_token_validity(mocker):
    import time as _time

    mocker.patch.object(ProofpointCTRAuthHandler, "_load_token_from_context")
    handler = ProofpointCTRAuthHandler(client_id="id", client_secret="secret")

    handler._access_token = "abc"
    handler._expires_at = int(_time.time()) + 3600
    assert handler._token_is_valid() is True

    handler._expires_at = int(_time.time()) - 1
    assert handler._token_is_valid() is False

    handler._access_token = None
    handler._expires_at = int(_time.time()) + 3600
    assert handler._token_is_valid() is False


# --------------------------------------------------------------------------- commands


def test_list_incidents_command_builds_output(client: Client, mocker):
    mocker.patch.object(Client, "list_incidents", return_value=_load("incidents_list.json"))

    result = proofpoint_ctr_incidents_list_command(
        client,
        {"limit": "10", "source_filters": "abuse_mailbox,tap"},
    )
    assert result.outputs_prefix == "ProofPointCloud.Incident"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "440def43-c322-42ba-a6d6-a2306128ea3b"
    assert "Suspicious login attempt" in result.readable_output


def test_list_incidents_rejects_invalid_filter(client: Client):
    with pytest.raises(Exception, match="other_filters"):
        proofpoint_ctr_incidents_list_command(client, {"other_filters": "bogus"})


def test_get_incident_command_iterates_ids(client: Client, mocker):
    calls: list[str] = []

    def _fake_get(self, incident_id: str) -> dict[str, Any]:
        calls.append(incident_id)
        return _load("incident_get.json")

    mocker.patch.object(Client, "get_incident", _fake_get)

    result = proofpoint_ctr_incident_get_command(client, {"incident_id": "aaa,bbb"})
    assert calls == ["aaa", "bbb"]
    assert len(result.outputs) == 2
    assert result.outputs[0]["summary"]["displayId"] == 781


def test_get_incident_requires_id(client: Client):
    with pytest.raises(Exception, match="incident_id"):
        proofpoint_ctr_incident_get_command(client, {})


# --------------------------------------------------------------------------- test_module


def test_test_module_ok(client: Client, mocker):
    mocker.patch.object(Client, "list_incidents", return_value={"incidents": []})
    assert run_test_module(client, {"isFetch": False}) == "ok"


def test_test_module_rejects_both_states(client: Client):
    msg = run_test_module(
        client,
        {"isFetch": True, "fetch_states": "open_incidents,closed_incidents"},
    )
    assert "empty result" in msg


def test_test_module_requires_state_when_fetching(client: Client):
    msg = run_test_module(client, {"isFetch": True, "fetch_states": ""})
    assert "must select at least one" in msg


# --------------------------------------------------------------------------- fetch


def test_fetch_incidents_first_run(client: Client, mocker):
    mocker.patch.object(Client, "list_incidents", return_value=_load("incidents_list.json"))
    mocker.patch.object(Client, "get_incident", return_value=_load("incident_get.json"))

    next_run, incidents = fetch_incidents(
        client,
        {
            "first_fetch": "3 days",
            "max_fetch": "50",
            "fetch_delta": "1",
            "fetch_states": "open_incidents",
        },
        last_run={},
    )
    assert len(incidents) == 2
    assert incidents[0]["dbotMirrorId"] == "440def43-c322-42ba-a6d6-a2306128ea3b"
    assert "last_fetch" in next_run
    assert "last_fetched_ids" in next_run


def test_fetch_incidents_dedupes_seen_ids(client: Client, mocker):
    mocker.patch.object(Client, "list_incidents", return_value=_load("incidents_list.json"))
    mocker.patch.object(Client, "get_incident", return_value=_load("incident_get.json"))

    next_run, incidents = fetch_incidents(
        client,
        {
            "first_fetch": "3 days",
            "max_fetch": "50",
            "fetch_delta": "1",
            "fetch_states": "open_incidents",
        },
        last_run={
            "last_fetch": "2024-11-26 16:18:00",
            "last_fetched_ids": ["440def43-c322-42ba-a6d6-a2306128ea3b"],
        },
    )
    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "550def43-c322-42ba-a6d6-a2306128ea3c"
    assert next_run["last_fetch"] != "2024-11-26 16:18:00"


def test_fetch_incidents_rejects_both_states(client: Client):
    with pytest.raises(Exception, match="empty result"):
        fetch_incidents(
            client,
            {
                "first_fetch": "3 days",
                "fetch_states": "open_incidents,closed_incidents",
            },
            last_run={},
        )


def test_fetch_incidents_caps_max_fetch(client: Client, mocker):
    captured: dict = {}

    def _capture(self, body):
        captured.update(body)
        return {"incidents": []}

    mocker.patch.object(Client, "list_incidents", _capture)

    fetch_incidents(
        client,
        {
            "first_fetch": "3 days",
            "max_fetch": "9999",
            "fetch_delta": "0",
            "fetch_states": "open_incidents",
        },
        last_run={},
    )
    # max_fetch is capped at MAX_PAGE_SIZE (200) -> endRow = 199
    assert captured["endRow"] == 199
    assert captured["startRow"] == 0
    assert captured["sortParams"] == [{"sort": "asc", "colId": "createdAt"}]
    assert captured["filters"]["other_filters"] == ["open_incidents"]
