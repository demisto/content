"""Unit tests for the Proofpoint Cloud Threat Response integration."""

import json
from pathlib import Path

import pytest

from ProofpointCloudThreatResponse import (
    AUTH_URL,
    Client,
    build_filters_body,
    fetch_incidents,
    format_ctr_date,
    parse_ctr_date,
    proofpoint_ctr_incident_get_command,
    proofpoint_ctr_incidents_list_command,
    test_module_command,
)

TEST_DATA = Path(__file__).parent / "test_data"
BASE_URL = "https://threatprotection-api.proofpoint.com"


def _load(name: str) -> dict:
    with (TEST_DATA / name).open() as fp:
        return json.load(fp)


@pytest.fixture()
def _clear_context(mocker):
    """Reset the integration_context between tests."""
    mocker.patch(
        "ProofpointCloudThreatResponse.get_integration_context",
        return_value={},
    )
    mocker.patch("ProofpointCloudThreatResponse.set_integration_context")


@pytest.fixture()
def client(_clear_context) -> Client:
    return Client(
        base_url=BASE_URL,
        client_id="id",
        client_secret="secret",
        verify=False,
        proxy=False,
    )


# --------------------------------------------------------------------------- helpers


def test_format_ctr_date_strips_timezone():
    from datetime import datetime

    formatted = format_ctr_date(datetime(2024, 11, 26, 16, 18, 7))
    assert formatted == "2024-11-26 16:18:07"


def test_parse_ctr_date_handles_freetext():
    parsed = parse_ctr_date("2024-11-26 16:18:07")
    assert parsed is not None
    assert parsed.year == 2024 and parsed.month == 11


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


def test_client_token_request_called_once_per_run(client: Client, mocker, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json=_load("incidents_list.json"))

    set_ctx = mocker.patch("ProofpointCloudThreatResponse.set_integration_context")

    client.list_incidents(build_filters_body(start_row=0, end_row=10))
    # set_integration_context should be called once after a fresh token retrieval
    assert set_ctx.call_count == 1


def test_client_token_cached_when_not_expired(mocker, requests_mock):
    import time as _time

    mocker.patch(
        "ProofpointCloudThreatResponse.get_integration_context",
        return_value={
            "access_token": "cached",
            "token_expires_at": int(_time.time()) + 3600,
        },
    )
    set_ctx = mocker.patch("ProofpointCloudThreatResponse.set_integration_context")
    auth_mock = requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json={"incidents": []})

    c = Client(BASE_URL, "id", "secret", verify=False, proxy=False)
    c.list_incidents(build_filters_body(start_row=0, end_row=1))

    assert auth_mock.called is False
    assert set_ctx.called is False


# --------------------------------------------------------------------------- commands


def test_list_incidents_command_builds_output(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json=_load("incidents_list.json"))

    result = proofpoint_ctr_incidents_list_command(
        client,
        {"limit": "10", "source_filters": "abuse_mailbox,tap"},
    )
    assert result.outputs_prefix == "ProofPointCloud.Incident"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "440def43-c322-42ba-a6d6-a2306128ea3b"
    assert "Suspicious login attempt" in result.readable_output


def test_list_incidents_rejects_invalid_filter(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    with pytest.raises(Exception, match="other_filters"):
        proofpoint_ctr_incidents_list_command(client, {"other_filters": "bogus"})


def test_get_incident_command_iterates_ids(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.get(
        f"{BASE_URL}/api/v1/tric/incidents/aaa",
        json=_load("incident_get.json"),
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/tric/incidents/bbb",
        json=_load("incident_get.json"),
    )

    result = proofpoint_ctr_incident_get_command(client, {"incident_id": "aaa,bbb"})
    assert len(result.outputs) == 2
    assert result.outputs[0]["summary"]["displayId"] == 781


def test_get_incident_requires_id(client: Client):
    with pytest.raises(Exception, match="incident_id"):
        proofpoint_ctr_incident_get_command(client, {})


# --------------------------------------------------------------------------- test_module


def test_test_module_ok(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json={"incidents": []})
    assert test_module_command(client, {"isFetch": False}) == "ok"


def test_test_module_rejects_both_states(client: Client):
    msg = test_module_command(
        client,
        {"isFetch": True, "fetch_states": "open_incidents,closed_incidents"},
    )
    assert "empty result" in msg


def test_test_module_requires_state_when_fetching(client: Client):
    msg = test_module_command(client, {"isFetch": True, "fetch_states": ""})
    assert "must select at least one" in msg


# --------------------------------------------------------------------------- fetch


def test_fetch_incidents_first_run(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json=_load("incidents_list.json"))
    requests_mock.get(
        f"{BASE_URL}/api/v1/tric/incidents/440def43-c322-42ba-a6d6-a2306128ea3b",
        json=_load("incident_get.json"),
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/tric/incidents/550def43-c322-42ba-a6d6-a2306128ea3c",
        json=_load("incident_get.json"),
    )

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


def test_fetch_incidents_dedupes_seen_ids(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json=_load("incidents_list.json"))
    requests_mock.get(
        f"{BASE_URL}/api/v1/tric/incidents/550def43-c322-42ba-a6d6-a2306128ea3c",
        json=_load("incident_get.json"),
    )

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


def test_fetch_incidents_caps_max_fetch(client: Client, requests_mock):
    requests_mock.post(AUTH_URL, json=_load("token_response.json"))
    captured: dict = {}

    def _matcher(request, _context):
        captured.update(request.json())
        return {"incidents": []}

    requests_mock.post(f"{BASE_URL}/api/v1/tric/incidents", json=_matcher)

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
