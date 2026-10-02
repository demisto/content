import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from CommonServerPython import DemistoException
import SprinklrEventCollector as integration


TEST_DATA = Path(__file__).parent / "test_data"


def load_json(name: str) -> dict:
    with (TEST_DATA / name).open(encoding="utf-8") as input_file:
        return json.load(input_file)


def test_load_json_object_returns_copy():
    source = {"reportingEngine": "OUTBOUND_MESSAGE"}

    result = integration._load_json_object(source, "payload")
    result["page"] = "1"

    assert source == {"reportingEngine": "OUTBOUND_MESSAGE"}


@pytest.mark.parametrize("value", ["not-json", "[]", ""])
def test_load_json_object_rejects_invalid_values(value):
    with pytest.raises(DemistoException):
        integration._load_json_object(value, "payload")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1759248010", 1759248010000),
        ("1759248010000", 1759248010000),
        (1759248010000, 1759248010000),
    ],
)
def test_to_epoch_ms(value, expected):
    assert integration._to_epoch_ms(value) == expected


def test_build_reporting_payload_does_not_modify_configured_payload():
    base = {"reportingEngine": "OUTBOUND_MESSAGE", "pageSize": "20"}

    result = integration._build_reporting_payload(base, 1000, 2000, 100, 2)

    assert base == {"reportingEngine": "OUTBOUND_MESSAGE", "pageSize": "20"}
    assert result["startTime"] == "1000"
    assert result["endTime"] == "2000"
    assert result["pageSize"] == "100"
    assert result["page"] == "2"


def test_extract_and_shape_nested_reporting_rows():
    response = load_json("reporting_response.json")

    records = integration._extract_records(response)
    events = integration._shape_events(records, "OUTBOUND_MESSAGE", 1759248010000)

    assert len(events) == 1
    assert events[0]["postId"] == 300001872142462
    assert events[0]["source_log_type"] == "OUTBOUND_MESSAGE"
    assert events[0]["_time"] == "2025-09-30T16:00:10.000000Z"


@pytest.mark.parametrize(
    "response,records_count,page_size,expected",
    [
        ({"data": {"hasMore": True}}, 1, 200, True),
        ({"data": {"hasMore": "false"}}, 200, 200, False),
        ({"data": {}}, 200, 200, True),
        ({"data": {}}, 199, 200, False),
    ],
)
def test_response_has_more(response, records_count, page_size, expected):
    assert integration._response_has_more(response, records_count, page_size) is expected


def test_record_matches_all_filters():
    record = {
        "authorId": 10,
        "accountId": 20,
        "postId": 30,
        "messageId": 40,
        "channelType": "FACEBOOK",
        "status": "SENT",
        "deleted": False,
    }

    assert integration._record_matches(
        record,
        {
            "author_id": "10",
            "account_id": "20",
            "post_id": "30",
            "message_id": "40",
            "channel": "FACEBOOK",
            "status": "SENT",
            "deleted": "false",
        },
    )
    assert not integration._record_matches(record, {"status": "FAILED"})


def test_fetch_events_advances_completed_checkpoint(monkeypatch):
    response = load_json("reporting_response.json")
    client = MagicMock()
    client.report_query.return_value = response
    monkeypatch.setattr(integration.demisto, "getLastRun", lambda: {"state_version": 2, "last_fetch_ms": 999})
    monkeypatch.setattr(integration.time, "time", lambda: 2.0)
    params = {
        "reporting_payload": json.dumps({"reportingEngine": "OUTBOUND_MESSAGE"}),
        "max_fetch": "200",
    }

    events, next_run = integration.fetch_events_command(client, params)

    assert len(events) == 1
    assert next_run == {"state_version": 2, "last_fetch_ms": 2000}
    request_payload = client.report_query.call_args.args[0]
    assert request_payload["startTime"] == "1000"
    assert request_payload["endTime"] == "2000"
    assert request_payload["page"] == "0"


def test_fetch_events_retains_window_when_more_pages_exist(monkeypatch):
    client = MagicMock()
    client.report_query.return_value = {"data": {"hasMore": True, "rows": []}}
    monkeypatch.setattr(
        integration.demisto,
        "getLastRun",
        lambda: {
            "state_version": 2,
            "last_fetch_ms": 999,
            "pending_start_ms": 1000,
            "pending_end_ms": 2000,
            "pending_page": 3,
        },
    )
    params = {
        "reporting_payload": json.dumps({"reportingEngine": "OUTBOUND_MESSAGE"}),
        "max_fetch": "200",
    }

    _, next_run = integration.fetch_events_command(client, params)

    assert next_run == {
        "state_version": 2,
        "last_fetch_ms": 999,
        "pending_start_ms": 1000,
        "pending_end_ms": 2000,
        "pending_page": 4,
    }


def test_request_new_token_encodes_credentials(monkeypatch):
    response = MagicMock()
    response.ok = True
    response.json.return_value = {"access_token": "token-value", "expires_in": 3600}
    post = MagicMock(return_value=response)
    monkeypatch.setattr(integration.requests, "post", post)
    monkeypatch.setattr(integration.demisto, "getIntegrationContext", lambda: {})
    set_context = MagicMock()
    monkeypatch.setattr(integration.demisto, "setIntegrationContext", set_context)
    client = integration.Client(
        server_url="https://api.example.invalid",
        environment="prod",
        client_id="client id",
        client_secret="secret value",
        reporting_path="/{env}/api/v2/reports/query",
        scim_delete_path="/{env}/api/v1/scim/v2/Users/{userId}",
    )

    assert client._request_new_token() == "token-value"
    assert "client_id=client+id" in post.call_args.kwargs["data"]
    assert "client_secret=secret+value" in post.call_args.kwargs["data"]
    set_context.assert_called_once()


def test_confirmation_is_required_for_state_changes():
    with pytest.raises(DemistoException, match="blocked"):
        integration._require_confirmation({"confirm": "no"}, "Delete user")

    integration._require_confirmation({"confirm": "yes"}, "Delete user")


def test_governance_account_action_rejects_false_response(monkeypatch):
    response = MagicMock()
    response.ok = True
    response.text = "false"
    response.json.return_value = False
    client = integration.Client(
        server_url="https://api.example.invalid",
        environment="prod",
        client_id="client-id",
        client_secret="client-secret",
        reporting_path="/{env}/api/v2/reports/query",
        scim_delete_path="/{env}/api/v1/scim/v2/Users/{userId}",
    )
    monkeypatch.setattr(client, "_authorized_request", MagicMock(return_value=response))

    with pytest.raises(DemistoException, match="returned false"):
        client.governance_account_team_action("attach", "ad", "team-1", "account-1")
