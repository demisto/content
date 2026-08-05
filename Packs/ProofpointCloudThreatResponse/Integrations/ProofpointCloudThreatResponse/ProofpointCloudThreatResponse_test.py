"""Unit tests for the Proofpoint Cloud Threat Response integration."""

import json
from pathlib import Path
from typing import Any

import pytest

from ProofpointCloudThreatResponse import (
    Client,
    ProofpointCTRAuthHandler,
    build_filters_body,
    build_messages_body,
    fetch_incidents,
    format_ctr_date,
    parse_ctr_date,
    proofpoint_ctr_blocklist_add_entry_command,
    proofpoint_ctr_blocklist_list_command,
    proofpoint_ctr_blocklist_remove_entry_command,
    proofpoint_ctr_incident_get_command,
    proofpoint_ctr_incident_upload_message_command,
    proofpoint_ctr_incidents_list_command,
    proofpoint_ctr_message_download_command,
    proofpoint_ctr_message_list_command,
    proofpoint_ctr_run_workflow_command,
    proofpoint_ctr_safelist_add_entry_command,
    proofpoint_ctr_safelist_list_command,
    proofpoint_ctr_safelist_remove_entry_command,
    proofpoint_ctr_workflows_list_command,
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
        {"limit": "10", "source_filters": "abuse_mailbox"},
    )
    assert result.outputs_prefix == "ProofPointCloud.Incident"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "00000000-0000-0000-0000-000000000001"
    assert "Suspicious phishing attempt" in result.readable_output


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
    # The get command flattens the summary fields to the top level so that
    # outputs_key_field="id" matches the list command and XSOAR can enrich
    # the existing context entry rather than creating a duplicate.
    assert result.outputs[0]["displayId"] == 12345


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
    assert incidents[0]["dbotMirrorId"] == "00000000-0000-0000-0000-000000000001"
    assert "last_fetch" in next_run
    assert "last_fetched_ids" in next_run
    # last_fetch must be the createdAt of the latest incident (incident 1: 2024-01-01T10:00:00)
    assert next_run["last_fetch"] == "2024-01-01 10:00:00"


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
            "last_fetch": "2024-01-01 08:00:00",
            "last_fetched_ids": ["00000000-0000-0000-0000-000000000001"],
        },
    )
    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "00000000-0000-0000-0000-000000000002"
    # last_fetch should advance to the createdAt of the latest new incident (incident 2)
    assert next_run["last_fetch"] == "2024-01-01 09:00:00"


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
    # max_fetch is capped at MAX_PAGE_SIZE (200) -> endRow = 200 (exclusive upper bound)
    assert captured["endRow"] == 200
    assert captured["startRow"] == 0
    assert captured["sortParams"] == [{"sort": "asc", "colId": "createdAt"}]
    assert captured["filters"]["other_filters"] == ["open_incidents"]


# --------------------------------------------------------------------------- new: incidents-list extras


def test_incidents_list_adds_priority_and_sort(client: Client, mocker):
    captured: dict = {}

    def _capture(self, body):
        captured.update(body)
        return {"incidents": []}

    mocker.patch.object(Client, "list_incidents", _capture)

    # Given priority_filters and sort=asc
    proofpoint_ctr_incidents_list_command(client, {"limit": "5", "priority_filters": "high,low", "sort": "asc"})
    # Then the body carries priority_filters and asc sort direction
    assert captured["filters"]["priority_filters"] == ["high", "low"]
    assert captured["sortParams"] == [{"sort": "asc", "colId": "createdAt"}]


def test_incidents_list_rejects_bad_sort(client: Client):
    with pytest.raises(Exception, match="sort"):
        proofpoint_ctr_incidents_list_command(client, {"sort": "bogus"})


# --------------------------------------------------------------------------- new: workflows


def test_workflows_list_command(client: Client, mocker):
    workflows = [
        {"id": "wf1", "name": "Quarantine", "enabled": True, "type": "incident", "createdAt": "2026-07-02T12:00:21Z"},
        {"id": "wf2", "name": "Notify", "enabled": False, "type": "message", "createdAt": "2026-07-02T12:00:21Z"},
    ]
    mocker.patch.object(Client, "list_workflows", return_value={"workflows": workflows})

    # Given a workflows response and limit=1
    result = proofpoint_ctr_workflows_list_command(client, {"limit": "1"})
    # Then only the first workflow is returned under the Workflow prefix
    assert result.outputs_prefix == "ProofPointCloud.Workflow"
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "wf1"


def test_workflows_list_all_results(client: Client, mocker):
    workflows = [{"id": f"wf{i}", "name": "x", "enabled": True, "type": "incident"} for i in range(5)]
    mocker.patch.object(Client, "list_workflows", return_value=workflows)

    result = proofpoint_ctr_workflows_list_command(client, {"limit": "1", "all_results": "true"})
    assert len(result.outputs) == 5


def test_workflows_list_rejects_bad_type(client: Client):
    with pytest.raises(Exception, match="type"):
        proofpoint_ctr_workflows_list_command(client, {"type": "bogus"})


# --------------------------------------------------------------------------- new: run-workflow (polling)


def test_run_workflow_initiate_continues_polling(client: Client, mocker):
    mocker.patch("ProofpointCloudThreatResponse.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    run = {"id": "run1", "state": "IN_PROGRESS", "workflowId": "wf1"}
    mocker.patch.object(Client, "run_workflow", return_value=run)

    # Given a fresh run that is still IN_PROGRESS
    result = proofpoint_ctr_run_workflow_command({"workflow_id": "wf1", "target_ids": "t1"}, client=client)
    # Then the polling decorator schedules a follow-up command
    assert result.scheduled_command is not None
    assert result.scheduled_command._args["run_id"] == "run1"


def test_run_workflow_terminal_stops_polling(client: Client, mocker):
    mocker.patch("ProofpointCloudThreatResponse.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    run = {"id": "run1", "state": "SUCCESS", "workflowId": "wf1"}
    mocker.patch.object(Client, "get_workflow_run", return_value=run)

    # Given a poll for an existing run that reached SUCCESS
    result = proofpoint_ctr_run_workflow_command({"run_id": "run1"}, client=client)
    # Then polling stops (no scheduled command) and the run output is returned
    assert result.scheduled_command is None
    assert result.outputs["state"] == "SUCCESS"


def test_run_workflow_requires_workflow_id(client: Client, mocker):
    mocker.patch("ProofpointCloudThreatResponse.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    with pytest.raises(Exception, match="workflow_id"):
        proofpoint_ctr_run_workflow_command({"target_ids": "t1"}, client=client)


# --------------------------------------------------------------------------- new: messages


def test_message_list_single_by_id(client: Client, mocker):
    msg = {"id": "m1", "email_subject": "Hi", "sender_address": "a@test.com"}
    getter = mocker.patch.object(Client, "get_message", return_value=msg)
    lister = mocker.patch.object(Client, "list_messages")

    # Given a message_id, the single GET endpoint is used
    result = proofpoint_ctr_message_list_command(client, {"message_id": "m1"})
    getter.assert_called_once_with("m1")
    lister.assert_not_called()
    assert result.outputs[0]["id"] == "m1"


def test_message_list_many_by_filters(client: Client, mocker):
    getter = mocker.patch.object(Client, "get_message")
    mocker.patch.object(Client, "list_messages", return_value={"messages": [{"id": "m1"}, {"id": "m2"}]})

    # Given no message_id, the POST list endpoint is used
    result = proofpoint_ctr_message_list_command(client, {"source_filters": "abuse_mailbox", "verdict_filters": "verdict_threat"})
    getter.assert_not_called()
    assert len(result.outputs) == 2


def test_build_messages_body_validates_filters():
    with pytest.raises(Exception, match="source_filters"):
        build_messages_body({"source_filters": "bogus"})


def test_message_download_returns_file(client: Client, mocker):
    mocker.patch.object(Client, "download_message", return_value=b"raw eml bytes")

    # Given a message_id, an EML fileResult is produced
    result = proofpoint_ctr_message_download_command(client, {"message_id": "m1"})
    assert result["File"] == "m1.eml"


def test_message_download_requires_id(client: Client):
    with pytest.raises(Exception, match="message_id"):
        proofpoint_ctr_message_download_command(client, {})


# --------------------------------------------------------------------------- new: upload message


def test_incident_upload_message_command(client: Client, mocker):
    response = {
        "rfcMessageId": "<a@test.com>",
        "incident_id": "inc1",
        "incidentDisplayId": 781,
        "uploadedRecipientsCount": 1,
    }
    captured: dict = {}

    def _capture(self, body):
        captured.update(body)
        return response

    mocker.patch.object(Client, "upload_message", _capture)

    # Given required args, the body is built with a nested message
    result = proofpoint_ctr_incident_upload_message_command(
        client,
        {"incident_id": "inc1", "rfc_message_id": "<a@test.com>", "recipient_addresses": "user@test.com"},
    )
    assert captured["incident_id"] == "inc1"
    assert captured["message"]["rfcMessageId"] == "<a@test.com>"
    assert captured["message"]["recipient_addresses"] == ["user@test.com"]
    assert result.outputs_prefix == "ProofPointCloud.Incident.Message"
    assert result.outputs["incidentDisplayId"] == 781


def test_incident_upload_message_requires_recipients(client: Client):
    with pytest.raises(Exception, match="recipient_addresses"):
        proofpoint_ctr_incident_upload_message_command(client, {"incident_id": "inc1", "rfc_message_id": "<a@test.com>"})


# --------------------------------------------------------------------------- new: safe list


def test_safelist_list_command(client: Client, mocker):
    entries = [
        {"attribute": "$from", "operator": "equal", "value": "a@test.com", "comment": "ok"},
        {"attribute": "$from", "operator": "equal", "value": "b@test.com"},
    ]
    mocker.patch.object(Client, "get_org_safelist", return_value={"entries": entries})

    result = proofpoint_ctr_safelist_list_command(client, {"cluster_id": "c1", "limit": "1"})
    assert result.outputs_prefix == "ProofPointCloud.SafeList"
    assert len(result.outputs) == 1


def test_safelist_add_entry_builds_body(client: Client, mocker):
    captured: dict = {}

    def _capture(self, cluster_id, body):
        captured["cluster_id"] = cluster_id
        captured["body"] = body

    mocker.patch.object(Client, "modify_org_safelist", _capture)

    result = proofpoint_ctr_safelist_add_entry_command(
        client,
        {"cluster_id": "c1", "attribute": "from", "operator": "equal", "value": "safe@test.com", "comment": "note"},
    )
    assert captured["cluster_id"] == "c1"
    assert captured["body"] == {
        "action": "add",
        "attribute": "$from",
        "operator": "equal",
        "value": "safe@test.com",
        "comment": "note",
    }
    assert "added to the Organizational Safe List" in result.readable_output


def test_safelist_remove_entry_builds_delete_body(client: Client, mocker):
    captured: dict = {}

    def _capture(self, cluster_id, body):
        captured["body"] = body

    mocker.patch.object(Client, "modify_org_safelist", _capture)

    proofpoint_ctr_safelist_remove_entry_command(
        client, {"cluster_id": "c1", "attribute": "from", "operator": "equal", "value": "safe@test.com"}
    )
    assert captured["body"]["action"] == "delete"
    assert "comment" not in captured["body"]


def test_safelist_add_rejects_bad_operator(client: Client):
    with pytest.raises(Exception, match="operator"):
        proofpoint_ctr_safelist_add_entry_command(
            client, {"cluster_id": "c1", "attribute": "from", "operator": "not_equal", "value": "x@test.com"}
        )


# --------------------------------------------------------------------------- new: block list


def test_blocklist_list_command(client: Client, mocker):
    entries = [{"attribute": "$from", "operator": "equal", "value": "bad@test.com"}]
    mocker.patch.object(Client, "get_org_blocklist", return_value={"entries": entries})

    result = proofpoint_ctr_blocklist_list_command(client, {"cluster_id": "c1"})
    assert result.outputs_prefix == "ProofPointCloud.BlockList"
    assert len(result.outputs) == 1


def test_blocklist_add_allows_not_equal_operator(client: Client, mocker):
    captured: dict = {}

    def _capture(self, cluster_id, body):
        captured["body"] = body

    mocker.patch.object(Client, "modify_org_blocklist", _capture)

    # Given not_equal (valid only for block list), the entry is added
    result = proofpoint_ctr_blocklist_add_entry_command(
        client, {"cluster_id": "c1", "attribute": "from", "operator": "not_equal", "value": "bad@test.com"}
    )
    assert captured["body"]["operator"] == "not_equal"
    assert "added to the Organizational Block List" in result.readable_output


def test_blocklist_remove_entry_command(client: Client, mocker):
    captured: dict = {}

    def _capture(self, cluster_id, body):
        captured["body"] = body

    mocker.patch.object(Client, "modify_org_blocklist", _capture)

    result = proofpoint_ctr_blocklist_remove_entry_command(
        client, {"cluster_id": "c1", "attribute": "from", "operator": "equal", "value": "bad@test.com"}
    )
    assert captured["body"]["action"] == "delete"
    assert "removed from the Organizational Block List" in result.readable_output


def test_list_commands_require_cluster_id(client: Client):
    with pytest.raises(Exception, match="cluster_id"):
        proofpoint_ctr_safelist_list_command(client, {})
    with pytest.raises(Exception, match="cluster_id"):
        proofpoint_ctr_blocklist_list_command(client, {})
