import json
from unittest.mock import patch

from LumuSecops import (
    COMMENT_MARK,
    Client,
    add_prefix_to_comment,
    close_incident_command,
    comment_incident_command,
    consult_incidents_updates_command,
    fetch_incidents,
    get_all_incidents_command,
    get_incident_details_command,
    get_incident_events_groupings_command,
    get_incident_security_events_details_command,
    get_open_incidents_command,
    get_remote_data_command,
    get_security_event_details_command,
    mark_incident_as_read_command,
    mute_incident_command,
    test_module,
    unmute_incident_command,
)


INCIDENTS_RESPONSE = {
    "items": [
        {
            "id": "inc-1",
            "timestamp": "2026-01-10T10:00:00Z",
            "status": "open",
            "description": "Suspicious communication",
            "totalEvents": 4,
        }
    ],
    "paginationInfo": {"page": 1, "items": 1},
}

INCIDENT_DETAILS_RESPONSE = {
    "id": "inc-1",
    "timestamp": "2026-01-10T10:00:00Z",
    "status": "open",
    "counts": {
        "endpointTargetsCount": 1,
        "userTargetsCount": 0,
        "otherTargetsCount": 0,
        "totalTargetsCount": 1,
        "offendersCount": 1,
    },
    "detectorType": "activity",
    "incidentType": "malicious-infrastructure",
    "incidentGroupingFields": {"adversary": "wicar.org"},
    "adversaryTypes": ["Malware"],
    "description": "Suspicious communication",
    "actions": [{"action": "comment", "comment": "Analyst note", "userId": 1, "datetime": "2026-01-10T10:01:00Z"}],
}

UPDATES_RESPONSE = {
    "updates": [
        {
            "IncidentUpdated": {
                "companyId": "company-1",
                "incident": {
                    "id": "inc-1",
                    "timestamp": "2026-01-10T10:00:00Z",
                    "status": "open",
                    "counts": {
                        "endpointTargetsCount": 1,
                        "userTargetsCount": 0,
                        "otherTargetsCount": 0,
                        "totalTargetsCount": 1,
                        "offendersCount": 1,
                    },
                    "detectorType": "activity",
                    "incidentType": "malicious-infrastructure",
                    "incidentGroupingFields": {"adversary": "wicar.org"},
                    "adversaryTypes": ["Malware"],
                    "description": "Suspicious communication",
                    "totalEvents": 4,
                },
            }
        }
    ],
    "offset": 456,
}

SPARSE_UPDATES_RESPONSE = {
    "updates": [
        {
            "IncidentUpdated": {
                "companyId": "company-1",
                "incident": {
                    "id": "inc-2",
                    "timestamp": "2026-01-10T10:02:00Z",
                    "status": "open",
                    "totalEvents": 1,
                },
                "event": {
                    "event_data": "malicious-infrastructure",
                    "incidentGroupingFields": {"adversary": "kys.cx"},
                    "adversaryTypes": ["C2C"],
                    "eventDescription": "Fallback description",
                },
            }
        }
    ],
    "offset": 789,
}


def get_client() -> Client:
    return Client("https://defender.lumu.io", True, False, {"Content-Type": "application/json"}, "api-key")


def test_add_prefix_to_comment() -> None:
    assert add_prefix_to_comment("hello") == "Cortex XSOAR: hello,"


@patch.object(Client, "get_all_incidents_request", return_value=INCIDENTS_RESPONSE)
def test_get_all_incidents_command(mock_request: patch) -> None:
    response = get_all_incidents_command(get_client(), {"page": 1, "items": 1})
    assert response.outputs_prefix == "LumuSecops.GetAllIncidents"
    assert response.outputs[0]["id"] == "inc-1"


@patch.object(Client, "get_open_incidents_request", return_value=INCIDENTS_RESPONSE)
def test_get_open_incidents_command(mock_request: patch) -> None:
    response = get_open_incidents_command(get_client(), {"page": 1, "items": 1})
    assert response.outputs_prefix == "LumuSecops.GetOpenIncidents"


@patch.object(Client, "get_incident_events_groupings_request", return_value=INCIDENTS_RESPONSE)
def test_get_incident_events_groupings_command(mock_request: patch) -> None:
    response = get_incident_events_groupings_command(get_client(), {"incident_id": "inc-1", "page": 1, "items": 1})
    assert response.outputs_prefix == "LumuSecops.GetIncidentEventsGroupings"


@patch.object(Client, "get_incident_details_request", return_value=INCIDENT_DETAILS_RESPONSE)
def test_get_incident_details_command(mock_request: patch) -> None:
    response = get_incident_details_command(get_client(), {"incident_id": "inc-1"})
    assert response.outputs_prefix == "LumuSecops.GetIncidentDetails"
    assert response.outputs["id"] == "inc-1"


@patch.object(Client, "mark_incident_as_read_request", return_value="")
def test_mark_incident_as_read_command(mock_request: patch) -> None:
    response = mark_incident_as_read_command(get_client(), {"incident_id": "inc-1"})
    assert response.outputs["statusCode"] == 200


@patch.object(Client, "comment_incident_request", return_value="")
def test_comment_incident_command(mock_request: patch) -> None:
    response = comment_incident_command(get_client(), {"incident_id": "inc-1", "comment": "test"})
    assert response.outputs_prefix == "LumuSecops.CommentIncident"
    assert response.outputs["statusCode"] == 200
    mock_request.assert_called_once_with("inc-1", f"{COMMENT_MARK} test")


@patch.object(Client, "mute_incident_request", return_value="")
def test_mute_incident_command(mock_request: patch) -> None:
    response = mute_incident_command(get_client(), {"incident_id": "inc-1", "comment": "test"})
    assert response.outputs_prefix == "LumuSecops.MuteIncident"
    mock_request.assert_called_once_with("inc-1", f"{COMMENT_MARK} test")


@patch.object(Client, "unmute_incident_request", return_value="")
def test_unmute_incident_command(mock_request: patch) -> None:
    response = unmute_incident_command(get_client(), {"incident_id": "inc-1", "comment": "test"})
    assert response.outputs_prefix == "LumuSecops.UnmuteIncident"
    mock_request.assert_called_once_with("inc-1", f"{COMMENT_MARK} test")


@patch.object(Client, "close_incident_request", return_value="")
def test_close_incident_command(mock_request: patch) -> None:
    response = close_incident_command(get_client(), {"incident_id": "inc-1", "comment": "test"})
    assert response.outputs_prefix == "LumuSecops.CloseIncident"
    mock_request.assert_called_once_with("inc-1", f"{COMMENT_MARK} test")


@patch.object(Client, "consult_incidents_updates_request", return_value=UPDATES_RESPONSE)
def test_consult_incidents_updates_command(mock_request: patch) -> None:
    response = consult_incidents_updates_command(get_client(), {"offset": 0, "items": 1, "time": 4})
    assert response.outputs_prefix == "LumuSecops.ConsultIncidentsUpdates"
    assert response.outputs["offset"] == 456


@patch.object(Client, "get_security_event_details_request", return_value={"items": []})
def test_get_security_event_details_command(mock_request: patch) -> None:
    response = get_security_event_details_command(
        get_client(), {"incident_id": "inc-1", "event_id": "evt-1", "page": 1, "items": 10}
    )
    assert response.outputs_prefix == "LumuSecops.GetSecurityEventDetails"


@patch.object(Client, "get_incident_security_events_details_request", return_value={"items": []})
def test_get_incident_security_events_details_command(mock_request: patch) -> None:
    response = get_incident_security_events_details_command(get_client(), {"incident_id": "inc-1", "page": 1, "items": 10})
    assert response.outputs_prefix == "LumuSecops.GetIncidentSecurityEventsDetails"


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={"cache": [], "lumu_secops_incident_ids": [], "source_records": {}, "users": {}, "labels": {}},
)
@patch.object(Client, "consult_incidents_updates_request", return_value=UPDATES_RESPONSE)
def test_fetch_incidents(mock_updates: patch, mock_context: patch, mock_set_context: patch) -> None:
    next_run, incidents = fetch_incidents(get_client(), "0", {"last_fetch": "0"}, 1, 4)
    assert next_run == {"last_fetch": "456"}
    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "inc-1"
    raw_json = json.loads(incidents[0]["rawJSON"])
    assert raw_json["lumu_secops_total_events"] == 4
    assert raw_json["lumu_secops_endpoint_targets_count"] == 1
    assert raw_json["lumu_secops_user_targets_count"] == 0
    assert raw_json["lumu_secops_other_targets_count"] == 0
    assert raw_json["lumu_secops_total_targets_count"] == 1
    assert raw_json["lumu_secops_offenders_count"] == 1
    assert raw_json["lumu_secops_actions_count"] == 0
    assert raw_json["lumu_secops_detector_type"] == "activity"
    assert raw_json["lumu_secops_incident_type"] == "malicious-infrastructure"
    assert raw_json["lumu_secops_adversary_types"] == ["Malware"]
    assert raw_json["lumu_secops_description"] == "Suspicious communication"
    assert raw_json["lumu_secops_incident_grouping_fields"] == '{"adversary": "wicar.org"}'


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={"cache": [], "lumu_secops_incident_ids": [], "source_records": {}, "users": {}, "labels": {}},
)
@patch.object(Client, "consult_incidents_updates_request", return_value=SPARSE_UPDATES_RESPONSE)
def test_fetch_incidents_sparse_updates_fallbacks(mock_updates: patch, mock_context: patch, mock_set_context: patch) -> None:
    next_run, incidents = fetch_incidents(get_client(), "0", {"last_fetch": "0"}, 1, 4)
    assert next_run == {"last_fetch": "789"}
    assert len(incidents) == 1
    raw_json = json.loads(incidents[0]["rawJSON"])
    assert raw_json["lumu_secops_incident_type"] == "malicious-infrastructure"
    assert raw_json["lumu_secops_adversary_types"] == ["C2C"]
    assert raw_json["lumu_secops_description"] == "Fallback description"
    assert raw_json["lumu_secops_incident_grouping_fields"] == '{"adversary": "kys.cx"}'


@patch("LumuSecops.GetRemoteDataArgs")
@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={"cache": [], "lumu_secops_incident_ids": [], "source_records": {}, "users": {}, "labels": {}},
)
@patch.object(Client, "list_all_labels", return_value=[{"id": 3, "name": "Prod", "relevance": 1}])
@patch.object(
    Client,
    "list_all_users",
    return_value=[
        {"id": 1, "role": "admin", "email": "a@example.com", "name": "Alice", "time_zone": "UTC", "deactivated": False}
    ],
)
@patch.object(Client, "get_incident_details_request", return_value=INCIDENT_DETAILS_RESPONSE)
def test_get_remote_data_command(
    mock_request: patch,
    mock_users: patch,
    mock_labels: patch,
    mock_context: patch,
    mock_set_context: patch,
    mock_args: patch,
) -> None:
    mock_args.return_value.remote_incident_id = "inc-1"
    response = get_remote_data_command(get_client(), {})
    assert response.mirrored_object["lumu_secops_incident_id"] == "inc-1"
    assert response.mirrored_object["lumu_secops_endpoint_targets_count"] == 1
    assert response.mirrored_object["lumu_secops_user_targets_count"] == 0
    assert response.mirrored_object["lumu_secops_other_targets_count"] == 0
    assert response.mirrored_object["lumu_secops_total_targets_count"] == 1
    assert response.mirrored_object["lumu_secops_offenders_count"] == 1
    assert response.mirrored_object["lumu_secops_detector_type"] == "activity"
    assert response.mirrored_object["lumu_secops_incident_type"] == "malicious-infrastructure"
    assert response.mirrored_object["lumu_secops_adversary_types"] == ["Malware"]
    assert response.mirrored_object["lumu_secops_description"].startswith("Lumu has detected an incident")
    assert response.mirrored_object["lumu_secops_incident_grouping_fields"] == '{"adversary": "wicar.org"}'
    assert response.mirrored_object["lumu_secops_last_action"] == "comment"
    assert response.mirrored_object["lumu_secops_last_comment"] == "Analyst note"
    assert response.mirrored_object["lumu_secops_last_action_time"] == "2026-01-10T10:01:00Z"
    assert response.mirrored_object["lumu_secops_last_action_user_id"] == "1"
    assert response.mirrored_object["lumu_secops_actions_count"] == 1
    assert len(response.entries) == 1


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={"cache": [], "lumu_secops_incident_ids": [], "source_records": {}, "users": {}, "labels": {}},
)
@patch.object(Client, "list_all_labels", return_value=[{"id": 3, "name": "Prod", "relevance": 1}])
@patch.object(
    Client,
    "list_all_users",
    return_value=[
        {"id": 1, "role": "admin", "email": "a@example.com", "name": "Alice", "time_zone": "UTC", "deactivated": False}
    ],
)
def test_test_module(mock_users: patch, mock_labels: patch, mock_context: patch, mock_set_context: patch) -> None:
    assert test_module(get_client(), {}) == "ok"
