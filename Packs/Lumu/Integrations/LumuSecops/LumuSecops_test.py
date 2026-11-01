import json
from unittest.mock import patch

import pytest

from LumuSecops import (
    COMMENT_MARK,
    CustomLumuException,
    Client,
    close_incident_command,
    comment_incident_command,
    consult_incidents_updates_command,
    extract_latest_action,
    fetch_incidents,
    get_all_incidents_command,
    get_incident_details_command,
    get_incident_events_groupings_command,
    get_modified_remote_data_command,
    get_incident_security_events_details_command,
    normalize_adversary_types,
    normalize_incident_grouping_fields,
    get_open_incidents_command,
    get_remote_data_command,
    get_security_event_details_command,
    mark_incident_as_read_command,
    mute_incident_command,
    test_module,
    unmute_incident_command,
    update_remote_system_command,
    wipe_cache,
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
@patch("LumuSecops.demisto.incidents")
@patch("LumuSecops.demisto.setLastRun")
@patch.object(Client, "consult_incidents_updates_request", return_value=UPDATES_RESPONSE)
def test_fetch_incidents(
    mock_updates: patch,
    mock_set_last_run: patch,
    mock_incidents: patch,
    mock_context: patch,
    mock_set_context: patch,
) -> None:
    fetch_incidents(get_client(), "0", {"last_fetch": "0"}, 1, 4, "instance-1", "In", ["tag-a"])

    mock_set_last_run.assert_called_once_with({"last_fetch": "456"})
    incidents = mock_incidents.call_args.args[0]
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
    assert raw_json["lumu_description"] == "Suspicious communication"
    assert raw_json["lumu_secops_incident_grouping_fields"] == '{"adversary": "wicar.org"}'
    assert raw_json["mirror_instance"] == "instance-1"
    assert raw_json["mirror_direction"] == "In"
    assert raw_json["mirror_tags"] == ["tag-a"]

    written_cache = mock_set_context.call_args.args[0]
    assert written_cache["cache"] == [["inc-1"]]
    assert "inc-1" in written_cache["lumu_secops_incident_ids"]
    assert "inc-1" in written_cache["source_records"]


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={"cache": [], "lumu_secops_incident_ids": [], "source_records": {}, "users": {}, "labels": {}},
)
@patch("LumuSecops.demisto.incidents")
@patch("LumuSecops.demisto.setLastRun")
@patch.object(Client, "consult_incidents_updates_request", return_value=SPARSE_UPDATES_RESPONSE)
def test_fetch_incidents_sparse_updates_fallbacks(
    mock_updates: patch,
    mock_set_last_run: patch,
    mock_incidents: patch,
    mock_context: patch,
    mock_set_context: patch,
) -> None:
    fetch_incidents(get_client(), "0", {"last_fetch": "0"}, 1, 4, "instance-1", "In", [])
    mock_set_last_run.assert_called_once_with({"last_fetch": "789"})

    incidents = mock_incidents.call_args.args[0]
    assert len(incidents) == 1
    raw_json = json.loads(incidents[0]["rawJSON"])
    assert raw_json["lumu_secops_incident_type"] == "malicious-infrastructure"
    assert raw_json["lumu_secops_adversary_types"] == ["C2C"]
    assert raw_json["lumu_description"] == "Fallback description"
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
    assert response.mirrored_object["lumu_incidentId"] == "inc-1"
    assert response.mirrored_object["lumu_secops_endpoint_targets_count"] == 1
    assert response.mirrored_object["lumu_secops_user_targets_count"] == 0
    assert response.mirrored_object["lumu_secops_other_targets_count"] == 0
    assert response.mirrored_object["lumu_secops_total_targets_count"] == 1
    assert response.mirrored_object["lumu_secops_offenders_count"] == 1
    assert response.mirrored_object["lumu_secops_detector_type"] == "activity"
    assert response.mirrored_object["lumu_secops_incident_type"] == "malicious-infrastructure"
    assert response.mirrored_object["lumu_secops_adversary_types"] == ["Malware"]
    assert response.mirrored_object["lumu_description"].startswith("Lumu has detected an incident")
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


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={
        "cache": [],
        "lumu_secops_incident_ids": ["inc-1", "inc-2"],
        "source_records": {"inc-1": {"event_type": "IncidentUpdated", "raw": {}}},
        "users": {},
        "labels": {},
    },
)
def test_wipe_cache(mock_context: patch, mock_set_context: patch) -> None:
    wipe_cache("inc-1")
    cache = mock_set_context.call_args.args[0]
    assert cache["lumu_secops_incident_ids"] == ["inc-2"]
    assert "inc-1" not in cache["source_records"]


@patch("LumuSecops.wipe_cache")
@patch.object(Client, "close_incident_request", return_value="ok")
@patch("LumuSecops.UpdateRemoteSystemArgs")
def test_update_remote_system_close_wipes_cache(mock_update_args: patch, mock_close: patch, mock_wipe_cache: patch) -> None:
    mock_update_args.return_value.remote_incident_id = "inc-1"
    mock_update_args.return_value.entries = ["entry"]
    mock_update_args.return_value.delta = {
        "closeReason": "Resolved",
        "closeNotes": "done",
        "closingUserId": "42",
    }

    response = update_remote_system_command(get_client(), {})
    assert response == "inc-1"
    mock_close.assert_called_once_with("inc-1", f"{COMMENT_MARK} Close - Notes=done, Reason=Resolved, User=42")
    mock_wipe_cache.assert_called_once_with("inc-1")


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={
        "cache": [],
        "lumu_secops_incident_ids": ["inc-known"],
        "source_records": {},
        "users": {},
        "labels": {},
    },
)
@patch("LumuSecops.demisto.incidents")
@patch("LumuSecops.demisto.setLastRun")
@patch.object(
    Client,
    "consult_incidents_updates_request",
    return_value={
        "updates": [
            {},
            {"OpenIncidentsStatusUpdated": {"openIncidentsStats": {"open": 1}}},
            {"BogusType": {"incident": {"id": "inc-skip-1"}}},
            {
                "IncidentClosed": {
                    "incident": {"id": "inc-skip-2"},
                    "payload": {"comment": f"{COMMENT_MARK} loop"},
                }
            },
            {
                "IncidentUpdated": {
                    "incident": {
                        "id": "inc-known",
                        "timestamp": "2026-01-10T10:00:00Z",
                        "description": "Known",
                        "totalEvents": 1,
                    }
                }
            },
            {
                "IncidentUpdated": {
                    "incident": {
                        "id": "inc-new",
                        "timestamp": "2026-01-10T10:00:00Z",
                        "description": "New",
                        "totalEvents": 2,
                    }
                }
            },
            {
                "IncidentUpdated": {
                    "incident": {
                        "id": "inc-new",
                        "timestamp": "2026-01-10T10:00:01Z",
                        "description": "New duplicate",
                        "totalEvents": 3,
                    }
                }
            },
        ],
        "offset": 900,
    },
)
def test_fetch_incidents_filters_and_avoids_duplicate_pushes(
    mock_updates: patch,
    mock_set_last_run: patch,
    mock_incidents: patch,
    mock_context: patch,
    mock_set_context: patch,
) -> None:
    fetch_incidents(get_client(), "0", {"last_fetch": "0"}, 10, 4, "instance-1", "Both", ["tag-a", "tag-b"])

    mock_set_last_run.assert_called_once_with({"last_fetch": "900"})
    pushed_incidents = mock_incidents.call_args.args[0]
    assert [incident["dbotMirrorId"] for incident in pushed_incidents] == ["inc-new"]

    updated_cache = mock_set_context.call_args.args[0]
    assert set(updated_cache["cache"][0]) == {"inc-known", "inc-new"}
    assert set(updated_cache["lumu_secops_incident_ids"]) == {"inc-known", "inc-new"}
    assert "inc-known" in updated_cache["source_records"]
    assert "inc-new" in updated_cache["source_records"]


@patch("LumuSecops.get_integration_context", return_value={"cache": [], "lumu_secops_incident_ids": [], "source_records": {}})
@patch("LumuSecops.set_integration_context")
@patch("LumuSecops.demisto.incidents")
@patch("LumuSecops.demisto.setLastRun")
@patch.object(Client, "consult_incidents_updates_request", return_value={"updates": []})
def test_fetch_incidents_keeps_last_offset_when_missing_in_response(
    mock_updates: patch,
    mock_set_last_run: patch,
    mock_incidents: patch,
    mock_set_context: patch,
    mock_context: patch,
) -> None:
    fetch_incidents(get_client(), "5", {"last_fetch": "12"}, 1, 4, "instance-1", "In", [])
    mock_set_last_run.assert_called_once_with({"last_fetch": "12"})
    mock_incidents.assert_called_once_with([])
    mock_set_context.assert_not_called()


@patch("LumuSecops.GetRemoteDataArgs")
@patch("LumuSecops.wipe_cache")
@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={
        "cache": [],
        "lumu_secops_incident_ids": ["inc-2"],
        "source_records": {
            "inc-2": {
                "event_type": "IncidentClosed",
                "raw": {
                    "IncidentClosed": {
                        "incident": {
                            "id": "inc-2",
                            "status": "closed",
                            "description": "Closed incident",
                            "statusTimestamp": "2026-01-10T10:03:00+00:00",
                            "counts": {},
                        },
                        "payload": {"comment": "resolved remotely"},
                        "userId": 7,
                    }
                },
            }
        },
        "users": {"0": {"id": 0, "role": "", "email": "", "name": "API User", "time_zone": "", "deactivated": False}},
        "labels": {"0": {"id": 0, "name": "Unlabeled activity", "relevance": 1}},
    },
)
@patch.object(
    Client,
    "retrieve_a_specific_user_request",
    return_value={"id": 7, "role": "analyst", "email": "b@example.com", "name": "Bob", "time_zone": "UTC", "deactivated": False},
)
def test_get_remote_data_command_from_status_event_closed_adds_notes_and_wipes_cache(
    mock_user: patch,
    mock_context: patch,
    mock_set_context: patch,
    mock_wipe_cache: patch,
    mock_args: patch,
) -> None:
    mock_args.return_value.remote_incident_id = "inc-2"
    response = get_remote_data_command(get_client(), {})

    assert response.mirrored_object["lumu_incidentId"] == "inc-2"
    assert response.mirrored_object["lumu_secops_event_type"] == "IncidentClosed"
    assert len(response.entries) == 2
    assert response.entries[0]["Type"] == 1
    assert response.entries[1]["Contents"]["dbotIncidentClose"] is True
    assert "resolved remotely" in response.entries[1]["Contents"]["closeReason"]
    mock_user.assert_called_once_with(user_id=7)
    mock_wipe_cache.assert_called_once_with("inc-2")


@patch("LumuSecops.GetRemoteDataArgs")
@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={
        "cache": [],
        "lumu_secops_incident_ids": ["inc-3"],
        "source_records": {
            "inc-3": {
                "event_type": "NewIncidentCreated",
                "raw": {
                    "NewIncidentCreated": {
                        "incident": {
                            "id": "inc-3",
                            "status": "open",
                            "description": "New incident description",
                            "counts": {},
                            "adversaryTypes": ["Malware"],
                            "targetsSamples": [
                                {"type": "endpoint", "name": "host-1", "label": 99},
                                {"type": "user", "name": "analyst", "realm": "HQ"},
                            ],
                            "offendersSamples": [{"value": "evil.example"}],
                            "totalEvents": 2,
                        }
                    }
                },
            }
        },
        "users": {"0": {"id": 0, "role": "", "email": "", "name": "API User", "time_zone": "", "deactivated": False}},
        "labels": {"0": {"id": 0, "name": "Unlabeled activity", "relevance": 1}},
    },
)
@patch.object(Client, "retrieve_a_specific_label_request", return_value={"id": 99, "name": "Prod", "relevance": 1})
def test_get_remote_data_command_new_event_creates_title_and_content_entries(
    mock_label: patch,
    mock_context: patch,
    mock_set_context: patch,
    mock_args: patch,
) -> None:
    mock_args.return_value.remote_incident_id = "inc-3"
    response = get_remote_data_command(get_client(), {})

    assert response.mirrored_object["lumu_secops_event_type"] == "NewIncidentCreated"
    assert len(response.entries) == 2
    assert response.entries[0]["ContentsFormat"] == "html"
    assert response.entries[1]["ContentsFormat"] == "html"
    mock_label.assert_called_once_with(label_id="99")


@patch("LumuSecops.GetRemoteDataArgs")
@patch("LumuSecops.get_integration_context")
@patch.object(Client, "retrieve_a_specific_label_request", side_effect=Exception("Rate limit exceeded"))
def test_get_remote_data_command_rate_limit_error_raises_custom_exception(
    mock_label: patch,
    mock_context: patch,
    mock_args: patch,
) -> None:
    mock_args.return_value.remote_incident_id = "inc-rate"
    mock_context.return_value = {
        "cache": [],
        "lumu_secops_incident_ids": ["inc-rate"],
        "source_records": {
            "inc-rate": {
                "event_type": "IncidentUpdated",
                "raw": {
                    "IncidentUpdated": {
                        "incident": {
                            "id": "inc-rate",
                            "status": "open",
                            "counts": {},
                            "targetsSamples": [{"type": "endpoint", "name": "host", "label": 100}],
                        }
                    }
                },
            }
        },
        "users": {},
        "labels": {"0": {"id": 0, "name": "Unlabeled activity", "relevance": 1}},
    }
    with pytest.raises(CustomLumuException, match="API rate limit"):
        get_remote_data_command(get_client(), {})


@patch("LumuSecops.GetRemoteDataArgs")
@patch("LumuSecops.get_integration_context")
@patch.object(Client, "retrieve_a_specific_label_request", side_effect=Exception("boom"))
def test_get_remote_data_command_non_rate_limit_errors_return_none(
    mock_label: patch,
    mock_context: patch,
    mock_args: patch,
) -> None:
    mock_args.return_value.remote_incident_id = "inc-none"
    mock_context.return_value = {
        "cache": [],
        "lumu_secops_incident_ids": ["inc-none"],
        "source_records": {
            "inc-none": {
                "event_type": "IncidentUpdated",
                "raw": {
                    "IncidentUpdated": {
                        "incident": {
                            "id": "inc-none",
                            "status": "open",
                            "counts": {},
                            "targetsSamples": [{"type": "endpoint", "name": "host", "label": 101}],
                        }
                    }
                },
            }
        },
        "users": {},
        "labels": {"0": {"id": 0, "name": "Unlabeled activity", "relevance": 1}},
    }
    assert get_remote_data_command(get_client(), {}) is None


@patch("LumuSecops.set_integration_context")
@patch(
    "LumuSecops.get_integration_context",
    return_value={
        "cache": [["inc-1", "inc-2"], ["inc-3"]],
        "lumu_secops_incident_ids": ["inc-1", "inc-2", "inc-3"],
        "source_records": {},
        "users": {},
        "labels": {},
    },
)
def test_get_modified_remote_data_command_pops_pending_ids(mock_context: patch, mock_set_context: patch) -> None:
    response = get_modified_remote_data_command(get_client(), {})
    assert response.modified_incident_ids == ["inc-1", "inc-2"]
    next_cache = mock_set_context.call_args.args[0]
    assert next_cache["cache"] == [["inc-3"]]


@patch.object(Client, "mute_incident_request", return_value="ok")
@patch("LumuSecops.UpdateRemoteSystemArgs")
def test_update_remote_system_mute_action(mock_update_args: patch, mock_mute: patch) -> None:
    mock_update_args.return_value.remote_incident_id = "inc-9"
    mock_update_args.return_value.entries = ["entry"]
    mock_update_args.return_value.delta = {
        "comment": "mute me",
        "Lumu SecOps Take Status Action": "mute",
    }
    response = update_remote_system_command(get_client(), {})
    assert response == "inc-9"
    mock_mute.assert_called_once_with("inc-9", f"{COMMENT_MARK} mute me Mute")


@patch.object(Client, "unmute_incident_request", return_value="ok")
@patch("LumuSecops.UpdateRemoteSystemArgs")
def test_update_remote_system_unmute_action_with_alt_key(mock_update_args: patch, mock_unmute: patch) -> None:
    mock_update_args.return_value.remote_incident_id = "inc-10"
    mock_update_args.return_value.entries = ["entry"]
    mock_update_args.return_value.delta = {
        "comment": "unmute me",
        "lumusecopstakestatusaction": "unmuted",
    }
    response = update_remote_system_command(get_client(), {})
    assert response == "inc-10"
    mock_unmute.assert_called_once_with("inc-10", f"{COMMENT_MARK} unmute me Unmute")


@patch.object(Client, "comment_incident_request", return_value="ok")
@patch("LumuSecops.UpdateRemoteSystemArgs")
def test_update_remote_system_comment_action(mock_update_args: patch, mock_comment: patch) -> None:
    mock_update_args.return_value.remote_incident_id = "inc-11"
    mock_update_args.return_value.entries = ["entry"]
    mock_update_args.return_value.delta = {"comment": "Analyst says hi"}
    response = update_remote_system_command(get_client(), {})
    assert response == "inc-11"
    mock_comment.assert_called_once_with("inc-11", f"{COMMENT_MARK} Analyst says hi")


@patch("LumuSecops.UpdateRemoteSystemArgs")
def test_update_remote_system_returns_early_when_no_entries_and_no_delta(mock_update_args: patch) -> None:
    mock_update_args.return_value.remote_incident_id = "inc-empty"
    mock_update_args.return_value.entries = []
    mock_update_args.return_value.delta = {}
    assert update_remote_system_command(get_client(), {}) == "inc-empty"


def test_extract_latest_action_handles_invalid_values() -> None:
    assert extract_latest_action([]) == {}
    assert extract_latest_action(["bad"]) == {}
    assert extract_latest_action([{"action": "mute", "comment": "note", "datetime": "2026", "userId": 3}]) == {
        "lumu_secops_last_action": "mute",
        "lumu_secops_last_comment": "note",
        "lumu_secops_last_action_time": "2026",
        "lumu_secops_last_action_user_id": "3",
    }


def test_normalization_helpers() -> None:
    assert normalize_adversary_types(["A", None, 7]) == ["A", "7"]
    assert normalize_adversary_types(None) == []
    assert normalize_adversary_types("malware") == ["malware"]

    assert normalize_incident_grouping_fields({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'
    assert normalize_incident_grouping_fields("") == ""
    assert normalize_incident_grouping_fields([1, 2]) == "[1, 2]"
