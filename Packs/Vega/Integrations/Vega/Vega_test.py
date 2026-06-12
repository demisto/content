import json
from datetime import datetime, UTC

import requests

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pytest

from Vega import (
    _alert_mirror_fingerprint,
    _alert_mirror_state_changed,
    _collect_modified_alert_mirror_ids,
    _incident_mirror_state_changed,
    _alert_events_command_results,
    _format_alert_events_markdown,
    _format_mitre_attack,
    Client,
    _build_fetch_filter_fingerprint,
    _build_vega_alert_custom_fields,
    _fetch_paginated_entities,
    _format_bullet_list,
    _format_key_findings_html,
    _format_raw_entity_for_xsoar,
    _format_timeline_events_html,
    _build_effective_alert_update_args,
    _build_effective_incident_update_args,
    _build_incident_update_input,
    _get_status_from_fields,
    _resolve_incident_status_for_update,
    MIRROR_ENTITY_SUFFIX_INCIDENT,
    VEGA_ALERT_STATUS_FIELD,
    VEGA_INCIDENT_STATUS_FIELD,
    _normalize_vega_status_for_display,
    _normalize_entity_id,
    _parse_alert_events_results,
    _resolve_fetch_from_time,
    _should_ingest_entity,
    _update_fetch_state,
    alert_to_incident,
    build_alert_events_custom_fields,
    build_mirror_id,
    fetch_alert_events_command,
    fetch_alert_events_page,
    fetch_incidents_command,
    set_detections_state_command,
    update_detections_command,
    get_mirroring,
    get_modified_remote_data_command,
    get_remote_data_command,
    incident_to_xsoar_incident,
    parse_backfill_days,
    load_current_incident,
    parse_mirror_id,
    resolve_alert_id_from_incident,
    resolve_incident_id_from_incident,
    update_alert_command,
    update_incident_command,
    RATE_LIMIT_INITIAL_WAIT_SECONDS,
    update_remote_system_command,
    validate_backfill_days,
    filter_alert_severities,
    filter_alert_statuses,
    filter_alert_verdicts,
    filter_incident_severities,
    filter_incident_statuses,
    filter_incident_verdicts,
    TEST_CONNECTION_ACCESS_KEY_ERROR,
    TEST_CONNECTION_ACCESS_KEY_ID_ERROR,
    TEST_CONNECTION_BASE_URL_ERROR,
    TEST_CONNECTION_URL_ERROR,
    test_module as vega_test_module,
    main as vega_main,
)

BASE_URL = "https://api.vega.com"

MOCK_JWT_RESPONSE = {
    "session_jwt": "mock-jwt-token",
    "session_max_age": 1999999999,  # Far in the future
    "error": "",
}


def test_test_module(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query", json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["security admin"]}}}
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "ok"


def test_test_module_unauthorized(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(f"{BASE_URL}/api/v1/query", json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["Viewer"]}}})

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == "You do not have required access to fetch incidents."


def test_test_module_incorrect_access_key_id(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query",
        json={
            "errors": [
                {
                    "message": "Internal Server Error",
                    "extensions": {
                        "error_code": "E000000000",
                        "error_code_name": "INTERNAL_SERVER_ERROR",
                        "extra_args": None,
                        "trace_id": 8786647935177050492,
                    },
                }
            ],
            "data": {"getAccessKey": None},
        },
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == TEST_CONNECTION_ACCESS_KEY_ID_ERROR


def test_test_module_incorrect_access_key(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", status_code=500)

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="wrong-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == TEST_CONNECTION_ACCESS_KEY_ERROR


def test_test_module_connection_error(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(
        f"{BASE_URL}/api/v1/login_machine",
        exc=requests.exceptions.ConnectionError("Failed to establish a new connection"),
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == TEST_CONNECTION_URL_ERROR


def test_test_module_wrong_url_not_found(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", status_code=404, text="Not Found")

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == TEST_CONNECTION_BASE_URL_ERROR


def test_test_module_whitespace_base_url(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    client = Client(
        base_url="   ",
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client) == TEST_CONNECTION_BASE_URL_ERROR


def test_main_invalid_entities(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "access_key": "key",
            "access_key_id": "id",
            "url": "url",
            "vega_entities": "",
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch("Vega.return_error")

    vega_main()

    mock_return_error.assert_called_once_with(
        "Failed to execute test-module command.\nError:\nAt least one of 'Fetch Alerts' or 'Fetch Incidents' must be checked."
    )


def test_url_normalization():
    # Test cases for URL normalization: (input_url, expected_normalized_url)
    test_cases = [
        ("https://api.vega.com", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/api/v1", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/api/v1/", "https://api.vega.com/api/v1/"),
        ("https://api.vega.com/API/V1", "https://api.vega.com/API/V1/"),
        ("https://api.vega.com/API/v1/", "https://api.vega.com/API/v1/"),
        ("  https://api.vega.com  ", "https://api.vega.com/api/v1/"),
    ]

    for input_url, expected in test_cases:
        client = Client(
            base_url=input_url,
            verify=False,
            proxy=False,
            access_key="test-key",
            access_key_id="test-key-id",
        )
        assert client._base_url == expected


FIRST_FETCH_TIME = "2026-01-01T00:00:00Z"
BACKFILL_DAYS = "30"
TIMESTAMP_T1 = "2026-06-01T10:00:00Z"
TIMESTAMP_T2 = "2026-06-01T11:00:00Z"
CURRENT_TIME_CURSOR = "2026-06-04T17:00:00Z"


def test_update_fetch_state_preserves_ids_when_all_dupes():
    previous_ids = ["alert-a", "alert-b"]
    fetched = [
        {"id": "alert-a", "createdAt": TIMESTAMP_T1},
        {"id": "alert-b", "createdAt": TIMESTAMP_T1},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert set(last_ids) == set(previous_ids)


def test_update_fetch_state_preserves_state_when_empty():
    previous_ids = ["alert-a", "alert-b"]

    last_fetch, last_ids = _update_fetch_state([], TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert last_ids == previous_ids


def test_update_fetch_state_merges_ids_at_same_timestamp():
    previous_ids = ["alert-a"]
    fetched = [
        {"id": "alert-a", "createdAt": TIMESTAMP_T1},
        {"id": "alert-c", "createdAt": TIMESTAMP_T1},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert set(last_ids) == {"alert-a", "alert-c"}


def test_update_fetch_state_handles_mixed_timestamp_formats():
    """Alerts with the same instant but different string formats share one boundary."""
    previous_ids = ["alert-a"]
    fetched = [
        {"id": "alert-a", "createdAt": "2026-06-01T10:00:00Z"},
        {"id": "alert-b", "createdAt": "2026-06-01T10:00:00.000Z"},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, "2026-06-01T10:00:00Z", previous_ids)

    assert last_fetch == TIMESTAMP_T1
    assert set(last_ids) == {"alert-a", "alert-b"}


def test_normalize_entity_id_coerces_numeric_ids():
    assert _normalize_entity_id({"id": 12345}) == "12345"
    assert _normalize_entity_id({"id": "12345"}) == "12345"


def test_should_ingest_entity_uses_timestamp_and_boundary_ids():
    cursor = TIMESTAMP_T1
    boundary_ids = ["alert-a"]

    assert _should_ingest_entity({"id": "alert-a", "createdAt": TIMESTAMP_T1}, cursor, boundary_ids) is False
    assert _should_ingest_entity({"id": "alert-b", "createdAt": TIMESTAMP_T1}, cursor, boundary_ids) is True
    assert _should_ingest_entity({"id": "alert-c", "createdAt": TIMESTAMP_T2}, cursor, boundary_ids) is True
    assert _should_ingest_entity({"id": "alert-old", "createdAt": "2026-06-01T09:00:00Z"}, cursor, boundary_ids) is False


def test_should_ingest_entity_treats_millisecond_timestamps_as_same_second():
    cursor = "2026-05-12T03:26:16Z"
    boundary_ids = ["alert-a"]
    millisecond_created_at = "2026-05-12T03:26:16.179Z"

    assert _should_ingest_entity({"id": "alert-a", "createdAt": millisecond_created_at}, cursor, boundary_ids) is False
    assert _should_ingest_entity({"id": "alert-b", "createdAt": millisecond_created_at}, cursor, boundary_ids) is True


def test_update_fetch_state_groups_boundary_ids_by_second_not_millisecond():
    fetched = [
        {"id": "alert-a", "createdAt": "2026-05-12T03:26:16.100Z"},
        {"id": "alert-b", "createdAt": "2026-05-12T03:26:16.179Z"},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, "2026-05-12T03:26:15Z", [])

    assert last_fetch == "2026-05-12T03:26:16Z"
    assert set(last_ids) == {"alert-a", "alert-b"}


def test_fetch_incidents_command_dedup_numeric_id_at_boundary(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    numeric_id = 987654321
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": numeric_id, "name": "Numeric ID Alert", "severity": "LOW", "createdAt": TIMESTAMP_T1},
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {
        "alerts_last_fetch": TIMESTAMP_T1,
        "alerts_last_ids": [str(numeric_id)],
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert incidents == []
    assert set(next_run["alerts_last_ids"]) == {str(numeric_id)}
    assert "alerts_seen_ids" not in next_run


def test_resolve_fetch_from_time_uses_backfill_when_cursor_not_anchored():
    last_run = {"incidents_last_fetch": CURRENT_TIME_CURSOR}

    assert (
        _resolve_fetch_from_time(
            last_run,
            "incidents_last_fetch",
            FIRST_FETCH_TIME,
        )
        == FIRST_FETCH_TIME
    )


def test_resolve_fetch_from_time_uses_stored_cursor_when_present():
    last_run = {
        "incidents_last_fetch": CURRENT_TIME_CURSOR,
        "incidents_fetch_config": _build_fetch_filter_fingerprint(None, None, None),
    }

    assert (
        _resolve_fetch_from_time(
            last_run,
            "incidents_last_fetch",
            FIRST_FETCH_TIME,
        )
        == CURRENT_TIME_CURSOR
    )


def test_resolve_fetch_from_time_keeps_cursor_when_fetch_filters_change():
    previous_config = _build_fetch_filter_fingerprint(["HIGH"], None, None)
    current_config = _build_fetch_filter_fingerprint(["HIGH", "MEDIUM"], None, None)
    last_run = {
        "alerts_last_fetch": CURRENT_TIME_CURSOR,
        "alerts_fetch_config": previous_config,
    }

    assert (
        _resolve_fetch_from_time(
            last_run,
            "alerts_last_fetch",
            FIRST_FETCH_TIME,
        )
        == CURRENT_TIME_CURSOR
    )
    assert current_config != previous_config


def test_fetch_incidents_command_uses_cursor_when_filters_expand(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-high", "name": "High Alert", "severity": "HIGH", "createdAt": TIMESTAMP_T1},
            {"id": "alert-medium", "name": "Medium Alert", "severity": "MEDIUM", "createdAt": TIMESTAMP_T2},
        ],
        "total": 2,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    previous_config = _build_fetch_filter_fingerprint(["HIGH"], None, None)
    last_run = {
        "alerts_last_fetch": TIMESTAMP_T1,
        "alerts_last_ids": ["alert-high"],
        "alerts_fetch_config": previous_config,
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=["HIGH", "MEDIUM"],
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert mock_client.get_alerts.call_args.kwargs["from_time"] == TIMESTAMP_T1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Medium Alert"
    assert "alert-high" in next_run["alerts_last_ids"]
    assert "alert-medium" in next_run["alerts_last_ids"]
    assert "alerts_seen_ids" not in next_run
    assert next_run["alerts_fetch_config"] == _build_fetch_filter_fingerprint(["HIGH", "MEDIUM"], None, None)


def test_fetch_incidents_command_uses_cursor_when_incident_filters_expand(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}
    mock_client.get_incidents.return_value = {
        "incidents": [
            {"id": "inc-1", "name": "Known Incident", "severity": "HIGH", "createdAt": TIMESTAMP_T1},
            {"id": "inc-2", "name": "New Verdict Match", "severity": "LOW", "createdAt": TIMESTAMP_T2},
        ],
        "total": 2,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incident_details.return_value = {"timelineEvents": []}

    previous_config = _build_fetch_filter_fingerprint(None, None, ["MALICIOUS"])
    last_run = {
        "incidents_last_fetch": TIMESTAMP_T1,
        "incidents_last_ids": ["inc-1"],
        "incidents_fetch_config": previous_config,
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=["MALICIOUS", "SUSPICIOUS"],
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert mock_client.get_incidents.call_args.kwargs["from_time"] == TIMESTAMP_T1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "New Verdict Match"
    assert "inc-1" in next_run["incidents_last_ids"]
    assert "inc-2" in next_run["incidents_last_ids"]
    assert "incidents_seen_ids" not in next_run
    assert next_run["incidents_fetch_config"] == _build_fetch_filter_fingerprint(None, None, ["MALICIOUS", "SUSPICIOUS"])


def test_update_fetch_state_advances_to_newer_timestamp():
    previous_ids = ["alert-a"]
    fetched = [
        {"id": "alert-a", "createdAt": TIMESTAMP_T1},
        {"id": "alert-d", "createdAt": TIMESTAMP_T2},
    ]

    last_fetch, last_ids = _update_fetch_state(fetched, TIMESTAMP_T1, previous_ids)

    assert last_fetch == TIMESTAMP_T2
    assert last_ids == ["alert-d"]


def test_fetch_paginated_entities_multiple_pages(mocker):
    page_one = {
        "alerts": [{"id": "1", "createdAt": TIMESTAMP_T1}],
        "total": 2,
        "limit": 1,
        "offset": 0,
    }
    page_two = {
        "alerts": [{"id": "2", "createdAt": TIMESTAMP_T2}],
        "total": 2,
        "limit": 1,
        "offset": 1,
    }
    mock_get_alerts = mocker.Mock(side_effect=[page_one, page_two])

    results = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 2
    assert results[0]["id"] == "1"
    assert results[1]["id"] == "2"
    assert mock_get_alerts.call_count == 2
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[1].kwargs["offset"] == 1


def test_fetch_paginated_entities_fetches_beyond_single_page(mocker):
    """Verify pagination continues until total is reached when the API returns multiple pages."""
    page_one = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T1} for i in range(200)],
        "total": 250,
        "limit": 200,
        "offset": 0,
    }
    page_two = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T2} for i in range(200, 250)],
        "total": 250,
        "limit": 200,
        "offset": 200,
    }
    mock_get_alerts = mocker.Mock(side_effect=[page_one, page_two])

    results = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 250
    assert mock_get_alerts.call_count == 2
    assert mock_get_alerts.call_args_list[0].kwargs.get("limit") is None
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[1].kwargs["offset"] == 200


def test_fetch_incidents_command_no_duplicate_reingest(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "name": "Test Alert", "severity": "HIGH", "createdAt": TIMESTAMP_T1},
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {
        "alerts_last_fetch": TIMESTAMP_T1,
        "alerts_last_ids": ["alert-1"],
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert incidents == []
    assert next_run["alerts_last_fetch"] == TIMESTAMP_T1
    assert set(next_run["alerts_last_ids"]) == {"alert-1"}
    assert "alerts_seen_ids" not in next_run


def test_fetch_incidents_command_no_duplicate_reingest_with_millisecond_timestamp(mocker):
    mocker.patch.object(demisto, "debug")
    millisecond_created_at = "2026-05-12T03:26:16.179Z"
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "name": "Millisecond Alert", "severity": "HIGH", "createdAt": millisecond_created_at},
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {
        "alerts_last_fetch": "2026-05-12T03:26:16Z",
        "alerts_last_ids": ["alert-1"],
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert incidents == []
    assert next_run["alerts_last_fetch"] == "2026-05-12T03:26:16Z"
    assert set(next_run["alerts_last_ids"]) == {"alert-1"}


def test_fetch_incidents_command_pagination(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.side_effect = [
        {
            "incidents": [{"id": "inc-1", "name": "Inc 1", "severity": "LOW", "createdAt": TIMESTAMP_T1}],
            "total": 2,
            "limit": 1,
            "offset": 0,
        },
        {
            "incidents": [{"id": "inc-2", "name": "Inc 2", "severity": "MEDIUM", "createdAt": TIMESTAMP_T2}],
            "total": 2,
            "limit": 1,
            "offset": 1,
        },
    ]
    mock_client.get_incident_details.return_value = {"timelineEvents": []}
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert len(incidents) == 2
    assert mock_client.get_incidents.call_count == 2
    assert mock_client.get_incidents.call_args_list[0].kwargs["from_time"] == FIRST_FETCH_TIME
    assert next_run["incidents_last_fetch"] == TIMESTAMP_T2
    assert next_run["incidents_last_ids"] == ["inc-2"]


def test_fetch_incidents_command_uses_stored_cursor_when_present(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    last_run = {
        "incidents_last_fetch": CURRENT_TIME_CURSOR,
        "incidents_fetch_config": _build_fetch_filter_fingerprint(None, None, None),
    }

    fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert mock_client.get_incidents.call_args.kwargs["from_time"] == CURRENT_TIME_CURSOR


def test_parse_backfill_days_today(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_days(0) == "2026-06-02T00:00:00Z"


def test_parse_backfill_days_days(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_days(7) == "2026-05-26T00:00:00Z"


def test_parse_backfill_days_defaults(mocker):
    fixed_now = datetime(2026, 6, 2, 15, 30, 0, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    assert parse_backfill_days(None) == "2026-05-03T00:00:00Z"


def test_filter_alert_statuses_maps_display_and_ignores_invalid():
    assert filter_alert_statuses(["OPEN", "IN PROGRESS", "PEER REVIEW", "RESOLVED"]) == [
        "OPEN",
        "IN_PROGRESS",
        "PEER_REVIEW",
        "RESOLVED",
    ]
    assert filter_alert_statuses(["IN_PROGRESS", "open"]) == ["IN_PROGRESS", "OPEN"]
    assert filter_alert_statuses(["OPEN", "not-a-status", ""]) == ["OPEN"]
    assert filter_alert_statuses(["garbage"]) is None
    assert filter_alert_statuses(None) is None


def test_filter_incident_statuses_maps_display_and_ignores_invalid():
    assert filter_incident_statuses(["NEW", "ON HOLD", "UNDER REVIEW"]) == [
        "NEW",
        "ON_HOLD",
        "UNDER_REVIEW",
    ]
    assert filter_incident_statuses(["EXTERNAL_ESCALATION", "review recommended"]) == [
        "EXTERNAL_ESCALATION",
        "REVIEW_RECOMMENDED",
    ]
    assert filter_incident_statuses(["NEW", "invalid"]) == ["NEW"]
    assert filter_incident_statuses([]) is None


def test_filter_severities_accepts_valid_and_ignores_invalid():
    assert filter_alert_severities(["LOW", "HIGH", "critical"]) == ["LOW", "HIGH", "CRITICAL"]
    assert filter_incident_severities(["MEDIUM", "invalid", ""]) == ["MEDIUM"]
    assert filter_alert_severities(["garbage"]) is None
    assert filter_incident_severities(None) is None


def test_filter_verdicts_accepts_valid_and_ignores_invalid():
    assert filter_alert_verdicts(["MALICIOUS", "N/A", "benign"]) == ["MALICIOUS", "NA", "BENIGN"]
    assert filter_incident_verdicts(["SUSPICIOUS", "INCONCLUSIVE", "not-a-verdict"]) == [
        "SUSPICIOUS",
        "INCONCLUSIVE",
    ]
    assert filter_alert_verdicts([]) is None


def test_normalize_vega_status_for_display_maps_api_values():
    assert _normalize_vega_status_for_display("IN_PROGRESS", "alert") == "IN PROGRESS"
    assert _normalize_vega_status_for_display("PEER_REVIEW", "alert") == "PEER REVIEW"
    assert _normalize_vega_status_for_display("OPEN", "alert") == "OPEN"
    assert _normalize_vega_status_for_display("ON_HOLD", "incident") == "ON HOLD"
    assert _normalize_vega_status_for_display("EXTERNAL_ESCALATION", "incident") == "EXTERNAL ESCALATION"
    assert _normalize_vega_status_for_display("IN PROGRESS", "alert") == "IN PROGRESS"


def test_format_raw_entity_for_xsoar_normalizes_status_for_dropdown():
    alert = {"vegaEntityType": "Vega Alert", "status": "IN_PROGRESS"}
    _format_raw_entity_for_xsoar(alert)
    assert alert["status"] == "IN PROGRESS"

    incident = {"vegaEntityType": "Vega Incident", "status": "UNDER_REVIEW"}
    _format_raw_entity_for_xsoar(incident)
    assert incident["status"] == "UNDER REVIEW"


def test_validate_backfill_days_rejects_out_of_range():
    with pytest.raises(ValueError, match="between 0 and 365"):
        validate_backfill_days(500)
    with pytest.raises(ValueError, match="between 0 and 365"):
        validate_backfill_days(-5)
    with pytest.raises(ValueError, match="must be an integer"):
        validate_backfill_days("not-a-number")


def test_parse_backfill_days_parses_decimal_string():
    assert parse_backfill_days("30.0") == parse_backfill_days(30)


def test_parse_backfill_days_legacy_first_fetch():
    result = parse_backfill_days(None, legacy_first_fetch="7 days")
    assert result.endswith("T00:00:00Z")
    parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    assert (today_start - parsed).days == 7


def test_format_bullet_list():
    assert _format_bullet_list(["CloudTrail", "VPC Flow Logs"]) == "• CloudTrail\n• VPC Flow Logs"
    assert _format_bullet_list([]) == []
    assert _format_bullet_list(None) is None
    assert _format_bullet_list("already formatted") == "already formatted"


def test_format_key_findings_html_dark_theme_layout():
    findings = [
        "Suspicious activity from 10.0.0.1",
        "Domain evil.com contacted by host",
    ]
    assets = ["10.0.0.1"]
    observables = ["evil.com"]

    result = _format_key_findings_html(findings, assets, observables)

    assert "background:#000000" in result
    assert "Key findings</div>" in result
    assert "See Investigation" not in result
    assert "border-radius:999px" in result
    assert "10.0.0.1" in result
    assert "evil.com" in result
    assert ">1</div>" in result
    assert ">2</div>" in result
    assert "border-bottom:1px solid #333333" in result


def test_format_key_findings_html_empty_state():
    result = _format_key_findings_html([], [], [])

    assert "No key findings are available" in result
    assert "background:#000000" in result


def test_format_raw_entity_for_xsoar_alert():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "vegaEntityType": "Vega Alert",
        "dataSources": ["CloudTrail", "GuardDuty"],
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["dataSources"] == "• CloudTrail\n• GuardDuty"
    assert alert["detectionDescription"] == "N/A"
    assert alert["detectionQuery"] == "N/A"
    assert set(alert.keys()) == {
        "id",
        "name",
        "vegaEntityType",
        "dataSources",
        "detectionDescription",
        "detectionQuery",
    }


def test_format_raw_entity_for_xsoar_alert_detection_fields():
    alert = {
        "id": "alert-1",
        "vegaEntityType": "Vega Alert",
        "detectionDescription": "  ",
        "detectionQuery": "SELECT * FROM events",
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["detectionDescription"] == "N/A"
    assert alert["detectionQuery"] == "```sql\nSELECT * FROM events\n```"


def test_format_raw_entity_for_xsoar_alert_empty_detection_fields():
    alert = {
        "id": "alert-1",
        "vegaEntityType": "Vega Alert",
        "detectionDescription": None,
        "detectionQuery": "",
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["detectionDescription"] == "N/A"
    assert alert["detectionQuery"] == "N/A"


def test_format_mitre_attack():
    assert _format_mitre_attack(None) is None
    assert _format_mitre_attack({}) is None
    assert (
        _format_mitre_attack({"mitreTactics": ["Discovery"], "mitreTechniques": ["Cloud Infrastructure Discovery"]})
        == "• Discovery\n• Cloud Infrastructure Discovery"
    )
    assert _format_mitre_attack({"mitreTactics": "Discovery", "mitreTechniques": "T1526"}) == "• Discovery\n• T1526"


def test_format_raw_entity_for_xsoar_mitre_attack():
    alert = {
        "id": "alert-1",
        "mitre": {"mitreTactics": ["Discovery"], "mitreTechniques": ["T1526"]},
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["vegaMitreAttack"] == "• Discovery\n• T1526"


def test_format_mitre_attack_object_items():
    mitre = {
        "mitreTactics": [{"name": "Discovery", "id": "TA0007"}],
        "mitreTechniques": [{"techniqueName": "Cloud Infrastructure Discovery", "techniqueId": "T1526"}],
    }
    assert _format_mitre_attack(mitre) == "• Discovery\n• Cloud Infrastructure Discovery"


def test_alert_to_incident_sets_vega_mitre_attack():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "mitre": {"mitreTactics": ["Discovery"], "mitreTechniques": ["T1526"]},
    }
    xsoar_incident = alert_to_incident(alert)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["vegaMitreAttack"] == "• Discovery\n• T1526"
    assert xsoar_incident["CustomFields"]["vegamitreattack"] == "• Discovery\n• T1526"
    assert xsoar_incident["CustomFields"]["vegacreatedat"] == TIMESTAMP_T1


def test_format_raw_entity_for_xsoar_incident():
    incident = {
        "id": "inc-1",
        "dataSources": ["CloudTrail"],
        "assets": ["i-12345"],
        "observables": ["10.0.0.1"],
        "incidentFindings": ["Instance i-12345 connected to 10.0.0.1"],
    }
    _format_raw_entity_for_xsoar(incident)

    assert incident["dataSources"] == "• CloudTrail"
    assert incident["assets"] == "• i-12345"
    assert incident["observables"] == "• 10.0.0.1"
    assert "vegaIncidentFindings" in incident
    assert "background:#000000" in incident["vegaIncidentFindings"]
    assert "i-12345" in incident["vegaIncidentFindings"]
    assert "10.0.0.1" in incident["vegaIncidentFindings"]


def test_alert_to_incident_formats_raw_json(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"autoclosure": "true", "comment_tag": "comment"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")

    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "dataSources": ["CloudTrail"],
    }
    xsoar_incident = alert_to_incident(alert, integration_url="https://api.vega.io")
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["dataSources"] == "• CloudTrail"
    assert raw["vegaEntityType"] == "Vega Alert"
    assert raw["link"] == "https://app.vega.io/incidents/alerts/investigation/alert-1"
    assert raw["detectionDescription"] == "N/A"
    assert raw["detectionQuery"] == "N/A"
    assert set(raw.keys()) == {
        "id",
        "name",
        "severity",
        "createdAt",
        "dataSources",
        "vegaEntityType",
        "link",
        "detectionDescription",
        "detectionQuery",
        "mirror_direction",
        "mirror_instance",
        "mirror_tags",
        "mirror_id",
    }


def test_incident_to_xsoar_incident_formats_raw_json():
    incident = {
        "id": "inc-1",
        "name": "Test Incident",
        "severity": "LOW",
        "createdAt": TIMESTAMP_T1,
        "assets": ["host-1"],
        "observables": ["host-1"],
        "incidentFindings": ["Activity detected on host-1"],
    }
    xsoar_incident = incident_to_xsoar_incident(incident)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["assets"] == "• host-1"
    assert raw["observables"] == "• host-1"
    assert "vegaIncidentFindings" in raw
    assert "Activity detected on" in raw["vegaIncidentFindings"]
    assert "host-1" in raw["vegaIncidentFindings"]
    assert xsoar_incident["CustomFields"]["vegaincidentfindings"]
    assert xsoar_incident["CustomFields"]["vegacreatedat"] == TIMESTAMP_T1
    assert "link" not in raw


def test_format_timeline_events_html_dark_theme_layout():
    timeline = [
        {
            "id": "evt-1",
            "timestamp": "2026-04-28T01:30:00Z",
            "summary": "SSM enumeration detected.",
            "entities": [],
            "dataSources": [{"vendor": "AWS", "displayName": "CloudTrail"}],
            "alert": {"id": "alert-1", "displayName": "AWS SSM Enumeration", "severity": 3},
        },
        {
            "id": "evt-2",
            "timestamp": "2026-04-28T02:00:00Z",
            "summary": "Authorized scanner context.",
            "entities": [
                {
                    "type": "ASSET",
                    "category": "USERNAME",
                    "value": "arn:aws:sts::890123456789:assumed-role/WizAccess-Role/wiz-scanner-session",
                }
            ],
            "dataSources": [{"vendor": "Wiz", "displayName": "Wiz Issues"}],
            "alert": None,
        },
    ]
    formatted = _format_timeline_events_html(timeline)

    assert "background:#000000" in formatted
    assert "color:#ffffff" in formatted
    assert "Timeline</div>" in formatted
    assert "2026-04-28 01:30:00" in formatted
    assert "AWS SSM Enumeration" in formatted
    assert "AWS · CloudTrail" in formatted
    assert "Wiz · Wiz Issues" in formatted
    assert "Severity: High" in formatted
    assert "SSM enumeration detected." in formatted
    assert "arn:aws:sts::890123456789:assumed-role/WizAccess-Role/wiz-scanner-session" in formatted
    assert formatted.count("align-items:stretch") == 2
    assert "border-radius:50%" not in formatted


def test_incident_to_xsoar_incident_includes_timeline_events():
    timeline = [
        {
            "id": "evt-1",
            "timestamp": "2026-04-28T01:30:00Z",
            "summary": "Test event.",
            "entities": [],
            "dataSources": [],
            "alert": None,
        }
    ]
    incident = {
        "id": "inc-1",
        "name": "Test Incident",
        "severity": "LOW",
        "createdAt": TIMESTAMP_T1,
    }
    xsoar_incident = incident_to_xsoar_incident(incident, timeline_events=timeline)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["timelineEvents"] == timeline
    assert "vegaTimelineEvents" in raw
    assert xsoar_incident["CustomFields"]["vegatimelineevents"]
    assert "Test event." in xsoar_incident["CustomFields"]["vegatimelineevents"]


def test_fetch_incidents_command_fetches_timeline_details(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {
        "incidents": [{"id": "inc-1", "name": "Inc 1", "severity": "LOW", "createdAt": TIMESTAMP_T2}],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incident_details.return_value = {
        "timelineEvents": [
            {
                "id": "evt-1",
                "timestamp": TIMESTAMP_T2,
                "summary": "Timeline summary.",
                "entities": [],
                "dataSources": [],
                "alert": None,
            }
        ],
        "keyFindings": ["Detail finding from Vega."],
    }
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    _, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert len(incidents) == 1
    mock_client.get_incident_details.assert_called_once_with("inc-1")
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["timelineEvents"][0]["summary"] == "Timeline summary."
    assert raw["keyFindings"] == ["Detail finding from Vega."]
    assert "Detail finding from Vega." in raw["vegaIncidentFindings"]


def test_format_raw_entity_for_xsoar_prefers_key_findings():
    incident = {
        "incidentFindings": ["List finding"],
        "keyFindings": ["Detail finding"],
        "assets": [],
        "observables": [],
    }
    _format_raw_entity_for_xsoar(incident)

    assert incident["assets"] == "No assets present."
    assert incident["observables"] == "No observables present."
    assert "Detail finding" in incident["vegaIncidentFindings"]
    assert "List finding" not in incident["vegaIncidentFindings"]


def test_alert_to_incident_normalizes_api_link():
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "link": "https://api.vega.io/incidents/alerts/alert-1",
    }
    raw = json.loads(alert_to_incident(alert)["rawJSON"])

    assert raw["link"] == "https://app.vega.io/incidents/alerts/alert-1"


def test_incident_to_xsoar_incident_normalizes_api_link():
    incident_id = "019e1b27-6d49-7ea1-a9d2-f2fe9227738f"
    incident = {
        "id": incident_id,
        "name": "Test Incident",
        "severity": "LOW",
        "createdAt": TIMESTAMP_T1,
        "link": f"https://api.vega.io/incidents/list/{incident_id}",
    }
    raw = json.loads(incident_to_xsoar_incident(incident)["rawJSON"])

    assert raw["link"] == f"https://app.vega.io/incidents/list/{incident_id}"


def test_parse_alert_events_results_handles_json_string():
    payload = json.dumps(
        [
            {
                "actor": {"user": {"uid": "arn:aws:iam::123:root"}},
                "timeframe": "2026-05-12 00:40:00.000",
                "event_count": 23,
            }
        ]
    )
    parsed = _parse_alert_events_results(payload)
    assert len(parsed) == 1
    assert parsed[0]["event_count"] == 23


def test_format_alert_events_markdown_table_layout():
    actor_arn = "arn:aws:iam::890123456789:root"
    alert_events = [
        {
            "actor": {"user": {"uid": actor_arn}},
            "timeframe": "2026-05-12 00:40:00.000",
            "event_count": 23,
            "unique_events_count": 6,
            "regions_count": 6,
            "unique_events": ["DescribeInstances", "GetCallerIdentity"],
        }
    ]
    formatted = _format_alert_events_markdown(alert_events, total=16, offset=0, page_size=50)

    assert "Alert Events (16)" in formatted
    assert "actor.user.uid" in formatted
    assert "timeframe" in formatted
    assert "event_count" in formatted
    assert "unique_events_count" in formatted
    assert "regions_count" in formatted
    assert "unique_events" in formatted
    assert actor_arn in formatted
    assert "DescribeInstances" in formatted
    assert "<div" not in formatted


def test_format_alert_events_markdown_handles_dynamic_eks_shape():
    fields_payload = {
        "cluster": {"name": "eks-prod-cluster"},
        "operation": "create",
        "actor": {
            "user": {
                "uid": "aws-iam-authenticator:890123456789:AIDASDRANJTZJUR47VREC",
                "name": "arn:aws:iam::890123456789:user/james.collins",
            }
        },
        "request": {"uri": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
        "status_code": "201",
    }
    alert_events = [
        {
            "catalog": "amazoneksaudit",
            "class": "Network Activity",
            "data_source": "amazon_eks_events",
            "fields": json.dumps(fields_payload),
            "index_timestamp": "2026-03-25 14:12:43.000",
            "raw": json.dumps({"auditID": "72cf9493-079d-4d73-872b-e1f4f0a099a8", "verb": "create"}),
            "source": "EKS",
            "storage": "AWS S3",
            "timestamp": "2026-03-25 17:26:18.000",
        }
    ]

    formatted = _format_alert_events_markdown(alert_events, total=1)

    assert "timestamp" in formatted
    assert "source" in formatted
    assert "catalog" in formatted
    assert "actor.user.uid" in formatted
    assert "operation" in formatted
    assert "request.uri" in formatted
    assert "eks-prod-cluster" in formatted
    assert "aws-iam-authenticator:890123456789:AIDASDRANJTZJUR47VREC" in formatted
    assert "raw" in formatted


def test_build_alert_events_custom_fields():
    fields = build_alert_events_custom_fields("alert-1", "### Alert Events (16)", 16, offset=50)
    assert fields["vegaalerteventsloadedfor"] == "alert-1"
    assert fields["vegaalertevents"] == "### Alert Events (16)"
    assert fields["vegaalerteventstotal"] == 16
    assert fields["vegaalerteventsoffset"] == 50


def test_resolve_alert_id_from_incident_uses_mirror_id_without_type():
    incident = {"CustomFields": {"dbotmirrorid": "alert-99-alert"}}
    assert resolve_alert_id_from_incident({}, incident) == "alert-99"


def test_load_current_incident_returns_incident_context(mocker):
    mocker.patch(
        "Vega.demisto.incident",
        return_value={
            "id": "123",
            "type": "Vega Alert",
            "CustomFields": {"vegaalertid": "alert-from-context"},
        },
    )

    incident = load_current_incident()

    assert incident["CustomFields"]["vegaalertid"] == "alert-from-context"


def test_resolve_alert_id_from_incident_uses_mirror_id_and_raw_json():
    incident = {
        "type": "Vega Alert",
        "CustomFields": {"dbotmirrorid": "alert-99-alert"},
        "rawJSON": json.dumps({"id": "alert-raw", "vegaEntityType": "Vega Alert"}),
    }
    assert resolve_alert_id_from_incident({}, incident) == "alert-99"

    incident_without_mirror = {
        "CustomFields": {},
        "rawJSON": json.dumps({"id": "alert-raw", "vegaEntityType": "Vega Alert"}),
    }
    assert resolve_alert_id_from_incident({}, incident_without_mirror) == "alert-raw"


def test_build_vega_alert_custom_fields_sets_alert_id():
    fields = _build_vega_alert_custom_fields({"id": "alert-1", "vegaMitreAttack": "T1059"})
    assert fields["vegaalertid"] == "alert-1"
    assert fields["vegamitreattack"] == "T1059"


def test_fetch_alert_events_page(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 2,
        "limit": 50,
        "offset": 0,
        "results": [
            {"timeframe": "2026-05-12 00:40:00.000", "event_count": 23},
            {"timeframe": "2026-05-12 00:50:00.000", "event_count": 26},
        ],
    }

    events, total = fetch_alert_events_page(mock_client, "alert-1", limit=50, offset=0)

    assert total == 2
    assert len(events) == 2
    mock_client.get_alert_events.assert_called_once_with("alert-1", limit=50, offset=0)


def test_alert_events_command_results_use_markdown_readable_output():
    result = _alert_events_command_results("### Alert Events (1)\n| actor.user.uid |", {"AlertId": "alert-1"})
    entry = result.to_context()

    assert entry["HumanReadable"] == "### Alert Events (1)\n| actor.user.uid |"
    assert "<div" not in str(entry.get("HumanReadable", ""))


def test_fetch_alert_events_command_fetches_all_and_slices_page(mocker):
    mocker.patch(
        "Vega.load_current_incident",
        return_value={"CustomFields": {"vegaalertid": "alert-1"}},
    )
    mock_client = mocker.Mock(spec=Client)
    alert_events_page_responses = [
        {
            "total": 3,
            "results": [
                {"timeframe": "2026-05-12 00:40:00.000", "event_count": 1},
                {"timeframe": "2026-05-12 00:50:00.000", "event_count": 2},
            ],
        },
        {
            "total": 3,
            "results": [{"timeframe": "2026-05-12 01:00:00.000", "event_count": 3}],
        },
    ]
    mock_client.get_alert_events.side_effect = alert_events_page_responses * 2

    first_page = fetch_alert_events_command(
        mock_client,
        {"alert_id": "alert-1", "limit": "2", "offset": "0"},
    )
    second_page = fetch_alert_events_command(
        mock_client,
        {"alert_id": "alert-1", "limit": "2", "offset": "2"},
    )

    assert first_page.outputs["Total"] == 3
    assert first_page.outputs["Count"] == 2
    assert first_page.outputs["Offset"] == 0
    assert second_page.outputs["Count"] == 1
    assert second_page.outputs["Offset"] == 2
    assert mock_client.get_alert_events.call_count == 4


def test_set_detections_state_command(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.set_detections_state.return_value = {"ids": ["det-1", "det-2"]}

    result = set_detections_state_command(
        mock_client,
        {"ids": ["det-1", "det-2"], "state": "ENABLED"},
    )

    mock_client.set_detections_state.assert_called_once_with(["det-1", "det-2"], "ENABLED")
    assert result.outputs["State"] == "ENABLED"
    assert result.outputs["IDs"] == ["det-1", "det-2"]
    assert result.outputs["Count"] == 2
    assert "Updated detection state to ENABLED" in result.readable_output


def test_set_detections_state_command_requires_ids(mocker):
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(DemistoException, match="ids is required"):
        set_detections_state_command(mock_client, {"state": "ENABLED"})


def test_set_detections_state_command_requires_valid_state(mocker):
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(DemistoException, match="state must be one of"):
        set_detections_state_command(mock_client, {"ids": ["det-1"], "state": "INVALID"})


def test_set_detections_state_command_test_mode(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.set_detections_state.return_value = {"ids": ["det-1"]}

    result = set_detections_state_command(mock_client, {"ids": ["det-1"], "state": "TEST_MODE"})

    mock_client.set_detections_state.assert_called_once_with(["det-1"], "TEST_MODE")
    assert result.outputs["State"] == "TEST_MODE"


def test_update_detections_command_single_id(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_detections.return_value = {
        "results": [
            {
                "status": "VALID",
                "name": "Detection 1",
                "detection": {"id": "det-1", "name": "Detection 1", "severity": "HIGH", "status": "VISIBLE"},
            }
        ],
        "summary": {"requested": 1, "valid": 1, "invalid": 0, "committed": True},
    }

    result = update_detections_command(
        mock_client,
        {"detection_id": "det-1", "severity": "HIGH", "status": "VISIBLE"},
    )

    mock_client.update_detections.assert_called_once_with([{"detectionId": "det-1", "severity": "HIGH", "status": "VISIBLE"}])
    assert result.outputs["ID"] == "det-1"
    assert result.outputs["Severity"] == "HIGH"
    assert result.outputs["Status"] == "VISIBLE"
    assert "Updated Vega Detections" in result.readable_output


def test_update_detections_command_multiple_ids(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_detections.return_value = {
        "results": [
            {
                "status": "VALID",
                "name": "Detection 1",
                "detection": {"id": "det-1", "name": "Detection 1", "severity": "LOW", "status": "HIDDEN"},
            },
            {
                "status": "VALID",
                "name": "Detection 2",
                "detection": {"id": "det-2", "name": "Detection 2", "severity": "LOW", "status": "HIDDEN"},
            },
        ],
        "summary": {"requested": 2, "valid": 2, "invalid": 0, "committed": True},
    }

    result = update_detections_command(
        mock_client,
        {"detection_id": ["det-1", "det-2"], "severity": "low", "status": "hidden"},
    )

    mock_client.update_detections.assert_called_once_with(
        [
            {"detectionId": "det-1", "severity": "LOW", "status": "HIDDEN"},
            {"detectionId": "det-2", "severity": "LOW", "status": "HIDDEN"},
        ]
    )
    assert result.outputs[0]["ID"] == "det-1"
    assert result.outputs[1]["ID"] == "det-2"


def test_update_detections_command_requires_detection_id(mocker):
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(DemistoException, match="detection_id is required"):
        update_detections_command(mock_client, {"severity": "HIGH"})


def test_update_detections_command_requires_update_fields(mocker):
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(DemistoException, match="At least one of severity or status"):
        update_detections_command(mock_client, {"detection_id": "det-1"})


def test_update_detections_command_raises_on_api_errors(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_detections.return_value = {
        "results": [
            {
                "status": "INVALID",
                "name": "Detection 1",
                "errors": [{"code": "INVALID_VALUE", "message": "Invalid severity", "field": "severity"}],
            }
        ],
        "summary": {"requested": 1, "valid": 0, "invalid": 1, "committed": False},
    }

    with pytest.raises(DemistoException, match="Vega API error updating detections"):
        update_detections_command(mock_client, {"detection_id": "det-1", "severity": "HIGH"})


def test_graphql_request_retries_on_graphql_rate_limit(mocker):
    mocker.patch.object(demisto, "debug")
    sleep_mock = mocker.patch("Vega.time.sleep")
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mocker.patch.object(client, "_authenticate", return_value="jwt-token")

    rate_limited_response = {
        "errors": [
            {
                "message": "Rate limit exceeded. Please retry after a brief wait.",
                "extensions": {
                    "code": "TooManyRequests",
                    "error_code_name": "REQUEST_RATE_LIMITED",
                    "retryAfter": 3,
                },
            }
        ],
        "data": None,
    }
    success_response = {"data": {"getAlerts": {"alerts": [], "total": 0}}}

    http_mock = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[rate_limited_response, rate_limited_response, success_response],
    )

    response = client._graphql_request("query { getAlerts { alerts { id } } }")

    assert response == success_response
    assert http_mock.call_count == 3
    assert sleep_mock.call_args_list[0].args[0] == 2
    assert sleep_mock.call_args_list[1].args[0] == 4
    assert client._rate_limit_wait_seconds == RATE_LIMIT_INITIAL_WAIT_SECONDS


def test_client_http_request_retries_on_429(mocker):
    mocker.patch.object(demisto, "debug")
    sleep_mock = mocker.patch("Vega.time.sleep")
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )

    rate_limited = DemistoException("Too Many Requests")
    rate_limited.res = mocker.Mock(status_code=429)
    success_response = {"data": {"getAlertsEvents": {"total": 0, "results": []}}}

    super_mock = mocker.patch(
        "Vega.BaseClient._http_request",
        side_effect=[rate_limited, rate_limited, success_response],
    )

    response = client._http_request(method="POST", url_suffix="query", resp_type="json")

    assert response == success_response
    assert super_mock.call_count == 3
    assert sleep_mock.call_args_list[0].args[0] == 2
    assert sleep_mock.call_args_list[1].args[0] == 4


def test_get_mirroring_autoclosure_enabled(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"autoclosure": "true", "comment_tag": "comment"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    mirroring = get_mirroring()

    assert mirroring["mirror_direction"] == "Both"
    assert mirroring["mirror_instance"] == "Vega_instance_1"
    assert mirroring["mirror_tags"] == "comment"


def test_get_mirroring_autoclosure_disabled(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "false"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    mirroring = get_mirroring()

    assert mirroring["mirror_direction"] == "In"


def test_parse_and_build_mirror_id():
    mirror_id = build_mirror_id("11111111-2222-3333-4444-555555555555", "incident")
    entity_id, entity_type = parse_mirror_id(mirror_id)

    assert entity_id == "11111111-2222-3333-4444-555555555555"
    assert entity_type == "incident"


def test_alert_to_incident_includes_mirroring_fields(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"autoclosure": "true", "comment_tag": "comment"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")

    xsoar_incident = alert_to_incident(
        {"id": "alert-1", "name": "Test Alert", "severity": "HIGH", "createdAt": "2026-01-01T00:00:00Z"}
    )
    raw = json.loads(xsoar_incident["rawJSON"])

    assert raw["mirror_direction"] == "Both"
    assert raw["mirror_id"] == "alert-1-alert"
    assert raw["mirror_instance"] == "Vega_instance_1"
    assert raw["mirror_tags"] == "comment"


def test_get_modified_remote_data_command(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "vega_alert_mirror_fingerprints": {
                "alert-2": _alert_mirror_fingerprint(
                    {
                        "id": "alert-2",
                        "status": "OPEN",
                        "severity": "HIGH",
                        "verdict": "NA",
                    }
                )
            },
            "vega_incident_mirror_last_updated": {
                "inc-1": json.dumps(
                    {
                        "lastUpdated": "2026-06-08T12:00:00Z",
                        "status": "OPEN",
                        "severity": "HIGH",
                        "verdict": "NA",
                        "verdictReasoning": "",
                        "assigneeEmail": None,
                    },
                    sort_keys=True,
                ),
                "inc-2": json.dumps(
                    {
                        "lastUpdated": "2026-06-08T12:00:00Z",
                        "status": "OPEN",
                        "severity": "HIGH",
                        "verdict": "NA",
                        "verdictReasoning": "",
                        "assigneeEmail": None,
                    },
                    sort_keys=True,
                ),
            },
        },
    )
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-2", "status": "RESOLVED", "severity": "HIGH", "verdict": "NA"},
        ]
    }
    mock_client.get_incidents.return_value = {
        "incidents": [
            {
                "id": "inc-1",
                "lastUpdated": "2026-06-10T12:00:00Z",
                "status": "OPEN",
                "severity": "HIGH",
                "verdict": "NA",
                "verdictReasoning": "",
            },
            {
                "id": "inc-2",
                "lastUpdated": "2026-06-08T12:00:00Z",
                "status": "OPEN",
                "severity": "HIGH",
                "verdict": "NA",
                "verdictReasoning": "",
            },
        ]
    }
    mocker.patch(
        "Vega._fetch_paginated_entities",
        side_effect=[
            [],
            [
                {"id": "alert-1", "status": "OPEN", "severity": "LOW", "verdict": "NA", "createdAt": "2026-06-10T11:00:00Z"},
            ],
        ],
    )

    response = get_modified_remote_data_command(
        mock_client,
        {"lastUpdate": "2026-06-09T00:00:00Z"},
        {"vega_entities": "Alerts,Incidents"},
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
    )

    assert response.modified_incident_ids == ["inc-1-incident", "alert-1-alert", "alert-2-alert"]
    mock_client.get_alerts.assert_called_once_with(alert_ids=["alert-2"], limit=1)
    mock_client.get_incidents.assert_called_once_with(incident_ids=["inc-1", "inc-2"], limit=2)
    mock_client.get_alert_by_id.assert_not_called()


def test_collect_modified_alert_mirror_ids_batches_cached_ids_up_to_1000(mocker):
    mocker.patch.object(demisto, "debug")
    fingerprints = {
        "alert-1": _alert_mirror_fingerprint({"id": "alert-1", "status": "OPEN", "severity": "HIGH", "verdict": "NA"}),
        "alert-2": _alert_mirror_fingerprint({"id": "alert-2", "status": "OPEN", "severity": "HIGH", "verdict": "NA"}),
    }
    mocker.patch("Vega._load_alert_mirror_fingerprints", return_value=fingerprints)
    mocker.patch("Vega._fetch_paginated_entities", return_value=[])

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "status": "OPEN", "severity": "HIGH", "verdict": "NA"},
            {"id": "alert-2", "status": "RESOLVED", "severity": "HIGH", "verdict": "NA"},
        ]
    }

    modified_ids = _collect_modified_alert_mirror_ids(
        mock_client,
        "2026-06-09T00:00:00Z",
        None,
        None,
        None,
    )

    assert modified_ids == ["alert-2-alert"]
    mock_client.get_alerts.assert_called_once_with(alert_ids=["alert-1", "alert-2"], limit=2)


def test_collect_modified_alert_mirror_ids_splits_cached_ids_into_1000_chunks(mocker):
    mocker.patch.object(demisto, "debug")
    fingerprints = {f"alert-{index}": "cached" for index in range(2500)}
    mocker.patch("Vega._load_alert_mirror_fingerprints", return_value=fingerprints)
    mocker.patch("Vega._fetch_paginated_entities", return_value=[])
    mocker.patch("Vega._append_changed_alert_mirror_ids")

    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {"alerts": []}

    _collect_modified_alert_mirror_ids(mock_client, "2026-06-09T00:00:00Z", None, None, None)

    assert mock_client.get_alerts.call_count == 3
    assert len(mock_client.get_alerts.call_args_list[0].kwargs["alert_ids"]) == 1000
    assert len(mock_client.get_alerts.call_args_list[1].kwargs["alert_ids"]) == 1000
    assert len(mock_client.get_alerts.call_args_list[2].kwargs["alert_ids"]) == 500


def test_alert_mirror_state_changed_detects_status_updates(mocker):
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "vega_alert_mirror_fingerprints": {
                "alert-2": _alert_mirror_fingerprint({"id": "alert-2", "status": "OPEN", "severity": "HIGH", "verdict": "NA"})
            }
        },
    )
    updated_alert = {"id": "alert-2", "status": "RESOLVED", "severity": "HIGH", "verdict": "NA"}

    assert _alert_mirror_state_changed(updated_alert) is True


def test_get_remote_data_command_alert_uses_fingerprint(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true", "comment_tag": "comment"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "vega_alert_mirror_fingerprints": {
                "alert-1": _alert_mirror_fingerprint({"id": "alert-1", "status": "OPEN", "severity": "HIGH", "verdict": "NA"})
            }
        },
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_by_id.return_value = {
        "id": "alert-1",
        "status": "RESOLVED",
        "severity": "HIGH",
        "verdict": "NA",
    }

    response = get_remote_data_command(
        mock_client,
        {"id": "alert-1-alert", "lastUpdate": "2026-06-09T00:00:00Z"},
    )

    assert response.mirrored_object["status"] == "RESOLVED"
    assert response.entries[0]["Contents"]["dbotIncidentClose"] is True


def test_incident_mirror_state_changed_detects_last_updated(mocker):
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "vega_incident_mirror_last_updated": {
                "inc-1": json.dumps(
                    {
                        "lastUpdated": "2026-06-08T12:00:00Z",
                        "status": "OPEN",
                        "severity": "HIGH",
                        "verdict": "NA",
                        "verdictReasoning": "",
                        "assigneeEmail": None,
                    },
                    sort_keys=True,
                ),
            }
        },
    )
    updated_incident = {"id": "inc-1", "lastUpdated": "2026-06-10T12:00:00Z", "status": "OPEN", "verdict": "NA"}

    assert _incident_mirror_state_changed(updated_incident) is True


def test_incident_mirror_state_changed_detects_verdict_without_last_updated_change(mocker):
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "vega_incident_mirror_last_updated": {
                "inc-1": json.dumps(
                    {
                        "lastUpdated": "2026-06-08T12:00:00Z",
                        "status": "OPEN",
                        "severity": "HIGH",
                        "verdict": "NA",
                        "verdictReasoning": "",
                        "assigneeEmail": None,
                    },
                    sort_keys=True,
                ),
            }
        },
    )
    updated_incident = {
        "id": "inc-1",
        "lastUpdated": "2026-06-08T12:00:00Z",
        "status": "OPEN",
        "severity": "HIGH",
        "verdict": "MALICIOUS",
    }

    assert _incident_mirror_state_changed(updated_incident) is True


def test_get_remote_data_command_incident_comment_does_not_reopen(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true", "comment_tag": "comment"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "vega_incident_mirror_last_updated": {
                "inc-1": json.dumps(
                    {
                        "lastUpdated": "2026-06-08T12:00:00Z",
                        "status": "OPEN",
                        "severity": "HIGH",
                        "verdict": "NA",
                        "verdictReasoning": "",
                        "assigneeEmail": None,
                    },
                    sort_keys=True,
                ),
            }
        },
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "OPEN",
        "severity": "HIGH",
        "lastUpdated": "2026-06-10T12:00:00Z",
        "comments": [
            {
                "text": "Investigating further",
                "addedBy": "analyst@example.com",
                "addedAt": "2026-06-10T12:00:00Z",
            }
        ],
    }

    response = get_remote_data_command(
        mock_client,
        {"id": "inc-1-incident", "lastUpdate": "2026-06-09T00:00:00Z"},
    )

    assert response.mirrored_object["status"] == "OPEN"
    assert response.entries
    assert all("dbotIncidentReopen" not in entry.get("Contents", {}) for entry in response.entries)
    assert all("dbotIncidentClose" not in entry.get("Contents", {}) for entry in response.entries)


def test_get_remote_data_command_incident_close(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true", "comment_tag": "comment"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "RESOLVED",
        "severity": "HIGH",
        "lastUpdated": "2026-06-10T12:00:00Z",
        "comments": [],
    }

    response = get_remote_data_command(
        mock_client,
        {"id": "inc-1-incident", "lastUpdate": "2026-06-09T00:00:00Z"},
    )

    assert response.mirrored_object["status"] == "RESOLVED"
    assert response.entries[0]["Contents"]["dbotIncidentClose"] is True


def test_update_remote_system_command_closes_alert(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert-1-alert",
            "data": {"id": "101"},
            "delta": {"closingUserId": "admin"},
            "status": IncidentStatus.DONE,
            "incidentChanged": True,
        },
        {"autoclosure": "true"},
    )

    assert remote_id == "alert-1-alert"
    mock_client.update_alerts.assert_called_once_with({"alertIds": ["alert-1"], "status": "RESOLVED"})


def test_update_remote_system_command_skips_when_autoclosure_disabled(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)

    remote_id = update_remote_system_command(
        mock_client,
        {"remoteId": "alert-1-alert", "data": {"id": "101"}, "delta": {}},
        {"autoclosure": "false"},
    )

    assert remote_id == "alert-1-alert"
    mock_client.update_alerts.assert_not_called()
    mock_client.update_incidents.assert_not_called()


def test_build_effective_incident_update_args_no_args_uses_custom_fields():
    incident = {
        "CustomFields": {
            VEGA_INCIDENT_STATUS_FIELD: "INVESTIGATING",
            "vegaverdict": "BENIGN",
        }
    }
    effective_args = _build_effective_incident_update_args({}, incident)

    assert effective_args["status"] == "INVESTIGATING"
    assert effective_args["verdict"] == "BENIGN"


def test_update_incident_command_no_args_uses_layout_fields(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch(
        "Vega.load_current_incident",
        return_value={
            "type": "Vega Incident",
            "CustomFields": {
                "vegaincidentid": "inc-1",
                VEGA_INCIDENT_STATUS_FIELD: "UNDER REVIEW",
                "vegaverdict": "SUSPICIOUS",
            },
        },
    )
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {
        "incidents": [{"incidentId": "inc-1", "status": "UNDER_REVIEW", "verdict": "SUSPICIOUS"}]
    }
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "UNDER_REVIEW",
        "verdict": "SUSPICIOUS",
    }

    update_incident_command(mock_client, {})

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "status": "UNDER_REVIEW",
            "verdict": {"value": "SUSPICIOUS", "reasoning": ""},
        }
    )


def test_update_alert_command_status_only_does_not_send_verdict(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch(
        "Vega.load_current_incident",
        return_value={"CustomFields": {"vegaverdict": "NA", "vegastatus": "OPEN"}},
    )
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_alerts.return_value = {"alerts": [{"id": "alert-1", "status": "IN_PROGRESS", "verdict": "BENIGN"}]}

    update_alert_command(mock_client, {"alert_id": "alert-1", "status": "IN PROGRESS"})

    mock_client.update_alerts.assert_called_once_with({"alertIds": ["alert-1"], "status": "IN_PROGRESS"})


def test_build_effective_alert_update_args_field_change_updates_status_only():
    effective_args = _build_effective_alert_update_args(
        {"old": "OPEN", "new": "IN PROGRESS"},
        {"CustomFields": {"vegaverdict": "NA"}},
    )

    assert effective_args["status"] == "IN PROGRESS"
    assert "verdict" not in effective_args


def test_build_effective_alert_update_args_field_change_updates_verdict_only():
    effective_args = _build_effective_alert_update_args(
        {"old": "NA", "new": "BENIGN"},
        {"CustomFields": {"vegastatus": "OPEN"}},
    )

    assert effective_args["verdict"] == "BENIGN"
    assert "status" not in effective_args


def test_update_alert_command_updates_multiple_alerts(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "status": "RESOLVED", "verdict": "MALICIOUS"},
            {"id": "alert-2", "status": "RESOLVED", "verdict": "MALICIOUS"},
        ]
    }
    mock_client.get_alert_by_id.return_value = {}

    result = update_alert_command(
        mock_client,
        {"alert_id": ["alert-1", "alert-2"], "status": "RESOLVED", "verdict": "MALICIOUS"},
    )

    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1", "alert-2"],
            "status": "RESOLVED",
            "verdict": "MALICIOUS",
        }
    )
    assert result.outputs[0]["id"] == "alert-1"
    assert result.outputs[1]["id"] == "alert-2"
    assert "Updated Vega Alerts" in result.readable_output


def test_update_alert_command_requires_update_fields(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(DemistoException, match="At least one of status or verdict"):
        update_alert_command(mock_client, {"alert_id": "alert-1"})


def test_update_incident_command_updates_with_comment(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {
        "incidents": [{"incidentId": "inc-1", "status": "INVESTIGATING", "verdict": "SUSPICIOUS"}]
    }
    mock_client.get_incident_by_id.return_value = {"id": "inc-1", "status": "INVESTIGATING", "verdict": "SUSPICIOUS"}

    result = update_incident_command(
        mock_client,
        {
            "incident_id": "inc-1",
            "status": "INVESTIGATING",
            "verdict": "SUSPICIOUS",
            "comment": "Reviewed in XSOAR",
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "status": "INVESTIGATING",
            "verdict": {"value": "SUSPICIOUS", "reasoning": ""},
            "comment": "Reviewed in XSOAR",
        }
    )
    assert result.outputs["id"] == "inc-1"
    assert "Updated Vega Incidents" in result.readable_output


def test_resolve_incident_id_from_incident_uses_explicit_incident_id():
    incident = {"type": "Vega Incident", "CustomFields": {"vegaincidentid": "inc-from-field"}}
    assert resolve_incident_id_from_incident({"incident_id": "inc-explicit"}, incident) == "inc-explicit"


def test_resolve_incident_id_from_incident_uses_mirror_id():
    incident = {"CustomFields": {"dbotmirrorid": "inc-99-incident"}}
    assert resolve_incident_id_from_incident({}, incident) == "inc-99"


def test_get_status_from_fields_uses_incident_status_field():
    custom_fields = {VEGA_INCIDENT_STATUS_FIELD: "INVESTIGATING"}
    assert _get_status_from_fields(custom_fields, {}, MIRROR_ENTITY_SUFFIX_INCIDENT) == "INVESTIGATING"


def test_get_status_from_fields_falls_back_to_legacy_vegastatus_for_incidents():
    custom_fields = {VEGA_ALERT_STATUS_FIELD: "ON HOLD"}
    assert _get_status_from_fields(custom_fields, {}, MIRROR_ENTITY_SUFFIX_INCIDENT) == "ON HOLD"


def test_build_incident_update_input_reads_vegaincidentstatus():
    payload = _build_incident_update_input(
        "inc-1",
        {"CustomFields": {VEGA_INCIDENT_STATUS_FIELD: "INVESTIGATING"}},
        {},
    )
    assert payload == {"incidentIds": ["inc-1"], "status": "INVESTIGATING"}


def test_resolve_incident_status_for_update_prefers_vegaincidentstatus():
    incident = {
        "CustomFields": {
            VEGA_INCIDENT_STATUS_FIELD: "UNDER REVIEW",
            VEGA_ALERT_STATUS_FIELD: "OPEN",
        }
    }
    assert _resolve_incident_status_for_update({}, incident) == "UNDER REVIEW"


def test_update_remote_system_command_closes_incident(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "inc-1-incident",
            "data": {"id": "202", "closeNotes": "Done", "closeReason": "Resolved"},
            "delta": {"closingUserId": "admin"},
            "status": IncidentStatus.DONE,
            "incidentChanged": True,
        },
        {"autoclosure": "true"},
    )

    assert remote_id == "inc-1-incident"
    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "status": "RESOLVED",
            "comment": "[Mirrored From XSOAR] XSOAR Incident ID: 202\n\nClose Reason: Resolved\n\nClose Notes: Done",
        }
    )
