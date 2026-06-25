import json
from datetime import datetime, timedelta, UTC

import requests

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pytest

from Vega import (
    ALERT_EVENTS_NOT_AVAILABLE_MARKDOWN,
    _alert_events_command_results,
    _event_has_bad_alert_events_shape,
    _events_have_bad_alert_events_shape,
    _format_alert_events_markdown,
    _format_mitre_attack,
    Client,
    GET_ALERT_MIRROR_QUERY,
    GET_INCIDENT_MIRROR_QUERY,
    _suppress_noisy_http_integration_logs,
    _build_fetch_filter_fingerprint,
    _build_vega_alert_custom_fields,
    _fetch_paginated_entities,
    _is_retryable_http_error,
    _format_bullet_list,
    _format_key_findings_html,
    _format_raw_entity_for_xsoar,
    _format_timeline_events_html,
    _format_vega_comments_html,
    _is_empty_vega_comment_text,
    _build_effective_alert_update_args,
    _build_effective_incident_update_args,
    _build_direct_alert_update_payload,
    _build_direct_incident_update_payload,
    _resolve_incident_status_for_update,
    _normalize_vega_severity_for_display,
    MIRROR_ENTITY_SUFFIX_ALERT,
    MIRROR_ENTITY_SUFFIX_INCIDENT,
    VEGA_ALERT_STATUS_FIELD,
    VEGA_INCIDENT_STATUS_FIELD,
    _normalize_vega_status_for_display,
    _normalize_entity_id,
    _normalize_verdict_reasoning_for_display,
    _extract_verdict_reasoning_from_entity,
    _mirror_entity_type_from_args,
    _entity_type_from_field_keys,
    _entity_type_from_mirror_payload,
    _parse_alert_events_results,
    _resolve_fetch_from_time,
    _resolve_next_fetch_state,
    _should_ingest_entity,
    _update_fetch_state,
    alert_to_incident,
    build_alert_events_custom_fields,
    fetch_alert_events_command,
    fetch_alert_events_page,
    fetch_incidents_command,
    _fetch_alert_events_for_ingest,
    set_detections_state_command,
    update_detections_command,
    incident_to_xsoar_incident,
    parse_backfill_days,
    load_current_incident,
    resolve_alert_id_from_incident,
    resolve_incident_id_from_incident,
    update_alert_command,
    update_incident_command,
    _build_comment_war_room_entry,
    _get_mirroring_fields,
    _is_xsoar_to_vega_mirroring_enabled,
    get_modified_remote_data_command,
    get_remote_data_command,
    update_remote_system_command,
    get_mapping_fields_command,
    _build_incoming_status_sync_entries,
    _entity_updated_after,
    _entity_matches_remote_id,
    _resolve_remote_entity,
    _normalize_incident_api_entity,
    _build_mirror_sync_object,
    _extract_vega_verdict_from_entity,
    _resolve_mirror_updated_from,
    _poll_entity_is_alert,
    _mirror_entity_suffix_from_poll_entity,
    _resolve_mirror_incident_lookup_filters,
    _resolve_mirror_entity_lookup_filters,
    _resolve_mirror_updated_to,
    _normalize_mirror_field_value,
    _mirror_field_value,
    _collect_outgoing_entry_comments,
    VEGA_NEW_COMMENT_FIELD,
    VEGA_MIRROR_TAG_FROM_VEGA,
    VEGA_MIRROR_TAG_TO_VEGA,
    RATE_LIMIT_INITIAL_WAIT_SECONDS,
    validate_backfill_days,
    validate_max_fetch,
    _resolve_max_fetch,
    MAX_FETCH_ERROR,
    filter_alert_severities,
    filter_alert_statuses,
    filter_alert_verdicts,
    filter_incident_severities,
    filter_incident_statuses,
    filter_incident_verdicts,
    resolve_has_related_incidents,
    TEST_CONNECTION_ACCESS_KEY_ERROR,
    TEST_CONNECTION_ACCESS_KEY_ID_ERROR,
    TEST_CONNECTION_BASE_URL_ERROR,
    TEST_CONNECTION_URL_ERROR,
    test_module as vega_test_module,
    main as vega_main,
)

_VEGA_API_HOST = "api" + ".vega.com"
BASE_URL = f"https://{_VEGA_API_HOST}"

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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == "ok"


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == "You do not have required access to fetch incidents."


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == TEST_CONNECTION_ACCESS_KEY_ID_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == TEST_CONNECTION_ACCESS_KEY_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == TEST_CONNECTION_URL_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == TEST_CONNECTION_BASE_URL_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50) == TEST_CONNECTION_BASE_URL_ERROR


def test_main_test_module_requires_backfill_days(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "access_key": "key",
            "access_key_id": "id",
            "url": BASE_URL,
            "vega_entities": ["Alerts", "Incidents"],
            "max_fetch": "50",
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_results = mocker.patch("Vega.return_results")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    vega_main()

    mock_return_results.assert_called_once_with("backfill_days must be an integer between 0 and 365.")


def test_main_test_module_rejects_invalid_max_fetch(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "access_key": "key",
            "access_key_id": "id",
            "url": BASE_URL,
            "vega_entities": ["Alerts", "Incidents"],
            "backfill_days": "30",
            "max_fetch": "100",
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_results = mocker.patch("Vega.return_results")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    vega_main()

    mock_return_results.assert_called_once_with(MAX_FETCH_ERROR)


def test_test_module_rejects_invalid_max_fetch(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )

    assert vega_test_module(client, backfill_days=30, max_fetch=0) == MAX_FETCH_ERROR
    assert vega_test_module(client, backfill_days=30, max_fetch=100) == MAX_FETCH_ERROR
    assert vega_test_module(client, backfill_days=30, max_fetch="abc") == 'Invalid number: "max_fetch"="abc"'


def test_validate_max_fetch_accepts_valid_range():
    validate_max_fetch(1)
    validate_max_fetch(50)
    validate_max_fetch("25")


def test_validate_max_fetch_rejects_invalid_values():
    with pytest.raises(ValueError, match=MAX_FETCH_ERROR):
        validate_max_fetch(0)
    with pytest.raises(ValueError, match=MAX_FETCH_ERROR):
        validate_max_fetch(51)
    with pytest.raises(ValueError, match='Invalid number: "max_fetch"="not-a-number"'):
        validate_max_fetch("not-a-number")
    with pytest.raises(ValueError, match=MAX_FETCH_ERROR):
        validate_max_fetch(None)


def test_resolve_max_fetch_defaults_invalid_values():
    assert _resolve_max_fetch(None) == 50
    assert _resolve_max_fetch("0") == 50
    assert _resolve_max_fetch("100") == 50
    assert _resolve_max_fetch("abc") == 50
    assert _resolve_max_fetch("25") == 25
    assert _resolve_max_fetch("50") == 50


def test_url_normalization():
    # Test cases for URL normalization: (input_url, expected_normalized_url)
    test_cases = [
        (BASE_URL, f"{BASE_URL}/api/v1/"),
        (f"{BASE_URL}/", f"{BASE_URL}/api/v1/"),
        (f"{BASE_URL}/api/v1", f"{BASE_URL}/api/v1/"),
        (f"{BASE_URL}/api/v1/", f"{BASE_URL}/api/v1/"),
        (f"{BASE_URL}/API/V1", f"{BASE_URL}/API/V1/"),
        (f"{BASE_URL}/API/v1/", f"{BASE_URL}/API/v1/"),
        (f"  {BASE_URL}  ", f"{BASE_URL}/api/v1/"),
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


def test_resolve_next_fetch_state_advances_to_now_on_empty_initial_backfill(mocker):
    mocker.patch.object(demisto, "debug")
    fixed_now = datetime(2026, 6, 4, 17, 30, 45, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)

    last_fetch, last_ids = _resolve_next_fetch_state({}, "alerts_last_fetch", [], FIRST_FETCH_TIME, [])

    assert last_fetch == "2026-06-04T17:30:45Z"
    assert last_ids == []


def test_resolve_next_fetch_state_preserves_cursor_on_empty_subsequent_fetch():
    last_run = {"alerts_last_fetch": TIMESTAMP_T1, "alerts_last_ids": ["alert-a"]}

    last_fetch, last_ids = _resolve_next_fetch_state(last_run, "alerts_last_fetch", [], TIMESTAMP_T1, ["alert-a"])

    assert last_fetch == TIMESTAMP_T1
    assert last_ids == ["alert-a"]


def test_fetch_incidents_command_empty_initial_backfill_advances_cursor(mocker):
    mocker.patch.object(demisto, "debug")
    fixed_now = datetime(2026, 6, 4, 17, 30, 45, tzinfo=UTC)
    mocker.patch("Vega.datetime", wraps=datetime)
    mocker.patch("Vega.datetime.now", return_value=fixed_now)
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 200, "offset": 0}

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert incidents == []
    assert "alerts_last_fetch" not in next_run
    assert "incidents_last_fetch" not in next_run
    assert next_run["alerts_fetch_config"] == _build_fetch_filter_fingerprint(None, None, None)
    assert next_run["incidents_fetch_config"] == _build_fetch_filter_fingerprint(None, None, None)


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
        has_related_incidents=None,
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
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert mock_client.get_alerts.call_args.kwargs["from_time"] == TIMESTAMP_T1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "Medium Alert"
    assert next_run["alerts_last_ids"] == ["alert-medium"]
    assert "alerts_seen_ids" not in next_run
    assert next_run["alerts_fetch_config"] == _build_fetch_filter_fingerprint(["HIGH", "MEDIUM"], None, None)


def test_fetch_incidents_command_skips_alerts_before_cursor_when_severity_filter_changes(mocker):
    mocker.patch.object(demisto, "debug")
    cursor = "2026-05-10T00:06:10Z"
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {"incidents": [], "total": 0, "limit": 50, "offset": 0}
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-old-high", "name": "Old High", "severity": "HIGH", "createdAt": "2026-05-10T00:01:06Z"},
            {"id": "alert-new-high", "name": "New High", "severity": "HIGH", "createdAt": "2026-05-10T00:07:00Z"},
        ],
        "total": 2,
        "limit": 50,
        "offset": 0,
    }

    previous_config = _build_fetch_filter_fingerprint(["CRITICAL"], None, None)
    last_run = {
        "alerts_last_fetch": cursor,
        "alerts_last_ids": ["alert-critical"],
        "alerts_fetch_config": previous_config,
        "alerts_offset": 50,
        "alerts_pagination_from": FIRST_FETCH_TIME,
    }

    _, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=False,
        alert_severities=["HIGH"],
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )

    assert mock_client.get_alerts.call_args.kwargs["from_time"] == cursor
    assert mock_client.get_alerts.call_args.kwargs["offset"] == 0
    assert len(incidents) == 1
    assert incidents[0]["name"] == "New High"


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
    mock_client.get_incident_timeline.return_value = {"events": []}

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
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=["MALICIOUS", "SUSPICIOUS"],
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert mock_client.get_incidents.call_args.kwargs["from_time"] == TIMESTAMP_T1
    assert len(incidents) == 1
    assert incidents[0]["name"] == "New Verdict Match"
    assert next_run["incidents_last_ids"] == ["inc-2"]
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

    results, next_offset = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 2
    assert next_offset is None
    assert results[0]["id"] == "1"
    assert results[1]["id"] == "2"
    assert mock_get_alerts.call_count == 2
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[1].kwargs["offset"] == 1


def test_fetch_paginated_entities_fetches_beyond_single_page(mocker):
    """Verify pagination continues until total is reached when the API returns multiple pages."""
    page_one = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T1} for i in range(100)],
        "total": 250,
        "limit": 100,
        "offset": 0,
    }
    page_two = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T2} for i in range(100, 200)],
        "total": 250,
        "limit": 100,
        "offset": 100,
    }
    page_three = {
        "alerts": [{"id": str(i), "createdAt": TIMESTAMP_T2} for i in range(200, 250)],
        "total": 250,
        "limit": 100,
        "offset": 200,
    }
    mock_get_alerts = mocker.Mock(side_effect=[page_one, page_two, page_three])

    results, next_offset = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 250
    assert next_offset is None
    assert mock_get_alerts.call_count == 3
    assert mock_get_alerts.call_args_list[0].kwargs["limit"] == 100
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[2].kwargs["offset"] == 200


def test_fetch_incidents_command_incidents_first_then_alerts(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incident_timeline.return_value = {"events": []}

    def make_incident_page(offset: int, count: int, total: int = 152):
        return {
            "incidents": [
                {"id": f"inc-{index}", "name": f"Inc {index}", "severity": "LOW", "createdAt": TIMESTAMP_T1}
                for index in range(offset, offset + count)
            ],
            "total": total,
            "limit": count,
            "offset": offset,
        }

    mock_client.get_incidents.side_effect = [
        make_incident_page(0, 50),
        make_incident_page(50, 50),
        make_incident_page(100, 50),
        make_incident_page(150, 2),
    ]
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": f"alert-{index}", "name": f"Alert {index}", "severity": "LOW", "createdAt": TIMESTAMP_T2}
            for index in range(48)
        ],
        "total": 200,
        "limit": 48,
        "offset": 0,
    }

    last_run: dict = {}
    total_created = 0

    for run_index in range(3):
        last_run, incidents = fetch_incidents_command(
            client=mock_client,
            last_run=last_run,
            fetch_alerts=True,
            fetch_incidents=True,
            alert_severities=None,
            alert_statuses=None,
            alert_verdicts=None,
            has_related_incidents=None,
            incident_severities=None,
            incident_statuses=None,
            incident_verdicts=None,
            first_fetch_time=FIRST_FETCH_TIME,
            max_fetch=50,
        )
        assert len(incidents) == 50
        assert last_run["incidents_offset"] == (run_index + 1) * 50
        assert mock_client.get_alerts.call_count == 0
        total_created += len(incidents)

    last_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run=last_run,
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )

    assert len(incidents) == 50
    assert "incidents_offset" not in last_run
    assert mock_client.get_alerts.call_count == 1
    assert mock_client.get_alerts.call_args.kwargs["limit"] == 48
    total_created += len(incidents)
    assert total_created == 200


def test_fetch_incidents_command_resumes_alert_pagination(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incident_timeline.return_value = {"events": []}
    mock_client.get_incidents.side_effect = [
        {
            "incidents": [
                {"id": f"inc-{index}", "name": f"Inc {index}", "severity": "LOW", "createdAt": TIMESTAMP_T1} for index in range(8)
            ],
            "total": 8,
            "limit": 8,
            "offset": 0,
        },
        {"incidents": [], "total": 8, "limit": 50, "offset": 0},
        {"incidents": [], "total": 8, "limit": 50, "offset": 0},
    ]
    mock_client.get_alerts.side_effect = [
        {
            "alerts": [
                {"id": f"alert-{index}", "name": f"Alert {index}", "severity": "LOW", "createdAt": TIMESTAMP_T2}
                for index in range(42)
            ],
            "total": 100,
            "limit": 42,
            "offset": 0,
        },
        {
            "alerts": [
                {"id": f"alert-{index}", "name": f"Alert {index}", "severity": "LOW", "createdAt": TIMESTAMP_T2}
                for index in range(42, 92)
            ],
            "total": 100,
            "limit": 50,
            "offset": 42,
        },
        {
            "alerts": [
                {"id": f"alert-{index}", "name": f"Alert {index}", "severity": "LOW", "createdAt": TIMESTAMP_T2}
                for index in range(92, 100)
            ],
            "total": 100,
            "limit": 8,
            "offset": 92,
        },
    ]

    first_run, first_incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )

    assert len(first_incidents) == 50
    assert first_run["alerts_offset"] == 42
    assert first_run["alerts_last_fetch"] == TIMESTAMP_T2
    assert "alert-0" in first_run["alerts_last_ids"]

    second_run, second_incidents = fetch_incidents_command(
        client=mock_client,
        last_run=first_run,
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )

    assert len(second_incidents) == 50
    assert second_run["alerts_offset"] == 92
    assert mock_client.get_alerts.call_args.kwargs["offset"] == 42

    third_run, third_incidents = fetch_incidents_command(
        client=mock_client,
        last_run=second_run,
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )

    assert len(third_incidents) == 8
    assert "alerts_offset" not in third_run
    assert len(first_incidents) + len(second_incidents) + len(third_incidents) == 108


def test_fetch_incidents_command_no_duplicates_across_pagination_runs(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incident_timeline.return_value = {"events": []}
    mock_client.get_incidents.side_effect = [
        {
            "incidents": [
                {"id": f"inc-{index}", "name": f"Inc {index}", "severity": "LOW", "createdAt": TIMESTAMP_T1}
                for index in range(50)
            ],
            "total": 80,
            "limit": 50,
            "offset": 0,
        },
        {
            "incidents": [
                {"id": f"inc-{index}", "name": f"Inc {index}", "severity": "LOW", "createdAt": TIMESTAMP_T1}
                for index in range(50, 80)
            ],
            "total": 80,
            "limit": 30,
            "offset": 50,
        },
        {"incidents": [], "total": 80, "limit": 50, "offset": 0},
    ]
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 50, "offset": 0}

    first_run, first_incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )
    second_run, second_incidents = fetch_incidents_command(
        client=mock_client,
        last_run=first_run,
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )
    third_run, third_incidents = fetch_incidents_command(
        client=mock_client,
        last_run=second_run,
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
        max_fetch=50,
    )

    assert len(first_incidents) == 50
    assert len(second_incidents) == 30
    assert len(third_incidents) == 0
    assert {incident["name"] for incident in first_incidents + second_incidents} == {f"Inc {index}" for index in range(80)}
    assert mock_client.get_incidents.call_count == 3


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
        has_related_incidents=None,
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
        has_related_incidents=None,
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
    mock_client.get_incident_timeline.return_value = {"events": []}
    mock_client.get_alerts.return_value = {"alerts": [], "total": 0, "limit": 200, "offset": 0}

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=False,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
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
        has_related_incidents=None,
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


def test_resolve_has_related_incidents():
    assert resolve_has_related_incidents(["Yes"]) is True
    assert resolve_has_related_incidents(["No"]) is False
    assert resolve_has_related_incidents(["Yes", "No"]) is None
    assert resolve_has_related_incidents([]) is None
    assert resolve_has_related_incidents(None) is None


def test_get_alerts_includes_has_related_incidents_when_set(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query",
        json={"data": {"getAlerts": {"alerts": [], "total": 0}}},
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    client.get_alerts(has_related_incidents=True)

    request_json = requests_mock.request_history[-1].json()
    assert request_json["variables"]["hasRelatedIncidents"] is True


def test_get_alerts_omits_has_related_incidents_when_unset(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query",
        json={"data": {"getAlerts": {"alerts": [], "total": 0}}},
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    client.get_alerts()

    request_json = requests_mock.request_history[-1].json()
    assert "hasRelatedIncidents" not in request_json["variables"]


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


def test_parse_backfill_days_defaults_when_none():
    result = parse_backfill_days(None)
    assert result.endswith("T00:00:00Z")
    parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    assert (today_start - parsed).days == 30


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
    assert alert["verdictReasoning"] == "N/A"
    assert "vegaAlertId" not in alert
    assert set(alert.keys()) == {
        "id",
        "name",
        "vegaEntityType",
        "dataSources",
        "detectionDescription",
        "detectionQuery",
        "verdictReasoning",
    }


def test_format_raw_entity_for_xsoar_alert_preserves_vega_alert_id():
    alert = {
        "id": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
        "vegaAlertId": "VEGA-3409",
        "vegaEntityType": "Vega Alert",
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["id"] == "019e1b27-513c-7dd0-a9ca-db2105bdddc4"
    assert alert["vegaAlertId"] == "VEGA-3409"


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


def test_alert_to_incident_fetches_alert_events_when_client_provided(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [
            {
                "actor.user.uid": "arn:aws:iam::890123456789:root",
                "timeframe": "2026-05-12 00:50:00.000",
            }
        ],
    }
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
    }

    xsoar_incident = alert_to_incident(alert, client=mock_client)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert len(raw["alertEvents"]) == 1
    assert "Alert Events (1)" in xsoar_incident["CustomFields"]["vegaalertevents"]
    assert xsoar_incident["CustomFields"]["vegaalerteventsloadedfor"] == "alert-1"
    assert "_alertEventsCustomFields" not in raw


def test_alert_to_incident_skips_alert_events_when_client_fetch_fails(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.side_effect = DemistoException("Gateway Timeout")
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
    }

    xsoar_incident = alert_to_incident(alert, client=mock_client)

    assert xsoar_incident["CustomFields"]["vegaalerteventsloadedfor"] == "alert-1"
    assert "No alert events found" in xsoar_incident["CustomFields"]["vegaalertevents"]
    assert json.loads(xsoar_incident["rawJSON"])["alertEvents"] == []


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
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "false"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
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
    assert raw["verdictReasoning"] == "N/A"
    assert "vegaAlertId" not in raw
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
        "verdictReasoning",
        "mirror_instance",
        "mirror_direction",
        "mirror_id",
    }
    assert raw["mirror_id"] == "alert:alert-1"
    assert xsoar_incident["dbotMirrorId"] == "alert:alert-1"


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
    assert xsoar_incident["dbotMirrorId"] == "incident:inc-1"
    assert xsoar_incident["CustomFields"]["vegaincidentfindings"]
    assert xsoar_incident["CustomFields"]["vegacreatedat"] == TIMESTAMP_T1
    assert "link" not in raw


def test_is_empty_vega_comment_text():
    assert _is_empty_vega_comment_text(None) is True
    assert _is_empty_vega_comment_text("") is True
    assert _is_empty_vega_comment_text("[{}]") is True
    assert _is_empty_vega_comment_text("[]") is True
    assert _is_empty_vega_comment_text("status to investigation and verdict to benign") is False


def test_format_vega_comments_html_filters_empty_comments():
    comments = [
        {"text": "[{}]", "addedBy": "K3E1sZgbbNR2v3DpC3QCStodL1ay", "addedAt": "2026-06-12T05:01:20.379Z"},
        {
            "text": "status to investigation and verdict to benign",
            "addedBy": "K3E1sZgbbNR2v3DpC3QCStodL1ay",
            "addedAt": "2026-06-12T11:27:06Z",
        },
        {"text": "[{}]", "addedBy": "K3E1sZgbbNR2v3DpC3QCStodL1ay", "addedAt": "2026-06-12T05:00:43.95Z"},
    ]
    html = _format_vega_comments_html(comments)

    assert "status to investigation and verdict to benign" in html
    assert "[{}]" not in html
    assert "background:#000000" in html
    assert "added a comment" in html
    assert "Unknown" in html
    assert "2026-06-12T11:27:06Z" in html


def test_format_raw_entity_for_xsoar_builds_vega_comments_html():
    incident = {
        "id": "inc-1",
        "vegaEntityType": "Vega Incident",
        "comments": [
            {"text": "[{}]", "addedBy": "machine-user", "addedAt": "2026-06-12T05:01:20.379Z"},
            {"text": "Reviewed in XSOAR", "addedBy": "Analyst One", "addedAt": "2026-06-12T11:27:06Z"},
        ],
    }
    _format_raw_entity_for_xsoar(incident)

    assert "vegaComments" in incident
    assert "Reviewed in XSOAR" in incident["vegaComments"]
    assert "[{}]" not in incident["vegaComments"]


def test_format_raw_entity_for_xsoar_builds_vega_alert_comments_html():
    alert = {
        "id": "alert-1",
        "vegaEntityType": "Vega Alert",
        "comments": [
            {"text": "[{}]", "addedBy": "machine-user", "addedAt": "2026-06-12T05:01:20.379Z"},
            {"text": "Escalated for review", "addedBy": "Analyst Two", "addedAt": "2026-06-12T12:00:00Z"},
        ],
    }
    _format_raw_entity_for_xsoar(alert)

    assert "vegaComments" in alert
    assert "Escalated for review" in alert["vegaComments"]
    assert "[{}]" not in alert["vegaComments"]


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
    mock_client.get_incident_timeline.return_value = {
        "events": [
            {
                "id": "evt-1",
                "timestamp": TIMESTAMP_T2,
                "summary": "Timeline summary.",
                "assets": [],
                "observables": [],
                "dataSources": [],
                "alert": None,
            }
        ],
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
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert len(incidents) == 1
    mock_client.get_incident_timeline.assert_called_once_with("inc-1")
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["timelineEvents"][0]["summary"] == "Timeline summary."


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


def test_normalize_verdict_reasoning_null_to_na():
    assert _normalize_verdict_reasoning_for_display({"verdictReasoning": None}) == "N/A"
    assert _normalize_verdict_reasoning_for_display({}) == "N/A"
    assert _normalize_verdict_reasoning_for_display({"verdictReasoning": "   "}) == "N/A"


def test_normalize_verdict_reasoning_displays_string():
    assert _normalize_verdict_reasoning_for_display({"verdictReasoning": "Confirmed malicious activity"}) == (
        "Confirmed malicious activity"
    )


def test_extract_verdict_reasoning_treats_na_placeholder_as_missing():
    assert _extract_verdict_reasoning_from_entity({"verdictReasoning": "N/A"}) is None
    assert _extract_verdict_reasoning_from_entity({"verdictReasoning": "n/a"}) is None
    assert (
        _extract_verdict_reasoning_from_entity(
            {"verdictReasoning": "N/A", "userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"}}
        )
        is None
    )


def test_extract_verdict_reasoning_ignores_user_verdict_and_nested_verdict():
    assert (
        _extract_verdict_reasoning_from_entity({"userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"}}) is None
    )
    assert (
        _extract_verdict_reasoning_from_entity(
            {"verdict": {"value": "SUSPICIOUS", "reasoning": "Multiple failed logins observed"}}
        )
        is None
    )
    assert _extract_verdict_reasoning_from_entity({"incidentSummary": "Incident summary text"}) is None


def test_normalize_verdict_reasoning_from_nested_verdict_dict():
    raw = {"verdict": {"value": "SUSPICIOUS", "reasoning": "Multiple failed logins observed"}}
    assert _normalize_verdict_reasoning_for_display(raw) == "N/A"


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


def test_event_has_bad_alert_events_shape_detects_cid_or_eid():
    assert _event_has_bad_alert_events_shape({"cid": "12345678901234567890123456789012", "eid": "118"}) is True
    assert _event_has_bad_alert_events_shape({"cid": "12345678901234567890123456789012"}) is True
    assert _event_has_bad_alert_events_shape({"eid": "118"}) is True


def test_event_has_bad_alert_events_shape_allows_normal_rows():
    summary_row = {
        "actor.user.uid": "arn:aws:iam::890123456789:root",
        "event_count": "23",
        "unique_events_count": "6",
        "timeframe": "2026-05-12 00:40:00.000",
    }
    parse_field_row = {
        "catalog": "amazoneksaudit",
        "timestamp": "2026-03-25 17:26:18.000",
        "fields": json.dumps({"operation": "create"}),
    }
    assert _event_has_bad_alert_events_shape(summary_row) is False
    assert _event_has_bad_alert_events_shape(parse_field_row) is False
    assert _events_have_bad_alert_events_shape([summary_row, parse_field_row]) is False


def test_events_have_bad_alert_events_shape_when_any_row_has_cid():
    vendor_row = {"cid": "12345678901234567890123456789012", "EventType": "Event_ExternalApiEvent"}
    good_row = {"event_count": "23", "unique_events_count": "6"}
    assert _events_have_bad_alert_events_shape([vendor_row]) is True
    assert _events_have_bad_alert_events_shape([good_row, vendor_row]) is True
    assert _events_have_bad_alert_events_shape([good_row]) is False


def test_format_alert_events_markdown_table_layout():
    actor_arn = "arn:aws:iam::890123456789:root"
    alert_events = [
        {
            "actor.user.uid": actor_arn,
            "event_count": "23",
            "regions_count": "6",
            "timeframe": "2026-05-12 00:40:00.000",
            "unique_events": "[DescribeInstances DescribeVolumes]",
            "unique_events_count": "6",
        }
    ]
    formatted = _format_alert_events_markdown(alert_events, total=16, offset=0, page_size=50)

    assert "Alert Events (16)" in formatted
    assert "actor.user.uid" in formatted
    assert "timeframe" in formatted
    assert "event_count" in formatted
    assert "unique_events_count" in formatted
    assert "regions_count" in formatted
    assert actor_arn in formatted
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


def test_load_current_incident_handles_demisto_incident_failure(mocker):
    mocker.patch("Vega.demisto.incident", side_effect=TypeError("'NoneType' object is not subscriptable"))
    mocker.patch("Vega.demisto.incidents", return_value=[])
    mocker.patch.object(demisto, "debug")

    incident = load_current_incident()

    assert incident == {}


def test_resolve_alert_id_from_incident_uses_raw_json():
    incident = {
        "type": "Vega Alert",
        "CustomFields": {},
        "rawJSON": json.dumps({"id": "alert-raw", "vegaEntityType": "Vega Alert"}),
    }
    assert resolve_alert_id_from_incident({}, incident) == "alert-raw"


def test_resolve_alert_id_from_incident_uses_alertid_custom_field():
    incident = {
        "type": "Vega Alert",
        "CustomFields": {
            "alertid": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
            "vegaalertid": "VEGA-3409",
        },
        "rawJSON": json.dumps({"id": "fallback-id", "vegaEntityType": "Vega Alert"}),
    }
    assert resolve_alert_id_from_incident({}, incident) == "019e1b27-513c-7dd0-a9ca-db2105bdddc4"


def test_resolve_alert_id_from_incident_ignores_display_vegaalertid():
    incident = {
        "type": "Vega Alert",
        "CustomFields": {"vegaalertid": "VEGA-3409"},
        "rawJSON": json.dumps(
            {
                "id": "019e1b27-513c-7dd0-a9ca-db2105bdddc4",
                "vegaAlertId": "VEGA-3409",
                "vegaEntityType": "Vega Alert",
            }
        ),
    }
    assert resolve_alert_id_from_incident({}, incident) == "019e1b27-513c-7dd0-a9ca-db2105bdddc4"


def test_build_vega_alert_custom_fields_sets_mitre_attack_and_alert_id():
    fields = _build_vega_alert_custom_fields({"id": "alert-1", "vegaMitreAttack": "T1059"})
    assert fields["alertid"] == "alert-1"
    assert "vegaalertid" not in fields
    assert fields["vegamitreattack"] == "T1059"


def test_fetch_alert_events_page(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 2,
        "limit": 50,
        "offset": 0,
        "results": [
            {
                "timestamp": "2026-05-12 00:40:00.000",
                "source": "AWS CloudTrail",
                "catalog": "awscloudtrail",
            },
            {
                "timestamp": "2026-05-12 00:50:00.000",
                "source": "AWS CloudTrail",
                "catalog": "awscloudtrail",
            },
        ],
    }

    events, total = fetch_alert_events_page(mock_client, "alert-1", limit=50, offset=0)

    assert total == 2
    assert len(events) == 2
    mock_client.get_alert_events.assert_called_once_with("alert-1", limit=50, offset=0)


def test_fetch_alert_events_for_ingest_returns_not_available_for_bad_shape(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [{"cid": "123", "eid": "118", "Name": "Access from IP with bad reputation"}],
    }

    events, custom_fields = _fetch_alert_events_for_ingest(mock_client, "alert-1")

    assert events == []
    assert "No alert events found" in custom_fields["vegaalertevents"]
    assert custom_fields["vegaalerteventsloadedfor"] == "alert-1"


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
                {
                    "actor.user.uid": "arn:aws:iam::890123456789:root",
                    "event_count": "1",
                    "timeframe": "2026-05-12 00:40:00.000",
                    "unique_events_count": "1",
                },
                {
                    "actor.user.uid": "arn:aws:iam::890123456789:root",
                    "event_count": "2",
                    "timeframe": "2026-05-12 00:50:00.000",
                    "unique_events_count": "2",
                },
            ],
        },
        {
            "total": 3,
            "results": [
                {
                    "actor.user.uid": "arn:aws:iam::890123456789:root",
                    "event_count": "3",
                    "timeframe": "2026-05-12 01:00:00.000",
                    "unique_events_count": "3",
                }
            ],
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
    assert first_page.outputs["HasAlertEvents"] is True
    assert second_page.outputs["Count"] == 1
    assert second_page.outputs["Offset"] == 2
    assert mock_client.get_alert_events.call_count == 4


def test_fetch_alert_events_command_returns_not_available_for_vendor_parse_fields(mocker):
    mocker.patch(
        "Vega.load_current_incident",
        return_value={"CustomFields": {"vegaalertid": "alert-1"}},
    )
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [
            {
                "cid": "12345678901234567890123456789012",
                "eid": "118",
                "Name": "Access from IP with bad reputation",
                "EventType": "Event_ExternalApiEvent",
                "ExternalApiType": "Event_IdpDetectionSummaryEvent",
                "MitreAttack": [{"Tactic": "Initial Access", "TechniqueID": "T1078"}],
                "SourceVendors": "CrowdStrike",
                "SourceProducts": "Falcon Identity Protection",
                "timestamp": 1774165347000,
            }
        ],
    }

    result = fetch_alert_events_command(mock_client, {"alert_id": "alert-1"})

    assert result.readable_output == ALERT_EVENTS_NOT_AVAILABLE_MARKDOWN
    assert result.outputs["Total"] == 0
    assert result.outputs["Count"] == 0
    assert result.outputs["HasAlertEvents"] is False
    assert "does not have alert events" not in result.outputs["CustomFields"]["vegaalertevents"]
    assert "No alert events found" in result.outputs["CustomFields"]["vegaalertevents"]
    mock_client.get_alert_events.assert_called_once()


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

    with pytest.raises(DemistoException, match="At least one of severity, status, state, or tags"):
        update_detections_command(mock_client, {"detection_id": "det-1"})


def test_update_detections_command_with_state_and_tags(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_detections.return_value = {
        "results": [
            {
                "status": "VALID",
                "name": "Detection 1",
                "detection": {
                    "id": "det-1",
                    "name": "Detection 1",
                    "severity": "HIGH",
                    "status": "VISIBLE",
                    "state": "ENABLED",
                    "tags": ["tag-a", "tag-b"],
                },
            }
        ],
        "summary": {"requested": 1, "valid": 1, "invalid": 0, "committed": True},
    }

    result = update_detections_command(
        mock_client,
        {"detection_id": "det-1", "state": "enabled", "tags": ["tag-a", "tag-b"]},
    )

    mock_client.update_detections.assert_called_once_with(
        [{"detectionId": "det-1", "state": "ENABLED", "tags": ["tag-a", "tag-b"]}]
    )
    assert result.outputs["State"] == "ENABLED"
    assert result.outputs["Tags"] == ["tag-a", "tag-b"]


def test_update_detections_command_invalid_state(mocker):
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(DemistoException, match="state must be one of"):
        update_detections_command(mock_client, {"detection_id": "det-1", "state": "INVALID"})


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


def test_client_http_request_retries_on_504(mocker):
    mocker.patch.object(demisto, "debug")
    sleep_mock = mocker.patch("Vega.time.sleep")
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )

    gateway_timeout = DemistoException("Gateway Timeout")
    gateway_timeout.res = mocker.Mock(status_code=504)
    success_response = {"data": {"getAlerts": {"alerts": [], "total": 0}}}

    super_mock = mocker.patch(
        "Vega.BaseClient._http_request",
        side_effect=[gateway_timeout, gateway_timeout, success_response],
    )

    response = client._http_request(method="POST", url_suffix="query", resp_type="json")

    assert response == success_response
    assert super_mock.call_count == 3
    assert sleep_mock.call_args_list[0].args[0] == 2
    assert sleep_mock.call_args_list[1].args[0] == 4


def test_is_retryable_http_error_detects_gateway_timeout():
    exc = DemistoException("Gateway Timeout")
    exc.res = type("Response", (), {"status_code": 504})()

    assert _is_retryable_http_error(exc) is True


def test_fetch_incidents_command_skips_alerts_on_transient_error(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mock_client = mocker.Mock(spec=Client)
    gateway_timeout = DemistoException("Gateway Timeout")
    gateway_timeout.res = mocker.Mock(status_code=504)
    mock_client.get_alerts.side_effect = gateway_timeout
    mock_client.get_incidents.return_value = {
        "incidents": [{"id": "inc-1", "name": "Incident 1", "severity": "HIGH", "createdAt": TIMESTAMP_T1}],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }

    next_run, incidents = fetch_incidents_command(
        client=mock_client,
        last_run={},
        fetch_alerts=True,
        fetch_incidents=True,
        alert_severities=None,
        alert_statuses=None,
        alert_verdicts=None,
        has_related_incidents=None,
        incident_severities=None,
        incident_statuses=None,
        incident_verdicts=None,
        first_fetch_time=FIRST_FETCH_TIME,
    )

    assert len(incidents) == 1
    assert incidents[0]["type"] == "Vega Incident"
    assert "alerts_last_fetch" not in next_run
    assert "incidents_last_fetch" in next_run
    demisto.error.assert_called_once()


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

    update_alert_command(mock_client, {"alert_ids": "alert-1", "status": "IN PROGRESS"})

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


def test_build_effective_alert_update_args_field_change_updates_severity_only():
    effective_args = _build_effective_alert_update_args(
        {"old": "LOW", "new": "HIGH"},
        {"CustomFields": {"vegastatus": "OPEN", "vegaverdict": "NA"}},
    )

    assert effective_args["severity"] == "HIGH"
    assert "status" not in effective_args
    assert "verdict" not in effective_args


def test_build_effective_alert_update_args_field_change_updates_verdict_reasoning_only():
    effective_args = _build_effective_alert_update_args(
        {"old": "Old reasoning", "new": "Confirmed malicious activity"},
        {"CustomFields": {"vegastatus": "OPEN", "vegaverdict": "MALICIOUS"}},
    )

    assert effective_args["verdict_reasoning"] == "Confirmed malicious activity"
    assert "status" not in effective_args
    assert "verdict" not in effective_args


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
        {"alert_ids": ["alert-1", "alert-2"], "status": "RESOLVED", "verdict": "MALICIOUS"},
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


def test_update_alert_command_accepts_comma_separated_alert_ids(mocker):
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

    update_alert_command(
        mock_client,
        {"alert_ids": "alert-1,alert-2", "status": "RESOLVED", "verdict": "MALICIOUS"},
    )

    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1", "alert-2"],
            "status": "RESOLVED",
            "verdict": "MALICIOUS",
        }
    )


def test_update_alert_command_accepts_alert_id_alias(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "status": "OPEN", "verdict": "NA"},
            {"id": "alert-2", "status": "OPEN", "verdict": "NA"},
        ]
    }

    update_alert_command(mock_client, {"alert_id": ["alert-1", "alert-2"], "status": "OPEN"})

    mock_client.update_alerts.assert_called_once_with({"alertIds": ["alert-1", "alert-2"], "status": "OPEN"})


def test_update_incident_command_updates_multiple_incidents(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {
        "incidents": [
            {"incidentId": "inc-1", "status": "RESOLVED", "verdict": "MALICIOUS"},
            {"incidentId": "inc-2", "status": "RESOLVED", "verdict": "MALICIOUS"},
        ]
    }

    result = update_incident_command(
        mock_client,
        {"incident_ids": ["inc-1", "inc-2"], "status": "RESOLVED", "verdict": "MALICIOUS"},
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1", "inc-2"],
            "status": "RESOLVED",
            "verdict": {"value": "MALICIOUS", "reasoning": ""},
        }
    )
    assert result.outputs[0]["id"] == "inc-1"
    assert result.outputs[1]["id"] == "inc-2"
    assert "Updated Vega Incidents" in result.readable_output


def test_update_incident_command_accepts_incident_id_alias(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {
        "incidents": [
            {"incidentId": "inc-1", "status": "INVESTIGATING", "verdict": "SUSPICIOUS"},
            {"incidentId": "inc-2", "status": "INVESTIGATING", "verdict": "SUSPICIOUS"},
        ]
    }

    update_incident_command(
        mock_client,
        {"incident_id": ["inc-1", "inc-2"], "status": "INVESTIGATING", "verdict": "SUSPICIOUS"},
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1", "inc-2"],
            "status": "INVESTIGATING",
            "verdict": {"value": "SUSPICIOUS", "reasoning": ""},
        }
    )


def test_update_alert_command_requires_update_fields(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(
        DemistoException, match="At least one of status, severity, verdict, verdict reasoning, comment, or assignees"
    ):
        update_alert_command(mock_client, {"alert_ids": "alert-1"})


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
            "incident_ids": "inc-1",
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


def test_update_incident_command_comment_only_returns_note(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {"incidents": [{"incidentId": "inc-1"}]}

    result = update_incident_command(mock_client, {"incident_ids": "inc-1", "comment": "test comment 1"})

    mock_client.update_incidents.assert_called_once_with({"incidentIds": ["inc-1"], "comment": "test comment 1"})
    assert result.readable_output == "test comment 1"
    assert result.entry_type == EntryType.NOTE
    assert result.mark_as_note is True


def test_build_comment_war_room_entry_uses_plain_text_note():
    entry = _build_comment_war_room_entry("test comment 2", tags=["From Vega"])

    assert entry["Type"] == EntryType.NOTE
    assert entry["Contents"] == "test comment 2"
    assert entry["ContentsFormat"] == EntryFormat.TEXT
    assert entry["Note"] is True
    assert entry["Tags"] == ["From Vega"]


def test_resolve_incident_id_from_incident_uses_explicit_incident_id():
    incident = {"type": "Vega Incident", "CustomFields": {"vegaincidentid": "inc-from-field"}}
    assert resolve_incident_id_from_incident({"incident_ids": "inc-explicit"}, incident) == "inc-explicit"
    assert resolve_incident_id_from_incident({"incident_id": "inc-legacy"}, incident) == "inc-legacy"


def test_resolve_incident_status_for_update_uses_incident_status_field():
    incident = {"CustomFields": {VEGA_INCIDENT_STATUS_FIELD: "INVESTIGATING"}}
    assert _resolve_incident_status_for_update({}, incident) == "INVESTIGATING"


def test_resolve_incident_status_for_update_falls_back_to_legacy_vegastatus():
    incident = {"CustomFields": {VEGA_ALERT_STATUS_FIELD: "ON HOLD"}}
    assert _resolve_incident_status_for_update({}, incident) == "ON HOLD"


def test_resolve_incident_status_for_update_prefers_vegaincidentstatus():
    incident = {
        "CustomFields": {
            VEGA_INCIDENT_STATUS_FIELD: "UNDER REVIEW",
            VEGA_ALERT_STATUS_FIELD: "OPEN",
        }
    }
    assert _resolve_incident_status_for_update({}, incident) == "UNDER REVIEW"


def test_format_raw_entity_for_xsoar_normalizes_severity():
    incident = {"id": "inc-1", "severity": "high", "vegaEntityType": "Vega Incident"}
    _format_raw_entity_for_xsoar(incident)

    assert incident["severity"] == "HIGH"


def test_normalize_vega_severity_for_display():
    assert _normalize_vega_severity_for_display("medium") == "MEDIUM"
    assert _normalize_vega_severity_for_display(2) == "MEDIUM"
    assert _normalize_vega_severity_for_display("3") == "HIGH"


def test_extract_vega_verdict_from_entity_prefers_user_verdict():
    entity = {
        "verdict": "SUSPICIOUS",
        "userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"},
    }
    assert _extract_vega_verdict_from_entity(entity) == "BENIGN"


def test_build_mirror_sync_object_includes_only_sync_fields():
    incident = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "severity": 2,
        "verdict": "SUSPICIOUS",
        "userVerdict": {"value": "BENIGN"},
        "verdictReasoning": "Confirmed benign",
        "incidentSummary": "Should not mirror",
        "assignee": {"displayName": "Analyst"},
        "comments": [{"text": "note", "addedAt": "2026-06-16T12:00:00Z", "addedBy": "a"}],
    }

    sync_object = _build_mirror_sync_object(incident, MIRROR_ENTITY_SUFFIX_INCIDENT)

    assert sync_object["id"] == "inc-1"
    assert sync_object["mirror_id"] == "incident:inc-1"
    assert "type" not in sync_object
    assert sync_object["vegaEntityType"] == "Vega Incident"
    assert sync_object["severity"] == "MEDIUM"
    assert sync_object["verdict"] == "BENIGN"
    assert sync_object["verdictReasoning"] == "Confirmed benign"
    assert sync_object["status"] == "INVESTIGATING"
    assert sync_object["CustomFields"]["vegaincidentid"] == "inc-1"
    assert sync_object["CustomFields"]["vegaincidentstatus"] == "INVESTIGATING"
    assert sync_object["CustomFields"]["vegaseverity"] == "MEDIUM"
    assert sync_object["CustomFields"]["vegaverdict"] == "BENIGN"
    assert sync_object["CustomFields"]["vegaverdictreasoning"] == "Confirmed benign"
    assert "incidentSummary" not in sync_object
    assert "assignee" not in sync_object
    assert "vegaComments" not in sync_object


def test_resolve_mirror_updated_from_uses_mirror_cursor():
    last_update = (datetime.now(UTC) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    updated_from = _resolve_mirror_updated_from(last_update)
    parsed = datetime.strptime(updated_from, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert parsed <= datetime.now(UTC) - timedelta(minutes=11)


def test_resolve_mirror_updated_to_uses_future_buffer():
    updated_to = _resolve_mirror_updated_to()
    parsed = datetime.strptime(updated_to, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert parsed >= datetime.now(UTC)


def test_entity_updated_after_returns_false_without_timestamp():
    entity = {"status": "OPEN"}
    assert _entity_updated_after(entity, MIRROR_ENTITY_SUFFIX_ALERT, datetime(2026, 6, 15, 11, 0, 0, tzinfo=UTC)) is False


def test_normalize_verdict_reasoning_from_user_verdict():
    raw = {"userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"}}
    assert _normalize_verdict_reasoning_for_display(raw) == "N/A"
    assert _extract_verdict_reasoning_from_entity(raw) is None


def test_build_mirror_sync_object_includes_alert_severity():
    alert = {
        "id": "alert-1",
        "status": "OPEN",
        "severity": "HIGH",
        "verdict": "SUSPICIOUS",
        "verdictReasoning": "Suspicious activity",
    }

    sync_object = _build_mirror_sync_object(alert, MIRROR_ENTITY_SUFFIX_ALERT)

    assert sync_object["id"] == "alert-1"
    assert sync_object["mirror_id"] == "alert:alert-1"
    assert "type" not in sync_object
    assert sync_object["vegaEntityType"] == "Vega Alert"
    assert sync_object["severity"] == "HIGH"
    assert sync_object["verdictReasoning"] == "Suspicious activity"
    assert sync_object["CustomFields"]["alertid"] == "alert-1"
    assert sync_object["CustomFields"]["vegaalertseverity"] == "HIGH"
    assert sync_object["CustomFields"]["vegastatus"] == "OPEN"


def test_build_mirror_sync_object_strips_prefixed_remote_id():
    alert = {
        "id": "019e1b27-5128-7633-9b70-77925a8971ca",
        "status": "OPEN",
        "severity": "HIGH",
    }

    sync_object = _build_mirror_sync_object(
        alert,
        MIRROR_ENTITY_SUFFIX_ALERT,
        remote_id="alert:019e1b27-5128-7633-9b70-77925a8971ca",
    )

    assert sync_object["id"] == "019e1b27-5128-7633-9b70-77925a8971ca"
    assert sync_object["mirror_id"] == "alert:019e1b27-5128-7633-9b70-77925a8971ca"


def test_build_mirror_sync_object_upgrades_legacy_bare_remote_id():
    alert = {
        "id": "alert-1",
        "status": "OPEN",
        "severity": "HIGH",
    }

    sync_object = _build_mirror_sync_object(
        alert,
        MIRROR_ENTITY_SUFFIX_ALERT,
        remote_id="alert-1",
    )

    assert sync_object["id"] == "alert-1"
    assert sync_object["mirror_id"] == "alert:alert-1"
    assert sync_object["CustomFields"]["alertid"] == "alert-1"


def test_build_mirror_sync_object_includes_verdict_reasoning_for_incident():
    incident = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdict": "SUSPICIOUS",
        "verdictReasoning": "Reviewed by analyst",
        "incidentSummary": "Should not mirror",
    }

    sync_object = _build_mirror_sync_object(incident, MIRROR_ENTITY_SUFFIX_INCIDENT)

    assert sync_object["verdict"] == "SUSPICIOUS"
    assert sync_object["verdictReasoning"] == "Reviewed by analyst"


def test_get_remote_data_command_enriches_incident_details(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {"id": "inc-1", "status": "INVESTIGATING"}
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Loaded from details",
    }

    result = get_remote_data_command(
        mock_client,
        {"id": "inc-1", "lastUpdate": "2026-06-15T11:00:00Z", "data": {"type": "Vega Incident"}},
    )

    lookup_filters = _resolve_mirror_incident_lookup_filters("2026-06-15T11:00:00Z")
    mock_client.get_incident_by_id.assert_called_once_with("inc-1", **lookup_filters)
    assert result.mirrored_object["verdictReasoning"] == "Loaded from details"


def test_get_remote_data_command_prefers_incident_detail_reasoning(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Stale list value",
    }
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Updated analyst note",
        "userVerdict": {"value": "BENIGN", "reasoning": "Should not be used"},
    }

    result = get_remote_data_command(
        mock_client,
        {"id": "inc-1", "lastUpdate": "2026-06-15T11:00:00Z", "data": {"type": "Vega Incident"}},
    )

    lookup_filters = _resolve_mirror_incident_lookup_filters("2026-06-15T11:00:00Z")
    mock_client.get_incident_by_id.assert_called_once_with("inc-1", **lookup_filters)
    assert result.mirrored_object["verdictReasoning"] == "Updated analyst note"


def test_resolve_remote_entity_vega_alert_context_skips_incident_lookup(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "name": "Test Alert",
        "status": "OPEN",
        "detectionId": "det-1",
    }

    entity, entity_type_suffix = _resolve_remote_entity(mock_client, "alert-1", "Vega Alert")

    mock_client.get_alert_for_mirror.assert_called_once_with(
        "alert-1",
        **_resolve_mirror_entity_lookup_filters(),
    )
    mock_client.get_alert_by_id.assert_not_called()
    mock_client.get_incident_for_mirror.assert_not_called()
    assert entity["id"] == "alert-1"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT


def test_resolve_remote_entity_falls_back_to_full_get_alerts(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {}
    mock_client.get_alert_by_id.return_value = {
        "id": "019e1b27-511f-7580-a3a6-064c90c35689",
        "status": "OPEN",
        "severity": "HIGH",
    }

    entity, entity_type_suffix = _resolve_remote_entity(
        mock_client,
        "019e1b27-511f-7580-a3a6-064c90c35689",
        "Vega Alert",
    )

    entity_lookup_filters = _resolve_mirror_entity_lookup_filters()
    mock_client.get_alert_for_mirror.assert_called_once_with(
        "019e1b27-511f-7580-a3a6-064c90c35689",
        **entity_lookup_filters,
    )
    mock_client.get_alert_by_id.assert_called_once_with(
        "019e1b27-511f-7580-a3a6-064c90c35689",
        **entity_lookup_filters,
    )
    assert entity["id"] == "019e1b27-511f-7580-a3a6-064c90c35689"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT


def test_entity_matches_remote_id_accepts_vega_alert_id(mocker):
    mocker.patch.object(demisto, "debug")
    entity = {"id": "019e1b27-511f-7580-a3a6-064c90c35689", "vegaAlertId": "VEGA-3409"}

    assert _entity_matches_remote_id(entity, "019e1b27-511f-7580-a3a6-064c90c35689")
    assert _entity_matches_remote_id(entity, "VEGA-3409")
    assert not _entity_matches_remote_id(entity, "missing-id")


def test_get_mirroring_fields_uses_calling_context_fallback(mocker):
    mocker.patch.object(demisto, "integrationInstance", return_value="")
    mocker.patch.object(
        demisto,
        "callingContext",
        {"context": {"IntegrationInstance": "Vega_prod"}},
    )
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})

    fields = _get_mirroring_fields()

    assert fields["mirror_instance"] == "Vega_prod"


def test_build_effective_incident_update_args_field_change_updates_severity_only():
    effective_args = _build_effective_incident_update_args(
        {"old": "LOW", "new": "HIGH"},
        {"CustomFields": {"vegaincidentstatus": "INVESTIGATING"}},
    )

    assert effective_args["severity"] == "HIGH"
    assert "status" not in effective_args


def test_build_effective_incident_update_args_field_change_updates_verdict_reasoning_only():
    effective_args = _build_effective_incident_update_args(
        {"old": "Old reasoning", "new": "Confirmed malicious activity"},
        {"CustomFields": {"vegaincidentstatus": "INVESTIGATING", "vegaverdict": "MALICIOUS"}},
    )

    assert effective_args["verdict_reasoning"] == "Confirmed malicious activity"
    assert effective_args["verdict"] == "MALICIOUS"
    assert "status" not in effective_args


def test_build_direct_incident_update_payload_supports_reasoning_only():
    payload = _build_direct_incident_update_payload({"verdict_reasoning": "Confirmed malicious activity"})

    assert payload["verdict"]["value"] == "NA"
    assert payload["verdict"]["reasoning"] == "Confirmed malicious activity"


def test_build_direct_alert_update_payload_supports_assignees():
    payload = _build_direct_alert_update_payload({"assignees": ["user-1", "user-2"]})

    assert payload == {"assignees": ["user-1", "user-2"]}


def test_build_direct_incident_update_payload_supports_assignee_emails():
    payload = _build_direct_incident_update_payload({"assignee_emails": ["analyst@example.com", "lead@example.com"]})

    assert payload == {"assigneeEmails": ["analyst@example.com", "lead@example.com"]}


def test_update_alert_command_supports_assignees(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_alerts.return_value = {
        "alerts": [
            {
                "id": "alert-1",
                "status": "OPEN",
                "verdict": "NA",
                "assignee": {"email": "analyst@example.com", "displayName": "Analyst"},
            }
        ]
    }

    result = update_alert_command(
        mock_client,
        {"alert_ids": "alert-1", "assignees": ["user-1", "user-2"]},
    )

    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1"],
            "assignees": ["user-1", "user-2"],
        }
    )
    assert result.outputs["assignee"] == "analyst@example.com"


def test_update_incident_command_supports_assignee_emails(mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {
        "incidents": [
            {
                "incidentId": "inc-1",
                "status": "NEW",
                "verdict": "NA",
                "assignee": {"email": "lead@example.com"},
            }
        ]
    }

    result = update_incident_command(
        mock_client,
        {
            "incident_ids": "inc-1",
            "assignee_emails": ["lead@example.com", "analyst@example.com"],
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "assigneeEmails": ["lead@example.com", "analyst@example.com"],
        }
    )
    assert result.outputs["assignee"] == "lead@example.com"


def test_get_mirroring_fields_autoclosure_enabled(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"autoclosure": "true"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    fields = _get_mirroring_fields()

    assert fields["mirror_direction"] == "Both"
    assert fields["mirror_instance"] == "Vega_instance_1"


def test_get_mirroring_fields_autoclosure_disabled(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"autoclosure": "false"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    fields = _get_mirroring_fields()

    assert fields["mirror_direction"] == "In"
    assert fields["mirror_instance"] == "Vega_instance_1"


def test_is_xsoar_to_vega_mirroring_disabled_when_autoclosure_false():
    assert _is_xsoar_to_vega_mirroring_enabled({"autoclosure": "false"}) is False


def test_is_xsoar_to_vega_mirroring_enabled_defaults_true():
    assert _is_xsoar_to_vega_mirroring_enabled({}) is True


def test_collect_outgoing_entry_comments_skips_mirror_tagged_notes():
    entries = [
        {"Type": EntryType.NOTE, "Contents": "Analyst note", "Tags": []},
        {"Type": EntryType.NOTE, "Contents": "From Vega comment", "Tags": [VEGA_MIRROR_TAG_FROM_VEGA]},
        {"Type": EntryType.NOTE, "Contents": "To Vega comment", "Tags": [VEGA_MIRROR_TAG_TO_VEGA]},
    ]

    assert _collect_outgoing_entry_comments(entries) == ["Analyst note"]


def test_resolve_remote_entity_prefers_alert_when_type_context_set(mocker):
    mock_client = mocker.Mock(spec=Client)
    shared_id = "shared-id"
    mock_client.get_alert_for_mirror.return_value = {
        "id": shared_id,
        "vegaAlertId": "VA-shared",
        "name": "Related Alert",
        "status": "OPEN",
        "detectionId": "det-1",
    }
    mock_client.get_incident_for_mirror.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
        "alertsCount": 1,
    }

    entity, entity_type_suffix = _resolve_remote_entity(mock_client, shared_id, "Vega Alert")

    assert entity["detectionId"] == "det-1"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT


def test_poll_entity_is_alert():
    assert _poll_entity_is_alert({"id": "a-1", "vegaAlertId": "VA-1"}) is True
    assert _poll_entity_is_alert({"id": "i-1"}) is False
    assert _poll_entity_is_alert({"id": "a-1", "vegaAlertId": "  "}) is False


def test_mirror_entity_suffix_from_poll_entity():
    assert _mirror_entity_suffix_from_poll_entity({"id": "a-1", "vegaAlertId": "VA-1"}) == MIRROR_ENTITY_SUFFIX_ALERT
    assert _mirror_entity_suffix_from_poll_entity({"id": "i-1"}) == MIRROR_ENTITY_SUFFIX_INCIDENT


def test_get_modified_remote_data_command_skips_ambiguous_shared_bare_id(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": []}}])
    shared_id = "019e1b27-511f-7580-a3a6-03f68cfea577"
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [{"id": shared_id, "vegaAlertId": "VA-123", "updatedAt": "2026-06-15T12:00:00Z"}],
        "total": 1,
    }
    mock_client.get_incidents.return_value = {
        "incidents": [{"id": shared_id, "lastUpdated": "2026-06-15T12:00:00Z"}],
        "total": 1,
    }

    result = get_modified_remote_data_command(
        mock_client,
        {"lastUpdate": "2026-06-01T00:00:00Z"},
    )

    assert set(result.modified_incident_ids) == {
        f"alert:{shared_id}",
        f"incident:{shared_id}",
    }


def test_get_modified_remote_data_command(mocker):
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": []}}])
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "vegaAlertId": "VA-1", "updatedAt": "2026-06-15T12:00:00Z"},
            {"id": "alert-2", "vegaAlertId": "VA-2", "updatedAt": "2026-06-15T12:00:00Z"},
        ],
        "total": 2,
    }
    mock_client.get_incidents.side_effect = DemistoException("incidents unavailable")

    result = get_modified_remote_data_command(
        mock_client,
        {"lastUpdate": "2026-06-01T00:00:00Z"},
    )

    assert mock_client.get_alerts.call_args.kwargs["updated_from"] is not None
    assert "updated_to" not in mock_client.get_alerts.call_args.kwargs
    assert set(result.modified_incident_ids) == {"alert:alert-1", "alert:alert-2", "alert-1", "alert-2"}


def test_get_modified_remote_data_command_respects_entity_filter(mocker):
    mocker.patch.object(demisto, "params", return_value={"vega_entities": ["Alerts"]})
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": []}}])
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [{"id": "alert-1", "vegaAlertId": "VA-1", "updatedAt": "2026-06-15T12:00:00Z"}],
        "total": 1,
    }

    result = get_modified_remote_data_command(
        mock_client,
        {"lastUpdate": "2026-06-01T00:00:00Z"},
    )

    mock_client.get_alerts.assert_called_once()
    assert mock_client.get_alerts.call_args.kwargs["updated_from"] is not None
    assert "updated_to" not in mock_client.get_alerts.call_args.kwargs
    mock_client.get_incidents.assert_not_called()
    assert set(result.modified_incident_ids) == {"alert:alert-1", "alert-1"}


def test_build_incoming_status_sync_entries_does_not_reopen_open_alert():
    entity = {"status": "OPEN", "updatedAt": "2026-06-15T12:00:00Z"}
    entries = _build_incoming_status_sync_entries(entity, MIRROR_ENTITY_SUFFIX_ALERT, datetime(2026, 6, 15, 11, 0, 0, tzinfo=UTC))

    assert entries == []


def test_build_incoming_status_sync_entries_closes_resolved_alert():
    entity = {"status": "RESOLVED", "updatedAt": "2026-06-15T12:00:00Z"}
    entries = _build_incoming_status_sync_entries(entity, MIRROR_ENTITY_SUFFIX_ALERT, datetime(2026, 6, 15, 11, 0, 0, tzinfo=UTC))

    assert len(entries) == 1
    assert entries[0]["Contents"]["dbotIncidentClose"] is True


def test_entity_updated_after_uses_incident_last_updated():
    entity = {"status": "INVESTIGATING", "lastUpdated": "2026-06-15T12:00:00Z"}
    assert _entity_updated_after(entity, MIRROR_ENTITY_SUFFIX_INCIDENT, datetime(2026, 6, 15, 11, 0, 0, tzinfo=UTC))


def test_get_modified_remote_data_command_both_entities(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": []}}])
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "vegaAlertId": "VA-1", "updatedAt": "2026-06-15T12:00:00Z"},
            {"id": "alert-2", "vegaAlertId": "VA-2", "updatedAt": "2026-06-15T12:00:00Z"},
        ],
        "total": 2,
    }
    mock_client.get_incidents.return_value = {
        "incidents": [{"id": "inc-1", "lastUpdated": "2026-06-15T12:00:00Z"}],
        "total": 1,
    }

    result = get_modified_remote_data_command(
        mock_client,
        {"lastUpdate": "2026-06-01T00:00:00Z"},
    )

    assert mock_client.get_alerts.call_args.kwargs["updated_from"] is not None
    assert "updated_to" not in mock_client.get_alerts.call_args.kwargs
    assert mock_client.get_incidents.call_args.kwargs["updated_to"] is not None
    assert set(result.modified_incident_ids) == {
        "alert:alert-1",
        "alert:alert-2",
        "alert-1",
        "alert-2",
        "incident:inc-1",
        "inc-1",
    }


def test_get_remote_data_command_alert_with_comment(mocker):
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "status": "OPEN",
        "verdict": "NA",
        "comments": [
            {
                "text": "Updated in Vega",
                "addedBy": "analyst@example.com",
                "addedAt": "2026-06-15T12:00:00Z",
            }
        ],
    }
    mock_client.get_incident_for_mirror.return_value = {}

    result = get_remote_data_command(
        mock_client,
        {
            "id": "alert-1",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Alert"},
        },
        integration_url="https://api.vega.io",
    )

    assert result.mirrored_object["id"] == "alert-1"
    assert result.mirrored_object["mirror_id"] == "alert:alert-1"
    assert "type" not in result.mirrored_object
    assert result.mirrored_object["vegaEntityType"] == "Vega Alert"
    assert result.mirrored_object["CustomFields"]["alertid"] == "alert-1"
    assert len(result.entries) >= 1
    assert result.entries[0]["Contents"].startswith("analyst@example.com")
    assert result.entries[0]["Tags"] == [VEGA_MIRROR_TAG_FROM_VEGA]


def test_get_remote_data_command_vega_alert_context_skips_incident_lookup(mocker):
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "status": "OPEN",
        "verdict": "BENIGN",
        "verdictReasoning": "Confirmed benign",
        "updatedAt": "2026-06-15T12:00:00Z",
        "comments": [],
    }

    result = get_remote_data_command(
        mock_client,
        {
            "id": "alert:alert-1",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Alert"},
        },
    )

    mock_client.get_alert_for_mirror.assert_called_once_with(
        "alert-1",
        **_resolve_mirror_entity_lookup_filters(),
    )
    mock_client.get_incident_for_mirror.assert_not_called()
    assert result.mirrored_object["id"] == "alert-1"
    assert result.mirrored_object["mirror_id"] == "alert:alert-1"
    assert "type" not in result.mirrored_object
    assert result.mirrored_object["vegaEntityType"] == "Vega Alert"
    assert result.mirrored_object["mirror_instance"] == "Vega_instance_1"
    assert result.mirrored_object["CustomFields"]["alertid"] == "alert-1"
    assert result.mirrored_object["severity"] == "HIGH"
    assert result.mirrored_object["verdictReasoning"] == "Confirmed benign"
    assert result.mirrored_object["CustomFields"]["vegaalertseverity"] == "HIGH"
    assert result.mirrored_object["CustomFields"]["vegastatus"] == "OPEN"


def test_get_remote_data_command_uses_investigation_context_for_bare_alert_id(mocker):
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "019e1b27-511f-7580-a3a6-063a06c73ecb",
        "name": "Test Alert",
        "severity": "HIGH",
        "status": "OPEN",
        "verdict": "BENIGN",
        "updatedAt": "2026-06-15T12:00:00Z",
        "comments": [],
    }

    result = get_remote_data_command(
        mock_client,
        {
            "id": "019e1b27-511f-7580-a3a6-063a06c73ecb",
            "lastUpdate": "2026-06-15T11:00:00Z",
        },
    )

    mock_client.get_alert_for_mirror.assert_called_once_with(
        "019e1b27-511f-7580-a3a6-063a06c73ecb",
        **_resolve_mirror_entity_lookup_filters(),
    )
    mock_client.get_incident_for_mirror.assert_not_called()
    assert result.mirrored_object["vegaEntityType"] == "Vega Alert"


def test_get_remote_data_command_enforces_incident_type_for_shared_id(mocker):
    """When alert and incident share a UUID, keep Vega Incident investigations on the incident path."""
    mocker.patch.object(demisto, "debug")
    mocker.patch(
        "Vega.load_current_incident",
        return_value={
            "type": "Vega Incident",
            "CustomFields": {"vegaincidentid": "019e1b27-6d49-7ea1-a9d2-f30bf8c69165"},
        },
    )
    shared_id = "019e1b27-6d49-7ea1-a9d2-f30bf8c69165"
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": shared_id,
        "name": "Related Alert",
        "status": "OPEN",
    }
    mock_client.get_incident_for_mirror.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
    }
    mock_client.get_incident_by_id.return_value = {
        "id": shared_id,
        "status": "INVESTIGATING",
        "verdictReasoning": "Confirmed benign",
    }

    result = get_remote_data_command(
        mock_client,
        {"id": shared_id, "lastUpdate": "2026-06-15T11:00:00Z"},
    )

    mock_client.get_alert_for_mirror.assert_not_called()
    assert "type" not in result.mirrored_object
    assert result.mirrored_object["vegaEntityType"] == "Vega Incident"
    assert result.mirrored_object["CustomFields"]["vegaincidentid"] == shared_id
    assert "alertid" not in result.mirrored_object["CustomFields"]
    assert result.mirrored_object["CustomFields"]["vegaincidentstatus"] == "INVESTIGATING"


def test_resolve_remote_entity_prefers_alert_when_both_match_without_context(mocker):
    mock_client = mocker.Mock(spec=Client)
    shared_id = "019e1b27-6d48-7f30-8932-f1d3596141ef"
    mock_client.get_alert_for_mirror.return_value = {
        "id": shared_id,
        "vegaAlertId": "VA-shared",
        "name": "Related Alert",
        "status": "OPEN",
        "detectionId": "det-1",
    }
    mock_client.get_incident_for_mirror.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
        "alertsCount": 2,
    }

    entity, entity_type_suffix = _resolve_remote_entity(mock_client, shared_id)

    assert entity["name"] == "Related Alert"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT


def test_resolve_remote_entity_prefers_incident_when_both_match(mocker):
    mock_client = mocker.Mock(spec=Client)
    shared_id = "019e1b27-6d48-7f30-8932-f1d3596141ef"
    mock_client.get_alert_for_mirror.return_value = {
        "id": shared_id,
        "vegaAlertId": "VA-shared",
        "name": "Related Alert",
        "status": "OPEN",
        "detectionId": "det-1",
    }
    mock_client.get_incident_for_mirror.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
        "alertsCount": 2,
    }

    entity, entity_type_suffix = _resolve_remote_entity(mock_client, shared_id, "Vega Incident")

    assert entity["name"] == "Vega Incident"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT


def test_resolve_remote_entity_ignores_mismatched_alert_payload(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "different-alert-id", "detectionId": "det-1"}
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
    }

    entity, entity_type_suffix = _resolve_remote_entity(mock_client, "inc-1")

    assert entity["id"] == "inc-1"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT


def test_get_remote_data_command_preserves_incident_type_context(mocker):
    mock_client = mocker.Mock(spec=Client)
    shared_id = "019e1b27-6d48-7f30-8932-f1d3596141ef"
    mock_client.get_incident_for_mirror.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
        "alertsCount": 1,
        "comments": [],
        "verdictReasoning": "Confirmed benign",
    }
    mock_client.get_incident_by_id.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
        "alertsCount": 1,
        "comments": [],
        "verdictReasoning": "Confirmed benign",
    }

    result = get_remote_data_command(
        mock_client,
        {
            "id": f"incident:{shared_id}",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Incident"},
        },
        integration_url="https://api.vega.io",
    )

    assert result.mirrored_object["id"] == shared_id
    assert "type" not in result.mirrored_object
    assert result.mirrored_object["vegaEntityType"] == "Vega Incident"
    assert result.mirrored_object["mirror_id"] == f"incident:{shared_id}"
    assert result.mirrored_object["CustomFields"]["vegaincidentid"] == shared_id
    assert result.mirrored_object["status"] == "INVESTIGATING"
    assert result.mirrored_object["CustomFields"]["vegaincidentstatus"] == "INVESTIGATING"
    assert result.mirrored_object["CustomFields"]["vegaverdictreasoning"] == "Confirmed benign"
    assert "detectionId" not in result.mirrored_object
    assert "incidentSummary" not in result.mirrored_object


def test_get_remote_data_command_preserves_incident_type_with_bare_id(mocker):
    mock_client = mocker.Mock(spec=Client)
    shared_id = "019e1b27-6d48-7f30-8932-f1d3596141ef"
    mock_client.get_incident_for_mirror.return_value = {
        "id": shared_id,
        "name": "Vega Incident",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
        "comments": [],
    }
    mock_client.get_incident_by_id.return_value = {
        "id": shared_id,
        "status": "INVESTIGATING",
        "verdictReasoning": "Confirmed benign",
    }

    result = get_remote_data_command(
        mock_client,
        {
            "id": shared_id,
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Incident", "CustomFields": {"vegaincidentid": shared_id}},
        },
    )

    mock_client.get_alert_for_mirror.assert_not_called()
    assert "type" not in result.mirrored_object
    assert result.mirrored_object["vegaEntityType"] == "Vega Incident"
    assert result.mirrored_object["CustomFields"]["vegaincidentstatus"] == "INVESTIGATING"


def test_resolve_remote_entity_uses_prefixed_incident_id(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "lastUpdated": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
    }

    entity, entity_type_suffix = _resolve_remote_entity(
        mock_client,
        "incident:inc-1",
        mirror_last_update="2026-06-15T11:00:00Z",
    )

    mock_client.get_alert_for_mirror.assert_not_called()
    mock_client.get_incident_for_mirror.assert_called_once()
    assert mock_client.get_incident_for_mirror.call_args.args[0] == "inc-1"
    lookup_filters = mock_client.get_incident_for_mirror.call_args.kwargs
    assert lookup_filters == _resolve_mirror_entity_lookup_filters()
    assert entity["id"] == "inc-1"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT


def test_normalize_incident_api_entity_uses_incident_id():
    normalized = _normalize_incident_api_entity(
        {
            "incidentId": "019e1b27-6d49-7ea1-a9d2-f30bf8c69165",
            "lastUpdate": "2026-06-16T12:00:00Z",
            "alertCount": 3,
        }
    )

    assert normalized["id"] == "019e1b27-6d49-7ea1-a9d2-f30bf8c69165"
    assert normalized["lastUpdated"] == "2026-06-16T12:00:00Z"
    assert normalized["alertsCount"] == 3


def test_get_incident_by_id_returns_empty_when_not_found(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mocker.patch.object(client, "get_incidents", return_value={"incidents": [], "total": 0})

    incident = client.get_incident_by_id("inc-1")

    assert incident == {}


def test_get_alert_for_mirror_uses_lightweight_query(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mock_graphql = mocker.patch.object(
        client,
        "_graphql_request",
        return_value={
            "data": {
                "getAlerts": {
                    "alerts": [{"id": "alert-1", "status": "OPEN", "updatedAt": "2026-06-15T12:00:00Z"}],
                    "total": 1,
                }
            }
        },
    )

    alert = client.get_alert_for_mirror("alert-1")

    assert alert["id"] == "alert-1"
    mock_graphql.assert_called_once()
    assert mock_graphql.call_args.args[0] == GET_ALERT_MIRROR_QUERY
    assert mock_graphql.call_args.args[1] == {"alertIds": ["alert-1"], "limit": 1, "offset": 0}


def test_get_alert_for_mirror_passes_from_time_filter(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mock_graphql = mocker.patch.object(
        client,
        "_graphql_request",
        return_value={
            "data": {
                "getAlerts": {
                    "alerts": [{"id": "alert-1", "status": "OPEN", "updatedAt": "2026-06-15T12:00:00Z"}],
                    "total": 1,
                }
            }
        },
    )

    alert = client.get_alert_for_mirror("alert-1", from_time="2026-06-01T00:00:00Z")

    assert alert["id"] == "alert-1"
    assert mock_graphql.call_args.args[1] == {
        "alertIds": ["alert-1"],
        "from": "2026-06-01T00:00:00Z",
        "limit": 1,
        "offset": 0,
    }


def test_resolve_remote_entity_alert_uses_lookup_filters(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "status": "OPEN",
        "updatedAt": "2026-06-15T12:00:00Z",
    }

    entity, entity_type_suffix = _resolve_remote_entity(
        mock_client,
        "alert:alert-1",
        mirror_last_update="2026-06-15T11:00:00Z",
    )

    mock_client.get_incident_for_mirror.assert_not_called()
    assert mock_client.get_alert_for_mirror.call_args.args[0] == "alert-1"
    assert mock_client.get_alert_for_mirror.call_args.kwargs == _resolve_mirror_entity_lookup_filters()
    assert entity["id"] == "alert-1"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_ALERT


def test_normalize_mirror_field_value_prefers_new_value():
    assert _normalize_mirror_field_value({"old": "OPEN", "new": "RESOLVED"}) == "RESOLVED"


def test_mirror_field_value_reads_old_new_delta_from_custom_fields():
    value = _mirror_field_value(
        VEGA_ALERT_STATUS_FIELD,
        {"CustomFields": {VEGA_ALERT_STATUS_FIELD: {"old": "OPEN", "new": "RESOLVED"}}},
        {},
    )

    assert value == "RESOLVED"


def test_update_remote_system_command_updates_alert_from_old_new_delta(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "alert-1", "status": "OPEN"}

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert:alert-1",
            "incidentChanged": "true",
            "delta": {"CustomFields": {VEGA_ALERT_STATUS_FIELD: {"old": "OPEN", "new": "RESOLVED"}}},
            "data": {"type": "Vega Alert", "CustomFields": {VEGA_ALERT_STATUS_FIELD: "OPEN"}},
        },
    )

    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1"],
            "status": "RESOLVED",
        }
    )


def test_get_incident_for_mirror_uses_lightweight_query(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mock_graphql = mocker.patch.object(
        client,
        "_graphql_request",
        return_value={
            "data": {
                "getIncidents": {
                    "incidents": [{"id": "inc-1", "status": "INVESTIGATING", "lastUpdated": "2026-06-15T12:00:00Z"}],
                    "total": 1,
                }
            }
        },
    )

    incident = client.get_incident_for_mirror("inc-1")

    assert incident["id"] == "inc-1"
    mock_graphql.assert_called_once()
    assert mock_graphql.call_args.args[0] == GET_INCIDENT_MIRROR_QUERY
    assert mock_graphql.call_args.args[1] == {"incidentIds": ["inc-1"], "limit": 1, "offset": 0}


def test_get_incident_for_mirror_passes_lookup_time_filters(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mock_graphql = mocker.patch.object(
        client,
        "_graphql_request",
        return_value={
            "data": {
                "getIncidents": {
                    "incidents": [{"id": "inc-1", "status": "INVESTIGATING", "lastUpdated": "2026-06-15T12:00:00Z"}],
                    "total": 1,
                }
            }
        },
    )

    incident = client.get_incident_for_mirror("inc-1", from_time="2026-06-15T10:00:00Z")

    assert incident["id"] == "inc-1"
    mock_graphql.assert_called_once()
    assert mock_graphql.call_args.args[0] == GET_INCIDENT_MIRROR_QUERY
    assert mock_graphql.call_args.args[1] == {
        "incidentIds": ["inc-1"],
        "limit": 1,
        "offset": 0,
        "from": "2026-06-15T10:00:00Z",
    }


def test_get_remote_data_command_passes_last_update_to_incident_lookup(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {"id": "inc-1", "status": "INVESTIGATING"}
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Loaded from details",
    }

    get_remote_data_command(
        mock_client,
        {"id": "incident:inc-1", "lastUpdate": "2026-06-15T11:00:00Z", "data": {"type": "Vega Incident"}},
    )

    entity_lookup_filters = _resolve_mirror_entity_lookup_filters()
    detail_lookup_filters = _resolve_mirror_incident_lookup_filters("2026-06-15T11:00:00Z")
    mock_client.get_incident_for_mirror.assert_called_once_with("inc-1", **entity_lookup_filters)
    mock_client.get_incident_by_id.assert_called_once_with("inc-1", **detail_lookup_filters)


def test_suppress_noisy_http_integration_logs_filters_header_lines(mocker):
    import http.client as http_client

    mocker.patch("Vega.is_debug_mode", return_value=True)
    captured: list[str] = []
    integration_logger_write = LOG.write
    had_filter_flag = getattr(LOG, "_vega_http_log_filter_installed", False)

    def capture_write(msg):
        text = msg.decode(LOG.encoding) if isinstance(msg, bytes) else str(msg)
        captured.append(text)
        integration_logger_write(msg)

    LOG.write = capture_write
    LOG._vega_http_log_filter_installed = False

    try:
        _suppress_noisy_http_integration_logs()

        LOG.write("header: X-Amz-Cf-Pop: MRS52-P5\n")
        LOG.write("Vega mirror | stage=resolve-entity | lookup completed\n")

        assert captured == ["Vega mirror | stage=resolve-entity | lookup completed\n"]
        assert http_client.HTTPConnection.debuglevel == 0
    finally:
        LOG.write = integration_logger_write
        LOG._vega_http_log_filter_installed = had_filter_flag


def test_get_remote_data_command_not_found_preserves_incident_type(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {}
    mock_client.get_incident_by_id.return_value = {}

    result = get_remote_data_command(
        mock_client,
        {"id": "incident:019e1b27-6d49-7ea1-a9d2-f30bf8c69165", "lastUpdate": "2026-06-15T11:00:00Z"},
    )

    assert result.mirrored_object["vegaEntityType"] == "Vega Incident"
    assert result.mirrored_object["id"] == "019e1b27-6d49-7ea1-a9d2-f30bf8c69165"
    assert result.mirrored_object["mirror_id"] == "incident:019e1b27-6d49-7ea1-a9d2-f30bf8c69165"


def test_resolve_remote_entity_accepts_incident_id_field(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "incidentId": "inc-1",
        "status": "INVESTIGATING",
        "lastUpdate": "2026-06-16T12:00:00Z",
        "incidentSummary": "Summary",
    }

    entity, entity_type_suffix = _resolve_remote_entity(mock_client, "incident:inc-1")

    mock_client.get_alert_for_mirror.assert_not_called()
    assert entity["id"] == "inc-1"
    assert entity_type_suffix == MIRROR_ENTITY_SUFFIX_INCIDENT


def test_entity_type_from_mirror_payload_prefers_vegaincidentid_over_wrong_type():
    payload = {
        "type": "Vega Alert",
        "CustomFields": {"vegaincidentid": "inc-1"},
    }
    assert _entity_type_from_mirror_payload(payload) == "Vega Incident"


def test_mirror_entity_type_from_args():
    assert _mirror_entity_type_from_args({"data": {"type": "Vega Incident"}}, "inc-1") == "Vega Incident"


def test_entity_type_from_field_keys_prefers_incident_when_both_present():
    payload = {
        "CustomFields": {
            "vegaincidentid": "inc-1",
            "alertid": "alert-1",
        }
    }
    assert _entity_type_from_field_keys(payload) == "Vega Incident"
    assert _mirror_entity_type_from_args({"data": json.dumps({"Type": "Vega Alert"})}, "alert-1") == "Vega Alert"
    assert _mirror_entity_type_from_args({"id": "alert:alert-1"}, "alert:alert-1") == "Vega Alert"
    assert _mirror_entity_type_from_args({"id": "incident:inc-1"}, "incident:inc-1") == "Vega Incident"
    assert _mirror_entity_type_from_args({"delta": {"vegaincidentstatus": "INVESTIGATING"}}, "inc-1") == "Vega Incident"
    assert _mirror_entity_type_from_args({"delta": {"vegastatus": "OPEN"}}, "alert-1") == "Vega Alert"


def test_mirror_entity_type_from_args_parses_raw_json_from_data():
    raw = {"id": "alert-1", "vegaEntityType": "Vega Alert"}
    assert _mirror_entity_type_from_args({"data": {"rawJSON": json.dumps(raw)}}, "alert-1") == "Vega Alert"


def test_mirror_entity_type_from_args_parses_custom_fields_from_data():
    assert _mirror_entity_type_from_args({"data": {"CustomFields": {"vegaincidentid": "inc-1"}}}, "inc-1") == "Vega Incident"
    assert _mirror_entity_type_from_args({"data": {"CustomFields": {"alertid": "alert-1"}}}, "alert-1") == "Vega Alert"


def test_mirror_entity_type_from_args_skips_investigation_context_when_disabled(mocker):
    load_current_incident = mocker.patch("Vega.load_current_incident")
    remote_id = "019e1b27-511f-7580-a3a6-063a06c73ecb"

    assert _mirror_entity_type_from_args({"id": remote_id}, remote_id, use_investigation_context=False) is None

    load_current_incident.assert_not_called()


def test_mirror_entity_type_from_args_uses_investigation_context(mocker):
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")

    assert (
        _mirror_entity_type_from_args({"id": "019e1b27-511f-7580-a3a6-063a06c73ecb"}, "019e1b27-511f-7580-a3a6-063a06c73ecb")
        == "Vega Alert"
    )


def test_update_remote_system_command_disabled(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "false"})
    mock_client = mocker.Mock(spec=Client)

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert-1",
            "incidentChanged": "true",
            "delta": {"vegastatus": "RESOLVED"},
            "data": {"vegastatus": "RESOLVED"},
        },
    )

    assert remote_id == "alert-1"
    mock_client.update_alerts.assert_not_called()


def test_update_remote_system_command_updates_alert_severity(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "alert-1", "status": "OPEN", "severity": "LOW"}
    mock_client.get_incident_for_mirror.return_value = {}

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert:alert-1",
            "incidentChanged": "true",
            "delta": {"vegaalertseverity": "CRITICAL"},
            "data": {"vegaalertseverity": "CRITICAL"},
        },
    )

    assert remote_id == "alert:alert-1"
    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1"],
            "severity": "CRITICAL",
        }
    )


def test_update_remote_system_command_updates_alert(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "alert-1", "status": "OPEN"}
    mock_client.get_incident_for_mirror.return_value = {}

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert-1",
            "incidentChanged": "true",
            "delta": {"vegaverdict": "MALICIOUS", "vegaverdictreasoning": "Confirmed"},
            "data": {
                "type": "Vega Alert",
                "vegaverdict": "MALICIOUS",
                "vegaverdictreasoning": "Confirmed",
            },
        },
    )

    assert remote_id == "alert-1"
    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1"],
            "verdict": "MALICIOUS",
            "verdictReasoning": "Confirmed",
        }
    )


def test_update_remote_system_command_pushes_new_comment(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "alert-1", "status": "OPEN"}
    mock_client.get_incident_for_mirror.return_value = {}

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert-1",
            "incidentChanged": "true",
            "delta": {VEGA_NEW_COMMENT_FIELD: "Reviewed in XSOAR"},
            "data": {"type": "Vega Alert", VEGA_NEW_COMMENT_FIELD: "Reviewed in XSOAR"},
        },
    )

    mock_client.update_alerts.assert_called_once_with({"alertIds": ["alert-1"], "comment": "Reviewed in XSOAR"})


def test_update_remote_system_command_updates_incident_from_custom_fields_delta(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "severity": "HIGH",
    }

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "incident:inc-1",
            "incidentChanged": "true",
            "delta": {"CustomFields": {"vegaincidentstatus": "UNDER REVIEW", "vegaverdict": "BENIGN"}},
            "data": {
                "type": "Vega Incident",
                "CustomFields": {
                    "vegaincidentstatus": "UNDER REVIEW",
                    "vegaverdict": "BENIGN",
                },
            },
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "status": "UNDER_REVIEW",
            "verdict": {"value": "BENIGN", "reasoning": ""},
        }
    )


def test_alert_to_incident_sets_mirror_metadata(mocker):
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
    }
    xsoar_incident = alert_to_incident(alert)

    assert xsoar_incident["dbotMirrorId"] == "alert:alert-1"
    assert xsoar_incident["dbotMirrorDirection"] == "Both"
    assert xsoar_incident["dbotMirrorInstance"] == "Vega_instance_1"


def test_get_alert_by_id_handles_null_get_alerts_response(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mocker.patch.object(client, "get_alerts", return_value=None)

    assert client.get_alert_by_id("alert-1") == {}


def test_update_alerts_handles_null_graphql_data(mocker):
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    mocker.patch.object(
        client,
        "_graphql_request",
        return_value={"data": None, "errors": [{"message": "Alert update failed"}]},
    )

    with pytest.raises(DemistoException, match="Alert update failed"):
        client.update_alerts({"alertIds": ["alert-1"], "status": "OPEN"})


def test_update_remote_system_command_surfaces_api_error_instead_of_none_type(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "019e1b27-511f-7580-a3a6-065e9e623a1a", "status": "OPEN"}
    mock_client.update_alerts.side_effect = DemistoException("Vega API error updating alerts: Alert update failed")

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "019e1b27-511f-7580-a3a6-065e9e623a1a",
            "incidentChanged": "true",
            "delta": {"vegastatus": "RESOLVED"},
            "data": {"type": "Vega Alert", "vegastatus": "RESOLVED"},
        },
    )

    assert remote_id == "019e1b27-511f-7580-a3a6-065e9e623a1a"
    mock_client.update_alerts.assert_called_once()


def test_update_remote_system_command_updates_incident_from_delta_status_field(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch("Vega.load_current_incident", return_value={})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "severity": "HIGH",
    }

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "inc-1",
            "incidentChanged": "true",
            "delta": {"vegaincidentstatus": "UNDER REVIEW"},
            "data": {"CustomFields": {"vegaincidentstatus": "INVESTIGATING"}},
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "status": "UNDER_REVIEW",
        }
    )
    mock_client.update_alerts.assert_not_called()


def test_update_remote_system_command_uses_api_fallback_without_investigation_context(mocker):
    mocker.patch.object(demisto, "params", return_value={"autoclosure": "true"})
    mocker.patch("Vega.demisto.incident", side_effect=TypeError("'NoneType' object is not subscriptable"))
    load_current_incident = mocker.patch("Vega.load_current_incident")
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "019e1b27-5128-7633-9b70-782afb20f198", "status": "OPEN"}
    mock_client.get_incident_for_mirror.return_value = {}

    remote_id = update_remote_system_command(
        mock_client,
        {
            "remoteId": "019e1b27-5128-7633-9b70-782afb20f198",
            "incidentChanged": "true",
            "delta": {"vegastatus": "RESOLVED"},
            "data": {"vegastatus": "RESOLVED"},
        },
    )

    assert remote_id == "019e1b27-5128-7633-9b70-782afb20f198"
    load_current_incident.assert_not_called()
    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["019e1b27-5128-7633-9b70-782afb20f198"],
            "status": "RESOLVED",
        }
    )


def test_get_mapping_fields_command():
    response = get_mapping_fields_command()

    assert len(response.scheme_types_mappings) == 2
    scheme_names = {scheme.type_name for scheme in response.scheme_types_mappings}
    assert scheme_names == {"Vega Alert", "Vega Incident"}
