import json
from datetime import datetime, timedelta, UTC

import requests

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pytest

from Vega import (
    _alert_events_command_results,
    _enrich_alert_event,
    _enrich_alert_events,
    _event_has_bad_alert_events_shape,
    _events_have_bad_alert_events_shape,
    _expand_flat_raw_fields,
    _format_alert_events_markdown,
    _format_mitre_attack,
    _promote_raw_into_alert_event_fields,
    Client,
    GET_ALERT_MIRROR_QUERY,
    GET_INCIDENT_MIRROR_QUERY,
    _suppress_noisy_http_integration_logs,
    _build_fetch_filter_fingerprint,
    _build_vega_alert_custom_fields,
    _build_vega_incident_custom_fields,
    _fetch_paginated_entities,
    _is_retryable_http_error,
    _format_key_findings_html,
    _format_raw_entity_for_xsoar,
    _format_recommended_actions_for_grid,
    VEGA_NO_RECOMMENDED_ACTIONS_DISPLAY,
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
    VEGA_ALERT_SEVERITY_FIELD,
    VEGA_VERDICT_FIELD,
    VEGA_INCIDENT_STATUS_FIELD,
    _normalize_vega_status_for_display,
    _normalize_verdict_reasoning_for_display,
    _extract_verdict_reasoning_from_entity,
    _mirror_entity_type_from_args,
    _entity_type_from_field_keys,
    _entity_type_from_mirror_payload,
    _parse_alert_events_results,
    _resolve_fetch_from_time,
    alert_to_incident,
    build_alert_events_custom_fields,
    fetch_alert_events_command,
    get_alert_metadata_command,
    fetch_alert_events_page,
    fetch_incidents_command,
    _fetch_alert_events_for_ids,
    _fetch_alert_events_for_ingest,
    set_detections_state_command,
    update_detections_command,
    incident_to_xsoar_incident,
    _enrich_incident_alerts,
    parse_backfill_days,
    load_current_incident,
    resolve_alert_id_from_incident,
    resolve_incident_id_from_incident,
    INCIDENT_ID_LOOKUP_FROM_TIME,
    update_alert_command,
    update_incident_command,
    _build_comment_war_room_entry,
    _configured_mirror_direction,
    _get_mirroring_fields,
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
    _mirror_field_changed_in_delta,
    _build_outgoing_alert_mirror_update,
    _collect_outgoing_entry_comments,
    _outgoing_mirror_comment_value,
    VEGA_NEW_COMMENT_FIELD,
    VEGA_NEW_COMMENT_LAYOUT_DEFAULT,
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
    filter_incident_investigation_statuses,
    filter_incident_verdicts,
    _build_incidents_query_variables,
    resolve_has_related_incidents,
    TEST_CONNECTION_ACCESS_KEY_ERROR,
    TEST_CONNECTION_ACCESS_KEY_ID_ERROR,
    TEST_CONNECTION_BASE_URL_ERROR,
    TEST_CONNECTION_URL_ERROR,
    test_module as vega_test_module,
    main as vega_main,
    GET_ALERT_IDS_QUERY,
    GET_INCIDENT_IDS_QUERY,
    RECONCILE_PAGE_SIZE,
    RECONCILE_COMPLETED_INCIDENTS_KEY,
    RECONCILE_COMPLETED_ALERTS_KEY,
    RECONCILE_NOT_FOUND_ALERTS_KEY,
    RECONCILE_NOT_FOUND_INCIDENTS_KEY,
    _parse_comma_separated_ids,
    _parse_reconcile_window,
    _collect_paged_ids,
    _collect_xsoar_entity_ids,
    _normalize_entity_id,
    _xsoar_vega_entity_id,
    reconcile_incidents_command,
    fetch_reconciliation_incidents_command,
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
        f"{BASE_URL}/api/v1/query",
        json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["security admin"]}}},
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5) == "ok"


def test_test_module_unauthorized(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")

    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query",
        json={"data": {"getAccessKey": {"id": "mock-key-id", "roles": ["Viewer"]}}},
    )

    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    assert (
        vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5)
        == "You do not have required access to fetch incidents."
    )


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5).startswith(
        TEST_CONNECTION_ACCESS_KEY_ID_ERROR
    )


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5) == TEST_CONNECTION_ACCESS_KEY_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5) == TEST_CONNECTION_URL_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5) == TEST_CONNECTION_BASE_URL_ERROR


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
    assert vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=5) == TEST_CONNECTION_BASE_URL_ERROR


def test_main_test_module_requires_backfill_days(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "access_key": {"password": "key"},
            "access_key_id": {"password": "id"},
            "url": BASE_URL,
            "vega_entities": ["Alerts", "Incidents"],
            "max_fetch": "50",
            "lookback_minutes": "5",
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
            "access_key": {"password": "key"},
            "access_key_id": {"password": "id"},
            "url": BASE_URL,
            "vega_entities": ["Alerts", "Incidents"],
            "backfill_days": "30",
            "max_fetch": "100",
            "lookback_minutes": "5",
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

    assert vega_test_module(client, backfill_days=30, max_fetch=0, lookback_minutes=5) == MAX_FETCH_ERROR
    assert vega_test_module(client, backfill_days=30, max_fetch=100, lookback_minutes=5) == MAX_FETCH_ERROR
    assert vega_test_module(client, backfill_days=30, max_fetch="abc", lookback_minutes=5) == 'Invalid number: "max_fetch"="abc"'


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


def test_normalize_entity_id_coerces_numeric_ids():
    assert _normalize_entity_id({"id": 12345}) == "12345"
    assert _normalize_entity_id({"id": "12345"}) == "12345"


def test_fetch_incidents_command_dedup_numeric_id_at_boundary(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    numeric_id = 987654321
    mock_client.get_alerts.return_value = {
        "alerts": [
            {
                "id": numeric_id,
                "name": "Numeric ID Alert",
                "severity": "LOW",
                "createdAt": TIMESTAMP_T1,
            },
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incidents.return_value = {
        "incidents": [],
        "total": 0,
        "limit": 200,
        "offset": 0,
    }

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

    results, next_offset, api_total = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 2
    assert next_offset is None
    assert api_total == 2
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

    results, next_offset, api_total = _fetch_paginated_entities(
        mock_get_alerts,
        entities_key="alerts",
        from_time=FIRST_FETCH_TIME,
    )

    assert len(results) == 250
    assert next_offset is None
    assert api_total == 250
    assert mock_get_alerts.call_count == 3
    assert mock_get_alerts.call_args_list[0].kwargs["limit"] == 100
    assert mock_get_alerts.call_args_list[0].kwargs["offset"] == 0
    assert mock_get_alerts.call_args_list[2].kwargs["offset"] == 200


def test_fetch_incidents_command_logs_created_against_api_totals(mocker):
    mocker.patch.object(demisto, "debug")
    info = mocker.patch.object(demisto, "info")
    mock_client = mocker.Mock()
    mock_client.get_incident_timeline.return_value = {"events": []}
    mock_client.get_incidents.return_value = {
        "incidents": [
            {"id": "inc-1", "name": "Inc 1", "severity": "LOW", "createdAt": TIMESTAMP_T1},
            {"id": "inc-2", "name": "Inc 2", "severity": "LOW", "createdAt": TIMESTAMP_T1},
        ],
        "total": 2,
    }
    mock_client.get_alerts.return_value = {
        "alerts": [
            {"id": "alert-1", "name": "Alert 1", "severity": "LOW", "createdAt": TIMESTAMP_T2},
        ],
        "total": 10,
    }

    _, incidents = fetch_incidents_command(
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
        max_fetch=3,
    )

    messages = [call.args[0] for call in info.call_args_list]
    assert len(incidents) == 3
    assert "Vega getIncidents total=2." in messages
    assert "Vega getAlerts total=10." in messages
    assert "Vega fetch cycle finished: 3 incidents created out of 12 (incidents total 2 + alerts total 10)." in messages


def test_fetch_incidents_command_incidents_first_then_alerts(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incident_timeline.return_value = {"events": []}

    def make_incident_page(offset: int, count: int, total: int = 152):
        return {
            "incidents": [
                {
                    "id": f"inc-{index}",
                    "name": f"Inc {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T1,
                }
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
            {
                "id": f"alert-{index}",
                "name": f"Alert {index}",
                "severity": "LOW",
                "createdAt": TIMESTAMP_T2,
            }
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
                {
                    "id": f"inc-{index}",
                    "name": f"Inc {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T1,
                }
                for index in range(8)
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
                {
                    "id": f"alert-{index}",
                    "name": f"Alert {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T2,
                }
                for index in range(42)
            ],
            "total": 100,
            "limit": 42,
            "offset": 0,
        },
        {
            "alerts": [
                {
                    "id": f"alert-{index}",
                    "name": f"Alert {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T2,
                }
                for index in range(42, 92)
            ],
            "total": 100,
            "limit": 50,
            "offset": 42,
        },
        {
            "alerts": [
                {
                    "id": f"alert-{index}",
                    "name": f"Alert {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T2,
                }
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
                {
                    "id": f"inc-{index}",
                    "name": f"Inc {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T1,
                }
                for index in range(50)
            ],
            "total": 80,
            "limit": 50,
            "offset": 0,
        },
        {
            "incidents": [
                {
                    "id": f"inc-{index}",
                    "name": f"Inc {index}",
                    "severity": "LOW",
                    "createdAt": TIMESTAMP_T1,
                }
                for index in range(50, 80)
            ],
            "total": 80,
            "limit": 30,
            "offset": 50,
        },
        {"incidents": [], "total": 80, "limit": 50, "offset": 0},
    ]
    mock_client.get_alerts.return_value = {
        "alerts": [],
        "total": 0,
        "limit": 50,
        "offset": 0,
    }

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


def test_fetch_incidents_command_uses_stored_cursor_when_present(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {
        "incidents": [],
        "total": 0,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_alerts.return_value = {
        "alerts": [],
        "total": 0,
        "limit": 200,
        "offset": 0,
    }

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

    assert mock_client.get_incidents.call_args.kwargs["from_time"] == "2026-06-04T16:55:00Z"


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
    assert filter_incident_statuses(["OPEN", "IN REVIEW", "ON HOLD", "RESOLVED"]) == [
        "OPEN",
        "IN_REVIEW",
        "ON_HOLD",
        "RESOLVED",
    ]
    assert filter_incident_statuses(["IN_REVIEW", "on hold"]) == ["IN_REVIEW", "ON_HOLD"]
    assert filter_incident_statuses(["OPEN", "invalid"]) == ["OPEN"]
    assert filter_incident_statuses(["NEW", "INVESTIGATING"]) is None
    assert filter_incident_statuses([]) is None


def test_filter_incident_investigation_statuses_maps_display_and_uses_all_when_empty():
    assert filter_incident_investigation_statuses(["NEW", "PENDING", "INVESTIGATING", "COMPLETED", "FAILED"]) == [
        "NEW",
        "INVESTIGATING",
        "COMPLETED",
        "FAILED",
    ]
    assert filter_incident_investigation_statuses(["pending", "invalid"]) == ["NEW"]
    assert filter_incident_investigation_statuses([]) is None
    assert filter_incident_investigation_statuses(None) is None


def test_build_incidents_query_variables_uses_user_and_investigation_status():
    variables = _build_incidents_query_variables(
        statuses=["OPEN", "RESOLVED"],
        investigation_statuses=["NEW", "INVESTIGATING"],
        offset=0,
    )

    assert variables["userStatuses"] == ["OPEN", "RESOLVED"]
    assert variables["investigationStatuses"] == ["NEW", "INVESTIGATING"]
    assert "statuses" not in variables


def test_build_incidents_query_variables_omits_empty_status_filters():
    variables = _build_incidents_query_variables(offset=0)

    assert "userStatuses" not in variables
    assert "investigationStatuses" not in variables


def test_filter_severities_accepts_valid_and_ignores_invalid():
    assert filter_alert_severities(["LOW", "HIGH", "critical"]) == [
        "LOW",
        "HIGH",
        "CRITICAL",
    ]
    assert filter_incident_severities(["MEDIUM", "invalid", ""]) == ["MEDIUM"]
    assert filter_alert_severities(["garbage"]) is None
    assert filter_incident_severities(None) is None


def test_filter_verdicts_accepts_valid_and_ignores_invalid():
    assert filter_alert_verdicts(["MALICIOUS", "N/A", "benign"]) == [
        "MALICIOUS",
        "NA",
        "BENIGN",
    ]
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
    assert _normalize_vega_status_for_display("IN_REVIEW", "incident") == "IN REVIEW"
    assert _normalize_vega_status_for_display("IN PROGRESS", "alert") == "IN PROGRESS"


def test_format_raw_entity_for_xsoar_normalizes_status_for_dropdown():
    alert = {"vegaEntityType": "Vega Alert", "status": "IN_PROGRESS"}
    _format_raw_entity_for_xsoar(alert)
    assert alert["status"] == "IN PROGRESS"

    incident = {
        "vegaEntityType": "Vega Incident",
        "userStatus": "IN_REVIEW",
        "investigationStatus": "PENDING",
    }
    _format_raw_entity_for_xsoar(incident)
    assert incident["status"] == "IN REVIEW"
    assert incident["investigationStatus"] == "NEW"


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


def test_format_recommended_actions_for_grid_empty_shows_placeholder():
    assert _format_recommended_actions_for_grid([]) == [{"name": VEGA_NO_RECOMMENDED_ACTIONS_DISPLAY}]
    assert _format_recommended_actions_for_grid(None) == [{"name": VEGA_NO_RECOMMENDED_ACTIONS_DISPLAY}]


def test_format_recommended_actions_for_grid_adds_description_newline():
    actions = [
        {"name": "Revoke sessions", "description": "Revoke active sessions", "actionKey": "revoke_user_sessions"},
        {"name": "Reset password", "description": "Reset the user password\n", "actionKey": "reset_user_password"},
    ]
    formatted = _format_recommended_actions_for_grid(actions)

    assert formatted[0]["description"] == "Revoke active sessions\n"
    assert formatted[1]["description"] == "Reset the user password\n"


def test_format_raw_entity_for_xsoar_empty_recommended_actions():
    incident = {
        "vegaEntityType": "Vega Incident",
        "recommendedActions": [],
    }
    _format_raw_entity_for_xsoar(incident)

    assert incident["recommendedActions"] == [{"name": VEGA_NO_RECOMMENDED_ACTIONS_DISPLAY}]


def test_format_key_findings_html_dark_theme_layout():
    findings = [
        "Suspicious activity from 10.0.0.1",
        "Domain test-observable contacted by host",
    ]
    assets = ["10.0.0.1"]
    observables = ["test-observable"]

    result = _format_key_findings_html(findings, assets, observables)

    assert "background:#000000" in result
    assert "Key findings</div>" in result
    assert "See Investigation" not in result
    assert "border-radius:999px" in result
    assert "10.0.0.1" in result
    assert "test-observable" in result
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

    assert alert["dataSources"] == [{"value": "CloudTrail"}, {"value": "GuardDuty"}]
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
    assert _format_mitre_attack(
        {
            "mitreTactics": ["Discovery"],
            "mitreTechniques": ["Cloud Infrastructure Discovery"],
        }
    ) == ["Discovery", "Cloud Infrastructure Discovery"]
    assert _format_mitre_attack({"mitreTactics": "Discovery", "mitreTechniques": "T1526"}) == ["Discovery", "T1526"]


def test_format_raw_entity_for_xsoar_mitre_attack():
    alert = {
        "id": "alert-1",
        "mitre": {"mitreTactics": ["Discovery"], "mitreTechniques": ["T1526"]},
    }
    _format_raw_entity_for_xsoar(alert)

    assert alert["vegaMitreAttack"] == [{"value": "Discovery"}, {"value": "T1526"}]


def test_format_mitre_attack_object_items():
    mitre = {
        "mitreTactics": [{"name": "Discovery", "id": "TA0007"}],
        "mitreTechniques": [{"techniqueName": "Cloud Infrastructure Discovery", "techniqueId": "T1526"}],
    }
    assert _format_mitre_attack(mitre) == ["Discovery", "Cloud Infrastructure Discovery"]


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

    assert raw["vegaMitreAttack"] == [{"value": "Discovery"}, {"value": "T1526"}]
    assert xsoar_incident["CustomFields"]["vegamitreattack"] == [{"value": "Discovery"}, {"value": "T1526"}]
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
        "typedAssets": [{"value": "i-12345", "type": "HOST"}],
        "observables": ["10.0.0.1"],
        "incidentFindings": ["Instance i-12345 connected to 10.0.0.1"],
    }
    _format_raw_entity_for_xsoar(incident)

    assert incident["dataSources"] == [{"value": "CloudTrail"}]
    assert incident["assets"] == ["i-12345"]
    assert incident["typedAssets"] == [{"type": "HOST", "value": "i-12345"}]
    assert incident["observables"] == [{"value": "10.0.0.1"}]
    assert "vegaIncidentFindings" in incident
    assert "background:#000000" in incident["vegaIncidentFindings"]
    assert "i-12345" in incident["vegaIncidentFindings"]
    assert "10.0.0.1" in incident["vegaIncidentFindings"]


def test_alert_to_incident_formats_raw_json(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming"})
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

    assert raw["dataSources"] == [{"value": "CloudTrail"}]
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
    assert raw["mirror_direction"] == "In"
    assert xsoar_incident["dbotMirrorDirection"] == "In"
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

    assert raw["assets"] == ["host-1"]
    assert raw["observables"] == [{"value": "host-1"}]
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
        {
            "text": "[{}]",
            "addedBy": "K3E1sZgbbNR2v3DpC3QCStodL1ay",
            "addedAt": "2026-06-12T05:01:20.379Z",
        },
        {
            "text": "status to investigation and verdict to benign",
            "addedBy": "K3E1sZgbbNR2v3DpC3QCStodL1ay",
            "addedAt": "2026-06-12T11:27:06Z",
        },
        {
            "text": "[{}]",
            "addedBy": "K3E1sZgbbNR2v3DpC3QCStodL1ay",
            "addedAt": "2026-06-12T05:00:43.95Z",
        },
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
            {
                "text": "[{}]",
                "addedBy": "machine-user",
                "addedAt": "2026-06-12T05:01:20.379Z",
            },
            {
                "text": "Reviewed in XSOAR",
                "addedBy": "Analyst One",
                "addedAt": "2026-06-12T11:27:06Z",
            },
        ],
    }
    _format_raw_entity_for_xsoar(incident)

    assert "vegaComments" in incident
    assert "Reviewed in XSOAR" in incident["vegaComments"]
    assert "[{}]" not in incident["vegaComments"]
    assert incident["VegaCommentsSource"] == incident["comments"]
    assert _build_vega_incident_custom_fields(incident)["vegacommentssource"] == incident["comments"]


def test_format_raw_entity_for_xsoar_builds_vega_alert_comments_html():
    alert = {
        "id": "alert-1",
        "vegaEntityType": "Vega Alert",
        "comments": [
            {
                "text": "[{}]",
                "addedBy": "machine-user",
                "addedAt": "2026-06-12T05:01:20.379Z",
            },
            {
                "text": "Escalated for review",
                "addedBy": "Analyst Two",
                "addedAt": "2026-06-12T12:00:00Z",
            },
        ],
    }
    _format_raw_entity_for_xsoar(alert)

    assert "vegaComments" in alert
    assert "Escalated for review" in alert["vegaComments"]
    assert "[{}]" not in alert["vegaComments"]
    assert alert["VegaCommentsSource"] == alert["comments"]
    assert _build_vega_alert_custom_fields(alert)["vegacommentssource"] == alert["comments"]


def test_format_timeline_events_html_dark_theme_layout():
    timeline = [
        {
            "id": "evt-1",
            "timestamp": "2026-04-28T01:30:00Z",
            "summary": "SSM enumeration detected.",
            "entities": [],
            "dataSources": [{"vendor": "AWS", "displayName": "CloudTrail"}],
            "alert": {
                "id": "alert-1",
                "displayName": "AWS SSM Enumeration",
                "severity": 3,
            },
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
    assert "VegaTimelineEventsSource" not in raw
    assert xsoar_incident["CustomFields"]["vegatimelineevents"]
    assert "Test event." in xsoar_incident["CustomFields"]["vegatimelineevents"]
    assert "vegatimelineeventssource" not in xsoar_incident["CustomFields"]


def test_fetch_incidents_command_fetches_timeline_details(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {
        "incidents": [
            {
                "id": "inc-1",
                "name": "Inc 1",
                "severity": "LOW",
                "createdAt": TIMESTAMP_T2,
            }
        ],
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
    mock_client.get_alerts.return_value = {
        "alerts": [],
        "total": 0,
        "limit": 200,
        "offset": 0,
    }

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


def _full_incident_alert(alert_id: str = "alert-1") -> dict:
    return {
        "id": alert_id,
        "vegaAlertId": "VA-1",
        "detectionId": "det-1",
        "name": "Suspicious login",
        "description": "Full alert description",
        "severity": "HIGH",
        "status": "OPEN",
        "assignee": {"userId": "user-1", "displayName": "Ada Lovelace", "email": "ada@example.com"},
        "assignees": [{"userId": "user-1", "displayName": "Ada Lovelace", "email": "ada@example.com"}],
        "dataSources": ["CloudTrail", "Okta"],
        "createdAt": TIMESTAMP_T1,
        "updatedAt": TIMESTAMP_T2,
        "mitre": {"mitreTactics": ["TA0001"], "mitreTechniques": ["T1078"]},
        "relatedIncidents": [{"incidentId": "inc-9", "name": "Related"}],
        "detectionSource": "Vega",
        "detectionDescription": "Detects suspicious logins",
        "detectionQuery": "event_type = login",
        "eventCount": 4,
        "isTestMode": False,
        "verdict": "SUSPICIOUS",
        "verdictReasoning": "Multiple failed logins",
        "dedupCount": 2,
        "comments": [{"text": "Review", "addedBy": "Ada", "addedAt": TIMESTAMP_T2}],
    }


def test_incident_to_xsoar_incident_enriches_alerts(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {
        "alerts": [_full_incident_alert()],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }
    incident = {
        "id": "inc-1",
        "name": "Test Incident",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
        "alerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}],
    }

    xsoar_incident = incident_to_xsoar_incident(incident, client=mock_client, include_alert_metadata=True)
    raw = json.loads(xsoar_incident["rawJSON"])
    row = raw["alerts"][0]

    mock_client.get_alerts.assert_called_once_with(
        alert_ids=["alert-1"],
        from_time="2026-05-31T10:00:00Z",
        limit=1,
        offset=0,
    )
    assert row["alertId"] == "alert-1"
    assert row["id"] == "alert-1"
    assert row["name"] == "Suspicious login"
    assert row["severity"] == "HIGH"
    assert row["status"] == "OPEN"
    assert row["verdict"] == "SUSPICIOUS"
    assert row["createdAt"] == TIMESTAMP_T1
    assert row["dataSources"] == ["CloudTrail", "Okta"]
    assert row["eventCount"] == "4"
    assert row["isTestMode"] == "false"
    assert row["assignee"] == _full_incident_alert()["assignee"]
    assert row["assignees"] == _full_incident_alert()["assignees"]
    assert row["mitre"] == _full_incident_alert()["mitre"]
    assert row["comments"] == _full_incident_alert()["comments"]
    assert row["labels"] == []
    assert row["escalation"] is None
    assert xsoar_incident["CustomFields"]["vegaalerts"] == raw["alerts"]


def test_enrich_incident_alerts_falls_back_to_stub_when_lookup_fails(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.side_effect = DemistoException("API rate limit exceeded after maximum retries.")
    stubs = [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}]

    rows = _enrich_incident_alerts(mock_client, stubs)

    assert rows == [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}]


def test_enrich_incident_alerts_keeps_stub_for_missing_alert(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {
        "alerts": [_full_incident_alert("alert-1")],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }
    stubs = [
        {"alertId": "alert-1", "name": "Found", "createdAt": TIMESTAMP_T1},
        {"alertId": "alert-2", "name": "Missing", "createdAt": TIMESTAMP_T2},
    ]

    rows = _enrich_incident_alerts(mock_client, stubs)

    assert rows[0]["alertId"] == "alert-1"
    assert rows[0]["detectionId"] == "det-1"
    assert rows[1] == {"alertId": "alert-2", "name": "Missing", "createdAt": TIMESTAMP_T2}


def test_enrich_incident_alerts_batches_above_one_thousand(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mock_client = mocker.Mock()
    alert_ids = [f"alert-{index}" for index in range(1001)]

    def alert_page(page_ids: list[str]) -> dict:
        return {
            "alerts": [{"id": alert_id, "name": "Alert", "createdAt": TIMESTAMP_T1} for alert_id in page_ids],
            "total": len(page_ids),
        }

    mock_client.get_alerts.side_effect = [alert_page(alert_ids[:1000]), alert_page(alert_ids[1000:])]
    stubs = [{"alertId": alert_id, "name": "Alert", "createdAt": TIMESTAMP_T1} for alert_id in alert_ids]

    rows = _enrich_incident_alerts(mock_client, stubs)

    assert len(rows) == 1001
    assert mock_client.get_alerts.call_count == 2
    assert mock_client.get_alerts.call_args_list[0].kwargs == {
        "alert_ids": alert_ids[:1000],
        "from_time": "2026-05-31T10:00:00Z",
        "limit": 1000,
        "offset": 0,
    }
    assert mock_client.get_alerts.call_args_list[1].kwargs["alert_ids"] == alert_ids[1000:]
    assert mock_client.get_alerts.call_args_list[1].kwargs["limit"] == 1


def test_fetch_incidents_command_enriches_incident_alerts(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {
        "incidents": [
            {
                "id": "inc-1",
                "name": "Inc 1",
                "severity": "HIGH",
                "createdAt": TIMESTAMP_T1,
                "alerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}],
            }
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incident_timeline.return_value = {"events": []}
    mock_client.get_alerts.return_value = {
        "alerts": [_full_incident_alert()],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }

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
        include_incident_alert_metadata=True,
    )

    assert incidents[0]["CustomFields"]["vegaalerts"][0]["detectionId"] == "det-1"
    mock_client.get_alerts.assert_called_once_with(
        alert_ids=["alert-1"],
        from_time="2026-05-31T10:00:00Z",
        limit=1,
        offset=0,
    )


def test_get_remote_data_command_mirrors_incident_alerts(mocker):
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "alerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}],
    }
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Loaded from details",
        "alerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}],
    }
    mock_client.get_alerts.return_value = {
        "alerts": [_full_incident_alert()],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }

    result = get_remote_data_command(
        mock_client,
        {
            "id": "inc-1",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Incident"},
        },
        include_alert_metadata=True,
    )

    mirrored_alerts = result.mirrored_object["CustomFields"]["vegaalerts"]
    assert mirrored_alerts[0]["alertId"] == "alert-1"
    assert mirrored_alerts[0]["detectionQuery"] == "event_type = login"
    assert mirrored_alerts[0]["comments"] == _full_incident_alert()["comments"]
    assert result.mirrored_object["alerts"] == mirrored_alerts
    mock_client.get_alerts.assert_called_once_with(
        alert_ids=["alert-1"],
        from_time="2026-05-31T10:00:00Z",
        limit=1,
        offset=0,
    )


def test_fetch_incidents_command_omits_alert_metadata_by_default(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock()
    mock_client.get_incidents.return_value = {
        "incidents": [
            {
                "id": "inc-1",
                "name": "Inc 1",
                "severity": "HIGH",
                "createdAt": TIMESTAMP_T1,
                "alerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1, "severity": "HIGH"}],
            }
        ],
        "total": 1,
        "limit": 200,
        "offset": 0,
    }
    mock_client.get_incident_timeline.return_value = {"events": []}

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

    assert incidents[0]["CustomFields"]["vegaalerts"] == [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}]
    mock_client.get_alerts.assert_not_called()


def test_get_alert_metadata_command_uses_single_incident_id(mocker):
    mocker.patch.object(demisto, "info")
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock()
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "alerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}],
    }
    mock_client.get_alerts.return_value = {"alerts": [_full_incident_alert()], "total": 1}

    result = get_alert_metadata_command(mock_client, {"incident_id": "inc-1"})

    assert set(result.outputs[0]) == {
        "id",
        "vegaAlertId",
        "detectionId",
        "name",
        "severity",
        "status",
        "verdict",
        "createdAt",
        "dataSources",
        "labels",
    }
    assert result.outputs[0]["id"] == "alert-1"
    assert result.outputs[0]["detectionId"] == "det-1"
    assert result.outputs[0]["dataSources"] == ["CloudTrail", "Okta"]
    assert result.outputs[0]["labels"] is None
    assert json.loads(result.readable_output) == result.outputs[0]
    mock_client.get_incident_by_id.assert_called_once_with("inc-1", from_time=INCIDENT_ID_LOOKUP_FROM_TIME)
    assert INCIDENT_ID_LOOKUP_FROM_TIME == "2024-01-01T00:00:00Z"


def test_get_alert_metadata_command_rejects_multiple_incident_ids(mocker):
    with pytest.raises(DemistoException, match="single Vega incident ID"):
        get_alert_metadata_command(mocker.Mock(), {"incident_id": "inc-1,inc-2"})


def test_get_alert_metadata_command_uses_related_alert_ids_from_incident(mocker):
    mocker.patch.object(demisto, "info")
    mocker.patch(
        "Vega.load_current_incident",
        return_value={
            "id": "100",
            "type": "Vega Incident",
            "CustomFields": {
                "vegaincidentid": "inc-1",
                "vegaalerts": [{"alertId": "alert-1", "name": "Stub name", "createdAt": TIMESTAMP_T1}],
            },
        },
    )
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {"alerts": [_full_incident_alert()], "total": 1}

    result = get_alert_metadata_command(mock_client, {})

    mock_client.get_incident_by_id.assert_not_called()
    assert mock_client.get_alerts.call_args.kwargs["alert_ids"] == ["alert-1"]
    assert result.outputs[0]["name"] == "Suspicious login"


def test_get_alert_metadata_command_uses_current_alert_id(mocker):
    mocker.patch.object(demisto, "info")
    mocker.patch(
        "Vega.load_current_incident",
        return_value={
            "id": "200",
            "type": "Vega Alert",
            "CustomFields": {"alertid": "alert-1", "vegacreatedat": TIMESTAMP_T1},
        },
    )
    mock_client = mocker.Mock()
    mock_client.get_alerts.return_value = {"alerts": [_full_incident_alert()], "total": 1}

    result = get_alert_metadata_command(mock_client, {})

    mock_client.get_incident_by_id.assert_not_called()
    assert mock_client.get_alerts.call_args.kwargs["alert_ids"] == ["alert-1"]
    assert result.outputs[0]["id"] == "alert-1"


def test_get_alert_metadata_command_requires_incident_id_outside_investigation(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})

    with pytest.raises(DemistoException, match="incident_id is required"):
        get_alert_metadata_command(mocker.Mock(), {})


def test_format_raw_entity_for_xsoar_prefers_key_findings():
    incident = {
        "incidentFindings": ["List finding"],
        "keyFindings": ["Detail finding"],
        "assets": [],
        "observables": [],
    }
    _format_raw_entity_for_xsoar(incident)

    assert incident["assets"] == []
    assert incident["observables"] == []
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
            {
                "verdictReasoning": "N/A",
                "userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"},
            }
        )
        is None
    )


def test_extract_verdict_reasoning_ignores_user_verdict_and_nested_verdict():
    assert (
        _extract_verdict_reasoning_from_entity({"userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"}}) is None
    )
    assert (
        _extract_verdict_reasoning_from_entity(
            {
                "verdict": {
                    "value": "SUSPICIOUS",
                    "reasoning": "Multiple failed logins observed",
                }
            }
        )
        is None
    )
    assert _extract_verdict_reasoning_from_entity({"incidentSummary": "Incident summary text"}) is None


def test_normalize_verdict_reasoning_from_nested_verdict_dict():
    raw = {
        "verdict": {
            "value": "SUSPICIOUS",
            "reasoning": "Multiple failed logins observed",
        }
    }
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
    vendor_row = {
        "cid": "12345678901234567890123456789012",
        "EventType": "Event_ExternalApiEvent",
    }
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


def test_expand_flat_raw_fields_expands_dotted_and_array_keys():
    expanded = _expand_flat_raw_fields(
        {
            "date_year": "2026",
            "vendorInformation.provider": "ASC",
            "securityResources{}.resourceType": "attacked",
            "userStates{}.logonIp": "10.0.0.1",
            "userStates{}.userPrincipalName": "user@example.com",
        }
    )

    assert expanded["date_year"] == "2026"
    assert expanded["vendorInformation"] == {"provider": "ASC"}
    assert expanded["securityResources"] == [{"resourceType": "attacked"}]
    assert expanded["userStates"] == [{"logonIp": "10.0.0.1", "userPrincipalName": "user@example.com"}]


def test_promote_raw_into_fields_keeps_schema_and_promotes_dotted_raw():
    fields = {
        "app_uid": None,
        "http_response": {"code": None},
        "request": {"uri": None},
        "auth_type": None,
        "risk_score": "medium",
        "_raw": json.dumps(
            {
                "date_year": "2026",
                "createdDateTime": "2026-07-21T14:23:19.063Z",
                "vendorInformation.provider": "ASC",
                "securityResources{}.resourceType": "attacked",
                "userStates{}.logonIp": "10.0.0.1",
                "userStates{}.userPrincipalName": "user@example.com",
                "source_server": "idx-example.example.com",
                "risk_score": "should-not-overwrite",
            }
        ),
    }

    promoted = _promote_raw_into_alert_event_fields(fields)

    assert promoted["risk_score"] == "medium"
    assert promoted["app_uid"] is None
    assert promoted["date_year"] == "2026"
    assert promoted["createdDateTime"] == "2026-07-21T14:23:19.063Z"
    assert promoted["vendorInformation"] == {"provider": "ASC"}
    assert promoted["securityResources"] == [{"resourceType": "attacked"}]
    assert promoted["userStates"] == [{"logonIp": "10.0.0.1", "userPrincipalName": "user@example.com"}]
    assert promoted["source_server"] == "idx-example.example.com"
    assert isinstance(promoted["_raw"], str)
    assert "date_year" in promoted["_raw"]


def test_enrich_alert_event_promotes_nested_eks_raw_object():
    raw_event = {
        "_index_timestamp": 1774447926000,
        "account_id": "890123456789",
        "auditID": "c6dcb49b-90fd-4ec8-ac88-a58990cf7dc4",
        "cluster_name": "eks-prod-cluster",
        "verb": "get",
        "user": {
            "uid": "8a75b43c-5278-4abb-91e1-eea07ad04ea6",
            "username": "system:serviceaccount:stratus-red-team-np-name-fatnmkvw:stratus-red-team-np-sa",
        },
        "sourceIPs": ["10.0.0.1"],
    }
    fields_payload = {
        "container": {"uid": None, "name": None},
        "cluster": {"name": "eks-prod-cluster"},
        "request": {
            "data": None,
            "uri": "/api/v1/nodes/ip-192-168-20-125.ec2.internal/proxy/runningpods/",
        },
        "status_code": "200",
        "operation": "get",
        "account": {"uid": "890123456789"},
        "_raw": raw_event,
    }
    event = {
        "catalog": "amazoneksaudit",
        "class": "Network Activity",
        "data_source": "amazon_eks_events",
        "fields": json.dumps(fields_payload),
        "raw": json.dumps(raw_event),
        "source": "EKS",
        "storage": "AWS S3",
        "timestamp": "2026-03-24 17:26:20.000",
    }

    enriched = _enrich_alert_event(event)
    fields = enriched["fields"]

    assert isinstance(fields, dict)
    assert fields["cluster"] == {"name": "eks-prod-cluster"}
    assert fields["status_code"] == "200"
    assert fields["auditID"] == "c6dcb49b-90fd-4ec8-ac88-a58990cf7dc4"
    assert fields["verb"] == "get"
    assert fields["account_id"] == "890123456789"
    assert fields["user"]["username"].startswith("system:serviceaccount:")
    assert fields["sourceIPs"] == ["10.0.0.1"]
    assert fields["_raw"] == raw_event
    assert enriched["raw"] == json.dumps(raw_event)


def test_enrich_alert_event_noop_without_fields_or_raw():
    event = {
        "actor.user.uid": "arn:aws:iam::890123456789:root",
        "event_count": "23",
        "timeframe": "2026-05-12 00:40:00.000",
    }
    assert _enrich_alert_event(event) == event


def test_enrich_alert_events_leaves_summary_rows_unchanged():
    events = [
        {
            "actor.user.uid": "arn:aws:iam::890123456789:root",
            "event_count": "23",
            "unique_events_count": "6",
        }
    ]
    assert _enrich_alert_events(events) == events


def test_fetch_alert_events_page_enriches_fields_from_raw(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [
            {
                "catalog": "siem_cloud__sandbox",
                "data_source": "microsoft_graph_events",
                "fields": json.dumps(
                    {
                        "app_uid": None,
                        "risk_score": "medium",
                        "_raw": {
                            "date_year": "2026",
                            "vendorInformation.provider": "ASC",
                            "securityResources{}.resourceType": "attacked",
                        },
                    }
                ),
                "raw": '{"date_year":"2026"}',
                "source": "Graph",
                "timestamp": "2026-07-21 14:23:55.887",
            }
        ],
    }

    events, total = fetch_alert_events_page(mock_client, "alert-1")

    assert total == 1
    assert events[0]["fields"]["date_year"] == "2026"
    assert events[0]["fields"]["vendorInformation"] == {"provider": "ASC"}
    assert events[0]["fields"]["securityResources"] == [{"resourceType": "attacked"}]
    assert events[0]["fields"]["risk_score"] == "medium"
    assert events[0]["fields"]["app_uid"] is None


def test_fetch_alert_events_command_outputs_enriched_events(mocker):
    mocker.patch(
        "Vega.load_current_incident",
        return_value={"CustomFields": {"vegaalertid": "alert-1"}},
    )
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [
            {
                "catalog": "amazoneksaudit",
                "fields": json.dumps(
                    {
                        "operation": "get",
                        "_raw": {"auditID": "abc-123", "verb": "get"},
                    }
                ),
                "source": "EKS",
                "timestamp": "2026-03-24 17:26:20.000",
            }
        ],
    }

    result = fetch_alert_events_command(mock_client, {"alert_id": "alert-1"})

    assert result.outputs["Count"] == 1
    assert result.outputs["Events"][0]["fields"]["auditID"] == "abc-123"
    assert result.outputs["Events"][0]["fields"]["operation"] == "get"
    assert "auditID" in result.readable_output or "operation" in result.readable_output


def test_alert_to_incident_stores_enriched_alert_events(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [
            {
                "catalog": "siem_cloud__sandbox",
                "fields": json.dumps(
                    {
                        "risk_score": "medium",
                        "_raw": '{"createdDateTime":"2026-07-21T14:23:19.063Z","vendorInformation.provider":"ASC"}',
                    }
                ),
                "source": "Graph",
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
    fields = raw["alertEvents"][0]["fields"]

    assert fields["createdDateTime"] == "2026-07-21T14:23:19.063Z"
    assert fields["vendorInformation"] == {"provider": "ASC"}
    assert fields["risk_score"] == "medium"


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
    mocker.patch(
        "Vega.demisto.incident",
        side_effect=TypeError("'NoneType' object is not subscriptable"),
    )
    incidents = mocker.patch("Vega.demisto.incidents")
    debug = mocker.patch.object(demisto, "debug")

    incident = load_current_incident()

    assert incident == {}
    incidents.assert_not_called()
    debug.assert_not_called()


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
    assert fields[VEGA_NEW_COMMENT_FIELD] == VEGA_NEW_COMMENT_LAYOUT_DEFAULT


def test_build_vega_incident_custom_fields_sets_layout_default_comment():
    fields = _build_vega_incident_custom_fields({"id": "inc-1"})
    assert fields["vegaincidentid"] == "inc-1"
    assert fields[VEGA_NEW_COMMENT_FIELD] == VEGA_NEW_COMMENT_LAYOUT_DEFAULT


def test_outgoing_mirror_comment_value_skips_layout_default():
    assert _outgoing_mirror_comment_value(VEGA_NEW_COMMENT_LAYOUT_DEFAULT) is None
    assert _outgoing_mirror_comment_value("Reviewed in XSOAR") == "Reviewed in XSOAR"


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


def test_get_alert_events_sends_up_to_ten_alert_ids(requests_mock, mocker):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "info")
    requests_mock.post(f"{BASE_URL}/api/v1/login_machine", json=MOCK_JWT_RESPONSE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/query",
        json={
            "data": {
                "getAlertsEvents": {
                    "alerts": [{"alertId": "alert-1", "total": 1, "results": [{"timestamp": "t1"}]}],
                }
            }
        },
    )
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )

    result = client.get_alert_events("alert-1", alert_ids=["alert-2"], limit=100, offset=0)

    request_json = requests_mock.request_history[-1].json()
    assert request_json["variables"] == {"alertIds": ["alert-2", "alert-1"], "limit": 100, "offset": 0}
    assert "$alertIds: [ID!]" in request_json["query"]
    assert "alerts {" in request_json["query"]
    assert result["alerts"][0]["alertId"] == "alert-1"


def test_get_alert_events_rejects_more_than_ten_ids():
    client = Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )
    with pytest.raises(DemistoException, match="maximum of 10"):
        client.get_alert_events(alert_ids=[f"alert-{index}" for index in range(11)])


def test_fetch_alert_events_page_reads_per_alert_results(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 2,
        "results": [{"timestamp": "other", "source": "combined"}],
        "alerts": [
            {"alertId": "alert-1", "total": 1, "results": [{"timestamp": "t1", "source": "one"}]},
            {"alertId": "alert-2", "total": 1, "results": [{"timestamp": "t2", "source": "two"}]},
        ],
    }

    events, total = fetch_alert_events_page(mock_client, "alert-1", limit=50, offset=0)

    assert total == 1
    assert events[0]["timestamp"] == "t1"
    assert events[0]["source"] == "one"


def test_fetch_alert_events_for_ids_requests_in_batches_of_ten(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    alert_ids = [f"alert-{index}" for index in range(12)]

    def _page(*_args, **kwargs):
        requested = kwargs.get("alert_ids") or []
        return {
            "alerts": [
                {"alertId": alert_id, "total": 1, "results": [{"timestamp": alert_id, "source": "src"}]} for alert_id in requested
            ]
        }

    mock_client.get_alert_events.side_effect = _page

    fetched = _fetch_alert_events_for_ids(mock_client, alert_ids)

    assert mock_client.get_alert_events.call_count == 2
    assert mock_client.get_alert_events.call_args_list[0].kwargs["alert_ids"] == alert_ids[:10]
    assert mock_client.get_alert_events.call_args_list[1].kwargs["alert_ids"] == alert_ids[10:]
    assert fetched["alert-11"][1]["vegaalerteventsloadedfor"] == "alert-11"
    assert "Alert Events (1)" in fetched["alert-11"][1]["vegaalertevents"]


def test_fetch_alert_events_command_returns_one_result_per_alert_id(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "alerts": [
            {"alertId": "alert-1", "total": 1, "results": [{"timestamp": "t1", "source": "one"}]},
            {"alertId": "alert-2", "total": 1, "results": [{"timestamp": "t2", "source": "two"}]},
        ]
    }

    results = fetch_alert_events_command(mock_client, {"alert_ids": "alert-1,alert-2"})

    assert [result.outputs["AlertId"] for result in results] == ["alert-1", "alert-2"]
    assert results[0].outputs["Count"] == 1
    assert results[1].outputs["Events"][0]["source"] == "two"
    mock_client.get_alert_events.assert_called_once()
    assert mock_client.get_alert_events.call_args.kwargs["alert_ids"] == ["alert-1", "alert-2"]


def test_fetch_alert_events_command_rejects_more_than_ten_alert_ids(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})
    with pytest.raises(DemistoException, match="maximum of 10"):
        fetch_alert_events_command(mocker.Mock(), {"alert_ids": ",".join(f"alert-{index}" for index in range(11))})


def test_fetch_alert_events_for_ingest_displays_vendor_raw_rows(mocker):
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_events.return_value = {
        "total": 1,
        "results": [{"cid": "123", "eid": "118", "Name": "Access from IP with bad reputation"}],
    }

    events, custom_fields = _fetch_alert_events_for_ingest(mock_client, "alert-1")

    assert events[0]["cid"] == "123"
    assert events[0]["eid"] == "118"
    markdown = custom_fields["vegaalertevents"]
    assert "|Timestamp|Source|Log|" in markdown
    assert "Access from IP with bad reputation" in markdown
    assert "No alert events found" not in markdown
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


def test_fetch_alert_events_command_displays_vendor_raw_rows(mocker):
    mocker.patch(
        "Vega.load_current_incident",
        return_value={"CustomFields": {"vegaalertid": "alert-1"}},
    )
    mock_client = mocker.Mock(spec=Client)
    long_command = "powershell.exe " + ("A" * 400)
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
                "CommandLine": long_command,
                "timestamp": 1774165347000,
            }
        ],
    }

    result = fetch_alert_events_command(mock_client, {"alert_id": "alert-1"})

    readable = result.readable_output
    assert "|Timestamp|Source|Log|" in readable
    assert "03/22/26 07:42:27" in readable
    assert "CrowdStrike" in readable
    assert "12345678901234567890123456789012" in readable
    assert '"eid":"118"' in readable
    assert "Falcon Identity Protection" in readable
    assert "T1078" in readable
    assert long_command in readable
    assert "1774165347000" not in readable
    assert '"SourceVendors"' not in readable
    assert result.outputs["Total"] == 1
    assert result.outputs["Count"] == 1
    assert result.outputs["HasAlertEvents"] is True
    assert result.outputs["Events"][0]["cid"] == "12345678901234567890123456789012"
    assert "No alert events found" not in result.outputs["CustomFields"]["vegaalertevents"]
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
                "detection": {
                    "id": "det-1",
                    "name": "Detection 1",
                    "severity": "HIGH",
                    "status": "VISIBLE",
                },
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
                "detection": {
                    "id": "det-1",
                    "name": "Detection 1",
                    "severity": "LOW",
                    "status": "HIDDEN",
                },
            },
            {
                "status": "VALID",
                "name": "Detection 2",
                "detection": {
                    "id": "det-2",
                    "name": "Detection 2",
                    "severity": "LOW",
                    "status": "HIDDEN",
                },
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
                "errors": [
                    {
                        "code": "INVALID_VALUE",
                        "message": "Invalid severity",
                        "field": "severity",
                    }
                ],
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


def _rate_limit_retry_client(mocker):
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
    return client, sleep_mock


def test_graphql_request_retries_on_rate_limit_message_without_extensions(mocker):
    client, sleep_mock = _rate_limit_retry_client(mocker)
    rate_limited_response = {
        "errors": [{"message": "Rate limit exceeded. Please retry after a brief wait."}],
        "data": None,
    }
    success_response = {"data": {"getAlertsEvents": {"total": 1, "results": [{"timestamp": "t1"}]}}}
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[rate_limited_response, success_response],
    )

    response = client._graphql_request("query { getAlertsEvents(alertId: $alertId) { results } }", {"alertId": "alert-1"})

    assert response == success_response
    assert http_mock.call_count == 2
    assert sleep_mock.call_args_list[0].args[0] == 2
    assert client._rate_limit_wait_seconds == RATE_LIMIT_INITIAL_WAIT_SECONDS


def test_graphql_request_retries_on_http_200_payload_rate_limit_message(mocker):
    client, sleep_mock = _rate_limit_retry_client(mocker)
    rate_limited_response = {
        "data": {
            "getAlertsEvents": {
                "total": 0,
                "results": None,
                "error": {"code": "INTERNAL", "message": "Rate limit exceeded"},
            }
        }
    }
    success_response = {"data": {"getAlertsEvents": {"total": 0, "results": [], "error": None}}}
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[rate_limited_response, success_response],
    )

    response = client._graphql_request("query { getAlertsEvents(alertId: $alertId) { results error { message } } }")

    assert response == success_response
    assert http_mock.call_count == 2
    sleep_mock.assert_called_once_with(2)


def test_graphql_request_does_not_retry_unrelated_payload_error(mocker):
    client, sleep_mock = _rate_limit_retry_client(mocker)
    payload_error_response = {
        "data": {
            "getAlertsEvents": {
                "total": 0,
                "results": [],
                "error": {"code": "NOT_FOUND", "message": "Alert not found"},
            }
        }
    }
    http_mock = mocker.patch.object(client, "_http_request", return_value=payload_error_response)

    response = client._graphql_request("query { getAlertsEvents(alertId: $alertId) { results error { message } } }")

    assert response == payload_error_response
    http_mock.assert_called_once()
    sleep_mock.assert_not_called()


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
        "incidents": [
            {
                "id": "inc-1",
                "name": "Incident 1",
                "severity": "HIGH",
                "createdAt": TIMESTAMP_T1,
            }
        ],
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
                VEGA_INCIDENT_STATUS_FIELD: "IN REVIEW",
                "vegaverdict": "SUSPICIOUS",
            },
        },
    )
    mock_client = mocker.Mock(spec=Client)
    mock_client.update_incidents.return_value = {
        "incidents": [{"incidentId": "inc-1", "userStatus": "IN_REVIEW", "verdict": "SUSPICIOUS"}]
    }
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "userStatus": "IN_REVIEW",
        "verdict": "SUSPICIOUS",
    }

    update_incident_command(mock_client, {})

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "userStatus": "IN_REVIEW",
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
        {
            "alert_ids": ["alert-1", "alert-2"],
            "status": "RESOLVED",
            "verdict": "MALICIOUS",
        },
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
        {
            "incident_ids": ["inc-1", "inc-2"],
            "status": "RESOLVED",
            "verdict": "MALICIOUS",
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1", "inc-2"],
            "userStatus": "RESOLVED",
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
        {
            "incident_id": ["inc-1", "inc-2"],
            "status": "IN REVIEW",
            "verdict": "SUSPICIOUS",
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1", "inc-2"],
            "userStatus": "IN_REVIEW",
            "verdict": {"value": "SUSPICIOUS", "reasoning": ""},
        }
    )


def test_update_alert_command_requires_update_fields(mocker):
    mocker.patch("Vega.load_current_incident", return_value={})
    mock_client = mocker.Mock(spec=Client)

    with pytest.raises(
        DemistoException,
        match="At least one of status, severity, verdict, verdict reasoning, comment, or assignees",
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
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdict": "SUSPICIOUS",
    }

    result = update_incident_command(
        mock_client,
        {
            "incident_ids": "inc-1",
            "status": "IN REVIEW",
            "verdict": "SUSPICIOUS",
            "comment": "Reviewed in XSOAR",
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "userStatus": "IN_REVIEW",
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
    incident = {
        "type": "Vega Incident",
        "CustomFields": {"vegaincidentid": "inc-from-field"},
    }
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
        "lastUpdated": "2026-06-16T12:00:00Z",
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
    assert sync_object["lastUpdated"] == "2026-06-16T12:00:00Z"
    assert sync_object["CustomFields"]["vegaincidentid"] == "inc-1"
    assert sync_object["CustomFields"]["vegaincidentstatus"] == "INVESTIGATING"
    assert sync_object["CustomFields"]["vegaseverity"] == "MEDIUM"
    assert sync_object["CustomFields"]["vegaverdict"] == "BENIGN"
    assert sync_object["CustomFields"]["vegaverdictreasoning"] == "Confirmed benign"
    assert "vegaComments" in sync_object
    assert "note" in sync_object["vegaComments"]
    assert sync_object["CustomFields"]["vegacomments"] == sync_object["vegaComments"]
    assert sync_object["VegaCommentsSource"] == incident["comments"]
    assert sync_object["CustomFields"]["vegacommentssource"] == incident["comments"]
    assert "incidentSummary" not in sync_object
    assert "assignee" not in sync_object


def test_build_mirror_sync_object_reflects_removed_comments():
    incident = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "severity": 2,
        "comments": [],
    }

    sync_object = _build_mirror_sync_object(incident, MIRROR_ENTITY_SUFFIX_INCIDENT)

    assert "vegaComments" in sync_object
    assert "No comments are available" in sync_object["vegaComments"]
    assert sync_object["CustomFields"]["vegacomments"] == sync_object["vegaComments"]
    assert sync_object["CustomFields"]["vegacommentssource"] == []
    assert "vegaComments" not in sync_object or "Removed comment" not in sync_object["vegaComments"]


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
    assert (
        _entity_updated_after(
            entity,
            MIRROR_ENTITY_SUFFIX_ALERT,
            datetime(2026, 6, 15, 11, 0, 0, tzinfo=UTC),
        )
        is False
    )


def test_normalize_verdict_reasoning_from_user_verdict():
    raw = {"userVerdict": {"value": "BENIGN", "reasoning": "Reviewed by analyst"}}
    assert _normalize_verdict_reasoning_for_display(raw) == "N/A"
    assert _extract_verdict_reasoning_from_entity(raw) is None


def test_build_mirror_sync_object_does_not_rewrite_mirror_direction(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    sync_object = _build_mirror_sync_object(
        {"id": "alert-1", "status": "OPEN", "severity": "HIGH"},
        MIRROR_ENTITY_SUFFIX_ALERT,
    )

    assert "dbotMirrorDirection" not in sync_object
    assert "mirror_direction" not in sync_object
    assert sync_object["dbotMirrorInstance"] == "Vega_instance_1"
    assert sync_object["dbotMirrorId"] == "alert:alert-1"


def test_build_mirror_sync_object_keeps_direction_off_when_instance_is_incoming(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming"})
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    sync_object = _build_mirror_sync_object(
        {"id": "inc-1", "status": "INVESTIGATING", "severity": "MEDIUM"},
        MIRROR_ENTITY_SUFFIX_INCIDENT,
    )

    assert "dbotMirrorDirection" not in sync_object
    assert "mirror_direction" not in sync_object


def test_build_mirror_sync_object_includes_alert_severity():
    alert = {
        "id": "alert-1",
        "status": "OPEN",
        "severity": "HIGH",
        "verdict": "SUSPICIOUS",
        "verdictReasoning": "Suspicious activity",
        "updatedAt": "2026-06-15T12:00:00Z",
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
    assert sync_object["updatedAt"] == "2026-06-15T12:00:00Z"


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
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
    }
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Loaded from details",
    }

    result = get_remote_data_command(
        mock_client,
        {
            "id": "inc-1",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Incident"},
        },
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
        {
            "id": "inc-1",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Incident"},
        },
    )

    lookup_filters = _resolve_mirror_incident_lookup_filters("2026-06-15T11:00:00Z")
    mock_client.get_incident_by_id.assert_called_once_with("inc-1", **lookup_filters)
    assert result.mirrored_object["verdictReasoning"] == "Updated analyst note"


def test_resolve_remote_entity_vega_alert_context_skips_incident_lookup(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})

    fields = _get_mirroring_fields()

    assert fields["mirror_instance"] == "Vega_prod"
    assert fields["mirror_direction"] == "Both"


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
        {
            "CustomFields": {
                "vegaincidentstatus": "INVESTIGATING",
                "vegaverdict": "MALICIOUS",
            }
        },
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


@pytest.mark.parametrize(
    ("selected", "expected"),
    [
        ("None", None),
        ("Incoming", "In"),
        ("Outgoing", "Out"),
        ("Incoming And Outgoing", "Both"),
        ("", None),
        ("unexpected", None),
    ],
)
def test_configured_mirror_direction(selected, expected):
    assert _configured_mirror_direction({"mirror_direction": selected}) == expected


def test_get_mirroring_fields_incoming_and_outgoing(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"mirror_direction": "Incoming And Outgoing"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    fields = _get_mirroring_fields()

    assert fields["mirror_direction"] == "Both"
    assert fields["mirror_instance"] == "Vega_instance_1"


def test_get_mirroring_fields_omits_direction_when_none(mocker):
    mocker.patch.object(
        demisto,
        "params",
        return_value={"mirror_direction": "None"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")

    fields = _get_mirroring_fields()

    assert "mirror_direction" not in fields
    assert fields["mirror_instance"] == "Vega_instance_1"


def test_collect_outgoing_entry_comments_skips_mirror_tagged_notes():
    entries = [
        {"Type": EntryType.NOTE, "Contents": "Analyst note", "Tags": []},
        {
            "Type": EntryType.NOTE,
            "Contents": "From Vega comment",
            "Tags": [VEGA_MIRROR_TAG_FROM_VEGA],
        },
        {
            "Type": EntryType.NOTE,
            "Contents": "To Vega comment",
            "Tags": [VEGA_MIRROR_TAG_TO_VEGA],
        },
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
        "alerts": [
            {
                "id": shared_id,
                "vegaAlertId": "VA-123",
                "updatedAt": "2026-06-15T12:00:00Z",
            }
        ],
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
            {
                "id": "alert-1",
                "vegaAlertId": "VA-1",
                "updatedAt": "2026-06-15T12:00:00Z",
            },
            {
                "id": "alert-2",
                "vegaAlertId": "VA-2",
                "updatedAt": "2026-06-15T12:00:00Z",
            },
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
    assert set(result.modified_incident_ids) == {
        "alert:alert-1",
        "alert:alert-2",
        "alert-1",
        "alert-2",
    }


def test_get_modified_remote_data_command_respects_entity_filter(mocker):
    mocker.patch.object(demisto, "params", return_value={"vega_entities": ["Alerts"]})
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": []}}])
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [
            {
                "id": "alert-1",
                "vegaAlertId": "VA-1",
                "updatedAt": "2026-06-15T12:00:00Z",
            }
        ],
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
    assert _entity_updated_after(
        entity,
        MIRROR_ENTITY_SUFFIX_INCIDENT,
        datetime(2026, 6, 15, 11, 0, 0, tzinfo=UTC),
    )


def test_get_modified_remote_data_command_both_entities(mocker):
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"data": []}}])
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alerts.return_value = {
        "alerts": [
            {
                "id": "alert-1",
                "vegaAlertId": "VA-1",
                "updatedAt": "2026-06-15T12:00:00Z",
            },
            {
                "id": "alert-2",
                "vegaAlertId": "VA-2",
                "updatedAt": "2026-06-15T12:00:00Z",
            },
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    assert "vegaComments" in result.mirrored_object
    assert "Updated in Vega" in result.mirrored_object["vegaComments"]
    assert "Updated in Vega" in result.mirrored_object["CustomFields"]["vegacomments"]
    assert (
        result.mirrored_object["CustomFields"]["vegacommentssource"] == mock_client.get_alert_for_mirror.return_value["comments"]
    )
    assert len(result.entries) >= 1
    assert result.entries[0]["Contents"].startswith("analyst@example.com")
    assert result.entries[0]["Tags"] == [VEGA_MIRROR_TAG_FROM_VEGA]


def test_get_remote_data_command_vega_alert_context_skips_incident_lookup(mocker):
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mock_client.get_alert_for_mirror.return_value = {
        "id": "different-alert-id",
        "detectionId": "det-1",
    }
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
            "data": {
                "type": "Vega Incident",
                "CustomFields": {"vegaincidentid": shared_id},
            },
        },
    )

    mock_client.get_alert_for_mirror.assert_not_called()
    assert "type" not in result.mirrored_object
    assert result.mirrored_object["vegaEntityType"] == "Vega Incident"
    assert result.mirrored_object["CustomFields"]["vegaincidentstatus"] == "INVESTIGATING"


def test_resolve_remote_entity_uses_prefixed_incident_id(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
                    "alerts": [
                        {
                            "id": "alert-1",
                            "status": "OPEN",
                            "updatedAt": "2026-06-15T12:00:00Z",
                        }
                    ],
                    "total": 1,
                }
            }
        },
    )

    alert = client.get_alert_for_mirror("alert-1")

    assert alert["id"] == "alert-1"
    mock_graphql.assert_called_once()
    assert mock_graphql.call_args.args[0] == GET_ALERT_MIRROR_QUERY
    assert mock_graphql.call_args.args[1] == {
        "alertIds": ["alert-1"],
        "limit": 1,
        "offset": 0,
    }


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
                    "alerts": [
                        {
                            "id": "alert-1",
                            "status": "OPEN",
                            "updatedAt": "2026-06-15T12:00:00Z",
                        }
                    ],
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {"id": "alert-1", "status": "OPEN"}

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert:alert-1",
            "incidentChanged": "true",
            "delta": {"CustomFields": {VEGA_ALERT_STATUS_FIELD: {"old": "OPEN", "new": "RESOLVED"}}},
            "data": {
                "type": "Vega Alert",
                "CustomFields": {VEGA_ALERT_STATUS_FIELD: "OPEN"},
            },
        },
    )

    mock_client.update_alerts.assert_called_once_with(
        {
            "alertIds": ["alert-1"],
            "status": "RESOLVED",
        }
    )


def test_mirror_field_changed_in_delta_treats_equivalent_values_as_unchanged():
    delta = {
        "CustomFields": {
            VEGA_ALERT_STATUS_FIELD: {"old": "Open", "new": "OPEN"},
            VEGA_ALERT_SEVERITY_FIELD: {"old": "Critical", "new": "CRITICAL"},
            VEGA_VERDICT_FIELD: {"old": "N/A", "new": "NA"},
        }
    }

    assert _mirror_field_changed_in_delta(VEGA_ALERT_STATUS_FIELD, delta, MIRROR_ENTITY_SUFFIX_ALERT) is False
    assert _mirror_field_changed_in_delta(VEGA_ALERT_SEVERITY_FIELD, delta, MIRROR_ENTITY_SUFFIX_ALERT) is False
    assert _mirror_field_changed_in_delta(VEGA_VERDICT_FIELD, delta, MIRROR_ENTITY_SUFFIX_ALERT) is False


def test_build_outgoing_alert_mirror_update_skips_unchanged_delta_fields():
    update_input = _build_outgoing_alert_mirror_update(
        {
            "CustomFields": {
                VEGA_ALERT_STATUS_FIELD: {"old": "Open", "new": "Open"},
                VEGA_ALERT_SEVERITY_FIELD: {"old": "Critical", "new": "Critical"},
                VEGA_VERDICT_FIELD: {"old": "N/A", "new": "NA"},
            }
        },
        {
            "type": "Vega Alert",
            "CustomFields": {
                VEGA_ALERT_STATUS_FIELD: "Open",
                VEGA_ALERT_SEVERITY_FIELD: "Critical",
                VEGA_VERDICT_FIELD: "N/A",
            },
        },
        None,
    )

    assert update_input == {}


def test_update_remote_system_command_skips_incoming_mirror_echo_updates(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "status": "OPEN",
        "severity": "CRITICAL",
        "verdict": "NA",
    }

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert:alert-1",
            "incidentChanged": "true",
            "delta": {
                "CustomFields": {
                    VEGA_ALERT_STATUS_FIELD: {"old": "Open", "new": "Open"},
                    VEGA_ALERT_SEVERITY_FIELD: {"old": "Critical", "new": "Critical"},
                    VEGA_VERDICT_FIELD: {"old": "N/A", "new": "NA"},
                }
            },
            "data": {
                "type": "Vega Alert",
                "CustomFields": {
                    VEGA_ALERT_STATUS_FIELD: "Open",
                    VEGA_ALERT_SEVERITY_FIELD: "Critical",
                    VEGA_VERDICT_FIELD: "N/A",
                },
            },
        },
    )

    mock_client.update_alerts.assert_not_called()


def test_update_remote_system_command_mirrors_war_room_comment_without_field_echo(
    mocker,
):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "status": "OPEN",
        "severity": "CRITICAL",
    }

    update_remote_system_command(
        mock_client,
        {
            "remoteId": "alert:alert-1",
            "incidentChanged": "true",
            "delta": {
                "CustomFields": {
                    VEGA_ALERT_STATUS_FIELD: {"old": "Open", "new": "Open"},
                    VEGA_ALERT_SEVERITY_FIELD: {"old": "Critical", "new": "Critical"},
                }
            },
            "data": {
                "type": "Vega Alert",
                "CustomFields": {
                    VEGA_ALERT_STATUS_FIELD: "Open",
                    VEGA_ALERT_SEVERITY_FIELD: "Critical",
                },
            },
            "entries": [
                {
                    "Type": EntryType.NOTE,
                    "Contents": "test 1",
                    "Tags": [],
                }
            ],
        },
    )

    mock_client.update_alerts.assert_called_once_with({"alertIds": ["alert-1"], "comment": "test 1"})


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
                    "incidents": [
                        {
                            "id": "inc-1",
                            "status": "INVESTIGATING",
                            "lastUpdated": "2026-06-15T12:00:00Z",
                        }
                    ],
                    "total": 1,
                }
            }
        },
    )

    incident = client.get_incident_for_mirror("inc-1")

    assert incident["id"] == "inc-1"
    mock_graphql.assert_called_once()
    assert mock_graphql.call_args.args[0] == GET_INCIDENT_MIRROR_QUERY
    assert mock_graphql.call_args.args[1] == {
        "incidentIds": ["inc-1"],
        "limit": 1,
        "offset": 0,
    }


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
                    "incidents": [
                        {
                            "id": "inc-1",
                            "status": "INVESTIGATING",
                            "lastUpdated": "2026-06-15T12:00:00Z",
                        }
                    ],
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
    }
    mock_client.get_incident_by_id.return_value = {
        "id": "inc-1",
        "status": "INVESTIGATING",
        "verdictReasoning": "Loaded from details",
    }

    get_remote_data_command(
        mock_client,
        {
            "id": "incident:inc-1",
            "lastUpdate": "2026-06-15T11:00:00Z",
            "data": {"type": "Vega Incident"},
        },
    )

    entity_lookup_filters = _resolve_mirror_entity_lookup_filters()
    detail_lookup_filters = _resolve_mirror_incident_lookup_filters("2026-06-15T11:00:00Z")
    mock_client.get_incident_for_mirror.assert_called_once_with("inc-1", **entity_lookup_filters)
    mock_client.get_incident_by_id.assert_called_once_with("inc-1", **detail_lookup_filters)


def test_suppress_noisy_http_integration_logs_filters_header_lines(mocker):
    import http.client as http_client
    import logging

    mocker.patch("Vega.is_debug_mode", return_value=True)
    captured: list[str] = []
    integration_logger_write = LOG.write
    had_filter_flag = getattr(LOG, "_vega_http_log_filter_installed", False)
    urllib3_logger = logging.getLogger("urllib3")
    previous_urllib3_level = urllib3_logger.level

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
        assert urllib3_logger.level == logging.WARNING
    finally:
        LOG.write = integration_logger_write
        LOG._vega_http_log_filter_installed = had_filter_flag
        urllib3_logger.setLevel(previous_urllib3_level)


def test_get_remote_data_command_not_found_preserves_incident_type(mocker):
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_incident_for_mirror.return_value = {}
    mock_client.get_incident_by_id.return_value = {}

    result = get_remote_data_command(
        mock_client,
        {
            "id": "incident:019e1b27-6d49-7ea1-a9d2-f30bf8c69165",
            "lastUpdate": "2026-06-15T11:00:00Z",
        },
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
        _mirror_entity_type_from_args(
            {"id": "019e1b27-511f-7580-a3a6-063a06c73ecb"},
            "019e1b27-511f-7580-a3a6-063a06c73ecb",
        )
        == "Vega Alert"
    )


def test_update_remote_system_command_pushes_when_platform_calls_it(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "None"})
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
            "delta": {"vegastatus": "RESOLVED"},
            "data": {"type": "Vega Alert", "vegastatus": "RESOLVED"},
        },
    )

    assert remote_id == "alert-1"
    mock_client.update_alerts.assert_called_once()


def test_update_remote_system_command_updates_alert_severity(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "alert-1",
        "status": "OPEN",
        "severity": "LOW",
    }
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
            "delta": {
                "CustomFields": {
                    "vegaincidentstatus": "IN REVIEW",
                    "vegaverdict": "BENIGN",
                }
            },
            "data": {
                "type": "Vega Incident",
                "CustomFields": {
                    "vegaincidentstatus": "IN REVIEW",
                    "vegaverdict": "BENIGN",
                },
            },
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "userStatus": "IN_REVIEW",
            "verdict": {"value": "BENIGN", "reasoning": ""},
        }
    )


@pytest.mark.parametrize(
    ("selected", "expected_direction"),
    [
        ("None", None),
        ("Incoming", "In"),
        ("Outgoing", "Out"),
        ("Incoming And Outgoing", "Both"),
    ],
)
def test_alert_to_incident_sets_mirror_metadata(mocker, selected, expected_direction):
    mocker.patch.object(demisto, "integrationInstance", return_value="Vega_instance_1")
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": selected})
    alert = {
        "id": "alert-1",
        "name": "Test Alert",
        "severity": "HIGH",
        "createdAt": TIMESTAMP_T1,
    }
    xsoar_incident = alert_to_incident(alert)
    raw = json.loads(xsoar_incident["rawJSON"])

    assert xsoar_incident["dbotMirrorId"] == "alert:alert-1"
    assert xsoar_incident["dbotMirrorInstance"] == "Vega_instance_1"
    assert raw["mirror_instance"] == "Vega_instance_1"
    if expected_direction is None:
        assert "dbotMirrorDirection" not in xsoar_incident
        assert "mirror_direction" not in raw
    else:
        assert xsoar_incident["dbotMirrorDirection"] == expected_direction
        assert raw["mirror_direction"] == expected_direction


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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch("Vega.load_current_incident", return_value={"type": "Vega Alert"})
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "019e1b27-511f-7580-a3a6-065e9e623a1a",
        "status": "OPEN",
    }
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
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
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
            "delta": {"vegaincidentstatus": "IN REVIEW"},
            "data": {"CustomFields": {"vegaincidentstatus": "OPEN"}},
        },
    )

    mock_client.update_incidents.assert_called_once_with(
        {
            "incidentIds": ["inc-1"],
            "userStatus": "IN_REVIEW",
        }
    )
    mock_client.update_alerts.assert_not_called()


def test_update_remote_system_command_uses_api_fallback_without_investigation_context(
    mocker,
):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch(
        "Vega.demisto.incident",
        side_effect=TypeError("'NoneType' object is not subscriptable"),
    )
    load_current_incident = mocker.patch("Vega.load_current_incident")
    mocker.patch.object(demisto, "debug")
    mock_client = mocker.Mock(spec=Client)
    mock_client.get_alert_for_mirror.return_value = {
        "id": "019e1b27-5128-7633-9b70-782afb20f198",
        "status": "OPEN",
    }
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


def test_validate_lookback_minutes_accepts_valid_range():
    from Vega import validate_lookback_minutes

    validate_lookback_minutes(1)
    validate_lookback_minutes(30)
    validate_lookback_minutes(60)
    validate_lookback_minutes("15")


def test_validate_lookback_minutes_rejects_invalid_values():
    from Vega import validate_lookback_minutes
    import pytest

    with pytest.raises(ValueError, match="Fetch Lookback"):
        validate_lookback_minutes(0)
    with pytest.raises(ValueError, match="Fetch Lookback"):
        validate_lookback_minutes(61)
    with pytest.raises(ValueError, match="Invalid number"):
        validate_lookback_minutes("not-a-number")
    with pytest.raises(ValueError, match="Fetch Lookback"):
        validate_lookback_minutes(None)


def test_test_module_rejects_invalid_lookback_minutes(mocker):
    from Vega import Client, test_module as vega_test_module

    mocker.patch("Vega.demisto.getIntegrationContext", return_value={})
    mocker.patch("Vega.demisto.setIntegrationContext")
    mocker.patch("Vega.demisto.info")

    client = Client(
        base_url="https://test.com",
        verify=False,
        proxy=False,
        access_key="test-key",
        access_key_id="test-key-id",
    )

    assert (
        vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=0)
        == "Fetch Lookback (minutes) must be an integer between 1 and 60."
    )
    assert (
        vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes=61)
        == "Fetch Lookback (minutes) must be an integer between 1 and 60."
    )
    assert (
        vega_test_module(client, backfill_days=30, max_fetch=50, lookback_minutes="abc")
        == 'Invalid number: "lookback_minutes"="abc"'
    )


def test_id_queries_select_only_uuid():
    assert "alerts { id }" in GET_ALERT_IDS_QUERY
    assert "incidents { id }" in GET_INCIDENT_IDS_QUERY
    assert "comments" not in GET_ALERT_IDS_QUERY
    assert "comments" not in GET_INCIDENT_IDS_QUERY


def test_parse_comma_separated_ids_trims_and_dedupes():
    assert _parse_comma_separated_ids(" a-1, a-2,a-1 , ,a-3 ") == ["a-1", "a-2", "a-3"]


def test_parse_reconcile_window_maps_dates_to_vega_from_and_to():
    start_time, end_time = _parse_reconcile_window({"start_date": "2024-06-01", "end_date": "2024-06-02"})
    assert start_time == "2024-06-01T00:00:00Z"
    assert end_time == "2024-06-02T23:59:59Z"


def test_parse_reconcile_window_rejects_inverted_range():
    with pytest.raises(DemistoException, match="start_date must be before"):
        _parse_reconcile_window({"start_date": "2024-06-03", "end_date": "2024-06-01"})


def test_collect_paged_ids_follows_total():
    pages = {
        0: {"alerts": [{"id": f"a-{index}"} for index in range(RECONCILE_PAGE_SIZE)], "total": RECONCILE_PAGE_SIZE + 1},
        RECONCILE_PAGE_SIZE: {"alerts": [{"id": "a-last"}], "total": RECONCILE_PAGE_SIZE + 1},
    }

    ids = _collect_paged_ids(lambda offset: pages[offset], "alerts", _normalize_entity_id)

    assert ids[-1] == "a-last"
    assert len(ids) == RECONCILE_PAGE_SIZE + 1


def test_collect_paged_ids_continues_after_short_page_when_total_remains():
    def fetch_page(offset: int) -> dict:
        if offset == 0:
            return {"alerts": [{"id": "a-1"}], "total": 2}
        return {"alerts": [{"id": "a-2"}], "total": 2}

    ids = _collect_paged_ids(fetch_page, "alerts", _normalize_entity_id)

    assert ids == ["a-1", "a-2"]


def test_collect_paged_ids_reads_past_the_former_page_cap():
    page_count = 51
    total = RECONCILE_PAGE_SIZE * page_count

    def fetch_page(offset: int) -> dict:
        return {
            "alerts": [{"id": f"a-{offset + index}"} for index in range(RECONCILE_PAGE_SIZE)],
            "total": total,
        }

    ids = _collect_paged_ids(fetch_page, "alerts", _normalize_entity_id)

    assert len(ids) == total
    assert ids[0] == "a-0"
    assert ids[-1] == f"a-{total - 1}"


def test_collect_xsoar_entity_ids_reads_every_vega_incident_and_alert(mocker):
    page_count = 51
    total = RECONCILE_PAGE_SIZE * page_count
    pages_requested: dict[str, list[int]] = {"Vega Incident": [], "Vega Alert": []}

    def search(_method, _uri, body=None):
        payload = json.loads(body)
        query = payload["filter"]["query"]
        page = payload["filter"]["page"]
        entity_type = "Vega Incident" if 'type:"Vega Incident"' in query else "Vega Alert"
        suffix = "incident" if entity_type == "Vega Incident" else "alert"
        pages_requested[entity_type].append(page)
        start = page * RECONCILE_PAGE_SIZE
        data = [{"dbotMirrorId": f"{suffix}:id-{start + index}", "type": entity_type} for index in range(RECONCILE_PAGE_SIZE)]
        return {"statusCode": 200, "body": json.dumps({"data": data, "total": total})}

    mocker.patch("Vega.demisto.internalHttpRequest", side_effect=search)

    incident_ids = _collect_xsoar_entity_ids("Vega Incident", "incident", "2024-06-01T00:00:00Z", "2024-06-02T23:59:59Z")
    alert_ids = _collect_xsoar_entity_ids("Vega Alert", "alert", "2024-06-01T00:00:00Z", "2024-06-02T23:59:59Z")

    assert len(incident_ids) == total
    assert len(alert_ids) == total
    assert pages_requested["Vega Incident"] == list(range(page_count))
    assert pages_requested["Vega Alert"] == list(range(page_count))
    assert "id-0" in incident_ids
    assert f"id-{total - 1}" in alert_ids


def test_xsoar_vega_entity_id_uses_mirror_uuid_not_display_id():
    incident = {
        "dbotMirrorId": "alert:uuid-1",
        "CustomFields": {"vegaalertid": "VEGA-1", "alertid": "other"},
    }
    assert _xsoar_vega_entity_id(incident, "alert") == "uuid-1"


def test_reconcile_incidents_command_returns_missing_uuids(mocker):
    client = mocker.Mock()
    client.get_alert_ids.return_value = {"alerts": [{"id": "a-1"}, {"id": "a-2"}], "total": 2}
    client.get_incident_ids.return_value = {"incidents": [{"id": "i-1"}, {"id": "i-2"}], "total": 2}

    def search(_method, _uri, body=None):
        payload = json.loads(body)
        query = payload["filter"]["query"]
        assert payload["filter"]["size"] == RECONCILE_PAGE_SIZE
        if 'type:"Vega Alert"' in query:
            data = [{"dbotMirrorId": "alert:a-1", "type": "Vega Alert"}]
        else:
            data = [{"CustomFields": {"vegaincidentid": "i-1"}, "type": "Vega Incident"}]
        return {"statusCode": 200, "body": json.dumps({"data": data, "total": 1})}

    mocker.patch("Vega.demisto.internalHttpRequest", side_effect=search)
    result = reconcile_incidents_command(
        client,
        {
            "start_date": "2024-06-01",
            "end_date": "2024-06-02",
            "vega_entities": "Alerts,Incidents",
            "alert_severities": "HIGH",
        },
    )

    assert result.outputs["MissingAlertIds"] == ["a-2"]
    assert result.outputs["MissingIncidentIds"] == ["i-2"]
    assert list(result.outputs).index("MissingIncidentIds") < list(result.outputs).index("MissingAlertIds")
    assert "Truncated" not in result.outputs
    assert result.readable_output.index("Missing Vega incident IDs") < result.readable_output.index("Missing Vega alert IDs")
    assert "a-2" in result.readable_output
    assert "i-2" in result.readable_output
    assert client.get_alert_ids.call_args.kwargs["from_time"] == "2024-06-01T00:00:00Z"
    assert client.get_alert_ids.call_args.kwargs["to_time"] == "2024-06-02T23:59:59Z"
    assert client.get_alert_ids.call_args.kwargs["limit"] == RECONCILE_PAGE_SIZE
    assert client.get_alert_ids.call_args.kwargs["severities"] == ["HIGH"]
    assert "has_related_incidents" not in client.get_alert_ids.call_args.kwargs
    assert "statuses" not in client.get_alert_ids.call_args.kwargs or client.get_alert_ids.call_args.kwargs["statuses"] is None


def test_reconcile_incidents_command_skips_unselected_entity(mocker):
    """Alert filters are ignored when Alerts is not selected."""
    client = mocker.Mock()
    client.get_incident_ids.return_value = {"incidents": [{"id": "i-1"}], "total": 1}
    queries: list[str] = []

    def search(_method, _uri, body=None):
        query = json.loads(body)["filter"]["query"]
        queries.append(query)
        return {"statusCode": 200, "body": json.dumps({"data": [], "total": 0})}

    mocker.patch("Vega.demisto.internalHttpRequest", side_effect=search)
    result = reconcile_incidents_command(
        client,
        {
            "start_date": "2024-06-01T12:00:00Z",
            "end_date": "2024-06-02T18:30:00Z",
            "vega_entities": "Incidents",
            "alert_severities": "HIGH",
        },
    )

    client.get_alert_ids.assert_not_called()
    assert queries
    assert all('type:"Vega Alert"' not in query for query in queries)
    assert "MissingAlertIds" not in result.outputs
    assert result.outputs["MissingIncidentIds"] == ["i-1"]
    assert client.get_incident_ids.call_args.kwargs["from_time"] == "2024-06-01T12:00:00Z"
    assert client.get_incident_ids.call_args.kwargs["to_time"] == "2024-06-02T18:30:00Z"


def test_reconcile_incidents_command_requires_an_entity(mocker):
    with pytest.raises(DemistoException, match="vega_entities"):
        reconcile_incidents_command(mocker.Mock(), {"start_date": "2024-06-01", "end_date": "2024-06-02"})


def _patch_reconciliation_runtime(mocker):
    mocker.patch("Vega.demisto.params", return_value={})
    mocker.patch("Vega.demisto.integrationInstance", return_value="reconcile")
    mocker.patch("Vega.demisto.info")
    mocker.patch("Vega._fetch_incident_timeline_events", return_value=[])
    mocker.patch("Vega._fetch_alert_events_for_ids", return_value={})


def test_fetch_reconciliation_uses_static_from_and_max_fetch(mocker):
    _patch_reconciliation_runtime(mocker)
    client = mocker.Mock()
    client.get_incidents.return_value = {
        "incidents": [{"id": "i-1", "name": "One", "createdAt": "2024-06-01T00:00:00Z", "severity": "LOW"}],
        "total": 1,
    }

    next_run, incidents = fetch_reconciliation_incidents_command(
        client,
        last_run={"alerts_last_fetch": "keep-me"},
        alert_ids=["a-1"],
        incident_ids=["i-1", "i-2"],
        max_fetch=1,
        integration_url="https://vega.example",
    )

    client.get_incidents.assert_called_once_with(
        incident_ids=["i-1"],
        from_time=INCIDENT_ID_LOOKUP_FROM_TIME,
        limit=1,
        offset=0,
    )
    client.get_alerts.assert_not_called()
    assert "severities" not in client.get_incidents.call_args.kwargs
    assert next_run["alerts_last_fetch"] == "keep-me"
    assert next_run[RECONCILE_COMPLETED_INCIDENTS_KEY] == ["i-1"]
    assert len(incidents) == 1
    assert incidents[0]["dbotMirrorId"] == "incident:i-1"


def test_fetch_reconciliation_marks_missing_ids_and_does_not_retry(mocker):
    _patch_reconciliation_runtime(mocker)
    client = mocker.Mock()
    client.get_incidents.return_value = {
        "incidents": [{"id": "i-1", "name": "One", "createdAt": "2024-06-01T00:00:00Z", "severity": "LOW"}],
        "total": 1,
    }
    client.get_alerts.return_value = {"alerts": [], "total": 0}

    next_run, created = fetch_reconciliation_incidents_command(
        client,
        last_run={},
        alert_ids=["a-missing"],
        incident_ids=["i-1"],
        max_fetch=50,
        integration_url="https://vega.example",
    )
    assert next_run[RECONCILE_NOT_FOUND_ALERTS_KEY] == ["a-missing"]
    assert next_run[RECONCILE_COMPLETED_ALERTS_KEY] == []
    assert len(created) == 1

    next_run, created_again = fetch_reconciliation_incidents_command(
        client,
        last_run=next_run,
        alert_ids=["a-missing"],
        incident_ids=["i-1"],
        max_fetch=50,
        integration_url="https://vega.example",
    )

    assert created_again == []
    assert client.get_alerts.call_count == 1
    assert client.get_incidents.call_count == 1


def test_fetch_reconciliation_leaves_ids_pending_on_transient_error(mocker):
    _patch_reconciliation_runtime(mocker)
    mocker.patch("Vega.demisto.error")
    client = mocker.Mock()
    client.get_alerts.side_effect = DemistoException("connection timeout error")

    next_run, created = fetch_reconciliation_incidents_command(
        client,
        last_run={},
        alert_ids=["a-1"],
        incident_ids=[],
        max_fetch=50,
    )

    assert created == []
    assert next_run[RECONCILE_NOT_FOUND_ALERTS_KEY] == []
    assert next_run[RECONCILE_COMPLETED_ALERTS_KEY] == []


def _invalid_uuid_exception(detail: str) -> DemistoException:
    payload = {
        "message": "Invalid request fields",
        "extensions": {
            "error_code": "E000000057",
            "error_code_name": "INVALID_REQUEST_FIELDS",
            "extra_args": {"error": detail},
            "trace_id": 1,
        },
    }
    return DemistoException(f"GraphQL error: {[payload]}")


def test_fetch_reconciliation_skips_invalid_uuid_and_fetches_the_rest(mocker):
    """One invalid UUID is logged and skipped. Valid IDs in the same list are still fetched."""
    _patch_reconciliation_runtime(mocker)
    info = mocker.patch("Vega.demisto.info")
    error = mocker.patch("Vega.demisto.error")
    good_id = "019e1b27-6d49-7ea1-a9d2-f30bf8c69165"
    bad_incident_id = "sdfsdfsafasdfsdfsda"
    bad_alert_id = "asdfsdf"
    client = mocker.Mock()

    def get_incidents(**kwargs):
        if bad_incident_id in kwargs["incident_ids"]:
            raise _invalid_uuid_exception(f'incidentIds entry "{bad_incident_id}" is not a valid UUID')
        return {
            "incidents": [{"id": good_id, "name": "One", "createdAt": "2024-06-01T00:00:00Z", "severity": "LOW"}],
            "total": 1,
        }

    client.get_incidents.side_effect = get_incidents
    client.get_alerts.side_effect = _invalid_uuid_exception(f'alertIds "{bad_alert_id}" is not a valid UUID')

    next_run, created = fetch_reconciliation_incidents_command(
        client,
        last_run={},
        alert_ids=[bad_alert_id],
        incident_ids=[bad_incident_id, good_id],
        max_fetch=50,
        integration_url="https://vega.example",
    )

    assert [incident["dbotMirrorId"] for incident in created] == [f"incident:{good_id}"]
    assert next_run[RECONCILE_COMPLETED_INCIDENTS_KEY] == [good_id]
    assert next_run[RECONCILE_NOT_FOUND_INCIDENTS_KEY] == [bad_incident_id]
    assert next_run[RECONCILE_NOT_FOUND_ALERTS_KEY] == [bad_alert_id]
    error_lines = [call.args[0] for call in error.call_args_list]
    assert f"Skipped incident ID '{bad_incident_id}' because it is not a valid UUID." in error_lines[0]
    assert f"Skipped alert ID '{bad_alert_id}' because it is not a valid UUID." in error_lines[1]
    assert all("GraphQL" not in line and "trace_id" not in line for line in error_lines)
    assert "Fetched 1 Vega incident." in [call.args[0] for call in info.call_args_list]

    info.reset_mock()
    client.get_incidents.reset_mock()
    client.get_alerts.reset_mock()
    _, created_again = fetch_reconciliation_incidents_command(
        client,
        last_run=next_run,
        alert_ids=[bad_alert_id],
        incident_ids=[bad_incident_id, good_id],
        max_fetch=50,
        integration_url="https://vega.example",
    )

    assert created_again == []
    client.get_incidents.assert_not_called()
    client.get_alerts.assert_not_called()
    assert "No Vega incidents or alerts were fetched." in [call.args[0] for call in info.call_args_list]


def test_fetch_reconciliation_skips_uuid_error_that_uses_single_quotes(mocker):
    _patch_reconciliation_runtime(mocker)
    mocker.patch("Vega.demisto.error")
    bad_id = "019e1b27-6d49-7ea1-a9d2-f30bf8c69165rtrtrfiyf t"
    client = mocker.Mock()
    client.get_incidents.side_effect = _invalid_uuid_exception(f"incidents entry '{bad_id}' is not valid UUID")

    next_run, created = fetch_reconciliation_incidents_command(
        client,
        last_run={},
        alert_ids=[],
        incident_ids=[bad_id],
        max_fetch=50,
    )

    assert created == []
    assert next_run[RECONCILE_NOT_FOUND_INCIDENTS_KEY] == [bad_id]


def test_fetch_reconciliation_still_fails_on_other_graphql_errors(mocker):
    _patch_reconciliation_runtime(mocker)
    client = mocker.Mock()
    client.get_alerts.side_effect = DemistoException("GraphQL error: [{'message': 'Something else'}]")

    with pytest.raises(DemistoException, match="Something else"):
        fetch_reconciliation_incidents_command(
            client,
            last_run={},
            alert_ids=["a-1"],
            incident_ids=[],
            max_fetch=50,
        )
