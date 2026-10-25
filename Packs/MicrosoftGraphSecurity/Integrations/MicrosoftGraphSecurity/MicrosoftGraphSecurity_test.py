from datetime import datetime, timezone
import itertools
import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, CommandResults, EntryFormat, EntryType, PollResult
from MicrosoftGraphSecurity import (
    MANAGED_IDENTITIES_TOKEN_URL,
    XSOAR_FIELD_TO_GRAPH_KEY,
    format_close_comment,
    MsGraphClient,
    Resources,
    activate_ediscovery_custodian_command,
    advanced_hunting_command,
    capitalize_dict_keys_first_letter,
    close_ediscovery_case_command,
    create_alert_comment_command,
    create_data_to_update,
    create_ediscovery_non_custodial_data_source_command,
    create_email_file_request_command,
    create_file_assessment_request_command,
    create_filter_query,
    create_mail_assessment_request_command,
    create_search_alerts_filters,
    create_url_assessment_request_command,
    created_by_fields_to_hr,
    fetch_alerts,
    fetch_incidents,
    fetch_incidents_and_alerts,
    get_alert_details_command,
    get_list_security_incident_command,
    get_message_user,
    get_users_command,
    list_ediscovery_case_command,
    list_ediscovery_custodian_command,
    list_ediscovery_custodian_site_sources_command,
    list_ediscovery_non_custodial_data_source_command,
    list_ediscovery_search_command,
    list_threat_assessment_requests_command,
    main,
    purge_ediscovery_data_command,
    release_ediscovery_custodian_command,
    reopen_ediscovery_case_command,
    search_alerts_command,
    set_url_suffix_list_incidents,
    to_msg_command_results,
    update_ediscovery_case_command,
    update_ediscovery_search_command,
    update_incident_command,
    create_ediscovery_case_hold_policy_command,
    delete_ediscovery_case_hold_policy_command,
    update_ediscovery_case_policy_command,
    list_ediscovery_case_hold_policy_command,
    list_case_operation_command,
    _extract_export_download_url,
    _extract_filename_from_headers,
    _download_operation_export_file,
    export_result_ediscovery_data_command,
    to_utc_datetime,
    run_estimate_statistics_command,
    _get_last_estimate_statistics_command,
    build_close_entry,
    get_close_entry,
    to_xsoar_close_reason,
    get_entries_for_comments,
    get_mapping_fields_command,
    get_mirroring_fields,
    get_modified_remote_data_command,
    get_remote_data_command,
    get_remote_data_wrapper_command,
    normalize_get_remote_data_args,
    infer_mirror_type,
    update_remote_system_command,
    to_graph_delta_keys,
    MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR,
    ALERT_PATCH_KEYS,
    INCIDENT_PATCH_KEYS,
    OUTGOING_ALERT_FIELDS,
    SEVERITY_MAP,
    additional_data_to_custom_details,
    apply_classification_label,
    build_patch_body,
    custom_details_to_list,
    strip_remote_id_suffix,
    get_delta_close_notes,
    add_mirror_marker,
    has_close_fields,
    is_open_graph_status,
    is_xsoar_incident_closed,
    test_function as msg_test_function,  # aliased so pytest does not collect it as a test
    validate_mirroring_comment_tags,
)

client_mocker = MsGraphClient(
    tenant_id="tenant_id",
    auth_id="auth_id",
    enc_key="enc_key",
    app_name="app_name",
    base_url="url",
    verify="use_ssl",
    proxy="proxy",
    self_deployed="self_deployed",
)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize(
    "api_response, keys_to_replace, expected_output",
    [
        (
            {"keyOne": {"keyTwo": {"keyThree": "a"}, "keyFour": {"keyFive": "b"}}},
            {},
            {"KeyOne": {"KeyFour": {"KeyFive": "b"}, "KeyTwo": {"KeyThree": "a"}}},
        ),
        (
            {"keyOne": {"keyTwo": "a"}, "customOverride": "a"},
            {"customOverride": "SOMETHING"},
            {"KeyOne": {"KeyTwo": "a"}, "SOMETHING": "a"},
        ),
    ],
)
def test_capitalize_dict_keys_first_letter(api_response, keys_to_replace, expected_output):
    """
    Given
        a response from the api
    When
        calling capitalize_dict_keys_first_letter with optional keys_to_replace
    Then
        Results are recursively formatted, manual keys are replaces

    """
    assert capitalize_dict_keys_first_letter(api_response, keys_to_replace) == expected_output


def test_get_users_command(mocker):
    test_data = load_json("./test_data/test_get_users_command.json")
    mocker.patch.object(client_mocker, "get_users", return_value=test_data.get("raw_user_data"))
    hr, ec, _ = get_users_command(client_mocker, {})
    assert hr == test_data.get("expected_hr")
    assert ec == test_data.get("expected_ec")


@pytest.mark.parametrize("test_case", ["test_case_3"])
def test_get_alert_details_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args including alert_id, response mock, expected hr and ec outputs.
    - Case 3: args with alert_id, response of an Alerts v2 alert.

    When:
    - Running get_alert_details_command.

    Then:
    - Ensure that the alert was parsed correctly and right HR and EC outputs are returned.
    - Case 3: Should parse all the response information into the HR,
              and all fields from the response into the ec.
    """
    test_data = load_json("./test_data/test_get_alert_details_command.json").get(test_case)
    mocker.patch.object(client_mocker, "get_alert_details", return_value=test_data.get("mock_response"))
    hr, ec, _ = get_alert_details_command(client_mocker, test_data.get("args"))
    assert hr == test_data.get("expected_hr")
    assert ec == test_data.get("expected_ec")


@pytest.mark.parametrize(
    "test_case",
    [
        "test_case_2",
    ],
)
def test_search_alerts_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args, response mock, expected hr and ec outputs.
    - Case 2: args with limit of 1 incident, response of a search_alert command results with 2 alerts.

    When:
    - Running search_alerts_command.

    Then:
    - Ensure that the response was parsed correctly and right HR and EC outputs are returned.
    - Case 2: Should concat the second incident from the response,
              parse all only the first incident response information into the HR,
              and all fields from the first incident response into the ec.
    """
    test_data = load_json("./test_data/test_search_alerts_command.json").get(test_case)
    mocker.patch.object(client_mocker, "search_alerts", return_value=test_data.get("mock_response"))
    hr, ec, _ = search_alerts_command(client_mocker, test_data.get("args"))
    assert hr == test_data.get("expected_hr")
    assert ec == test_data.get("expected_ec")


@pytest.mark.parametrize(
    "test_case",
    [
        "test_case_1",
    ],
)
def test_fetch_alerts_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include a response mock.
    - Case 1: Response of a search_alert command results.

    When:
    - Running fetch_alerts.

    Then:
    - Ensure that the length of the results and the different fields of the fetched alerts are returned correctly.
    - Case 1: Ensure that the len of the alerts returned in the first iteration is 3, then 1 and then 0.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19 08:14:21", "never mind"))
    test_data = load_json("./test_data/test_fetch_incidents_command.json").get(test_case)
    mocker.patch.object(client_mocker, "search_alerts", return_value=test_data.get("mock_response"))
    alerts, _ = fetch_alerts(client_mocker, fetch_time="1 hour", fetch_limit=10, extra_filter="", service_sources="", last_run={})
    assert len(alerts) == 3
    assert alerts[0].get("severity") == 2
    assert alerts[2].get("occurred") == "2020-04-20T16:54:50.2722072Z"

    alerts, _ = fetch_alerts(client_mocker, fetch_time="1 hour", fetch_limit=1, extra_filter="", service_sources="", last_run={})
    assert len(alerts) == 1
    assert alerts[0].get("name") == "test alert - da637218501473413212_-1554891308"

    alerts, _ = fetch_alerts(client_mocker, fetch_time="1 hour", fetch_limit=0, extra_filter="", service_sources="", last_run={})
    assert len(alerts) == 0


def test_fetch_incidents_command(mocker):
    """
    Given:
    - A mocked /security/incidents response with two incidents, each embedding its alerts.

    When:
    - Running fetch_incidents with an empty last_run.

    Then:
    - Both incidents are mapped to XSOAR incidents (name/occurred/severity/rawJSON).
    - The severity is mapped via SEVERITY_MAP and the embedded alerts are kept in rawJSON.
    - The returned last_run advances to the newest incident's createdDateTime.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "never mind"))
    mock_response = {
        "value": [
            {
                "id": "1",
                "displayName": "Incident One",
                "createdDateTime": "2020-04-20T10:00:00.0000000Z",
                "severity": "medium",
                "alerts": [{"id": "a1", "title": "alert one"}],
            },
            {
                "id": "2",
                "displayName": "Incident Two",
                "createdDateTime": "2020-04-20T11:00:00.0000000Z",
                "severity": "informational",
                "alerts": [{"id": "a2", "title": "alert two"}],
            },
        ]
    }
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=mock_response)

    incidents, new_last_run = fetch_incidents(client_mocker, fetch_time="1 hour", fetch_limit=10, extra_filter="", last_run={})

    assert len(incidents) == 2
    assert incidents[0].get("name") == "Incident One - 1"
    assert incidents[0].get("severity") == 2
    assert incidents[1].get("severity") == 0.5
    assert '"alerts"' in incidents[0].get("rawJSON")
    assert new_last_run.get("time") == "2020-04-20T11:00:00.0000000Z"


def test_fetch_incidents_command_dedup_by_last_run(mocker):
    """
    Given:
    - A last_run cursor set to the first incident's createdDateTime.

    When:
    - Running fetch_incidents.

    Then:
    - Only the newer incident (created after the cursor) is returned.
    """
    mock_response = {
        "value": [
            {"id": "1", "displayName": "Old", "createdDateTime": "2020-04-20T10:00:00.0000000Z", "severity": "low"},
            {"id": "2", "displayName": "New", "createdDateTime": "2020-04-20T11:00:00.0000000Z", "severity": "high"},
        ]
    }
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=mock_response)

    incidents, _ = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        last_run={"time": "2020-04-20T10:00:00.0000000Z"},
    )

    assert len(incidents) == 1
    assert incidents[0].get("name") == "New - 2"


def test_fetch_incidents_and_alerts_selection_gating(mocker):
    """
    Given:
    - The "Fetch incidents type" parameter set to "Incidents" only.

    When:
    - Running fetch_incidents_and_alerts.

    Then:
    - Only fetch_incidents is called (alerts are not fetched).
    - The combined last run is persisted under the per-type "incidents_last_run" key.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    fetch_alerts_mock = mocker.patch(
        "MicrosoftGraphSecurity.fetch_alerts", return_value=([{"name": "alert"}], {"time": "alerts_cursor"})
    )
    fetch_incidents_mock = mocker.patch(
        "MicrosoftGraphSecurity.fetch_incidents", return_value=([{"name": "incident"}], {"time": "incidents_cursor"})
    )

    result = fetch_incidents_and_alerts(client_mocker, {"fetch_incidents_type": "Incidents"})

    assert fetch_alerts_mock.call_count == 0
    assert fetch_incidents_mock.call_count == 1
    assert result == [{"name": "incident"}]
    set_last_run.assert_called_once_with({"incidents_last_run": {"time": "incidents_cursor"}})


def test_fetch_incidents_and_alerts_both_types(mocker):
    """
    Given:
    - The "Fetch incidents type" parameter set to both "Alerts,Incidents".

    When:
    - Running fetch_incidents_and_alerts.

    Then:
    - Both fetchers are called and their results combined.
    - Each type's cursor is stored under its own last-run key.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch("MicrosoftGraphSecurity.fetch_alerts", return_value=([{"name": "alert"}], {"time": "alerts_cursor"}))
    mocker.patch("MicrosoftGraphSecurity.fetch_incidents", return_value=([{"name": "incident"}], {"time": "incidents_cursor"}))

    result = fetch_incidents_and_alerts(client_mocker, {"fetch_incidents_type": "Alerts,Incidents"})

    assert {"name": "alert"} in result
    assert {"name": "incident"} in result
    set_last_run.assert_called_once_with(
        {"alerts_last_run": {"time": "alerts_cursor"}, "incidents_last_run": {"time": "incidents_cursor"}}
    )


def test_fetch_incidents_and_alerts_migrates_old_flat_last_run(mocker):
    """
    Given:
    - An instance that was upgraded from a version storing the old flat last_run format: {"time": "..."}.

    When:
    - Running fetch_incidents_and_alerts for both types.

    Then:
    - The old flat cursor is migrated to the new nested format and passed to both fetchers,
      so the whole fetch window is not re-fetched (preventing duplicate incidents).
    """
    old_time = "2020-04-20T10:00:00.0000000Z"
    mocker.patch.object(demisto, "getLastRun", return_value={"time": old_time})
    mocker.patch.object(demisto, "setLastRun")
    fetch_alerts_mock = mocker.patch("MicrosoftGraphSecurity.fetch_alerts", return_value=([], {"time": old_time}))
    fetch_incidents_mock = mocker.patch("MicrosoftGraphSecurity.fetch_incidents", return_value=([], {"time": old_time}))

    fetch_incidents_and_alerts(client_mocker, {"fetch_incidents_type": "Alerts,Incidents"})

    assert fetch_alerts_mock.call_args.kwargs["last_run"] == {"time": old_time}
    assert fetch_incidents_mock.call_args.kwargs["last_run"] == {"time": old_time}


@pytest.mark.parametrize(
    "extra_data, should_expand",
    [("true", True), ("false", False), (None, False)],
)
def test_set_url_suffix_list_incidents_extra_data(extra_data, should_expand):
    """
    Given:
    - The msg-list-security-incident args, with the extra_data arg set to true/false/unset.

    When:
    - Building the request URL suffix.

    Then:
    - $expand=alerts is included only when extra_data is true.
    """
    args = {"limit": "50"}
    if extra_data is not None:
        args["extra_data"] = extra_data

    url_suffix = set_url_suffix_list_incidents(args)

    assert ("$expand=alerts" in url_suffix) is should_expand


def test_set_url_suffix_list_incidents_extra_data_with_filter():
    """
    Given:
    - extra_data=true together with a typed filter (severity).

    When:
    - Building the request URL suffix.

    Then:
    - Both $expand=alerts and the $filter clause are present.
    """
    args = {"limit": "50", "extra_data": "true", "severity": "high"}

    url_suffix = set_url_suffix_list_incidents(args)

    assert "$expand=alerts" in url_suffix
    assert "$filter=severity eq 'high'" in url_suffix


def test_fetch_incidents_does_not_mutate_last_run(mocker):
    """
    Given:
    - A last_run dict passed to fetch_incidents.

    When:
    - Running fetch_incidents and it advances the cursor.

    Then:
    - The original last_run argument is not mutated (a copy is returned instead).
    """
    mock_response = {
        "value": [
            {"id": "2", "displayName": "New", "createdDateTime": "2020-04-20T11:00:00.0000000Z", "severity": "high"},
        ]
    }
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=mock_response)

    original_last_run = {"time": "2020-04-20T10:00:00.0000000Z"}
    _, new_last_run = fetch_incidents(
        client_mocker, fetch_time="1 hour", fetch_limit=10, extra_filter="", last_run=original_last_run
    )

    assert original_last_run == {"time": "2020-04-20T10:00:00.0000000Z"}
    assert new_last_run is not original_last_run
    assert new_last_run.get("time") == "2020-04-20T11:00:00.0000000Z"


def test_fetch_alerts_does_not_mutate_last_run(mocker):
    """
    Given:
    - A last_run dict passed to fetch_alerts.

    When:
    - Running fetch_alerts and it advances the cursor.

    Then:
    - The original last_run argument is not mutated (a copy is returned instead).
    """
    mock_response = {
        "value": [
            {"id": "2", "title": "New", "createdDateTime": "2020-04-20T11:00:00.0000000Z", "severity": "high"},
        ]
    }
    mocker.patch.object(client_mocker, "search_alerts", return_value=mock_response)

    original_last_run = {"time": "2020-04-20T10:00:00.0000000Z"}
    _, new_last_run = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run=original_last_run,
    )

    assert original_last_run == {"time": "2020-04-20T10:00:00.0000000Z"}
    assert new_last_run is not original_last_run
    assert new_last_run.get("time") == "2020-04-20T11:00:00.0000000Z"


def test_fetch_alerts_subsecond_ordering_and_deduplication(mocker):
    """
    Given:
    - 10 alerts occurring within the exact same second with varying fractional seconds,
      including one ending in 'Z' (e.g. 12:40:42Z) and others with microsecond precision.
    - Multiple alerts sharing identical timestamps.

    When:
    - Running fetch_alerts across two consecutive runs.

    Then:
    - Alerts are sorted chronologically: '12:40:42Z' (12:40:42.000Z) is not placed after '12:40:42.23Z'.
    - The true latest timestamp ('12:40:42.23Z') is recorded as new_last_run['time'].
    - In Run 2, alerts sharing that same timestamp are deduplicated by ID, and new alerts are fetched.
    """
    timestamps = [
        "2026-09-08T12:40:41.99Z",
        "2026-09-08T12:40:42.0066667Z",
        "2026-09-08T12:40:42.01Z",
        "2026-09-08T12:40:42.1133333Z",
        "2026-09-08T12:40:42.1133333Z",
        "2026-09-08T12:40:42.11Z",
        "2026-09-08T12:40:42.11Z",
        "2026-09-08T12:40:42.2266667Z",
        "2026-09-08T12:40:42.23Z",
        "2026-09-08T12:40:42Z",
    ]
    mock_alerts = [
        {"id": f"alert_{i}", "createdDateTime": ts, "title": f"alert_{i}", "severity": "medium"}
        for i, ts in enumerate(timestamps)
    ]
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": mock_alerts})

    # Run 1: initial fetch with last_run starting before second 42
    alerts_run1, last_run1 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run={"time": "2026-09-08T12:40:41.99Z", "last_fetched_ids": ["alert_0"]},
    )
    assert len(alerts_run1) == 9
    assert last_run1["time"] == "2026-09-08T12:40:42.23Z"
    assert "alert_8" in last_run1.get("last_fetched_ids", [])

    # Run 2: next fetch cycle with mock_alerts[8] (same timestamp) and a new alert in next second
    new_alert = {"id": "alert_new", "createdDateTime": "2026-09-08T12:40:43.00Z", "title": "new", "severity": "high"}
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": [mock_alerts[8], new_alert]})

    alerts_run2, last_run2 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run=last_run1,
    )
    assert len(alerts_run2) == 1
    assert json.loads(alerts_run2[0]["rawJSON"])["id"] == "alert_new"
    assert "id" not in alerts_run2[0]
    assert last_run2["time"] == "2026-09-08T12:40:43.00Z"


def test_fetch_incidents_subsecond_ordering_and_deduplication(mocker):
    """
    Given:
    - 10 incidents occurring within the exact same second with varying fractional seconds,
      including one ending in 'Z' (e.g. 12:40:42Z) and others with microsecond precision.
    - Multiple incidents sharing identical timestamps.

    When:
    - Running fetch_incidents across two consecutive runs.

    Then:
    - Incidents are sorted chronologically: '12:40:42Z' is not placed last.
    - The latest timestamp is recorded as new_last_run['time'].
    - In Run 2, incidents sharing that timestamp are deduplicated by ID, and new incidents are fetched.
    """
    timestamps = [
        "2026-09-08T12:40:41.99Z",
        "2026-09-08T12:40:42.0066667Z",
        "2026-09-08T12:40:42.01Z",
        "2026-09-08T12:40:42.1133333Z",
        "2026-09-08T12:40:42.1133333Z",
        "2026-09-08T12:40:42.11Z",
        "2026-09-08T12:40:42.11Z",
        "2026-09-08T12:40:42.2266667Z",
        "2026-09-08T12:40:42.23Z",
        "2026-09-08T12:40:42Z",
    ]
    mock_incidents = [
        {"id": f"incident_{i}", "createdDateTime": ts, "displayName": f"incident_{i}", "severity": "medium", "alerts": []}
        for i, ts in enumerate(timestamps)
    ]
    mocker.patch.object(client_mocker, "get_incidents_request", return_value={"value": mock_incidents})

    # Run 1
    incidents_run1, last_run1 = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        last_run={"time": "2026-09-08T12:40:41.99Z", "last_fetched_ids": ["incident_0"]},
    )
    assert len(incidents_run1) == 9
    assert last_run1["time"] == "2026-09-08T12:40:42.23Z"
    assert "incident_8" in last_run1.get("last_fetched_ids", [])

    # Run 2
    new_incident = {
        "id": "incident_new",
        "createdDateTime": "2026-09-08T12:40:43.00Z",
        "displayName": "new",
        "severity": "high",
        "alerts": [],
    }
    mocker.patch.object(client_mocker, "get_incidents_request", return_value={"value": [mock_incidents[8], new_incident]})

    incidents_run2, last_run2 = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        last_run=last_run1,
    )
    assert len(incidents_run2) == 1
    assert json.loads(incidents_run2[0]["rawJSON"])["id"] == "incident_new"
    assert "id" not in incidents_run2[0]
    assert last_run2["time"] == "2026-09-08T12:40:43.00Z"


def test_fetch_alerts_same_timestamp_pagination_across_runs(mocker):
    """
    Given:
    - 4 alerts sharing the exact same timestamp, with fetch_limit=2.

    When:
    - Running fetch_alerts across consecutive runs.

    Then:
    - Run 1 fetches first 2 alerts and sets last_fetched_ids to [a1, a2].
    - Run 2 fetches the remaining 2 alerts and unions last_fetched_ids to [a1, a2, a3, a4].
    - Run 3 returns 0 alerts without duplicating any.
    """
    ts = "2026-09-08T12:40:42.500Z"
    all_alerts = [{"id": f"alert_{i}", "createdDateTime": ts, "title": f"alert_{i}", "severity": "medium"} for i in range(1, 5)]

    def mock_search_alerts(params):
        top = int(params.get("$top", len(all_alerts)))
        return {"value": all_alerts[:top]}

    mocker.patch.object(client_mocker, "search_alerts", side_effect=mock_search_alerts)

    # Run 1: limit 2
    alerts1, last_run1 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        service_sources="",
        last_run={},
    )
    assert len(alerts1) == 2
    assert [json.loads(a["rawJSON"])["id"] for a in alerts1] == ["alert_1", "alert_2"]
    assert all("id" not in a for a in alerts1)
    assert set(last_run1["last_fetched_ids"]) == {"alert_1", "alert_2"}

    # Run 2: limit 2, same search response returned
    alerts2, last_run2 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        service_sources="",
        last_run=last_run1,
    )
    assert len(alerts2) == 2
    assert [json.loads(a["rawJSON"])["id"] for a in alerts2] == ["alert_3", "alert_4"]
    assert all("id" not in a for a in alerts2)
    assert set(last_run2["last_fetched_ids"]) == {"alert_1", "alert_2", "alert_3", "alert_4"}

    # Run 3: all 4 are in last_fetched_ids, so none are fetched
    alerts3, last_run3 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        service_sources="",
        last_run=last_run2,
    )
    assert len(alerts3) == 0


def test_fetch_incidents_same_timestamp_pagination_across_runs(mocker):
    """
    Given:
    - 4 incidents sharing the exact same timestamp, with fetch_limit=2.

    When:
    - Running fetch_incidents across consecutive runs.

    Then:
    - Run 1 fetches first 2 incidents and sets last_fetched_ids to [inc_1, inc_2].
    - Run 2 fetches the remaining 2 incidents and unions last_fetched_ids to [inc_1, inc_2, inc_3, inc_4].
    - Run 3 returns 0 incidents without duplicating any.
    """
    ts = "2026-09-08T12:40:42.500Z"
    all_incidents = [
        {"id": f"inc_{i}", "createdDateTime": ts, "displayName": f"inc_{i}", "severity": "medium", "alerts": []}
        for i in range(1, 5)
    ]

    def mock_get_incidents(url_suffix, *args, **kwargs):
        match = re.search(r"\$top=(\d+)", url_suffix)
        top = int(match.group(1)) if match else len(all_incidents)
        return {"value": all_incidents[:top]}

    mocker.patch.object(client_mocker, "get_incidents_request", side_effect=mock_get_incidents)

    # Run 1: limit 2
    inc1, last_run1 = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        last_run={},
    )
    assert len(inc1) == 2
    assert [json.loads(i["rawJSON"])["id"] for i in inc1] == ["inc_1", "inc_2"]
    assert all("id" not in i for i in inc1)
    assert set(last_run1["last_fetched_ids"]) == {"inc_1", "inc_2"}

    # Run 2: limit 2
    inc2, last_run2 = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        last_run=last_run1,
    )
    assert len(inc2) == 2
    assert [json.loads(i["rawJSON"])["id"] for i in inc2] == ["inc_3", "inc_4"]
    assert all("id" not in i for i in inc2)
    assert set(last_run2["last_fetched_ids"]) == {"inc_1", "inc_2", "inc_3", "inc_4"}

    # Run 3: all 4 are in last_fetched_ids
    inc3, last_run3 = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        last_run=last_run2,
    )
    assert len(inc3) == 0


def test_fetch_upgrade_migration_without_last_fetched_ids(mocker):
    """
    Given:
    - An existing deployment upgrading to 2.6.2 where last_run only contains {"time": "..."}
      without 'last_fetched_ids'.
    - An API response containing items with the exact boundary timestamp as well as strictly newer items.

    When:
    - Running fetch_incidents and fetch_alerts with this legacy last_run.

    Then:
    - Items with the exact boundary timestamp are skipped.
    - Strictly newer items are ingested.
    - 'last_fetched_ids' is properly populated for subsequent runs so future same-timestamp items deduplicate correctly.
    """
    ts_boundary = "2026-09-08T12:00:00.000000Z"
    ts_newer = "2026-09-08T12:00:01.000000Z"

    # Test for fetch_incidents
    incidents_payload = [
        {"id": "inc_boundary_1", "createdDateTime": ts_boundary, "displayName": "inc_b1", "severity": "medium", "alerts": []},
        {"id": "inc_boundary_2", "createdDateTime": ts_boundary, "displayName": "inc_b2", "severity": "medium", "alerts": []},
        {"id": "inc_newer_1", "createdDateTime": ts_newer, "displayName": "inc_new1", "severity": "high", "alerts": []},
    ]
    mocker.patch.object(client_mocker, "get_incidents_request", return_value={"value": incidents_payload})

    incidents_run1, last_run1 = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        last_run={"time": ts_boundary},  # No 'last_fetched_ids' key
    )
    assert len(incidents_run1) == 1
    assert json.loads(incidents_run1[0]["rawJSON"])["id"] == "inc_newer_1"
    assert "id" not in incidents_run1[0]
    assert last_run1["time"] == ts_newer
    assert last_run1["last_fetched_ids"] == ["inc_newer_1"]

    # Test for fetch_alerts
    alerts_payload = [
        {"id": "alert_boundary_1", "createdDateTime": ts_boundary, "title": "alert_b1", "severity": "medium"},
        {"id": "alert_boundary_2", "createdDateTime": ts_boundary, "title": "alert_b2", "severity": "medium"},
        {"id": "alert_newer_1", "createdDateTime": ts_newer, "title": "alert_new1", "severity": "high"},
    ]
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": alerts_payload})

    alerts_run1, last_run_alert1 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run={"time": ts_boundary},  # No 'last_fetched_ids' key
    )
    assert len(alerts_run1) == 1
    assert json.loads(alerts_run1[0]["rawJSON"])["id"] == "alert_newer_1"
    assert "id" not in alerts_run1[0]
    assert last_run_alert1["time"] == ts_newer
    assert last_run_alert1["last_fetched_ids"] == ["alert_newer_1"]


def test_fetch_boundary_deduplication_3_at_t_and_1_at_t_plus_1(mocker):
    """
    Given:
    - 3 alerts sharing timestamp T and 1 alert with timestamp T+1.
    - Fetch limit is 2.

    When:
    - Running fetch_alerts across consecutive runs.

    Then:
    - Run 1 ingests 2 boundary alerts at timestamp T up to fetch limit.
    - Run 2 correctly skips the 2 already-fetched IDs at timestamp T, ingesting the 3rd alert at T
      and the 4th alert at T+1.
    """
    ts_t = "2026-09-08T12:00:00.000Z"
    ts_t_plus_1 = "2026-09-08T12:00:01.000Z"

    all_alerts = [
        {"id": "alert_1", "createdDateTime": ts_t, "title": "alert_1", "severity": "low"},
        {"id": "alert_2", "createdDateTime": ts_t, "title": "alert_2", "severity": "low"},
        {"id": "alert_3", "createdDateTime": ts_t, "title": "alert_3", "severity": "medium"},
        {"id": "alert_4", "createdDateTime": ts_t_plus_1, "title": "alert_4", "severity": "high"},
    ]
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": all_alerts})

    # Run 1: limit 2 -> Ingest alert_1, alert_2 at timestamp T
    alerts_run1, last_run1 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        service_sources="",
        last_run={},
    )
    assert len(alerts_run1) == 2
    assert [json.loads(a["rawJSON"])["id"] for a in alerts_run1] == ["alert_1", "alert_2"]
    assert last_run1["time"] == ts_t
    assert set(last_run1["last_fetched_ids"]) == {"alert_1", "alert_2"}

    # Run 2: limit 2 with last_run1 -> skips alert_1, alert_2; ingests alert_3 (at T) and alert_4 (at T+1)
    alerts_run2, last_run2 = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=2,
        extra_filter="",
        service_sources="",
        last_run=last_run1,
    )
    assert len(alerts_run2) == 2
    assert [json.loads(a["rawJSON"])["id"] for a in alerts_run2] == ["alert_3", "alert_4"]
    assert last_run2["time"] == ts_t_plus_1
    assert last_run2["last_fetched_ids"] == ["alert_4"]


def test_fetch_malformed_missing_none_timestamps(mocker):
    """
    Given:
    - Incidents / alerts with None, missing 'createdDateTime', or unparseable timestamp strings.

    When:
    - to_utc_datetime is called directly and fetch_incidents / fetch_alerts are executed.

    Then:
    - to_utc_datetime gracefully returns None without raising exceptions.
    - Sorting gracefully handles None by defaulting to UTC datetime.min without crashing.
    - All items are processed and ingested cleanly.
    """
    # Direct to_utc_datetime edge case checks
    assert to_utc_datetime(None) is None
    assert to_utc_datetime("") is None
    assert to_utc_datetime("not-a-timestamp") is None
    assert to_utc_datetime(["invalid", "type"]) is None
    assert to_utc_datetime({}) is None

    # Test fetch_incidents with malformed, missing, None timestamps
    items = [
        {"id": "inc_none", "createdDateTime": None, "displayName": "None Date", "severity": "low", "alerts": []},
        {"id": "inc_missing", "displayName": "Missing Date", "severity": "low", "alerts": []},
        {
            "id": "inc_invalid",
            "createdDateTime": "unparseable-date",
            "displayName": "Invalid Date",
            "severity": "low",
            "alerts": [],
        },
        {
            "id": "inc_valid",
            "createdDateTime": "2026-09-08T12:00:00.000Z",
            "displayName": "Valid Date",
            "severity": "high",
            "alerts": [],
        },
    ]
    mocker.patch.object(client_mocker, "get_incidents_request", return_value={"value": items})

    incidents, new_last_run = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        last_run={},
    )
    assert len(incidents) == 4
    # The valid item with true timestamp is sorted to the end
    assert json.loads(incidents[-1]["rawJSON"])["id"] == "inc_valid"
    assert new_last_run["time"] == "2026-09-08T12:00:00.000Z"
    assert new_last_run["last_fetched_ids"] == ["inc_valid"]

    # Test fetch_alerts with malformed, missing, None timestamps
    alert_items = [
        {"id": "a_none", "createdDateTime": None, "title": "None Date", "severity": "low"},
        {"id": "a_missing", "title": "Missing Date", "severity": "low"},
        {"id": "a_invalid", "createdDateTime": "unparseable-date", "title": "Invalid Date", "severity": "low"},
        {"id": "a_valid", "createdDateTime": "2026-09-08T12:00:00.000Z", "title": "Valid Date", "severity": "high"},
    ]
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": alert_items})

    alerts, new_last_run_alerts = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run={},
    )
    assert len(alerts) == 4
    assert json.loads(alerts[-1]["rawJSON"])["id"] == "a_valid"
    assert new_last_run_alerts["time"] == "2026-09-08T12:00:00.000Z"
    assert new_last_run_alerts["last_fetched_ids"] == ["a_valid"]


def test_fetch_timezone_offset_normalization(mocker):
    """
    Given:
    - Alerts with timestamps having non-UTC offsets (e.g., +02:00, -04:00, and Z).

    When:
    - Running fetch_alerts.

    Then:
    - Timestamps are normalized to UTC datetimes.
    - Alerts are sorted chronologically rather than lexicographically:
      +02:00 (12:30 UTC) comes before Z (13:00 UTC), which comes before -04:00 (15:00 UTC).
    """
    # Offset +02:00 is 12:30 UTC
    dt_plus2 = to_utc_datetime("2026-09-08T14:30:00+02:00")
    # Z is 13:00 UTC
    dt_z = to_utc_datetime("2026-09-08T13:00:00Z")
    # Offset -04:00 is 15:00 UTC
    dt_minus4 = to_utc_datetime("2026-09-08T11:00:00-04:00")

    assert dt_plus2 is not None
    assert dt_z is not None
    assert dt_minus4 is not None
    assert dt_plus2.tzinfo == timezone.utc  # noqa: UP017
    assert dt_z.tzinfo == timezone.utc  # noqa: UP017
    assert dt_minus4.tzinfo == timezone.utc  # noqa: UP017
    assert dt_plus2 < dt_z < dt_minus4

    # API returns items where lexicographical order ("11:00..." < "13:00..." < "14:30...") differs from chronological
    alerts_payload = [
        {"id": "alert_minus4", "createdDateTime": "2026-09-08T11:00:00-04:00", "title": "minus4", "severity": "low"},
        {"id": "alert_plus2", "createdDateTime": "2026-09-08T14:30:00+02:00", "title": "plus2", "severity": "low"},
        {"id": "alert_z", "createdDateTime": "2026-09-08T13:00:00Z", "title": "z", "severity": "low"},
    ]
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": alerts_payload})

    alerts, new_last_run = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run={},
    )
    # Chronological order must be: plus2 (12:30 UTC), z (13:00 UTC), minus4 (15:00 UTC)
    ingested_ids = [json.loads(a["rawJSON"])["id"] for a in alerts]
    assert ingested_ids == ["alert_plus2", "alert_z", "alert_minus4"]
    assert new_last_run["time"] == "2026-09-08T11:00:00-04:00"
    assert new_last_run["last_fetched_ids"] == ["alert_minus4"]


def test_fetch_empty_api_response_retains_last_run_state(mocker):
    """
    Given:
    - An empty response (0 incidents/alerts) from the API.

    When:
    - Running fetch_incidents and fetch_alerts with an existing last_run.

    Then:
    - Both functions return an empty list.
    - last_run retains its previous 'time' and 'last_fetched_ids' state without modification or corruption.
    """
    initial_last_run = {
        "time": "2026-09-08T12:00:00.000Z",
        "last_fetched_ids": ["item_prev_1", "item_prev_2"],
    }
    mocker.patch.object(client_mocker, "get_incidents_request", return_value={"value": []})
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": []})

    incidents, new_last_run_inc = fetch_incidents(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        last_run=initial_last_run,
    )
    assert len(incidents) == 0
    assert new_last_run_inc == initial_last_run

    alerts, new_last_run_alerts = fetch_alerts(
        client_mocker,
        fetch_time="1 hour",
        fetch_limit=10,
        extra_filter="",
        service_sources="",
        last_run=initial_last_run,
    )
    assert len(alerts) == 0
    assert new_last_run_alerts == initial_last_run


def test_fetch_realistic_pagination_simulation(mocker):
    """
    Given:
    - A mock server dataset of 5 incidents where the API respects $top and 'createdDateTime ge <time>' filter.

    When:
    - Simulating sequential fetch cycles with fetch_limit=2.

    Then:
    - Each fetch cycle queries with the last_run timestamp, skips already-seen IDs, and ingests new items.
    - All 5 items are ingested sequentially without duplicates or missing items.
    """
    dataset = [
        {"id": f"inc_{i}", "createdDateTime": ts, "displayName": f"inc_{i}", "severity": "low", "alerts": []}
        for i, ts in enumerate(
            [
                "2026-09-08T10:00:00.000Z",
                "2026-09-08T10:05:00.000Z",
                "2026-09-08T10:10:00.000Z",
                "2026-09-08T10:15:00.000Z",
                "2026-09-08T10:20:00.000Z",
            ],
            start=1,
        )
    ]

    def mock_get_incidents(url_suffix, timeout, headers=None):
        top_match = re.search(r"\$top=(\d+)", url_suffix)
        top = int(top_match.group(1)) if top_match else len(dataset)

        ge_match = re.search(r"createdDateTime ge ([^\s&]+)", url_suffix)
        if ge_match:
            time_from_str = ge_match.group(1)
            time_from_dt = to_utc_datetime(time_from_str) or datetime.min.replace(tzinfo=timezone.utc)  # noqa: UP017
            filtered = [
                item
                for item in dataset
                if (to_utc_datetime(item["createdDateTime"]) or datetime.min.replace(tzinfo=timezone.utc)) >= time_from_dt  # noqa: UP017
            ]
        else:
            filtered = dataset

        return {"value": filtered[:top]}

    mocker.patch.object(client_mocker, "get_incidents_request", side_effect=mock_get_incidents)

    all_ingested_ids = []
    current_last_run = {"time": "2026-09-08T09:59:00.000Z", "last_fetched_ids": []}

    # Run cycles until all items are ingested
    for _ in range(5):
        incidents, current_last_run = fetch_incidents(
            client_mocker,
            fetch_time="1 hour",
            fetch_limit=2,
            extra_filter="",
            last_run=current_last_run,
        )
        if not incidents:
            break
        all_ingested_ids.extend([json.loads(i["rawJSON"])["id"] for i in incidents])

    assert all_ingested_ids == ["inc_1", "inc_2", "inc_3", "inc_4", "inc_5"]
    assert current_last_run["time"] == "2026-09-08T10:20:00.000Z"
    assert current_last_run["last_fetched_ids"] == ["inc_5"]


def test_create_search_alerts_filters_orderby():
    """
    Given:
    - Arguments for create_search_alerts_filters.

    When:
    - Calling with is_fetch=True vs is_fetch=False.

    Then:
    - is_fetch=True includes "$orderby": "createdDateTime asc".
    - is_fetch=False does NOT include "$orderby".
    """
    params_fetch = create_search_alerts_filters({}, is_fetch=True)
    assert params_fetch.get("$orderby") == "createdDateTime asc"

    params_no_fetch = create_search_alerts_filters({}, is_fetch=False)
    assert "$orderby" not in params_no_fetch


@pytest.mark.parametrize(
    "args, expected_params, is_fetch",
    [
        (
            {"filter": "Category eq 'Malware' and Severity eq 'High'", "status": "resolved"},
            {
                "$filter": "(Category eq 'Malware' and Severity eq 'High') and status eq 'resolved'",
                "$orderby": "createdDateTime asc",
            },
            True,
        ),
        (
            {"filter": "Category eq 'Malware' and Severity eq 'High'", "status": "resolved"},
            {"$top": "50", "$filter": "(Category eq 'Malware' and Severity eq 'High') and status eq 'resolved'"},
            False,
        ),
        ({"page": "2"}, {"$top": "50", "$skip": 100, "$filter": ""}, False),
    ],
)
def test_create_search_alerts_filters(args, expected_params, is_fetch):
    """
    Given:
    - args, expected_params results, and is_fetch flag.
    - Case 1: args with filter and status fields, is_fetch is True.
    - Case 2: args with filter and status fields, is_fetch is False.
    - Case 3: args with only page field, is_fetch is False.

    When:
    - Running create_search_alerts_filters.

    Then:
    - Ensure that the right fields were parsed into the query.
    - Case 1: Should include both the value of the filter field from the args (wrapped in parentheses) and the status.
    - Case 2: Should include the filter (wrapped in parentheses) and status in the $filter field, and 50 in the $top field.
    - Case 3: Should return a params dict with empty $filter field, 50 in the $top field, and 100 in the $skip field.
    """
    params = create_search_alerts_filters(args, is_fetch=is_fetch)
    assert params == expected_params


@pytest.mark.parametrize(
    "args, expected_filter",
    [
        (
            {"service_source": "microsoftDefenderForEndpoint"},
            "serviceSource eq 'microsoftDefenderForEndpoint'",
        ),
        (
            {"service_source": "microsoftDefenderForOffice365", "status": "resolved"},
            "serviceSource eq 'microsoftDefenderForOffice365' and status eq 'resolved'",
        ),
        (
            {
                "classification": "truePositive",
                "service_source": "microsoftDefenderForCloudApps",
                "status": "inProgress",
            },
            "classification eq 'truePositive' and serviceSource eq 'microsoftDefenderForCloudApps' " "and status eq 'inProgress'",
        ),
        (
            {"filter": "Category eq 'Malware'", "service_source": "microsoftDefenderForIdentity"},
            "(Category eq 'Malware') and serviceSource eq 'microsoftDefenderForIdentity'",
        ),
        ({"classification": "falsePositive"}, "classification eq 'falsePositive'"),
        ({"status": "newAlert"}, "status eq 'newAlert'"),
        ({}, ""),
    ],
)
def test_create_search_alerts_filters_maps_snake_case_args_to_odata_properties(args, expected_filter):
    """
    Regression test for XSUP-77232 - msg-search-alerts dropped the service_source argument.

    Given:
    - The msg-search-alerts command arguments, as declared in the YAML (snake_case, e.g. `service_source`).
    - Case 1: Only service_source.
    - Case 2: service_source together with status.
    - Case 3: classification, service_source and status together.
    - Case 4: A user-supplied `filter` together with service_source.
    - Case 5: Only classification (regression guard - identically named arg must keep working).
    - Case 6: Only status (regression guard - identically named arg must keep working).
    - Case 7: No filtering arguments at all.

    When:
    - Running create_search_alerts_filters on the command path (is_fetch=False).

    Then:
    - The XSOAR argument name `service_source` must be translated to the Graph OData property `serviceSource`
      and appended to the $filter. Before the fix the code looked up `args.get("serviceSource")`, which was always
      None for the snake_case YAML argument, so the clause was silently dropped and alerts from every service
      source were returned.
    - `classification` and `status` must keep producing their identically named OData clauses.
    - Multiple clauses must be joined with ` and `, and a user-supplied `filter` stays wrapped in parentheses.
    - With no filtering arguments the $filter must be an empty string.
    """
    params = create_search_alerts_filters(args, is_fetch=False)

    assert params["$filter"] == expected_filter


@pytest.mark.parametrize(
    "user_filter",
    [
        "severity eq 'high' or severity eq 'medium'",
        "severity eq 'high'",
    ],
)
def test_create_search_alerts_filters_wraps_user_filter_in_parentheses(user_filter):
    """
    Given:
    - A time window (time_from/time_to) and a user-provided OData filter that may contain an `or` clause.

    When:
    - Running create_search_alerts_filters (the fetch-alerts path).

    Then:
    - The user filter must be wrapped in parentheses so that OData `and`/`or` precedence does not let an
      `or` clause escape the createdDateTime time window (regression test for the "pulls ~6 months of alerts" bug).
    """
    args = {
        "time_from": "2020-04-20T10:00:00Z",
        "time_to": "2020-04-20T11:00:00Z",
        "filter": user_filter,
    }

    params = create_search_alerts_filters(args, is_fetch=True)

    expected = "createdDateTime ge 2020-04-20T10:00:00Z and " "createdDateTime le 2020-04-20T11:00:00Z and " f"({user_filter})"
    assert params["$filter"] == expected


@pytest.mark.parametrize(
    "args, expected_error",
    [
        ({"page_size": "2001"}, "Please note that the page size limit is 2000"),
    ],
)
def test_create_search_alerts_filters_errors(args, expected_error):
    """
    Given:
    - args and expected_error.
    - Case 1: Args with page_size = 2001.

    When:
    - Running create_search_alerts_filters.

    Then:
    - Ensure that the right error was thrown.
    - Case 1: Should throw an error for page_size too big.
    """
    with pytest.raises(DemistoException) as e:
        create_search_alerts_filters(args, is_fetch=False)
    assert str(e.value.message) == expected_error


@pytest.mark.parametrize(argnames="client_id", argvalues=["test_client_id", None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Given:
        - Managed Identities client id for authentication.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """
    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f"^{Resources.graph}.*"), json={"value": []})

    params = {
        "managed_identities_client_id": {"password": client_id},
        "use_managed_identities": "True",
        "resource_group": "test_resource_group",
        "host": Resources.graph,
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results")
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in demisto.results.call_args[0][0]["Contents"]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert (client_id and qs["client_id"] == [client_id]) or "client_id" not in qs


EQUAL_COMMENT_TAGS_ERROR = (
    "The 'Comment Entry Tag (to Microsoft)' and 'Comment Entry Tag (from Microsoft)' parameters cannot have the same value."
)
EMPTY_COMMENT_TAGS_ERROR = (
    "The 'Comment Entry Tag (to Microsoft)' and 'Comment Entry Tag (from Microsoft)' parameters must not be empty."
)
MIRRORING_ON = {"mirror_direction": "Incoming And Outgoing"}


@pytest.mark.parametrize("mirror_direction", ["Incoming", "Outgoing", "Incoming And Outgoing"])
def test_validate_mirroring_comment_tags_equal_tags_raise(mirror_direction):
    """
    Given:
        - Mirroring is enabled (any direction), and the outgoing and incoming comment tags are equal.
    When:
        - Running validate_mirroring_comment_tags.
    Then:
        - Ensure a DemistoException with a clear message is raised.
    """
    params = {"mirror_direction": mirror_direction, "comment_tag": "same", "comment_tag_from_microsoft_graph_security": "same"}
    with pytest.raises(DemistoException) as e:
        validate_mirroring_comment_tags(params)
    assert str(e.value.message) == EQUAL_COMMENT_TAGS_ERROR


@pytest.mark.parametrize(
    "tag_params",
    [
        pytest.param({}, id="both missing"),
        pytest.param({"comment_tag": "", "comment_tag_from_microsoft_graph_security": None}, id="both empty"),
        pytest.param({"comment_tag": "to"}, id="from-tag missing"),
        pytest.param({"comment_tag": "", "comment_tag_from_microsoft_graph_security": "from"}, id="to-tag empty"),
    ],
)
def test_validate_mirroring_comment_tags_empty_tags_raise(tag_params):
    """
    Given:
        - Mirroring is enabled, and at least one comment tag is missing or empty (there are no code defaults).
    When:
        - Running validate_mirroring_comment_tags.
    Then:
        - Ensure a DemistoException with the "must not be empty" message is raised (not the "same value" message).
    """
    with pytest.raises(DemistoException) as e:
        validate_mirroring_comment_tags({**MIRRORING_ON, **tag_params})
    assert str(e.value.message) == EMPTY_COMMENT_TAGS_ERROR


def test_validate_mirroring_comment_tags_different_tags_pass():
    """
    Given:
        - Mirroring is enabled, with two different, non-empty comment tags.
    When:
        - Running validate_mirroring_comment_tags.
    Then:
        - Ensure no exception is raised.
    """
    validate_mirroring_comment_tags({**MIRRORING_ON, "comment_tag": "to", "comment_tag_from_microsoft_graph_security": "from"})


@pytest.mark.parametrize(
    "params",
    [
        pytest.param({}, id="mirror_direction missing, tags missing"),
        pytest.param({"mirror_direction": "None"}, id="mirror_direction None, tags missing"),
        pytest.param({"mirror_direction": ""}, id="mirror_direction empty, tags missing"),
        pytest.param(
            {"mirror_direction": "None", "comment_tag": "same", "comment_tag_from_microsoft_graph_security": "same"},
            id="mirror_direction None, equal tags",
        ),
    ],
)
def test_validate_mirroring_comment_tags_skipped_when_mirroring_off(params):
    """
    Given:
        - Mirroring is off (mirror_direction None, empty or missing), with missing, empty or equal comment tags,
          e.g. an instance upgraded from a version without mirroring.
    When:
        - Running validate_mirroring_comment_tags.
    Then:
        - Ensure no exception is raised, so the Test button doesn't fail for instances that don't use mirroring.
    """
    validate_mirroring_comment_tags(params)


def test_test_function_fails_on_equal_comment_tags(mocker):
    """
    Given:
        - Integration params with equal comment tags.
    When:
        - Running test_function (the Test button).
    Then:
        - Ensure the validation error is raised before any API call is made.
    """
    params = {**MIRRORING_ON, "comment_tag": "same", "comment_tag_from_microsoft_graph_security": "same"}
    mocker.patch.object(demisto, "params", return_value=params)
    http_request = mocker.patch.object(client_mocker.ms_client, "http_request")

    with pytest.raises(DemistoException) as e:
        msg_test_function(client_mocker, {})

    assert str(e.value.message) == EQUAL_COMMENT_TAGS_ERROR
    http_request.assert_not_called()


@pytest.mark.parametrize(
    "args, expected_results",
    [
        ({"status": "new"}, {"status": "new"}),
        ({"assigned_to": "someone", "status": "inProgress"}, {"assignedTo": "someone", "status": "inProgress"}),
        (
            {"determination": "malware", "classification": "truePositive"},
            {"determination": "malware", "classification": "truePositive"},
        ),
    ],
)
def test_create_data_to_update(args, expected_results):
    """
    Given:
    - args and expected_results.
    - Case 1: args with status field.
    - Case 2: args with assigned_to and status fields.
    - Case 3: args with determination and classification fields.

    When:
    - Running create_data_to_update.

    Then:
    - Ensure that the right fields were parsed into the data dict.
    - Case 1: Should parse only status into the data dict.
    - Case 2: Should parse assigned_to as assignedTo and status into the data dict.
    - Case 3: Should parse determination and classification into the data dict.
    """
    data = create_data_to_update(args)
    assert data == expected_results


@pytest.mark.parametrize(
    "args, expected_error",
    [
        (
            {"closed_date_time": "now"},
            "No data to update was provided, please provide at least one of the "
            "following: assigned_to, determination, classification, status.",
        ),
    ],
)
def test_create_data_to_update_errors(args, expected_error):
    """
    Given:
    - args and expected_error.
    - Case 1: Args with only 'closed_date_time' field (not a valid update field).

    When:
    - Running create_data_to_update.

    Then:
    - Ensure that the right error was thrown.
    - Case 1: Should throw an error for missing relevant data to update.
    """
    with pytest.raises(DemistoException) as e:
        create_data_to_update(args)
    assert str(e.value.message) == expected_error


@pytest.mark.parametrize("test_case", ["test_case_1", "test_case_2"])
def test_create_alert_comment_command(mocker, test_case):
    """
    Given:
    - test case that point to the relevant test case in the json test data which include:
      args including alert_id and comment to add, response mock, and expected hr and ec outputs
    - Case 1: Mock response of a comment with only one comment (the one that just got added).
    - Case 2: Mock response of a comment with two comments.
    When:
    - Running create_alert_comment_command.

    Then:
    - Ensure that the alert was parsed correctly and right HR and EC outputs are returned.
    - Case 1: Should return a table with one entry.
    - Case 2: Should return a table with two entries, one for each comment.
    """
    test_data = load_json("./test_data/test_create_alert_comment_command.json").get(test_case)
    mocker.patch.object(client_mocker, "create_alert_comment", return_value=test_data.get("mock_response"))
    hr, ec, _ = create_alert_comment_command(client_mocker, test_data.get("args"))
    assert hr == test_data.get("expected_hr")
    assert ec == test_data.get("expected_ec")


@pytest.mark.parametrize(
    "param, service_sources_param, expected_results",
    [
        ("param", "service_sources_param", "param"),
        ("", "service_sources_param", "serviceSource in ('service_sources_param')"),
        (
            "",
            "service_source1,service_source2",
            "serviceSource in ('service_source1','service_source2')",
        ),
        ("", "", ""),
    ],
)
def test_create_filter_query(param, service_sources_param, expected_results):
    """
    Given:
    - param and service_sources_param function arguments, and expected_results.
    - Case 1: param and service_sources_param function arguments filled.
    - Case 2: Only service_sources_param function argument filled.
    - Case 3: Multiple service sources are provided.
    - Case 4: All arguments empty.

    When:
    - Running create_filter_query.

    Then:
    - Ensure that the right option was returned.
    - Case 1: Should return param.
    - Case 2: Should return service_sources_param as query.
    - Case 3: Should return service_sources_param as query operator $in.
    - Case 4: Should return an empty string.
    """
    filter_query = create_filter_query(param, service_sources_param)
    assert filter_query == expected_results


def test_to_msg_command_results():
    """
    Given: An example msg edsicvoery response
    When: calling to_msg_command_results
    Then:
        1. Outputs are replaced properly
        2. data.context is stripped out
        3. none is removed

    """
    res = load_json("./test_data/list_cases_response.json")

    results = to_msg_command_results(
        raw_object_list=res.get("value"),
        raw_res=res,
        outputs_prefix="MsGraph.SomePrefix",
        output_key_field="SomeId",
        raw_keys_to_replace={"status": "SomeStatus", "id": "SomeId"},
    )

    assert all("@odata.context" not in o for o in results.outputs)
    assert all("SomeId" in o for o in results.outputs)
    assert all("SomeId" in o for o in results.outputs)
    assert all(None not in o.values() for o in results.outputs)


def test_create_ediscovery_custodian_site_source_command(mocker):
    """
    Given: An example msg edsicvoery list site source response
    When: calling list_ediscovery_custodian_site_sources_command
    Then:
        1. The proper URL is used in the request
        2. @odata.id is stripped out of context
        3. The proper ids and output prefixes are used

    """
    mock = mocker.patch.object(
        client_mocker.ms_client, "http_request", return_value=load_json("./test_data/list_site_source_single.json")
    )

    results = list_ediscovery_custodian_site_sources_command(
        client_mocker, {"case_id": "case_id", "custodian_id": "custodian_id"}
    )
    assert mock.call_args.kwargs["url_suffix"] == "security/cases/ediscoveryCases/case_id/custodians/custodian_id/siteSources"
    assert not any("@odata.id" in o for o in results.outputs)
    assert results.outputs_prefix == "MsGraph.CustodianSiteSource"
    assert results.outputs_key_field == "SiteSourceId"
    assert all("SiteSourceId" in o for o in results.outputs)
    assert "Created By Name" in results.readable_output


@pytest.mark.parametrize(
    "command_function, description, external_id",
    list(
        itertools.product(
            [update_ediscovery_case_command, update_ediscovery_search_command], ["value", "", None], ["value", "", None]
        )
    ),
)
def test_update_ediscovery_case_command(mocker, command_function, description, external_id):
    """
    Given:
        update ediscovery commands
    When:
        an empty value is recieved as an argument
    Then:
        the argument shouldnt be sent to the api (dont want to override a real value with an update)
    """
    mock = mocker.patch.object(client_mocker.ms_client, "http_request")

    some_id = "some_id"
    command_function(
        client_mocker, {"display_name": "name", "description": description, "external_id": external_id, "case_id": some_id}
    )
    assert not set(mock.call_args.kwargs["json_data"].values()) & {None, ""}


def test_created_by_fields_to_hr():
    """
    Given
        A context dictionary
    When
        Calling created_by_fields_to_hr
    Then
        get the created fields flattened onto main dict
    """
    assert created_by_fields_to_hr(
        {"Field1": "val1", "CreatedBy": {"User": {"DisplayName": "Bob", "UserPrincipalName": "Frank"}}}
    ) == {"CreatedByAppName": None, "CreatedByName": "Bob", "CreatedByUPN": "Frank", "Field1": "val1"}


def test_list_ediscovery_search_command(mocker):
    """

    Given:
        A raw response with one result
    When:
        calling list search command
    Then:
    Prefixes are correct, nested value is in the readable output
    """
    raw_response = load_json("./test_data/list_search_single_response.json")
    mocker.patch.object(client_mocker, "list_ediscovery_search", return_value=raw_response)

    results = list_ediscovery_search_command(client_mocker, {})

    assert results.raw_response == raw_response
    assert results.outputs_key_field == "SearchId"
    assert results.outputs_key_field == "SearchId"
    assert results.outputs_prefix == "MsGraph.eDiscoverySearch"
    assert results.outputs[0]["CreatedBy"]["User"]["DisplayName"] in results.readable_output


@pytest.mark.parametrize("command_to_check", ["all", "ediscovery", "alerts"])
def test_test_auth_code_command(mocker, command_to_check):
    """
    Given
        a permission set to test
    When
        Calling test_auth_code_command

    Then
        The proper permissions are called

    """
    from MicrosoftGraphSecurity import test_auth_code_command

    mock_ediscovery = mocker.patch.object(
        client_mocker, "list_ediscovery_cases", return_value=load_json("./test_data/list_cases_response.json")
    )
    mock_alerts = mocker.patch("MicrosoftGraphSecurity.test_function")
    mock_threat_assessment = mocker.patch.object(
        client_mocker, "list_threat_assessment_requests", return_value=load_json("./test_data/list_threat_assessment.json")
    )
    test_auth_code_command(client_mocker, {"permission_type": command_to_check})

    if command_to_check == "alerts":
        assert not mock_ediscovery.called
        assert not mock_threat_assessment.called
        assert mock_alerts.called
    elif command_to_check == "any":
        assert mock_ediscovery.called
        assert mock_alerts.called
        assert mock_threat_assessment.called
    elif command_to_check == "ediscovery":
        assert mock_ediscovery.called
        assert not mock_alerts.called
        assert not mock_threat_assessment.called
    elif command_to_check == "threat assessment":
        assert not mock_ediscovery.called
        assert not mock_alerts.called
        assert mock_threat_assessment.called


def test_purge_ediscovery_data_command(mocker):
    """
    Given:
        A purge response with no Location header.
    When:
        Calling purge_ediscovery_data_command.
    Then:
        Ensure the status is success and the null Operation ID is removed from the
        context outputs.
    """
    mocker.patch.object(client_mocker, "purge_ediscovery_data", return_value=SimpleNamespace(headers={}))
    result = purge_ediscovery_data_command(client_mocker, {})
    assert result.readable_output == "eDiscovery purge status is success.\n- Operation ID: None"
    assert result.outputs == {"Status": "success"}
    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.Purge"


def test_purge_ediscovery_data_command_with_operation_id(mocker):
    """
    Given:
        A purge response that includes a Location header with an operation ID.
    When:
        Calling purge_ediscovery_data_command.
    Then:
        Ensure the Operation ID is extracted and returned to the context outputs.
    """
    location = "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/case_123/operations/op_456"
    mocker.patch.object(client_mocker, "purge_ediscovery_data", return_value=SimpleNamespace(headers={"Location": location}))
    mocker.patch.object(client_mocker, "get", return_value={"status": "succeeded"})
    result = purge_ediscovery_data_command(client_mocker, {})
    assert result.outputs == {"OperationID": "op_456", "Status": "succeeded"}
    assert "op_456" in result.readable_output


def test_purge_ediscovery_data_command_with_malformed_location(mocker):
    """
    Given:
        A purge response that includes a Location header without a parseable operation ID.
    When:
        Calling purge_ediscovery_data_command.
    Then:
        Ensure the null Operation ID is removed from the context outputs and the
        readable output shows None.
    """
    location = "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/case_123/"
    mocker.patch.object(client_mocker, "purge_ediscovery_data", return_value=SimpleNamespace(headers={"Location": location}))
    mocker.patch.object(client_mocker, "get", return_value={"status": "succeeded"})
    result = purge_ediscovery_data_command(client_mocker, {})
    assert result.outputs == {"Status": "succeeded"}
    assert result.readable_output == "eDiscovery purge status is succeeded.\n- Operation ID: None"


def test_list_ediscovery_non_custodial_data_source_command_empty_output(mocker):
    mocker.patch.object(client_mocker, "list_ediscovery_noncustodial_datasources", return_value={"value": []})
    assert (
        list_ediscovery_non_custodial_data_source_command(client_mocker, {}).readable_output == "### Results:\n**No entries.**\n"
    )


def test_list_ediscovery_case_command(mocker):
    raw_response = load_json("./test_data/list_cases_response.json")
    mocker.patch.object(client_mocker, "list_ediscovery_cases", return_value=raw_response)
    results = list_ediscovery_case_command(client_mocker, {})
    assert len(raw_response["value"]) == len(results.outputs)
    assert all(output["CreatedDateTime"] in results.readable_output for output in results.outputs)


def test_activate_ediscovery_custodian_command(mocker):
    mocker.patch.object(client_mocker, "activate_edsicovery_custodian", return_value=None)
    assert (
        activate_ediscovery_custodian_command(
            client_mocker, {"case_id": "caseid", "custodian_id": "custodian_id"}
        ).readable_output
        == "Custodian with id custodian_id Case was reactivated on case with id caseid successfully."
    )


def test_release_ediscovery_custodian_command(mocker):
    mocker.patch.object(client_mocker, "release_edsicovery_custodian", return_value=None)
    assert (
        release_ediscovery_custodian_command(client_mocker, {"case_id": "caseid", "custodian_id": "custodian_id"}).readable_output
        == "Custodian with id custodian_id was released from case with id caseid successfully."
    )


def test_close_ediscovery_case_command(mocker):
    mocker.patch.object(client_mocker, "close_edsicovery_case", return_value=None)
    assert (
        close_ediscovery_case_command(client_mocker, {"case_id": "caseid"}).readable_output
        == "Case with id caseid was closed successfully."
    )


def test_reopen_ediscovery_case_command(mocker):
    mocker.patch.object(client_mocker, "reopen_edsicovery_case", return_value=None)
    assert (
        reopen_ediscovery_case_command(client_mocker, {"case_id": "caseid"}).readable_output
        == "Case with id caseid was reopened successfully."
    )


@pytest.mark.parametrize(
    "site, email, should_error",
    [("exists", None, False), ("", "Exists", False), ("exists", "also exists", True), (None, None, True)],
)
def test_create_ediscovery_non_custodial_data_source_command_invalid_args(mocker, site, email, should_error):
    """
    Given:
        Arguments that arent valid for this command
    When:
        Calling the command
    Then
        An exception is raised

    """
    mocker.patch.object(client_mocker, "create_ediscovery_non_custodial_data_source", return_value=None)
    try:
        create_ediscovery_non_custodial_data_source_command(client_mocker, {"site": site, "email": email})
        assert not should_error
    except ValueError:
        assert should_error


def test_empty_list_ediscovery_custodian_command(mocker):
    mocker.patch.object(client_mocker, "list_ediscovery_custodians", return_value={})
    assert list_ediscovery_custodian_command(client_mocker, {}).readable_output == "### Results:\n**No entries.**\n"


THREAT_ASSESSMENT_COMMANDS = {
    "mail_assessment_request": create_mail_assessment_request_command,
    "email_file_assessment_request": create_email_file_request_command,
    "file_assessment_request": create_file_assessment_request_command,
    "url_assessment_request": create_url_assessment_request_command,
    "list_assessment_requests": list_threat_assessment_requests_command,
}


@pytest.mark.parametrize(
    "mock_func, command_name, expected_result",
    [
        ("create_mail_assessment_request", "mail_assessment_request", "mail_assessment_request.json"),
        ("create_email_file_assessment_request", "email_file_assessment_request", "email_file_assessment_request.json"),
        ("create_file_assessment_request", "file_assessment_request", "file_assessment_request.json"),
        ("create_url_assessment_request", "url_assessment_request", "url_assessment_request.json"),
    ],
)
def test_create_mail_assessment_request_command(mocker, mock_func, command_name, expected_result):
    """

    Given:
        A raw response with one result
    When:
        calling list search command
    Then:
        Nested value is in the readable output
    """
    raw_response = load_json(f"./test_data/{expected_result}")
    mocker.patch.object(client_mocker, mock_func, return_value={"request_id": "123"})
    mocker.patch.object(client_mocker, "get_threat_assessment_request_status", return_value={"status": "completed"})
    mocker.patch.object(client_mocker, "get_threat_assessment_request", return_value=raw_response)
    mocker.patch("MicrosoftGraphSecurity.get_content_data", return_value="content_data")
    mocker.patch("MicrosoftGraphSecurity.get_message_user", return_value="user_mail")
    mocker.patch("CommonServerPython.is_demisto_version_ge", return_value=True)
    results = THREAT_ASSESSMENT_COMMANDS[command_name]({}, client_mocker)

    assert results.raw_response == raw_response
    assert results.outputs.get("ID") == raw_response.get("id")
    assert results.outputs.get("Content Type") == raw_response.get("contentType")


def test_list_threat_assessment_requests_command(mocker):
    raw_response = load_json("./test_data/list_threat_assessment.json")
    mocker.patch.object(client_mocker, "list_threat_assessment_requests", return_value=raw_response)

    result = list_threat_assessment_requests_command(client_mocker, {})
    assert len(result) == 2
    assert result[0].outputs_prefix == "MSGraphMail.AssessmentRequest"
    assert len(result[0].outputs) == 4
    assert result[1].outputs_prefix == "MsGraph.AssessmentRequestNextToken"
    assert result[1].outputs == {"next_token": "test_token"}


@pytest.mark.parametrize("user, expected_result", [("testuser@test.com", "test user id"), ("test user id", "test user id")])
def test_get_message_user(mocker, user, expected_result):
    mocker.patch.object(client_mocker, "get_user_id", return_value={"value": [{"id": "test user id"}]})
    message_user = get_message_user(client_mocker, user)
    assert message_user == expected_result


def test_advanced_hunting_command(mocker):
    response = load_json("./test_data/advanced_hunting_response.json")
    mocker.patch.object(client_mocker, "advanced_hunting_request", return_value=response)
    args = {"query": "AlertInfo", "limit": 2, "timeout": 50}

    results = advanced_hunting_command(client_mocker, args)

    expected_results = load_json("./test_data/advanced_hunting_results.json")
    assert results.outputs_prefix == expected_results["outputs_prefix"]
    assert results.outputs_key_field == expected_results["outputs_key_field"]
    assert results.outputs == expected_results["outputs"]
    assert results.readable_output == expected_results["readable_output"]

    mocker.patch.object(demisto, "params", return_value={"microsoft_365_defender_context": True})
    results = advanced_hunting_command(client_mocker, args)

    expected_results = load_json("./test_data/advanced_hunting_results_365_defenfer.json")
    assert results[1].outputs_prefix == expected_results["outputs_prefix"]
    assert results[1].outputs_key_field == expected_results["outputs_key_field"]
    assert results[1].outputs == expected_results["outputs"]
    assert results[1].readable_output == expected_results["readable_output"]


def test_get_list_security_incident_command_single_case(mocker):
    response = load_json("./test_data/incidents_single_response.json")
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=response)
    args = {"incident_id": 12345, "limit": 1, "timeout": 50}
    results = get_list_security_incident_command(client_mocker, args)
    expected_results = load_json("./test_data/incidents_single_results.json")
    assert results.outputs_prefix == expected_results["outputs_prefix"]
    assert results.outputs_key_field == expected_results["outputs_key_field"]
    assert results.outputs == expected_results["outputs"]
    assert results.readable_output == expected_results["readable_output"]


def test_get_list_security_incident_command_list_case(mocker):
    response = load_json("./test_data/incidents_list_response.json")
    mocker.patch.object(client_mocker, "get_incidents_request", return_value=response)
    args = {"limit": 2, "timeout": 50}
    results = get_list_security_incident_command(client_mocker, args)
    expected_results = load_json("./test_data/incidents_list_results.json")
    assert results.outputs_prefix == expected_results["outputs_prefix"]
    assert results.outputs_key_field == expected_results["outputs_key_field"]
    assert results.outputs == expected_results["outputs"]
    assert results.readable_output == expected_results["readable_output"]


def test_update_incident_command(mocker):
    response = load_json("./test_data/incident_update_response.json")
    mocker.patch.object(client_mocker, "update_incident_request", return_value=response)
    args = {
        "incident_id": "12345",
        "custom_tags": "test1,test2",
        "status": "active",
        "classification": "unknown",
        "determination": "unknown",
        "assigned_to": "",
        "severity": "unknown",
        "resolving_comment": "resolve_test",
        "timeout": 50,
    }

    results = update_incident_command(client_mocker, args)

    expected_results = load_json("./test_data/incident_update_results.json")

    assert results.outputs_prefix == expected_results["outputs_prefix"]
    assert results.outputs_key_field == expected_results["outputs_key_field"]
    assert results.outputs == expected_results["outputs"]
    assert results.readable_output == expected_results["readable_output"]


# ==============================
# Dummy Client
# ==============================
class DummyEstimateClient:
    """Dummy client simulating Microsoft Graph eDiscovery estimate statistics operations."""

    def __init__(self):
        # Store operations by (case_id, search_id)
        self.operations = {}

    def start_estimate_statistics_request(self, case_id, search_id, statistics_options=None):
        """
        Simulate starting an estimate statistics request.
        """
        self.operations[(case_id, search_id)] = {
            "id": "OP123",
            "status": "running",
            "percentProgress": 0,
            "createdDateTime": "2025-11-16T10:00:00Z",
            "lastActionDateTime": "2025-11-16T10:00:00Z",
            "indexedItemCount": 100,
            "indexedItemsSize": 50000,
            "unindexedItemCount": 2,
            "unindexedItemsSize": 1024,
            "totalItemCount": 102,
            "totalItemsSize": 51024,
            "mailboxCount": 3,
            "siteCount": 2,
            "call_count": 0,  # track how many times get_last was called
        }

    def get_last_estimate_statistics_operation(self, case_id, search_id):
        """
        Simulate polling: first call returns running, second call returns succeeded.
        """
        op = self.operations.get((case_id, search_id))
        if not op:
            raise KeyError(f"No estimate operation found for case {case_id}, search {search_id}")

        # Increment call count
        op["call_count"] += 1

        # First call: still running
        if op["call_count"] == 1:
            op["status"] = "running"
            op["percentProgress"] = 50
        else:
            op["status"] = "succeeded"
            op["percentProgress"] = 100

        return op


# ==============================
# Tests
# ==============================
def test_run_estimate_statistics_command():
    """
    Given:
        A case_id and search_id
    When:
        Calling run_estimate_statistics_command
    Then:
        The estimate request is started and confirmation CommandResults is returned
    """
    client = DummyEstimateClient()
    args = {"case_id": "CASE1", "search_id": "SEARCH1"}

    result = run_estimate_statistics_command(client, args)

    assert isinstance(result, CommandResults)
    assert "initiated" in result.readable_output
    assert ("CASE1", "SEARCH1") in client.operations


def test_get_last_estimate_statistics_command_missing_operation():
    """
    Given:
        A case_id and search_id with no started operation
    When:
        Calling get_last_estimate_statistics_command
    Then:
        Raises KeyError indicating no operation found
    """
    client = DummyEstimateClient()
    args = {"case_id": "CASE_UNKNOWN", "search_id": "SEARCH_UNKNOWN"}

    with pytest.raises(KeyError) as e:
        _get_last_estimate_statistics_command(args, client)

    assert "No estimate operation found" in str(e.value)


def test_get_last_estimate_statistics_command_pending():
    args = {"case_id": "case-123", "search_id": "search-456"}
    mock_client = MagicMock()
    mock_client.get_last_estimate_statistics_operation.return_value = {
        "status": "running",
        "id": "op-123",
        "percentProgress": 50,
    }

    result = _get_last_estimate_statistics_command(args, mock_client)

    assert isinstance(result, PollResult)
    assert result.continue_to_poll is True
    assert result.args_for_next_run == args
    assert result.response is None
    assert isinstance(result.partial_result, CommandResults)
    assert "still running" in result.partial_result.readable_output.lower()


def test_get_last_estimate_statistics_command_completed():
    # Arrange
    args = {"case_id": "case-123", "search_id": "search-456"}
    mock_client = MagicMock()
    # Simulate a completed operation
    response_data = {
        "id": "op-789",
        "status": "Succeeded",
        "percentProgress": 100,
        "createdDateTime": "2025-11-16T00:00:00Z",
        "lastActionDateTime": "2025-11-16T01:00:00Z",
        "indexedItemCount": 50,
        "indexedItemsSize": 1024,
        "unindexedItemCount": 5,
        "unindexedItemsSize": 512,
        "totalItemCount": 55,
        "totalItemsSize": 1536,
        "mailboxCount": 3,
        "siteCount": 2,
    }
    mock_client.get_last_estimate_statistics_operation.return_value = response_data

    result = _get_last_estimate_statistics_command(args, mock_client)

    assert isinstance(result, PollResult)
    assert result.continue_to_poll is False or result.continue_to_poll is None  # completed
    assert isinstance(result.response, CommandResults)
    assert result.partial_result is None
    assert result.response.outputs_prefix == "MsGraph.eDiscovery.EstimateStatistics"
    assert result.response.raw_response == response_data
    assert "eDiscovery Estimate Statistics" in result.response.readable_output


def test_create_ediscovery_case_hold_policy_command(mocker):
    """
    Given:
        Case ID, display name, description, and content query.
    When:
        Calling create_ediscovery_case_hold_policy_command.
    Then:
        Ensure the command returns the expected CommandResults with the created hold policy.
    """
    args = {
        "case_id": "case_123",
        "display_name": "Hold Policy 1",
        "description": "Test Hold Policy",
        "content_query": "size>100",
    }
    mock_response = {
        "id": "hold_123",
        "displayName": "Hold Policy 1",
        "status": "enabled",
        "description": "Test Hold Policy",
        "contentQuery": "size>100",
    }
    mocker.patch.object(client_mocker, "create_ediscovery_case_hold_policy", return_value=mock_response)

    result = create_ediscovery_case_hold_policy_command(client_mocker, args)

    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.HoldPolicy"
    assert result.outputs_key_field == "ID"
    assert result.outputs["ID"] == "hold_123"
    assert result.outputs["DisplayName"] == "Hold Policy 1"
    assert "Hold Policy 1" in result.readable_output


def test_delete_ediscovery_case_hold_policy_command(mocker):
    """
    Given:
        Case ID and hold policy ID.
    When:
        Calling delete_ediscovery_case_hold_policy_command.
    Then:
        Ensure the command returns a success message.
    """
    args = {"case_id": "case_123", "hold_policy_id": "hold_123"}
    mocker.patch.object(client_mocker, "delete_ediscovery_case_hold_policy", return_value=None)

    result = delete_ediscovery_case_hold_policy_command(client_mocker, args)

    assert "was sent successfully" in result.readable_output
    assert "hold_123" in result.readable_output


def test_update_ediscovery_case_policy_command(mocker):
    """
    Given:
        Case ID, hold policy ID, and fields to update.
    When:
        Calling update_ediscovery_case_policy_command.
    Then:
        Ensure the command returns a success message.
    """
    args = {"case_id": "case_123", "hold_policy_id": "hold_123", "description": "Updated Description"}
    mocker.patch.object(client_mocker, "update_ediscovery_case_policy", return_value=None)

    result = update_ediscovery_case_policy_command(client_mocker, args)

    assert "updated successfully" in result.readable_output
    assert "hold_123" in result.readable_output


def test_list_ediscovery_case_hold_policy_command_list(mocker):
    """
    Given:
        Case ID.
    When:
        Calling list_ediscovery_case_hold_policy_command (listing all).
    Then:
        Ensure the command returns the list of hold policies.
    """
    args = {"case_id": "case_123", "all_results": "true"}
    mock_response = {
        "value": [
            {"id": "hold_1", "displayName": "Hold 1", "status": "enabled"},
            {"id": "hold_2", "displayName": "Hold 2", "status": "disabled"},
        ]
    }
    mocker.patch.object(client_mocker, "list_ediscovery_case_hold_policy", return_value=mock_response)

    result = list_ediscovery_case_hold_policy_command(client_mocker, args)

    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.HoldPolicy"
    assert result.outputs_key_field == "ID"
    assert len(result.outputs) == 2
    assert result.outputs[0]["ID"] == "hold_1"
    assert result.outputs[1]["ID"] == "hold_2"
    assert "Hold 1" in result.readable_output
    assert "Hold 2" in result.readable_output


def test_list_ediscovery_case_hold_policy_command_get(mocker):
    """
    Given:
        Case ID and hold policy ID.
    When:
        Calling list_ediscovery_case_hold_policy_command (getting one).
    Then:
        Ensure the command returns the specific hold policy.
    """
    args = {"case_id": "case_123", "hold_policy_id": "hold_1", "all_results": "true"}
    mock_response = {"id": "hold_1", "displayName": "Hold 1", "status": "enabled"}
    mocker.patch.object(client_mocker, "get_ediscovery_case_hold_policy", return_value=mock_response)

    result = list_ediscovery_case_hold_policy_command(client_mocker, args)

    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.HoldPolicy"
    assert result.outputs_key_field == "ID"
    assert len(result.outputs) == 1
    assert result.outputs[0]["ID"] == "hold_1"
    assert "Hold 1" in result.readable_output


def test_list_case_operation_command_list(mocker):
    """
    Given:
        Case ID.
    When:
        Calling list_case_operation_command (listing all).
    Then:
        Ensure the command returns the list of operations.
    """
    args = {"case_id": "case_123", "all_results": "true"}
    mock_response = {
        "value": [
            {"id": "op_1", "action": "AddToReviewSet", "status": "Succeeded"},
            {"id": "op_2", "action": "Export", "status": "InProgress"},
        ]
    }
    mocker.patch.object(client_mocker, "list_case_operation", return_value=mock_response)

    result = list_case_operation_command(client_mocker, args)

    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.Operation"
    assert result.outputs_key_field == "ID"
    assert len(result.outputs) == 2
    assert result.outputs[0]["ID"] == "op_1"
    assert result.outputs[1]["ID"] == "op_2"
    assert "AddToReviewSet" in result.readable_output
    assert "Export" in result.readable_output


def test_list_case_operation_command_get(mocker):
    """
    Given:
        Case ID and operation ID.
    When:
        Calling list_case_operation_command (getting one).
    Then:
        Ensure the command returns the specific operation.
    """
    args = {"case_id": "case_123", "operation_id": "op_1", "all_results": "true"}
    mock_response = {"id": "op_1", "action": "AddToReviewSet", "status": "Succeeded"}
    mocker.patch.object(client_mocker, "get_case_operation", return_value=mock_response)

    result = list_case_operation_command(client_mocker, args)

    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.Operation"
    assert result.outputs_key_field == "ID"
    assert len(result.outputs) == 1
    assert result.outputs[0]["ID"] == "op_1"
    assert "AddToReviewSet" in result.readable_output


def test_list_case_operation_command_with_download(mocker):
    """
    Given:
        Arguments requesting a specific operation ID with download_file='true'.
    When:
        Calling list_case_operation_command.
    Then:
        1. The operation details are fetched.
        2. The download helper is called.
        3. A list containing [FileResult, CommandResult] is returned.
    """
    args = {"case_id": "case_1", "operation_id": "op_1", "download_file": "true"}

    op_data = {
        "id": "op_1",
        "action": "Export",
        "status": "Succeeded",
        "exportFileMetadata": {"downloadUrl": "https://download.me"},
    }
    mocker.patch.object(client_mocker, "get_case_operation", return_value=op_data)

    mock_file_result = {"Type": 3, "File": "export.zip", "Contents": b"data"}
    mocker.patch("MicrosoftGraphSecurity._download_operation_export_file", return_value=mock_file_result)

    results = list_case_operation_command(client_mocker, args)

    assert isinstance(results, list)
    assert len(results) == 2

    assert results[0] == mock_file_result

    assert isinstance(results[1], CommandResults)
    assert results[1].outputs[0]["ID"] == "op_1"


def test_export_result_ediscovery_data_command(mocker):
    """
    Given:
        Case ID, search ID, and export parameters.
    When:
        Calling export_result_ediscovery_data_command.
    Then:
        Ensure the command returns the export location.
    """
    args = {"case_id": "case_123", "search_id": "search_123", "export_criteria": "searchHits", "export_format": "standard"}
    mock_response = MagicMock()
    mock_response.headers = {
        "Location": "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/case_123/operations/op_123"
    }
    mocker.patch.object(client_mocker, "export_result_ediscovery_data", return_value=mock_response)

    result = export_result_ediscovery_data_command(client_mocker, args)

    assert "eDiscovery export request was submitted successfully" in result.readable_output
    assert "op_123" in result.readable_output
    assert result.outputs_prefix == "MsGraph.eDiscoveryCase.Export"
    assert result.outputs["OperationID"] == "op_123"
    assert result.outputs["CaseID"] == "case_123"
    assert result.outputs["Location"] == mock_response.headers["Location"]


# ==========================================
# Helper Function Tests
# ==========================================


@pytest.mark.parametrize(
    "operation_data, expected_url",
    [
        # Case 1: exportFileMetadata is a dictionary
        (
            {"exportFileMetadata": {"downloadUrl": "https://example.com/file1.zip"}},
            "https://example.com/file1.zip",
        ),
        # Case 2: exportFileMetadata is a list of dictionaries
        (
            {"exportFileMetadata": [{"downloadUrl": "https://example.com/file2.zip"}]},
            "https://example.com/file2.zip",
        ),
        # Case 3: No exportFileMetadata
        ({"id": "op1"}, None),
        # Case 4: exportFileMetadata exists but has no downloadUrl
        ({"exportFileMetadata": {}}, None),
    ],
)
def test_extract_export_download_url(operation_data, expected_url):
    """
    Given:
        An operation dictionary with varying structures for 'exportFileMetadata'.
    When:
        Calling _extract_export_download_url.
    Then:
        The correct download URL is extracted or None is returned.
    """
    assert _extract_export_download_url(operation_data) == expected_url


@pytest.mark.parametrize(
    "headers, default, expected_filename",
    [
        # Case 1: Standard double-quoted filename
        ({"Content-Disposition": 'attachment; filename="export_123.zip"'}, "def.zip", "export_123.zip"),
        # Case 2: Unquoted filename
        ({"Content-Disposition": "attachment; filename=plain.csv"}, "def.zip", "plain.csv"),
        # Case 3: Case insensitive header key
        ({"content-disposition": 'attachment; filename="lower.zip"'}, "def.zip", "lower.zip"),
        # Case 4: Header missing
        ({}, "default.zip", "default.zip"),
        # Case 5: Header exists but no filename parameter
        ({"Content-Disposition": "attachment; size=100"}, "fallback.zip", "fallback.zip"),
    ],
)
def test_extract_filename_from_headers(headers, default, expected_filename):
    """
    Given:
        Response headers and a default filename.
    When:
        Calling _extract_filename_from_headers.
    Then:
        The filename is correctly parsed from the Content-Disposition header,
        or the default is returned if missing.
    """
    assert _extract_filename_from_headers(headers, default) == expected_filename


# ==========================================
# Download Logic Tests
# ==========================================


def test_download_operation_export_file_success(mocker):
    """
    Given:
        An operation with a valid download URL.
    When:
        Calling _download_operation_export_file.
    Then:
        The client downloads the file, and a fileResult dict is returned with the correct content and name.
    """
    operation = {"exportFileMetadata": {"downloadUrl": "https://fake-url.com/data"}}

    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.content = b"file_content_bytes"
    mock_response.headers = {"Content-Disposition": 'attachment; filename="results.csv"'}

    mocker.patch.object(client_mocker, "download_export_file", return_value=mock_response)

    result = _download_operation_export_file(client_mocker, operation)

    assert result["File"] == "results.csv"


@pytest.mark.parametrize(
    "mock_attrs, expected_error_msg",
    [
        # Case 1: HTTP Error (ok=False)
        (
            {"ok": False, "status_code": 404, "text": "Not Found", "content": b""},
            "Failed to download export file. HTTP 404. Not Found",
        ),
        # Case 2: Empty content (ok=True but content is empty)
        (
            {"ok": True, "status_code": 200, "content": b"", "headers": {}},
            "Downloaded export file is empty. HTTP 200.",
        ),
    ],
)
def test_download_operation_export_file_errors(mocker, mock_attrs, expected_error_msg):
    """
    Given:
        A client response that indicates failure (404 error or empty body).
    When:
        Calling _download_operation_export_file.
    Then:
        A DemistoException is raised with the specific error message.
    """
    operation = {"exportFileMetadata": {"downloadUrl": "https://fake-url.com/data"}}

    mock_response = MagicMock()
    for key, value in mock_attrs.items():
        setattr(mock_response, key, value)

    mocker.patch.object(client_mocker, "download_export_file", return_value=mock_response)

    with pytest.raises(DemistoException) as e:
        _download_operation_export_file(client_mocker, operation)

    assert expected_error_msg in str(e.value)


def test_download_export_file_resets_token_to_default_scope(mocker):
    """
    Given:
        A client downloading an eDiscovery export file (which uses a non-default Purview scope).
    When:
        Calling download_export_file.
    Then:
        The download uses the Purview scope, and afterwards a default-scope token is fetched
        to reset the shared refresh token and avoid token-scope drift (XSUP-71559).
    """
    mock_response = MagicMock()
    http_request = mocker.patch.object(client_mocker.ms_client, "http_request", return_value=mock_response)
    get_access_token = mocker.patch.object(client_mocker.ms_client, "get_access_token")

    result = client_mocker.download_export_file("https://fake-url.com/data")

    assert result is mock_response
    assert http_request.call_args.kwargs["scope"] == "b26e684c-5068-4120-a679-64a5d2c909d9/.default"
    get_access_token.assert_called_once_with(scope=client_mocker.ms_client.scope)


def test_download_export_file_reset_uses_default_not_purview_scope(mocker):
    """
    Given:
        A client downloading an eDiscovery export file.
    When:
        Calling download_export_file.
    Then:
        The post-download token reset requests the client's default scope, not the Purview scope.
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=MagicMock())
    get_access_token = mocker.patch.object(client_mocker.ms_client, "get_access_token")

    client_mocker.download_export_file("https://fake-url.com/data")

    reset_scope = get_access_token.call_args.kwargs["scope"]
    assert reset_scope == client_mocker.ms_client.scope
    assert reset_scope != "b26e684c-5068-4120-a679-64a5d2c909d9/.default"


""" MIRRORING TESTS """

MIRROR_PARAMS = {
    "mirror_direction": "Incoming And Outgoing",
    "comment_tag": "CommentToMicrosoftGraphSecurity",
    "comment_tag_from_microsoft_graph_security": "CommentFromMicrosoftGraphSecurity",
    "close_incident": True,
    "close_out": True,
    "fetch_incidents_type": "Alerts,Incidents",
}
REMOTE_OBJECTS = load_json("./test_data/mirroring_remote_objects.json")
ALERT_ID = REMOTE_OBJECTS["alert"]["id"]
INCIDENT_ID = REMOTE_OBJECTS["incident"]["id"]


def _remote_object(key: str, **overrides) -> dict:
    obj = json.loads(json.dumps(REMOTE_OBJECTS[key]))
    obj.update(overrides)
    return obj


def _http_calls(http_mock, method: str) -> list:
    return [c for c in http_mock.call_args_list if c.kwargs.get("method") == method]


def _patch_http(mocker) -> MagicMock:
    """Patches the Graph HTTP client with an empty (PATCH-like) response and returns the mock."""
    return mocker.patch.object(client_mocker.ms_client, "http_request", return_value="")


def test_fetch_alerts_injects_mirroring_fields(mocker):
    """
    Given: an alert returned by the API and mirroring params.
    When: running fetch_alerts.
    Then: the raw JSON includes the mirroring fields and mirror_type=alert.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "x"))
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    mocker.patch.object(
        client_mocker, "search_alerts", return_value={"value": [{"id": "a1", "createdDateTime": "2020-04-20T10:00:00Z"}]}
    )
    alerts, _ = fetch_alerts(client_mocker, "1 hour", 10, "", "", {}, params=MIRROR_PARAMS)
    raw = json.loads(alerts[0]["rawJSON"])
    assert raw["mirror_direction"] == "Both"
    assert raw["mirror_instance"] == "instance_1"
    assert raw["mirror_tags"] == ["CommentToMicrosoftGraphSecurity", "CommentFromMicrosoftGraphSecurity"]
    assert raw["mirror_type"] == "alert"
    assert alerts[0]["name"] == "Unknown - a1"


def test_fetch_incidents_injects_mirroring_fields(mocker):
    """
    Given: an incident returned by the API, and no params passed (falls back to demisto.params()).
    When: running fetch_incidents.
    Then: the raw JSON includes the mirroring fields and mirror_type=incident.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "x"))
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "mirror_direction": "Incoming",
            "comment_tag": "CommentToMicrosoftGraphSecurity",
            "comment_tag_from_microsoft_graph_security": "CommentFromMicrosoftGraphSecurity",
        },
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    mocker.patch.object(
        client_mocker,
        "get_incidents_request",
        return_value={"value": [{"id": "1", "displayName": "Inc", "createdDateTime": "2020-04-20T10:00:00Z"}]},
    )
    incidents, _ = fetch_incidents(client_mocker, "1 hour", 10, "", {})
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["mirror_direction"] == "In"
    assert raw["mirror_type"] == "incident"
    assert raw["mirror_tags"] == ["CommentToMicrosoftGraphSecurity", "CommentFromMicrosoftGraphSecurity"]
    assert incidents[0]["name"] == "Inc - 1"


@pytest.mark.parametrize(
    "direction_param, expected_direction",
    [
        ("Incoming", "In"),
        ("Outgoing", "Out"),
        ("Incoming And Outgoing", "Both"),
        ("None", None),
        ("", None),
        (None, None),
    ],
)
@pytest.mark.parametrize("mirror_type", ["alert", "incident"])
def test_get_mirroring_fields(mocker, direction_param, expected_direction, mirror_type):
    """
    Given: each Incident Mirroring Direction param value (including "None", empty and missing), for alerts and incidents.
    When: building the mirroring fields with get_mirroring_fields.
    Then: the direction maps to In/Out/Both, or None when mirroring is off; the instance, tags and mirror_type are
          always set (mirroring off doesn't drop them, the server ignores them when the direction is None).
    """
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    params = {**MIRROR_PARAMS, "mirror_direction": direction_param}
    assert get_mirroring_fields(params, mirror_type) == {
        "mirror_direction": expected_direction,
        "mirror_instance": "instance_1",
        "mirror_tags": ["CommentToMicrosoftGraphSecurity", "CommentFromMicrosoftGraphSecurity"],
        "mirror_type": mirror_type,
    }


def test_fetch_incidents_mirroring_off_direction_none(mocker):
    """
    Given: an incident returned by the API, and the mirroring direction param set to "None" (mirroring off).
    When: running fetch_incidents.
    Then: the raw JSON has mirror_direction=None, and still holds mirror_instance and mirror_type=incident.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "x"))
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    mocker.patch.object(
        client_mocker,
        "get_incidents_request",
        return_value={"value": [{"id": "1", "displayName": "Inc", "createdDateTime": "2020-04-20T10:00:00Z"}]},
    )
    params = {**MIRROR_PARAMS, "mirror_direction": "None"}
    incidents, _ = fetch_incidents(client_mocker, "1 hour", 10, "", {}, params=params)
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["mirror_direction"] is None
    assert raw["mirror_instance"] == "instance_1"
    assert raw["mirror_type"] == "incident"


def test_fetch_alerts_mirroring_off_direction_none(mocker):
    """
    Given: alerts returned by the API, and no mirroring direction param at all (mirroring off).
    When: running fetch_alerts.
    Then: every fetched record has mirror_direction=None, mirror_instance and mirror_type=alert.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "x"))
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    alerts_response = [
        {"id": "a1", "createdDateTime": "2020-04-20T10:00:00Z"},
        {"id": "a2", "createdDateTime": "2020-04-20T11:00:00Z"},
    ]
    mocker.patch.object(client_mocker, "search_alerts", return_value={"value": alerts_response})
    alerts, _ = fetch_alerts(client_mocker, "1 hour", 10, "", "", {}, params={})
    assert len(alerts) == 2
    for alert in alerts:
        raw = json.loads(alert["rawJSON"])
        assert raw["mirror_direction"] is None
        assert raw["mirror_instance"] == "instance_1"
        assert raw["mirror_type"] == "alert"
        assert raw["mirror_tags"] == []


def test_fetch_alerts_mirror_tags_skip_empty_params(mocker):
    """
    Given: mirroring params where the comment tags are missing or empty (there are no code defaults).
    When: running fetch_alerts.
    Then: mirror_tags doesn't contain None or empty strings, and fetch doesn't fail.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "x"))
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    mocker.patch.object(
        client_mocker, "search_alerts", return_value={"value": [{"id": "a1", "createdDateTime": "2020-04-20T10:00:00Z"}]}
    )
    params = {"mirror_direction": "Incoming", "comment_tag": "", "comment_tag_from_microsoft_graph_security": "from"}
    alerts, _ = fetch_alerts(client_mocker, "1 hour", 10, "", "", {}, params=params)
    assert json.loads(alerts[0]["rawJSON"])["mirror_tags"] == ["from"]


def test_get_mapping_fields_command():
    """
    Given: nothing.
    When: running get-mapping-fields.
    Then: two schemes are returned, with the Graph Security Alert/Incident type names, and `determination` is not offered
          (it is derived from the combined Classification label). closeReason is offered (read by close-out),
          and the alert scheme offers closeNotes (read by close-out for the alert close comment). Both schemes offer
          classification. The alert scheme doesn't offer severity (mirrored in only: Graph rejects an alert severity PATCH).
          Only the incident scheme offers severity.
    """
    schemes = get_mapping_fields_command().extract_mapping()
    assert set(schemes.keys()) == {"Graph Security Alert", "Graph Security Incident"}
    assert set(schemes["Graph Security Alert"]) == {"closeReason", "closeNotes", "status", "classification", "customDetails"}
    assert set(schemes["Graph Security Incident"]) == {
        "closeReason",
        "status",
        "classification",
        "severity",
        "displayName",
        "description",
        "customTags",
        "resolvingComment",
    }


@pytest.mark.parametrize(
    "fetch_type, expected_urls, expected_ids",
    [
        ("Alerts", ["security/alerts_v2"], ["a1"]),
        ("Incidents", ["security/incidents"], ["10"]),
        ("Alerts,Incidents", ["security/alerts_v2", "security/incidents"], ["a1", "10"]),
    ],
)
def test_get_modified_remote_data_command_types(mocker, fetch_type, expected_urls, expected_ids):
    """
    Given: the fetch_incidents_type param.
    When: running get-modified-remote-data.
    Then: only the selected object types are queried, with the lastUpdateDateTime filter and the Prefer header.
    """

    def router(**kwargs):
        return {"value": [{"id": "a1"}]} if kwargs["url_suffix"].startswith("security/alerts_v2") else {"value": [{"id": 10}]}

    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=router)
    res = get_modified_remote_data_command(
        client_mocker, {"lastUpdate": "2026-10-10T10:00:00Z"}, {"fetch_incidents_type": fetch_type}
    )
    assert res.modified_incident_ids == expected_ids
    urls = [c.kwargs["url_suffix"] for c in http_mock.call_args_list]
    assert [u.split("?")[0] for u in urls] == expected_urls
    assert all("$filter=lastUpdateDateTime ge 2026-10-10T10:00:00Z" in u for u in urls)
    assert all(c.kwargs["headers"] == {"Prefer": "include-unknown-enum-members"} for c in http_mock.call_args_list)


@pytest.mark.parametrize("params", [{}, {"fetch_incidents_type": ""}])
def test_get_modified_remote_data_command_no_fetch_type(mocker, params):
    """
    Given: the fetch_incidents_type param is missing or empty.
    When: running get-modified-remote-data.
    Then: nothing is queried (same as fetch, there is no "Alerts" fallback) and no IDs are returned.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request")
    res = get_modified_remote_data_command(client_mocker, {"lastUpdate": "2026-10-10T10:00:00Z"}, params)
    assert res.modified_incident_ids == []
    http_mock.assert_not_called()


ALERTS_ONLY_PARAMS = {"fetch_incidents_type": "Alerts"}


def test_get_modified_remote_data_command_paging(mocker):
    """
    Given: a list response with an @odata.nextLink.
    When: running get-modified-remote-data (default type: Alerts).
    Then: the next page is followed via full_url and all IDs are returned.
    """
    http_mock = mocker.patch.object(
        client_mocker.ms_client,
        "http_request",
        side_effect=[{"value": [{"id": "a1"}], "@odata.nextLink": "https://graph.microsoft.com/next"}, {"value": [{"id": "a2"}]}],
    )
    res = get_modified_remote_data_command(client_mocker, {"lastUpdate": "2026-10-10T10:00:00Z"}, ALERTS_ONLY_PARAMS)
    assert res.modified_incident_ids == ["a1", "a2"]
    assert http_mock.call_args_list[1].kwargs["full_url"] == "https://graph.microsoft.com/next"


def test_get_modified_remote_data_command_no_page_cap(mocker):
    """
    Given: 8 list pages chained by @odata.nextLink, where the last page has no nextLink.
    When: running get-modified-remote-data.
    Then: there is no page cap: all 8 pages are requested, all IDs are returned, and the total is logged with demisto.debug.
    """
    total_pages = 8
    pages = [
        {"value": [{"id": f"a{i}"}], "@odata.nextLink": f"https://graph.microsoft.com/next/{i + 1}"}
        for i in range(total_pages - 1)
    ]
    pages.append({"value": [{"id": f"a{total_pages - 1}"}]})
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=pages)
    debug_mock = mocker.patch.object(demisto, "debug")
    res = get_modified_remote_data_command(client_mocker, {"lastUpdate": "2026-10-10T10:00:00Z"}, ALERTS_ONLY_PARAMS)
    assert res.modified_incident_ids == [f"a{i}" for i in range(total_pages)]
    assert http_mock.call_count == total_pages
    assert [c.kwargs["full_url"] for c in http_mock.call_args_list[1:]] == [
        f"https://graph.microsoft.com/next/{i}" for i in range(1, total_pages)
    ]
    assert any("Listed 8 modified IDs from security/alerts_v2 in 8 page(s)" in c.args[0] for c in debug_mock.call_args_list)


def _rate_limit_error() -> DemistoException:
    """A DemistoException like the one BaseClient raises on HTTP 429, with the response."""
    return DemistoException("Error in API call [429] - Too Many Requests", res=SimpleNamespace(status_code=429, headers={}))


def test_get_modified_remote_data_command_page_failure_raises(mocker):
    """
    Given: a nextLink chain where the 3rd page request fails with HTTP 429.
    When: running get-modified-remote-data.
    Then: an "API rate limit" DemistoException is raised at once (no retry, no sleep), instead of returning a partial ID
        list, so return_error adds "skip update" and lastUpdate is not advanced.
    """
    http_mock = mocker.patch.object(
        client_mocker.ms_client,
        "http_request",
        side_effect=[
            {"value": [{"id": "a1"}], "@odata.nextLink": "https://graph.microsoft.com/next/1"},
            {"value": [{"id": "a2"}], "@odata.nextLink": "https://graph.microsoft.com/next/2"},
            _rate_limit_error(),
        ],
    )
    with pytest.raises(DemistoException, match=r"^API rate limit: .*HTTP 429"):
        get_modified_remote_data_command(client_mocker, {"lastUpdate": "2026-10-10T10:00:00Z"}, ALERTS_ONLY_PARAMS)
    assert http_mock.call_count == 3
    assert http_mock.call_args_list[2].kwargs["full_url"] == "https://graph.microsoft.com/next/2"


def test_mirror_get_does_not_retry_429(mocker):
    """
    Given: an HTTP 429 from Microsoft Graph.
    When: calling mirror_get.
    Then: an "API rate limit" DemistoException is raised after a single request (no retry, no sleep in mirroring),
        keeping the original response.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_rate_limit_error())
    with pytest.raises(DemistoException, match="^API rate limit") as exc_info:
        client_mocker.mirror_get(url_suffix="security/alerts_v2")
    assert http_mock.call_count == 1
    assert exc_info.value.res.status_code == 429


def test_mirror_get_does_not_wrap_other_errors(mocker):
    """
    Given: a non-429 API error (HTTP 500).
    When: calling mirror_get.
    Then: the original error is raised as-is, after a single request.
    """
    error = DemistoException("Error in API call [500] - Server Error", res=SimpleNamespace(status_code=500, headers={}))
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=error)
    with pytest.raises(DemistoException, match=r"\[500\]") as exc_info:
        client_mocker.mirror_get(url_suffix="security/alerts_v2")
    assert exc_info.value is error
    assert http_mock.call_count == 1


@pytest.mark.parametrize(
    "remote_id, expected_url",
    [
        ("123", "security/incidents/123?$expand=alerts"),
        ("da637", "security/alerts_v2/da637"),
    ],
)
def test_get_remote_data_raises_api_rate_limit_on_429(mocker, remote_id, expected_url):
    """
    Given: the single alert/incident GET fails with HTTP 429.
    When: running get-remote-data.
    Then: the exact "API rate limit" error is raised (no in_mirror_error fallback, no retry),
        so the server stops this sync cycle and retries on the next one.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_rate_limit_error())
    with pytest.raises(DemistoException) as exc_info:
        get_remote_data_command(client_mocker, {"id": remote_id, "lastUpdate": "2026-10-10T10:00:00Z"}, MIRROR_PARAMS)
    assert str(exc_info.value) == "API rate limit"
    assert [c.kwargs["url_suffix"] for c in http_mock.call_args_list] == [expected_url]


@pytest.mark.parametrize("args", [{"lastUpdate": "not a date at all"}, {}])
def test_get_modified_remote_data_command_unparseable_last_update(mocker, args):
    """
    Given: an unparseable or missing lastUpdate.
    When: running get-modified-remote-data.
    Then: a DemistoException is raised (return_error then adds "skip update", so the server keeps the same lastUpdate),
        and no request is sent. An empty ID list would let the server advance lastUpdate and lose the window.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request")
    with pytest.raises(DemistoException, match="failed to parse lastUpdate"):
        get_modified_remote_data_command(client_mocker, args, ALERTS_ONLY_PARAMS)
    assert http_mock.call_count == 0


@pytest.mark.parametrize(
    "args, expected_args, expected_hint",
    [
        ({"id": "123", "lastUpdate": "2026-01-01"}, {"id": "123", "lastUpdate": "2026-01-01"}, None),
        ({"incident_id": "123", "lastUpdate": "2026-01-01"}, {"id": "123", "lastUpdate": "2026-01-01"}, "incident"),
        ({"alert_id": "da1"}, {"id": "da1", "lastUpdate": "0"}, "alert"),
    ],
)
def test_normalize_get_remote_data_args(args, expected_args, expected_hint):
    """
    Given: get-remote-data args in the engine or design format.
    When: normalizing them.
    Then: the standard id/lastUpdate args and the type hint are returned.
    """
    assert normalize_get_remote_data_args(args) == (expected_args, expected_hint)


@pytest.mark.parametrize(
    "remote_id, hint, expected",
    [("2972395", None, "incident"), ("da637551227677560813_-961444813", None, "alert"), ("123", "alert", "alert")],
)
def test_infer_mirror_type(remote_id, hint, expected):
    """
    Given: a remote ID and an optional type hint.
    When: inferring the mirror type.
    Then: digits-only IDs are incidents and anything else is an alert, unless a hint is given.
    """
    assert infer_mirror_type(remote_id, hint) == expected


@pytest.mark.parametrize(
    "args, expected_url",
    [
        ({"id": INCIDENT_ID, "lastUpdate": "0"}, f"security/incidents/{INCIDENT_ID}?$expand=alerts"),
        ({"incident_id": INCIDENT_ID}, f"security/incidents/{INCIDENT_ID}?$expand=alerts"),
        ({"alert_id": ALERT_ID}, f"security/alerts_v2/{ALERT_ID}"),
        ({"id": ALERT_ID}, f"security/alerts_v2/{ALERT_ID}"),
    ],
)
def test_get_remote_data_wrapper_command(mocker, args, expected_url):
    """
    Given: get-remote-data args with id, incident_id or alert_id.
    When: running the get-remote-data wrapper.
    Then: a single GET is sent to the right URL with the Prefer header, and @odata.context is stripped.
    """
    key = "incident" if "incidents" in expected_url else "alert"
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object(key))
    res = get_remote_data_wrapper_command(client_mocker, args, {})
    assert http_mock.call_count == 1
    assert http_mock.call_args.kwargs["url_suffix"] == expected_url
    assert http_mock.call_args.kwargs["headers"] == {"Prefer": "include-unknown-enum-members"}
    assert "@odata.context" not in res.mirrored_object
    assert res.mirrored_object["mirror_type"] == key


def test_get_remote_data_close_entry_when_resolved(mocker):
    """
    Given: a resolved alert, close_incident on, and a lastUpdate between the two remote comments.
    When: running get-remote-data.
    Then: a close entry is added, and only the new, non-mirrored comment becomes a tagged note entry.
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("alert"))
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "2026-10-05T00:00:00Z"}, MIRROR_PARAMS)
    close_entry, *comment_entries = res.entries
    assert close_entry["Contents"]["dbotIncidentClose"] is True
    assert close_entry["Contents"]["closeReason"] == "Resolved"
    assert len(comment_entries) == 1
    assert "New comment from Defender" in comment_entries[0]["Contents"]
    assert comment_entries[0]["Tags"] == ["CommentFromMicrosoftGraphSecurity"]
    assert comment_entries[0]["Note"] is True


@pytest.mark.parametrize(
    "incoming_tag_params",
    [{}, {"comment_tag_from_microsoft_graph_security": ""}, {"comment_tag_from_microsoft_graph_security": None}],
)
def test_get_remote_data_empty_incoming_tag_leaves_note_untagged(mocker, incoming_tag_params):
    """
    Given: the 'Comment Entry Tag (from Microsoft)' param is missing, empty or None.
    When: running get-remote-data on an alert with a new comment.
    Then: the note entry is still created, with no tags (never an empty-string tag).
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("alert"))
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "2026-10-05T00:00:00Z"}, incoming_tag_params)
    assert len(res.entries) == 1
    assert res.entries[0]["Tags"] == []


def test_get_remote_data_no_close_entry_when_close_incident_off(mocker):
    """
    Given: a resolved alert and close_incident off.
    When: running get-remote-data.
    Then: no close/reopen entry is added.
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("alert", comments=[]))
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "0"}, {"close_incident": False})
    assert res.entries == []


@pytest.mark.parametrize("status", ["active", "inProgress", "awaitingAction"])
def test_get_remote_data_reopen_entry(mocker, status):
    """
    Given: an incident with an open status, close_incident on, and an XSOAR investigation with no status.
    When: running get-remote-data.
    Then: a reopen entry is added (unknown XSOAR status falls back to the remote status only).
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("incident", status=status))
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == [{"Type": EntryType.NOTE, "Contents": {"dbotIncidentReopen": True}, "ContentsFormat": EntryFormat.JSON}]
    assert res.mirrored_object["status"] == status


REOPEN_ENTRY = {"Type": EntryType.NOTE, "Contents": {"dbotIncidentReopen": True}, "ContentsFormat": EntryFormat.JSON}


@pytest.mark.parametrize(
    "investigation, expected_logs",
    [
        (
            {"id": "42", "status": 0},
            ["XSOAR investigation 42 status: 0", "status: active, remote closed: False, XSOAR closed: False."],
        ),
        (
            {"id": "42", "status": 1},
            ["XSOAR investigation 42 status: 1", "status: active, remote closed: False, XSOAR closed: True."],
        ),
        (
            {"id": "42"},
            [
                "XSOAR investigation 42 status: None",
                "status is unknown, falling back",
                "status: active, remote closed: False, XSOAR closed: None.",
            ],
        ),
    ],
    ids=["open", "closed", "unknown"],
)
def test_get_remote_data_close_reopen_debug_logs(mocker, investigation, expected_logs):
    """
    Given: an active incident and an XSOAR investigation that is open, closed or has no status.
    When: running get-remote-data.
    Then: the XSOAR investigation status, the fallback (if any) and the decision are logged with demisto.debug.
    """
    mocker.patch.object(demisto, "investigation", return_value=investigation)
    debug_mock = mocker.patch.object(demisto, "debug")
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("incident", status="active"))
    get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    logs = " | ".join(str(c.args[0]) for c in debug_mock.call_args_list)
    for expected in expected_logs:
        assert expected in logs


@pytest.mark.parametrize("status", ["active", "inProgress", "awaitingAction"])
def test_get_remote_data_no_reopen_entry_when_xsoar_already_open(mocker, status):
    """
    Given: an incident that is not resolved in Microsoft, and the XSOAR investigation is already open (status 0).
    When: running get-remote-data (e.g. triggered by a comment mirrored out from XSOAR).
    Then: no reopen entry is added, since both sides are already open.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1", "status": 0})
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("incident", status=status))
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == []


@pytest.mark.parametrize(
    "overrides, expected_notes",
    [
        ({"redirectIncidentId": "999"}, "Redirected in Microsoft Defender to incident 999."),
        ({"redirectIncidentId": None}, "Redirected in Microsoft Defender."),
        (
            {"redirectIncidentId": "999", "resolvingComment": "Merged by Defender"},
            "Redirected in Microsoft Defender to incident 999.\nMerged by Defender",
        ),
    ],
    ids=["with-target", "no-target", "with-resolving-comment"],
)
@pytest.mark.parametrize("investigation", [{"id": "1", "status": 0}, {"id": "1"}], ids=["xsoar-open", "xsoar-unknown"])
def test_get_remote_data_redirected_incident_closes_as_resolved(mocker, overrides, expected_notes, investigation):
    """
    Given: an incident redirected in Microsoft (merged into another incident), and an open or unknown XSOAR state.
    When: running get-remote-data with close_incident on.
    Then: a close entry is added, with close reason Resolved and the redirect note.
    """
    mocker.patch.object(demisto, "investigation", return_value=investigation)
    remote = _remote_object("incident", status="redirected", comments=[], classification="truePositive", **overrides)
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=remote)
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == [
        {
            "Type": EntryType.NOTE,
            "Contents": {"dbotIncidentClose": True, "closeReason": "Resolved", "closeNotes": expected_notes},
            "ContentsFormat": EntryFormat.JSON,
        }
    ]


def test_get_remote_data_redirected_incident_no_entry_when_xsoar_closed(mocker):
    """
    Given: a redirected incident, and the XSOAR investigation is already closed.
    When: running get-remote-data.
    Then: no close or reopen entry is added.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1", "status": 1})
    remote = _remote_object("incident", status="redirected", comments=[])
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=remote)
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == []


def test_get_remote_data_redirected_alert_status_is_not_a_close(mocker):
    """
    Given: an alert with status "redirected" (not a Graph alert status) and a closed XSOAR investigation.
    When: running get-remote-data.
    Then: only incidents treat redirected as closed, and it is not an active alert status, so no entry is added.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1", "status": 1})
    remote = _remote_object("alert", status="redirected", comments=[])
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=remote)
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == []


@pytest.mark.parametrize(
    "mirror_type, status, expected_key",
    [
        ("alert", "resolved", "dbotIncidentClose"),
        ("incident", "resolved", "dbotIncidentClose"),
        ("incident", "active", "dbotIncidentReopen"),
        ("incident", "inProgress", "dbotIncidentReopen"),
        ("incident", "awaitingAction", "dbotIncidentReopen"),
        ("alert", "new", "dbotIncidentReopen"),
        ("alert", "inProgress", "dbotIncidentReopen"),
    ],
)
def test_get_remote_data_close_or_reopen_on_explicit_status(mocker, mirror_type, status, expected_key):
    """
    Given: a resolved or explicitly active Graph alert/incident, and an XSOAR investigation with no status.
    When: running get-remote-data with close_incident on.
    Then: `resolved` adds a close entry, and an active status adds a reopen entry.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1"})
    remote = _remote_object(mirror_type, status=status, comments=[])
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=remote)
    res = get_remote_data_command(client_mocker, {"id": remote["id"], "lastUpdate": "0"}, MIRROR_PARAMS)
    assert len(res.entries) == 1
    assert res.entries[0]["Contents"][expected_key] is True


@pytest.mark.parametrize(
    "mirror_type, status",
    [
        ("incident", None),
        ("alert", None),
        ("incident", "unknown"),
        ("incident", "unknownFutureValue"),
        ("alert", "unknownFutureValue"),
        ("alert", "redirected"),
    ],
)
@pytest.mark.parametrize("investigation", [{"id": "1", "status": 1}, {"id": "1"}], ids=["xsoar-closed", "xsoar-unknown"])
def test_get_remote_data_no_close_or_reopen_on_unknown_status(mocker, mirror_type, status, investigation):
    """
    Given: a Graph alert/incident with a missing, unknown, unknownFutureValue or unexpected status,
        and a closed or unknown XSOAR investigation.
    When: running get-remote-data with close_incident on.
    Then: no close and no reopen entry is added, and the skip is logged.
    """
    mocker.patch.object(demisto, "investigation", return_value=investigation)
    debug_mock = mocker.patch.object(demisto, "debug")
    remote = _remote_object(mirror_type, comments=[])
    remote.pop("status", None)
    if status is not None:
        remote["status"] = status
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=remote)
    res = get_remote_data_command(client_mocker, {"id": remote["id"], "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == []
    logs = " | ".join(str(c.args[0]) for c in debug_mock.call_args_list)
    assert f"status '{status}' is not actionable; not closing or reopening." in logs


def test_get_remote_data_reopen_entry_when_xsoar_closed(mocker):
    """
    Given: an incident that is active in Microsoft, and the XSOAR investigation is closed (status 1).
    When: running get-remote-data.
    Then: a reopen entry is added.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1", "status": 1})
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("incident", status="active"))
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == [REOPEN_ENTRY]


def test_get_remote_data_no_close_entry_when_xsoar_already_closed(mocker):
    """
    Given: a resolved alert with one new comment, and the XSOAR investigation is already closed (status 1).
    When: running get-remote-data.
    Then: no close entry is added, but the new comment is still mirrored in.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1", "status": 1})
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("alert"))
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "2026-10-05T00:00:00Z"}, MIRROR_PARAMS)
    assert len(res.entries) == 1
    assert "dbotIncidentClose" not in str(res.entries[0]["Contents"])
    assert "New comment from Defender" in res.entries[0]["Contents"]


def test_get_remote_data_close_entry_when_xsoar_open(mocker):
    """
    Given: a resolved alert, and the XSOAR investigation is open (status 0).
    When: running get-remote-data.
    Then: a close entry is added.
    """
    mocker.patch.object(demisto, "investigation", return_value={"id": "1", "status": 0})
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("alert", comments=[]))
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert len(res.entries) == 1
    assert res.entries[0]["Contents"]["dbotIncidentClose"] is True


@pytest.mark.parametrize(
    "investigation_mock",
    [
        {"return_value": None},
        {"return_value": {"id": "1"}},
        {"return_value": {"id": "1", "status": None}},
        {"side_effect": Exception("investigation not available")},
    ],
    ids=["none", "missing-status", "null-status", "raises"],
)
def test_get_remote_data_unknown_xsoar_status_falls_back_to_remote_status(mocker, investigation_mock):
    """
    Given: the XSOAR investigation status cannot be read (None, missing/null status, or demisto.investigation() raises).
    When: running get-remote-data on an active incident.
    Then: a reopen entry is still added (previous behavior), and no error is raised.
    """
    mocker.patch.object(demisto, "investigation", **investigation_mock)
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("incident", status="active"))
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.entries == [REOPEN_ENTRY]
    assert res.mirrored_object["in_mirror_error"] == ""


@pytest.mark.parametrize(
    "overrides, expected_reason",
    [
        ({"classification": "falsePositive"}, "False Positive"),
        ({"classification": "unknown"}, "Other"),
        ({"classification": None}, "Other"),
        ({}, "Other"),
    ],
)
def test_get_close_entry_reason_mapping(overrides, expected_reason):
    """
    Given: a resolved Graph object with a falsePositive, unknown, null or missing classification.
    When: building the close entry.
    Then: the close reason is mapped (falsePositive -> False Positive; unknown/missing -> Other) and default notes are used.
    """
    entry = get_close_entry({"id": "1", "status": "resolved", **overrides})
    assert entry["Type"] == EntryType.NOTE
    assert entry["ContentsFormat"] == EntryFormat.JSON
    assert entry["Contents"]["dbotIncidentClose"] is True
    assert entry["Contents"]["closeReason"] == expected_reason
    assert entry["Contents"]["closeNotes"] == "Resolved in Microsoft Graph Security."


@pytest.mark.parametrize(
    "graph_object, expected_reason",
    [
        ({"classification": "falsePositive"}, "False Positive"),
        ({"classification": "unknown"}, "Other"),
        ({"classification": "someFutureClassification"}, "Other"),
        ({"classification": None}, "Other"),
        ({"classification": ""}, "Other"),
        ({}, "Other"),
    ],
)
def test_to_xsoar_close_reason(graph_object, expected_reason):
    """
    Given: a Graph object with a known, unknown, unmapped, null, empty or missing classification.
    When: mapping it to the XSOAR close reason.
    Then: a known classification is mapped, any other value falls back to Other, and get_close_entry uses the same reason.
    """
    assert to_xsoar_close_reason(graph_object) == expected_reason
    assert get_close_entry(graph_object)["Contents"]["closeReason"] == expected_reason


def test_build_close_entry():
    """
    Given: a close reason and close notes.
    When: building the close entry.
    Then: the entry is an exact JSON note entry that closes the XSOAR incident with them.
    """
    assert build_close_entry("Resolved", "some notes") == {
        "Type": EntryType.NOTE,
        "Contents": {"dbotIncidentClose": True, "closeReason": "Resolved", "closeNotes": "some notes"},
        "ContentsFormat": EntryFormat.JSON,
    }


@pytest.mark.parametrize(
    "bad_time_fields",
    [{"createdDateTime": "not-a-date"}, {"createdDateTime": None}, {"createdDateTime": ""}, {}],
    ids=["unparseable", "null", "empty", "missing-key"],
)
def test_get_entries_for_comments_bad_created_time(bad_time_fields):
    """
    Given: a comment with an unparseable, null, empty or missing createdDateTime, next to a valid new comment.
    When: building the comment entries.
    Then: the bad comment is skipped without raising, and the valid one is returned.
    """
    comments = [
        {"comment": "bad time", "createdByDisplayName": "u", **bad_time_fields},
        {"comment": "good", "createdByDisplayName": "u", "createdDateTime": "2026-10-06T00:00:00Z"},
    ]
    last_update = datetime(2026, 10, 5, tzinfo=timezone.utc)  # noqa: UP017
    entries = get_entries_for_comments(comments, last_update, "tag")
    assert len(entries) == 1
    assert entries[0]["Contents"].endswith("good")


def test_get_remote_data_error_fallback(mocker):
    """
    Given: the API raises an error.
    When: running get-remote-data.
    Then: no exception is raised, and the {id, in_mirror_error} fallback is returned.
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=DemistoException("boom"))
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, MIRROR_PARAMS)
    assert res.mirrored_object["id"] == INCIDENT_ID
    assert res.mirrored_object["in_mirror_error"] == "boom"
    assert res.entries == []


def test_get_remote_data_clears_in_mirror_error_after_failure(mocker):
    """
    Given: the API fails on the first get-remote-data call for an ID, and succeeds on the next call for the same ID.
    When: running get-remote-data twice.
    Then: the first response carries the error in `in_mirror_error`; the second sends `in_mirror_error == ""`,
          so the server clears the stale error on the incident.
    """
    mocker.patch.object(
        client_mocker.ms_client,
        "http_request",
        side_effect=[DemistoException("boom"), _remote_object("incident", status="active")],
    )
    args = {"id": INCIDENT_ID, "lastUpdate": "0"}

    failed = get_remote_data_command(client_mocker, args, MIRROR_PARAMS)
    assert failed.mirrored_object["in_mirror_error"] == "boom"
    assert failed.entries == []

    recovered = get_remote_data_command(client_mocker, args, MIRROR_PARAMS)
    assert recovered.mirrored_object["id"] == INCIDENT_ID
    assert recovered.mirrored_object["in_mirror_error"] == ""


def _update_args(remote_id, delta, mirror_type, status=1, entries=None, changed=True):
    """
    Builds realistic update-remote-system args: `data` holds only outgoing-mapper keys (no `mirror_type`),
    so the type is resolved from the remote ID, as in production. `mirror_type` is only used to pick realistic data.
    """
    data = {"status": "active" if mirror_type == "incident" else "new", "classification": "", "determination": ""}
    if mirror_type == "incident":
        data |= {"severity": 2, "displayName": "Inc", "description": "", "customTags": [], "resolvingComment": ""}
    return {
        "remoteId": remote_id,
        "delta": delta,
        "data": data,
        "status": status,
        "incidentChanged": changed,
        "entries": entries or [],
    }


@pytest.mark.parametrize(
    "remote_id, mirror_type, expected_url",
    [
        (INCIDENT_ID, "incident", "security/incidents"),
        (ALERT_ID, "alert", "security/alerts_v2"),
        ("b3c5a1e2-7f4d-4c1a-9e8b-2d6f0a1b3c4d", "alert", "security/alerts_v2"),
    ],
)
def test_update_remote_system_mirror_type_from_id(mocker, remote_id, mirror_type, expected_url):
    """
    Given: a numeric incident ID, a `da...` alert ID or a GUID-like alert ID.
    When: running update-remote-system.
    Then: the type is inferred from the ID (digits only -> incident, else alert) and the matching URL is PATCHed.
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(remote_id, {"status": "resolved"}, mirror_type), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["url_suffix"] == f"{expected_url}/{remote_id}"


def test_update_remote_system_missing_remote_id(mocker):
    """
    Given: update-remote-system args without remoteId (manual run).
    When: running update-remote-system.
    Then: a clear DemistoException is raised and no request is sent.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request")
    mocker.patch.object(demisto, "error")
    with pytest.raises(DemistoException, match="remoteId argument is required"):
        update_remote_system_command(client_mocker, {"delta": {"status": "resolved"}, "incidentChanged": True}, MIRROR_PARAMS)
    assert http_mock.call_count == 0


@pytest.mark.parametrize(
    "mirror_type, remote_id, delta, expected_body",
    [
        ("incident", INCIDENT_ID, {"status": "unknownFutureValue", "displayName": "x"}, {"displayName": "x"}),
        ("incident", INCIDENT_ID, {"classification": "unknownFutureValue", "displayName": "x"}, {"displayName": "x"}),
        ("alert", ALERT_ID, {"status": "unknownFutureValue", "customDetails": ["k: v"]}, {"customDetails": {"k": "v"}}),
        ("alert", ALERT_ID, {"status": "inProgress", "classification": "unknownFutureValue"}, {"status": "inProgress"}),
        ("alert", ALERT_ID, {"status": "new", "determination": "unknownFutureValue"}, {"status": "new"}),
    ],
)
def test_update_remote_system_drops_unknown_future_value(mocker, mirror_type, remote_id, delta, expected_body):
    """
    Given: a delta with unknownFutureValue in status, classification or determination.
    When: running update-remote-system.
    Then: unknownFutureValue is never sent in the PATCH body (for alerts and incidents).
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == expected_body


def test_update_remote_system_logs_delta_keys_only(mocker):
    """
    Given: a delta with customer content.
    When: running update-remote-system.
    Then: the debug log contains the delta keys, not their values.
    """
    _patch_http(mocker)
    debug_mock = mocker.patch.object(demisto, "debug")
    delta = {"displayName": "secret customer title", "status": "resolved"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), MIRROR_PARAMS)
    logs = " ".join(str(c.args[0]) for c in debug_mock.call_args_list)
    assert "displayName" in logs
    assert "secret customer title" not in logs


def test_update_remote_system_incident_patch(mocker):
    """
    Given: an incident delta with allowed, disallowed and cleared keys, and an XSOAR severity.
    When: running update-remote-system.
    Then: the PATCH body is filtered, severity is mapped (3 -> high), the label is translated, and the cleared
        description is sent as "".
    """
    http_mock = _patch_http(mocker)
    delta = {
        "severity": 3,
        "displayName": "New name",
        "description": "",
        "customTags": "t1,t2",
        "classification": "True positive - Malware",
        "notAllowed": "x",
    }
    res = update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), MIRROR_PARAMS)
    assert res == INCIDENT_ID
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/incidents/{INCIDENT_ID}"
    assert patch_call.kwargs["json_data"] == {
        "severity": "high",
        "displayName": "New name",
        "description": "",
        "customTags": ["t1", "t2"],
        "classification": "truePositive",
        "determination": "malware",
    }


def test_alert_patch_keys_exclude_severity():
    """
    Given: the alert PATCH keys and the outgoing alert fields.
    When: checking for severity.
    Then: severity is in neither (Graph alerts_v2 rejects a severity update, so the alert severity is mirrored in only).
    """
    assert "severity" not in ALERT_PATCH_KEYS
    assert "severity" not in OUTGOING_ALERT_FIELDS


def test_update_remote_system_alert_severity_only_sends_no_patch(mocker):
    """
    Given: an alert delta that holds only an XSOAR severity (3).
    When: running update-remote-system.
    Then: no PATCH is sent (the alert severity is mirrored in only).
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, {"severity": 3}, "alert"), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH") == []


def test_update_remote_system_alert_severity_with_status_sends_status_only(mocker):
    """
    Given: an alert delta with an XSOAR severity (3) and a status.
    When: running update-remote-system.
    Then: the alert PATCH sends only the status, the severity is dropped.
    """
    http_mock = _patch_http(mocker)
    delta = {"severity": 3, "status": "inProgress"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert"), MIRROR_PARAMS)
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}"
    assert patch_call.kwargs["json_data"] == {"status": "inProgress"}


@pytest.mark.parametrize("severity", [0, 0.5, 1, 2, 3, "medium", 4])
def test_build_patch_body_alert_severity_not_sent(severity):
    """
    Given: an alert delta with an XSOAR severity (or a Graph severity string).
    When: building the alert PATCH body.
    Then: the severity is never sent for alerts.
    """
    assert build_patch_body({"severity": severity}, "alert") == {}


@pytest.mark.parametrize("section", ["Graph Security Alert", "Graph Security Incident"])
def test_outgoing_mapper_maps_closing_user_id(section):
    """
    Given: the outgoing mapper.
    When: reading the alert and incident sections.
    Then: closingUserId is mapped from the XSOAR closingUserId field, so the server keeps the cleared value in the
        update-remote-system delta on an XSOAR reopen (is_xsoar_reopen reads it). It is never PATCHed.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    assert _outgoing_mapper_source(mapping[section]["internalMapping"]["closingUserId"]) == "closingUserId"
    assert "closingUserId" not in INCIDENT_PATCH_KEYS | ALERT_PATCH_KEYS


def test_outgoing_mapper_alert_has_no_severity():
    """
    Given: the outgoing mapper.
    When: reading the alert and incident sections.
    Then: the alert section has no severity entry, and the incident section still maps severity.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    assert "severity" not in mapping["Graph Security Alert"]["internalMapping"]
    assert "severity" in mapping["Graph Security Incident"]["internalMapping"]


@pytest.mark.parametrize(
    "mirror_type, remote_id, delta, expected_body",
    [
        ("incident", INCIDENT_ID, {"assignedTo": "analyst@example.com", "displayName": "x"}, {"displayName": "x"}),
        ("alert", ALERT_ID, {"assignedTo": "analyst@example.com", "status": "inProgress"}, {"status": "inProgress"}),
    ],
)
def test_update_remote_system_never_sends_assigned_to(mocker, mirror_type, remote_id, delta, expected_body):
    """
    Given: an alert/incident delta that contains assignedTo (mirror-in only, Defender-specific user IDs).
    When: running update-remote-system.
    Then: assignedTo is never sent in the PATCH body.
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert "assignedTo" not in body
    assert body == expected_body


def test_alert_patch_keys_include_classification():
    """
    Given: the allowed alert PATCH keys.
    When: checking them.
    Then: classification and determination are allowed (the combined label is split and mirrored out, as for incidents).
    """
    assert "classification" in ALERT_PATCH_KEYS
    assert "determination" in ALERT_PATCH_KEYS


@pytest.mark.parametrize(
    "delta",
    [
        {"classification": "True positive - Malware", "status": "inProgress"},
        {"microsoftgraphsecurityclassification": "True positive - Malware", "status": "inProgress"},
        {"classification": "truePositive", "determination": "malware", "status": "inProgress"},
    ],
    ids=["label", "raw-field-name", "graph-values"],
)
def test_update_remote_system_alert_sends_classification(mocker, delta):
    """
    Given: an alert delta with a classification (label, raw field name or Graph values) and a status change.
    When: running update-remote-system.
    Then: the status and the alert classification/determination are PATCHed.
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert"), MIRROR_PARAMS)
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}"
    assert patch_call.kwargs["json_data"] == {
        "status": "inProgress",
        "classification": "truePositive",
        "determination": "malware",
    }


def test_update_remote_system_alert_classification_only_sends_patch(mocker):
    """
    Given: an open alert whose delta only changes the Microsoft Graph Security Classification field.
    When: running update-remote-system.
    Then: the alert PATCH holds the classification and the determination name (`notMalicious`).
    """
    http_mock = _patch_http(mocker)
    delta = {"classification": "False positive - Not malicious"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert"), MIRROR_PARAMS)
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}"
    assert patch_call.kwargs["json_data"] == {"classification": "falsePositive", "determination": "notMalicious"}


def test_outgoing_mapper_classification_both_types():
    """
    Given: the outgoing mapper.
    When: reading the alert and incident sections.
    Then: both map classification out from the Microsoft Graph Security Classification field.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    for section in ("Graph Security Alert", "Graph Security Incident"):
        rule = mapping[section]["internalMapping"]["classification"]
        assert rule == {"complex": {"filters": [], "root": "microsoftgraphsecurityclassification", "transformers": []}}


def test_patch_keys_exclude_assigned_to():
    """
    Given: the allowed PATCH key sets.
    When: checking them.
    Then: assignedTo is in neither set (it is mirror-in only).
    """
    assert "assignedTo" not in INCIDENT_PATCH_KEYS
    assert "assignedTo" not in ALERT_PATCH_KEYS


def test_build_patch_body_incident_drops_summary():
    """
    Given: an incident delta that holds summary and status.
    When: building the PATCH body.
    Then: summary is dropped (it is not an allowed incident PATCH key) and status is kept.
    """
    assert "summary" not in INCIDENT_PATCH_KEYS
    assert build_patch_body({"summary": "x", "status": "active"}, "incident") == {"status": "active"}


@pytest.mark.parametrize(
    "graph_severity, expected",
    [("unknownFutureValue", 0), ("unknown", 0), ("informational", 0.5), ("high", 3)],
)
def test_severity_map_unknown_future_value(graph_severity, expected):
    """
    Given: a Graph severity, including the unknownFutureValue sentinel.
    When: mapping it with SEVERITY_MAP.
    Then: unknownFutureValue maps to Unknown (0), like unknown.
    """
    assert SEVERITY_MAP[graph_severity] == expected


@pytest.mark.parametrize("close_reason", ["False Positive", "Duplicate", "Other", "Resolved"])
def test_update_remote_system_incident_close_out(mocker, close_reason):
    """
    Given: a closed XSOAR incident with close fields in the delta, and close_out on.
    When: running update-remote-system for an incident.
    Then: the PATCH sends only status=resolved and resolvingComment (close reason + notes). The close reason never sets
        the classification/determination.
    """
    http_mock = _patch_http(mocker)
    delta = {"closeReason": close_reason, "closeNotes": "done"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body == {"status": "resolved", "resolvingComment": f"Closed in Cortex XSOAR as: {close_reason}\nComment: done"}
    assert _http_calls(http_mock, "POST") == []


@pytest.mark.parametrize("mirror_type, remote_id", [("incident", INCIDENT_ID), ("alert", ALERT_ID)])
def test_update_remote_system_close_out_ignores_classification_in_data(mocker, mirror_type, remote_id):
    """
    Given: a False Positive close, with a Microsoft Graph Security Classification value in the data (not changed).
    When: running update-remote-system with close_out on.
    Then: no classification/determination is sent: only a change of the classification field itself sends it.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(remote_id, {"closeReason": "False Positive"}, mirror_type, status=2)
    args["data"]["classification"] = "False positive - Not malicious"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert "classification" not in body
    assert "determination" not in body
    assert body["status"] == "resolved"


@pytest.mark.parametrize(
    "close_reason, close_notes, expected",
    [
        ("False Positive", "Benign admin script.", "Closed in Cortex XSOAR as: False Positive\nComment: Benign admin script."),
        ("Duplicate", "Same as 1234.", "Closed in Cortex XSOAR as: Duplicate\nComment: Same as 1234."),
        ("Other", "", "Closed in Cortex XSOAR as: Other"),
        ("Other", None, "Closed in Cortex XSOAR as: Other"),
        (None, "Benign admin script.", "Benign admin script."),
        ("", "Benign admin script.", "Benign admin script."),
        (None, None, None),
        (None, "", None),
        # Notes mirrored back in from Microsoft already hold the prefix: they are sent as-is (no double prefix).
        (
            "False Positive",
            "Closed in Cortex XSOAR as: False Positive\nComment: Benign admin script.",
            "Closed in Cortex XSOAR as: False Positive\nComment: Benign admin script.",
        ),
    ],
)
def test_format_close_comment(close_reason, close_notes, expected):
    """
    Given: an XSOAR close reason and close notes (each may be missing).
    When: building the close comment sent to Microsoft.
    Then: "Closed in Cortex XSOAR as: <reason>" plus "Comment: <notes>" when there are notes; only the notes without a
        reason; None when both are missing; notes that already hold the prefix are returned as-is.
    """
    assert format_close_comment(close_reason, close_notes) == expected


def test_update_remote_system_alert_close_out_comment_has_close_reason(mocker):
    """
    Given: a closed XSOAR incident mirrored to an alert, closed as Duplicate with notes, and close_out on.
    When: running update-remote-system.
    Then: the alert close comment holds the close reason and the notes, with the mirrored-out marker.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    delta = {"closeReason": "Duplicate", "closeNotes": "Same as alert 1."}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    comment = _http_calls(http_mock, "POST")[0].kwargs["json_data"]["comment"]
    assert comment.startswith("Closed in Cortex XSOAR as: Duplicate\nComment: Same as alert 1.")
    assert MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR in comment


def test_update_remote_system_close_reason_never_patched(mocker):
    """
    Given: a delta with closeReason (mapped out only so the server includes it) on a closed incident.
    When: running update-remote-system.
    Then: closeReason is not a key of the PATCH body.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {"closeReason": "Other"}, "incident", status=2)
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert "closeReason" not in body
    assert body["resolvingComment"] == "Closed in Cortex XSOAR as: Other"


def test_outgoing_mapper_maps_close_reason():
    """
    Given: the outgoing mapper.
    When: reading the alert and incident sections.
    Then: closeReason is mapped from the XSOAR closeReason field, so the server includes it in the delta.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    for section in ("Graph Security Alert", "Graph Security Incident"):
        assert mapping[section]["internalMapping"]["closeReason"]["complex"]["root"] == "closeReason"


def test_outgoing_mapper_maps_alert_close_notes():
    """
    Given: the outgoing mapper.
    When: reading the alert section.
    Then: closeNotes is mapped from the XSOAR closeNotes field, so the server includes it in the delta and the alert
        close comment holds the close notes (alerts have no resolvingComment).
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    assert mapping["Graph Security Alert"]["internalMapping"]["closeNotes"]["complex"]["root"] == "closeNotes"


def test_update_remote_system_alert_close_notes_never_patched(mocker):
    """
    Given: an alert close with closeNotes in the delta (mapped out only so the server includes it).
    When: running update-remote-system with close_out on.
    Then: closeNotes is not a key of the alert PATCH body; it is only sent in the close comment.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    delta = {"closeReason": "Resolved", "closeNotes": "handled"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved"}
    assert "Comment: handled" in _http_calls(http_mock, "POST")[0].kwargs["json_data"]["comment"]


def test_update_remote_system_incident_close_out_only_resolving_comment(mocker):
    """
    Given: a closed XSOAR incident whose delta holds only resolvingComment (the mapped closeNotes), as seen on the tenant.
    When: running update-remote-system with close_out on.
    Then: the incident is resolved in the same PATCH, so Graph doesn't reject resolvingComment on a non-resolved incident.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {"resolvingComment": "Resolved"}, "incident", status=2)
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body == {"status": "resolved", "resolvingComment": "Resolved"}


@pytest.mark.parametrize("close_reason", ["False Positive", "Duplicate", "Other"])
def test_update_remote_system_close_notes_edit_reads_close_reason_from_data(mocker, close_reason):
    """
    Given: a closed XSOAR incident whose delta holds only resolvingComment (e.g. reclosed with the same close reason and new
        notes), and the close reason in the data.
    When: running update-remote-system with close_out on.
    Then: only status and the updated resolvingComment (with the close reason from the data) are sent.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {"resolvingComment": "n"}, "incident", status=2)
    args["data"]["closeReason"] = close_reason
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body == {"status": "resolved", "resolvingComment": f"Closed in Cortex XSOAR as: {close_reason}\nComment: n"}


def test_update_remote_system_alert_close_notes_edit_posts_no_comment(mocker):
    """
    Given: a closed XSOAR incident mirrored to an alert, whose delta holds only closeNotes (no closeReason), and the data
        doesn't show the alert resolved.
    When: running update-remote-system with close_out on.
    Then: no close comment is POSTed again (no duplicate close comment), and only status is sent.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    args = _update_args(ALERT_ID, {"closeNotes": "edited notes"}, "alert", status=2)
    args["data"]["closeReason"] = "Resolved"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "POST") == []
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved"}


@pytest.mark.parametrize(
    "remote_id, mirror_type, delta",
    [
        (INCIDENT_ID, "incident", {"resolvingComment": ""}),
        (INCIDENT_ID, "incident", {"closeNotes": ""}),
        (INCIDENT_ID, "incident", {"closeReason": "", "closeNotes": ""}),
        (INCIDENT_ID, "incident", {"closingUserId": "admin"}),
        (ALERT_ID, "alert", {"closeNotes": ""}),
    ],
)
def test_update_remote_system_cleared_close_fields_without_closing_user_is_not_a_reopen(mocker, remote_id, mirror_type, delta):
    """
    Given: an open XSOAR incident whose delta clears close fields but doesn't clear closingUserId.
    When: running update-remote-system with close_out on.
    Then: nothing is sent (no GET, no PATCH) - only an XSOAR reopen clears closingUserId.
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type, status=1), MIRROR_PARAMS)
    assert http_mock.call_count == 0


def test_update_remote_system_incident_close_out_keeps_label(mocker):
    """
    Given: a close where the Microsoft Graph Security Classification field also changed in the same update.
    When: running update-remote-system.
    Then: the changed label's classification/determination are sent with the close.
    """
    http_mock = _patch_http(mocker)
    delta = {"closeReason": "Resolved", "classification": "Informational - Confirmed activity"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body["classification"] == "informationalExpectedActivity"
    assert body["determination"] == "confirmedActivity"


def test_update_remote_system_alert_close_out(mocker):
    """
    Given: a closed XSOAR incident mirrored to an alert, with close notes, and close_out on.
    When: running update-remote-system.
    Then: the alert is PATCHed with only status=resolved, and the close notes are POSTed as a marked comment.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    delta = {"closeReason": "False Positive", "closeNotes": "not malicious"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body == {"status": "resolved"}
    post_call = _http_calls(http_mock, "POST")[0]
    assert post_call.kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}/comments"
    assert post_call.kwargs["json_data"]["@odata.type"] == "microsoft.graph.security.alertComment"
    assert "not malicious" in post_call.kwargs["json_data"]["comment"]
    assert MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR in post_call.kwargs["json_data"]["comment"]


@pytest.mark.parametrize("delta", [{}, {"closeReason": "", "closeNotes": ""}], ids=["empty-delta", "empty-close-fields"])
def test_update_remote_system_incident_close_without_reason_or_notes(mocker, delta):
    """
    Given: an XSOAR incident closed (status=2) without a close reason or close notes, mirrored to an active Microsoft
        incident, with close_out on.
    When: running update-remote-system.
    Then: the incident is resolved with the default resolvingComment "Closed in Cortex XSOAR.", the path is logged with
        demisto.debug, and no comment is POSTed.
    """
    http_mock = _patch_http(mocker)
    debug_mock = mocker.patch.object(demisto, "debug")
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body == {"status": "resolved", "resolvingComment": "Closed in Cortex XSOAR."}
    assert _http_calls(http_mock, "POST") == []
    assert any("without a close reason or close notes" in c.args[0] for c in debug_mock.call_args_list)


@pytest.mark.parametrize("delta", [{}, {"closeReason": "", "closeNotes": ""}], ids=["empty-delta", "empty-close-fields"])
def test_update_remote_system_alert_close_without_reason_or_notes(mocker, delta):
    """
    Given: an XSOAR incident closed (status=2) without a close reason or close notes, mirrored to a new Microsoft alert,
        with close_out on.
    When: running update-remote-system.
    Then: the alert is PATCHed with status=resolved and the marked default comment "Closed in Cortex XSOAR." is POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved"}
    post_calls = _http_calls(http_mock, "POST")
    assert len(post_calls) == 1
    comment = post_calls[0].kwargs["json_data"]["comment"]
    assert comment.startswith("Closed in Cortex XSOAR.")
    assert MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR in comment


def test_update_remote_system_incident_close_without_reason_keeps_existing_resolving_comment(mocker):
    """
    Given: a closed XSOAR incident without a close reason or close notes in the delta, whose outgoing data already holds
        a resolvingComment, and close_out on.
    When: running update-remote-system.
    Then: the incident is resolved, and the existing resolvingComment is not overwritten with the default comment.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {}, "incident", status=2)
    args["data"]["resolvingComment"] = "Investigated by SOC"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved"}


@pytest.mark.parametrize("mirror_type, remote_id", [("incident", INCIDENT_ID), ("alert", ALERT_ID)])
def test_update_remote_system_close_without_reason_remote_already_resolved(mocker, mirror_type, remote_id):
    """
    Given: a closed XSOAR incident without a close reason or close notes, whose outgoing data shows the remote object is
        already resolved, and close_out on.
    When: running update-remote-system.
    Then: nothing is PATCHed or POSTed (no default close comment is sent again).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    args = _update_args(remote_id, {}, mirror_type, status=2)
    args["data"]["status"] = "resolved"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert http_mock.call_count == 0


@pytest.mark.parametrize("close_out", [False, "false"])
def test_update_remote_system_close_without_reason_close_out_off(mocker, close_out):
    """
    Given: a closed XSOAR incident without a close reason or close notes, and close_out off.
    When: running update-remote-system.
    Then: the remote object is not resolved: nothing is PATCHed or POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    params = MIRROR_PARAMS | {"close_out": close_out}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, {}, "incident", status=2), params)
    assert http_mock.call_count == 0


def test_update_remote_system_open_incident_empty_delta_sends_nothing(mocker):
    """
    Given: an open XSOAR incident (status=1) with an empty delta, and close_out on.
    When: running update-remote-system.
    Then: nothing is PATCHed or POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, {}, "incident", status=1), MIRROR_PARAMS)
    assert http_mock.call_count == 0


def _remote_status_http(remote_status: str | None = None, get_error: Exception | None = None):
    """
    Returns an http_request side effect for the already-resolved close-out guard: GET returns the remote object with
    `remote_status` (or raises `get_error`), PATCH returns "" and POST returns {}.
    The remote object is classified falsePositive, so incoming mirroring would close XSOAR as "False Positive" with
    close notes "Benign - tested by SOC".
    """

    def side_effect(*args, **kwargs):
        if kwargs.get("method") != "GET":
            return "" if kwargs.get("method") == "PATCH" else {}
        if get_error:
            raise get_error
        return {
            "id": "x",
            "status": remote_status,
            "classification": "falsePositive",
            "resolvingComment": "Benign - tested by SOC",
        }

    return side_effect


TAGGED_ENTRY = {"id": "1", "contents": "tagged note", "tags": ["CommentToMicrosoftGraphSecurity"], "user": "admin"}


@pytest.mark.parametrize(
    "delta",
    [
        {"closeReason": "False Positive", "resolvingComment": "Benign - tested by SOC"},
        {"closeReason": "False Positive"},
        {"resolvingComment": "Benign - tested by SOC"},
        {"closeReason": "False Positive", "resolvingComment": " Benign -  tested by SOC\n"},
        {"closeReason": "False Positive", "status": "resolved"},
        {},
    ],
    ids=["reason-and-notes", "reason-only", "resolving-comment-only", "whitespace-differs", "explicit-status", "default-close"],
)
def test_update_remote_system_incident_already_resolved_no_close_out(mocker, delta):
    """
    Given: a Microsoft incident already resolved in Defender (classification falsePositive, resolvingComment
        "Benign - tested by SOC"), and the XSOAR incident closed (status=2) by incoming mirroring, with close_out on.
        The delta only echoes the incoming close (tenant shapes: ['closeReason', 'resolvingComment'] and ['closeReason']).
    When: running update-remote-system.
    Then: the close-out is skipped: nothing is PATCHed (no status, no resolvingComment overwrite), nothing is POSTed,
        and the skip is logged with demisto.debug.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    debug_mock = mocker.patch.object(demisto, "debug")
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), MIRROR_PARAMS)
    assert [c.kwargs["url_suffix"] for c in _http_calls(http_mock, "GET")] == [f"security/incidents/{INCIDENT_ID}"]
    assert _http_calls(http_mock, "PATCH") == []
    assert _http_calls(http_mock, "POST") == []
    assert any("already resolved" in str(c.args[0]) and "echo" in str(c.args[0]) for c in debug_mock.call_args_list)


@pytest.mark.parametrize(
    "delta",
    [
        {"closeReason": "False Positive", "closeNotes": "Resolved in Microsoft Graph Security."},
        {"closeReason": "False Positive"},
        {},
    ],
    ids=["incoming-default-notes", "reason-only", "default-close"],
)
def test_update_remote_system_alert_already_resolved_no_close_out(mocker, delta):
    """
    Given: a Microsoft alert already resolved in Defender (classification falsePositive), and the XSOAR incident closed
        (status=2) by incoming mirroring, with close_out on. The delta holds no close keys, or only the close reason and
        notes incoming mirroring set (an echo of the incoming close).
    When: running update-remote-system.
    Then: no status PATCH and no close comment ("Mirrored from Cortex XSOAR") is POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    assert [c.kwargs["url_suffix"] for c in _http_calls(http_mock, "GET")] == [f"security/alerts_v2/{ALERT_ID}"]
    assert _http_calls(http_mock, "PATCH") == []
    assert _http_calls(http_mock, "POST") == []


@pytest.mark.parametrize(
    "remote_id, mirror_type, remote_status, delta, expected_body, expected_comment",
    [
        (
            INCIDENT_ID,
            "incident",
            "active",
            {"closeReason": "Other", "closeNotes": "n"},
            {"status": "resolved", "resolvingComment": "Closed in Cortex XSOAR as: Other\nComment: n"},
            None,
        ),
        (INCIDENT_ID, "incident", "inProgress", {}, {"status": "resolved", "resolvingComment": "Closed in Cortex XSOAR."}, None),
        (
            ALERT_ID,
            "alert",
            "new",
            {"closeReason": "Other", "closeNotes": "n"},
            {"status": "resolved"},
            "Closed in Cortex XSOAR as: Other\nComment: n",
        ),
        (ALERT_ID, "alert", "inProgress", {}, {"status": "resolved"}, "Closed in Cortex XSOAR."),
    ],
    ids=["incident-reason", "incident-default", "alert-reason", "alert-default"],
)
def test_update_remote_system_remote_not_resolved_close_out_proceeds(
    mocker, remote_id, mirror_type, remote_status, delta, expected_body, expected_comment
):
    """
    Given: the remote object is not resolved (GET), and the XSOAR incident is closed, with close_out on.
    When: running update-remote-system with a close reason/notes, or without them (default close message).
    Then: the close-out runs as before: status=resolved (+ resolvingComment for incidents, close comment for alerts).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http(remote_status))
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type, status=2), MIRROR_PARAMS)
    assert len(_http_calls(http_mock, "GET")) == 1
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == expected_body
    posts = _http_calls(http_mock, "POST")
    if expected_comment:
        assert posts[0].kwargs["json_data"]["comment"].startswith(expected_comment)
    else:
        assert posts == []


def test_update_remote_system_incident_already_resolved_other_fields_and_entries_still_sent(mocker):
    """
    Given: a Microsoft incident already resolved, a closed XSOAR incident whose delta also holds a severity, a display
        name and a classification label change, and a tagged entry.
    When: running update-remote-system with close_out on.
    Then: the other fields are PATCHed (without status/resolvingComment), and the tagged entry is POSTed as a comment.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {
        "closeReason": "False Positive",
        "resolvingComment": "Benign - tested by SOC",
        "severity": 3,
        "displayName": "New name",
        "classification": "Informational - Confirmed activity",
    }
    args = _update_args(INCIDENT_ID, delta, "incident", status=2, entries=[TAGGED_ENTRY])
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {
        "severity": "high",
        "displayName": "New name",
        "classification": "informationalExpectedActivity",
        "determination": "confirmedActivity",
    }
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert "(admin): tagged note" in posts[0].kwargs["json_data"]["comment"]


def test_update_remote_system_alert_already_resolved_other_fields_and_entries_still_sent(mocker):
    """
    Given: a Microsoft alert already resolved, a closed XSOAR incident whose delta also holds a classification label and
        customDetails change, and a tagged entry.
    When: running update-remote-system with close_out on.
    Then: classification/determination/customDetails are PATCHed (no status), only the tagged entry is POSTed (no close
        comment).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {"closeReason": "False Positive", "classification": "True positive - Malware", "customDetails": ["k: v"]}
    args = _update_args(ALERT_ID, delta, "alert", status=2, entries=[TAGGED_ENTRY])
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert "status" not in body
    assert body["classification"] == "truePositive"
    assert body["customDetails"] == {"k": "v"}
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert "(admin): tagged note" in posts[0].kwargs["json_data"]["comment"]


@pytest.mark.parametrize(
    "delta, close_reason_in_data, expected_comment",
    [
        (
            {"resolvingComment": "Phishing test"},
            "False Positive",
            "Closed in Cortex XSOAR as: False Positive\nComment: Phishing test",
        ),
        (
            {"closeReason": "False Positive", "resolvingComment": "Phishing test"},
            None,
            "Closed in Cortex XSOAR as: False Positive\nComment: Phishing test",
        ),
        ({"closeReason": "Duplicate"}, None, "Closed in Cortex XSOAR as: Duplicate"),
        (
            {"closeReason": "Duplicate", "resolvingComment": "Benign - tested by SOC"},
            None,
            "Closed in Cortex XSOAR as: Duplicate\nComment: Benign - tested by SOC",
        ),
    ],
    ids=["notes-edit", "reclose-new-notes", "reason-only-edit", "reason-edit-same-notes"],
)
def test_update_remote_system_incident_already_resolved_close_edit_is_sent(mocker, delta, close_reason_in_data, expected_comment):
    """
    Given: a Microsoft incident already resolved, and the XSOAR incident closed with a different close reason and/or
        close notes (reopened and closed again in the same sync, or right after incoming mirroring closed it), close_out on.
    When: running update-remote-system.
    Then: one GET, then status=resolved and the new prefixed resolvingComment are PATCHed; the push is logged.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    debug_mock = mocker.patch.object(demisto, "debug")
    args = _update_args(INCIDENT_ID, delta, "incident", status=2)
    if close_reason_in_data:
        args["data"]["closeReason"] = close_reason_in_data
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert len(_http_calls(http_mock, "GET")) == 1
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved", "resolvingComment": expected_comment}
    assert _http_calls(http_mock, "POST") == []
    assert any("not an echo" in str(c.args[0]) for c in debug_mock.call_args_list)


@pytest.mark.parametrize(
    "delta, close_reason_in_data, expected_comment",
    [
        (
            {"closeReason": "Duplicate", "closeNotes": "Same as alert 1."},
            None,
            "Closed in Cortex XSOAR as: Duplicate\nComment: Same as alert 1.",
        ),
        ({"closeNotes": "edited notes"}, "False Positive", "Closed in Cortex XSOAR as: False Positive\nComment: edited notes"),
    ],
    ids=["reason-and-notes", "notes-only"],
)
def test_update_remote_system_alert_already_resolved_close_edit_posts_comment(
    mocker, delta, close_reason_in_data, expected_comment
):
    """
    Given: a Microsoft alert already resolved, and the XSOAR incident closed with a different close reason and/or
        close notes (reopened and closed again in the same sync, or right after incoming mirroring closed it), close_out on.
    When: running update-remote-system.
    Then: one GET, status=resolved is PATCHed (idempotent), and the new close comment is POSTed with the mirror marker.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    args = _update_args(ALERT_ID, delta, "alert", status=2)
    if close_reason_in_data:
        args["data"]["closeReason"] = close_reason_in_data
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert len(_http_calls(http_mock, "GET")) == 1
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved"}
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert posts[0].kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}/comments"
    assert posts[0].kwargs["json_data"]["comment"].startswith(expected_comment)
    assert MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR in posts[0].kwargs["json_data"]["comment"]


@pytest.mark.parametrize("remote_status", ["resolved", "active"])
@pytest.mark.parametrize(
    "delta",
    [{"status": "inProgress"}, {"status": "inProgress", "resolvingComment": "n"}, {"status": "active", "closeReason": "Other"}],
    ids=["status-only", "status-with-notes", "active-with-reason"],
)
def test_update_remote_system_closed_incident_explicit_open_status_is_sent(mocker, remote_status, delta):
    """
    Given: a closed XSOAR incident (status=2) whose delta holds an explicit non-resolved status, with close_out on, and the
        Microsoft incident resolved or active.
    When: running update-remote-system.
    Then: only the explicit status is PATCHed as-is (not overwritten with resolved, not dropped), with no GET, no
        resolvingComment and no comment POST.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http(remote_status))
    debug_mock = mocker.patch.object(demisto, "debug")
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "GET") == []
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": delta["status"]}
    assert _http_calls(http_mock, "POST") == []
    assert any("explicit status" in str(c.args[0]) for c in debug_mock.call_args_list)


def test_update_remote_system_closed_alert_explicit_open_status_is_sent(mocker):
    """
    Given: a closed XSOAR incident mirrored to a resolved alert, whose delta holds the raw alert status field set to
        inProgress, with close_out on.
    When: running update-remote-system.
    Then: status=inProgress is PATCHed, with no GET and no close comment.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {"microsoftgraphsecurityalertstatus": "inProgress"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "GET") == []
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "inProgress"}
    assert _http_calls(http_mock, "POST") == []


@pytest.mark.parametrize(
    "delta",
    [{"closeReason": "Duplicate", "resolvingComment": "Phishing test"}, {"resolvingComment": "Phishing test"}],
    ids=["reason-and-notes", "notes-only"],
)
def test_update_remote_system_closed_incident_close_edit_close_out_off(mocker, delta):
    """
    Given: a closed XSOAR incident whose delta holds close fields (a reclose), mirrored to a resolved Microsoft incident,
        with close_out off.
    When: running update-remote-system.
    Then: nothing is sent: no GET, no PATCH, no POST (resolvingComment is dropped when close_out is off).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    params = MIRROR_PARAMS | {"close_out": False}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), params)
    assert http_mock.call_count == 0


@pytest.mark.parametrize("remote_id, mirror_type", [(INCIDENT_ID, "incident"), (ALERT_ID, "alert")])
def test_update_remote_system_close_out_status_get_fails_close_out_proceeds(mocker, remote_id, mirror_type):
    """
    Given: the GET of the remote status fails with a non-429 error (HTTP 500), and a closed XSOAR incident with a
        close reason, with close_out on.
    When: running update-remote-system.
    Then: the failure is logged and the close-out proceeds as before (status=resolved is PATCHed).
    """
    error = DemistoException("Error in API call [500] - Server Error", res=SimpleNamespace(status_code=500, headers={}))
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http(get_error=error))
    debug_mock = mocker.patch.object(demisto, "debug")
    delta = {"closeReason": "Other", "closeNotes": "n"}
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type, status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]["status"] == "resolved"
    assert any("Failed to get the remote status" in str(c.args[0]) for c in debug_mock.call_args_list)


def test_update_remote_system_close_out_status_get_rate_limited(mocker):
    """
    Given: the GET of the remote status fails with HTTP 429, a closed XSOAR incident with a close reason, a tagged entry,
        and close_out on.
    When: running update-remote-system.
    Then: the "API rate limit" error is raised, so the server retries; nothing is PATCHed and no entry is POSTed.
    """
    http_mock = mocker.patch.object(
        client_mocker.ms_client, "http_request", side_effect=_remote_status_http(get_error=_rate_limit_error())
    )
    mocker.patch.object(demisto, "debug")
    args = _update_args(INCIDENT_ID, {"closeReason": "Other"}, "incident", status=2, entries=[TAGGED_ENTRY])
    with pytest.raises(DemistoException, match="API rate limit"):
        update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH") == []
    assert _http_calls(http_mock, "POST") == []


@pytest.mark.parametrize(
    "remote_id, mirror_type, delta, inc_status, params, data_overrides",
    [
        (INCIDENT_ID, "incident", {"displayName": "x"}, 1, MIRROR_PARAMS, {}),
        (INCIDENT_ID, "incident", {"closeReason": "Other"}, 2, MIRROR_PARAMS | {"close_out": False}, {}),
        (INCIDENT_ID, "incident", {"closeReason": "Other"}, 2, MIRROR_PARAMS, {"status": "redirected"}),
        (ALERT_ID, "alert", {}, 2, MIRROR_PARAMS, {"status": "resolved"}),
    ],
    ids=["xsoar-open", "close-out-off", "redirected", "default-close-data-already-resolved"],
)
def test_update_remote_system_no_status_get_when_close_out_would_not_patch(
    mocker, remote_id, mirror_type, delta, inc_status, params, data_overrides
):
    """
    Given: an update where close-out would not PATCH (XSOAR open, close_out off, redirected incident, or the default
        close-out already skipped because the outgoing data shows a resolved remote object).
    When: running update-remote-system.
    Then: no extra GET of the remote status is made.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    args = _update_args(remote_id, delta, mirror_type, status=inc_status)
    args["data"] |= data_overrides
    update_remote_system_command(client_mocker, args, params)
    assert _http_calls(http_mock, "GET") == []


# All 15 combined labels -> (Graph classification, Graph determination). Alerts and incidents use the same names.
ALL_CLASSIFICATION_LABELS = [
    ("Unclassified", "unknown", "unknown"),
    ("True positive - Multi staged attack", "truePositive", "multiStagedAttack"),
    ("True positive - Malware", "truePositive", "malware"),
    ("True positive - Malicious user activity", "truePositive", "maliciousUserActivity"),
    ("True positive - Unwanted software", "truePositive", "unwantedSoftware"),
    ("True positive - Phishing", "truePositive", "phishing"),
    ("True positive - Compromised account", "truePositive", "compromisedAccount"),
    ("True positive - Other", "truePositive", "other"),
    ("Informational - Security testing", "informationalExpectedActivity", "securityTesting"),
    ("Informational - Confirmed activity", "informationalExpectedActivity", "confirmedActivity"),
    ("Informational - Line of business application", "informationalExpectedActivity", "lineOfBusinessApplication"),
    ("Informational - Other", "informationalExpectedActivity", "other"),
    ("False positive - Not malicious", "falsePositive", "notMalicious"),
    ("False positive - Not enough data to validate", "falsePositive", "notEnoughDataToValidate"),
    ("False positive - Other", "falsePositive", "other"),
]
# Old alert determination names -> current names. Graph rejects the old names on PATCH (HTTP 400), but alerts may still
# come in with them, so the incoming Alert mapper keeps both.
LEGACY_ALERT_DETERMINATIONS = {
    "compromisedUser": "compromisedAccount",
    "confirmedUserActivity": "confirmedActivity",
    "clean": "notMalicious",
    "insufficientData": "notEnoughDataToValidate",
}


@pytest.mark.parametrize("label, classification, determination", ALL_CLASSIFICATION_LABELS)
def test_apply_classification_label(label, classification, determination):
    """
    Given: a combined Classification label in a delta (all 15 labels).
    When: splitting it.
    Then: it becomes the Graph classification and the current determination name (the same for alerts and incidents),
        other keys stay.
    """
    delta = {"classification": label, "status": "new"}
    apply_classification_label(delta)
    assert delta == {"classification": classification, "determination": determination, "status": "new"}
    assert delta["determination"] not in LEGACY_ALERT_DETERMINATIONS


def test_apply_classification_label_non_label_unchanged():
    """
    Given: a delta whose classification is already a Graph value, not a combined label.
    When: splitting it.
    Then: the delta is left unchanged.
    """
    delta = {"classification": "truePositive", "determination": "malware"}
    apply_classification_label(delta)
    assert delta == {"classification": "truePositive", "determination": "malware"}


def test_update_remote_system_alert_close_out_with_label_change_sends_classification(mocker):
    """
    Given: an alert close where the classification field also changed to "False positive - Not malicious".
    When: running update-remote-system with close_out on.
    Then: the alert PATCH sends status=resolved and the split label (determination `notMalicious`).
    """
    http_mock = _patch_http(mocker)
    delta = {"closeReason": "Resolved", "classification": "False positive - Not malicious"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert body == {"status": "resolved", "classification": "falsePositive", "determination": "notMalicious"}


def test_update_remote_system_alert_not_enough_data_sends_current_determination(mocker):
    """
    Given: an open alert whose delta sets the label "False positive - Not enough data to validate".
    When: running update-remote-system.
    Then: the alerts_v2 PATCH sends `determination: notEnoughDataToValidate`, not the rejected `insufficientData`.
    """
    http_mock = _patch_http(mocker)
    delta = {"classification": "False positive - Not enough data to validate"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert"), MIRROR_PARAMS)
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}"
    assert patch_call.kwargs["json_data"] == {"classification": "falsePositive", "determination": "notEnoughDataToValidate"}


def test_update_remote_system_incident_classification_label(mocker):
    """
    Given: an open incident whose delta sets the label "False positive - Not malicious".
    When: running update-remote-system.
    Then: the PATCH body holds the incident classification and determination (`notMalicious`).
    """
    http_mock = _patch_http(mocker)
    delta = {"classification": "False positive - Not malicious"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), MIRROR_PARAMS)
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/incidents/{INCIDENT_ID}"
    assert patch_call.kwargs["json_data"] == {"classification": "falsePositive", "determination": "notMalicious"}


NEW_INCOMING_MAPPER_PATH = "../../Classifiers/classifier-mapper-incoming-Graph_Security.json"
OLD_INCOMING_MAPPER_PATH = "../../Classifiers/classifier-Graph_Security_Alert_Mapper.json"
MAPPER_TYPE_SECTIONS = ["Graph Security Alert", "Graph Security Incident"]


def _mapper_classification_pairs(section: str) -> tuple[list[str], list[str]]:
    """Returns the (inputs, outputs) of the incoming mapper's Classification MapValuesTransformer for a section."""
    mapper = load_json(NEW_INCOMING_MAPPER_PATH)
    rule = mapper["mapping"][section]["internalMapping"]["Microsoft Graph Security Classification"]
    transformer = next(t for t in rule["complex"]["transformers"] if t["operator"] == "MapValuesTransformer")
    inputs = transformer["args"]["input_values"]["value"]["simple"].split(",")
    outputs = transformer["args"]["mapped_values"]["value"]["simple"].split(",")
    return inputs, outputs


@pytest.mark.parametrize("section, expected_count", [("Graph Security Alert", 19), ("Graph Security Incident", 15)])
def test_incoming_mapper_classification_per_type(section, expected_count):
    """
    Given: the incoming mapper Classification rule of the Alert and Incident sections.
    When: reading its MapValuesTransformer inputs/outputs.
    Then: inputs and outputs are aligned with no duplicate inputs (15 for incidents, 15 + 4 old names for alerts),
        and every current "classification|determination" pair maps to its label.
    """
    inputs, outputs = _mapper_classification_pairs(section)
    assert len(inputs) == len(outputs) == expected_count
    assert len(set(inputs)) == len(inputs)
    pairs = dict(zip(inputs, outputs))
    for label, classification, determination in ALL_CLASSIFICATION_LABELS:
        assert pairs[f"{classification}|{determination}"] == label


@pytest.mark.parametrize("legacy_determination, current_determination", LEGACY_ALERT_DETERMINATIONS.items())
def test_incoming_alert_mapper_maps_old_and_new_names_to_same_label(legacy_determination, current_determination):
    """
    Given: the incoming mapper Classification rule of the Alert section.
    When: looking up an alert that comes in with the old or the current determination name.
    Then: both names map to the same Classification label.
    """
    inputs, outputs = _mapper_classification_pairs("Graph Security Alert")
    pairs = dict(zip(inputs, outputs))
    classification = next(c for _, c, d in ALL_CLASSIFICATION_LABELS if d == current_determination)
    assert pairs[f"{classification}|{legacy_determination}"] == pairs[f"{classification}|{current_determination}"]


def test_new_incoming_mapper_metadata_and_sections():
    """
    Given: the new incoming mapper.
    When: reading its metadata and sections.
    Then: its id and name match the YML defaultmapperin, and it has only the Alert and Incident sections.
    """
    mapper = load_json(NEW_INCOMING_MAPPER_PATH)
    assert mapper["id"] == mapper["name"] == "Graph Security Mapper - Incoming"
    assert mapper["type"] == "mapping-incoming"
    assert sorted(mapper["mapping"]) == MAPPER_TYPE_SECTIONS


@pytest.mark.parametrize("section", MAPPER_TYPE_SECTIONS)
def test_new_incoming_mapper_description_only(section):
    """
    Given: a section of the new incoming mapper.
    When: reading its rules.
    Then: Description is mapped from description, and details is not mapped.
    """
    rules = load_json(NEW_INCOMING_MAPPER_PATH)["mapping"][section]["internalMapping"]
    assert rules["Description"] == {"simple": "description"}
    assert "details" not in rules


@pytest.mark.parametrize(
    "section, expected_rule",
    [("Graph Security Alert", {"simple": "classification"}), ("Graph Security Incident", None)],
)
def test_new_incoming_mapper_common_classification_alert_only(section, expected_rule):
    """
    Given: a section of the new incoming mapper.
    When: reading its rules.
    Then: the system Classification field is mapped from the Graph classification for alerts only (as in the original
        alert mapper), not for incidents. Both map the combined label to Microsoft Graph Security Classification.
    """
    rules = load_json(NEW_INCOMING_MAPPER_PATH)["mapping"][section]["internalMapping"]
    assert rules.get("Classification") == expected_rule
    assert "Microsoft Graph Security Classification" in rules


@pytest.mark.parametrize("section", MAPPER_TYPE_SECTIONS)
def test_new_incoming_mapper_no_source_status(section):
    """
    Given: a section of the new incoming mapper.
    When: reading its rules.
    Then: the generic Source Status field isn't mapped (status goes to the dedicated status field only).
    """
    rules = load_json(NEW_INCOMING_MAPPER_PATH)["mapping"][section]["internalMapping"]
    assert "Source Status" not in rules


def test_new_incoming_mapper_alert_has_no_name_rule():
    """
    Given: the Alert section of the new incoming mapper.
    When: reading its rules.
    Then: name isn't mapped, so the fetch name "title - id" is kept (the alert title can't be edited in Microsoft).
    """
    rules = load_json(NEW_INCOMING_MAPPER_PATH)["mapping"]["Graph Security Alert"]["internalMapping"]
    assert "name" not in rules


def test_new_incoming_mapper_incident_name_rule():
    """
    Given: the Incident section of the new incoming mapper.
    When: reading the name rule.
    Then: name is built as "<displayName> - <id>" (the same format as the fetch name), so a rename in Microsoft is
        mirrored in without changing the name format.
    """
    rule = load_json(NEW_INCOMING_MAPPER_PATH)["mapping"]["Graph Security Incident"]["internalMapping"]["name"]["complex"]
    assert rule["root"] == "displayName"
    first, second = rule["transformers"]
    assert first["operator"] == second["operator"] == "concat"
    assert first["args"]["suffix"] == {"isContext": False, "value": {"simple": " - "}}
    assert second["args"]["suffix"] == {"isContext": True, "value": {"simple": "id"}}


@pytest.mark.parametrize(
    "name, expected",
    [
        ("Multi-stage incident - 2972395", "Multi-stage incident"),
        ("Renamed in XSOAR", "Renamed in XSOAR"),
        ("Name - 111", "Name - 111"),
        ("Name - 2972395 extra", "Name - 2972395 extra"),
        ("A - 2972395 - 2972395", "A - 2972395"),
        ("", ""),
    ],
    ids=["suffix", "no-suffix", "other-id", "suffix-not-at-end", "suffix-twice", "empty"],
)
def test_strip_remote_id_suffix(name, expected):
    """
    Given: an XSOAR incident name and the remote incident ID.
    When: stripping the " - <id>" suffix.
    Then: only a trailing " - <remote id>" is removed (once); any other name is returned unchanged.
    """
    assert strip_remote_id_suffix(name, INCIDENT_ID) == expected


@pytest.mark.parametrize(
    "delta, expected_body",
    [
        ({"displayName": f"Multi-stage incident - {INCIDENT_ID}"}, {"displayName": "Multi-stage incident"}),
        ({"name": f"Renamed - {INCIDENT_ID}"}, {"displayName": "Renamed"}),
        ({"displayName": "Renamed without id"}, {"displayName": "Renamed without id"}),
        ({"displayName": f" - {INCIDENT_ID}", "status": "active"}, {"status": "active"}),
    ],
    ids=["mapped-key", "raw-name-field", "no-suffix", "only-suffix-dropped"],
)
def test_update_remote_system_strips_id_suffix_from_display_name(mocker, delta, expected_body):
    """
    Given: an incident name in the delta that ends with " - <remote id>" (the fetch / incoming name format).
    When: running update-remote-system.
    Then: displayName is sent without the suffix; a name that is only the suffix isn't sent (displayName is never empty).
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == expected_body


def test_old_incoming_mapper_unchanged():
    """
    Given: the original "Graph Security Alert" incoming mapper.
    When: reading its sections.
    Then: it keeps its id and has no Graph Security Incident section (it is left as on master).
    """
    mapper = load_json(OLD_INCOMING_MAPPER_PATH)
    assert mapper["id"] == "Graph Security Alert"
    assert "Graph Security Incident" not in mapper["mapping"]


def test_yml_default_incoming_mapper_is_new_mapper():
    """
    Given: the integration YML.
    When: reading defaultmapperin.
    Then: it points to the new incoming mapper.
    """
    with open("MicrosoftGraphSecurity.yml") as yml_file:
        assert "defaultmapperin: Graph Security Mapper - Incoming\n" in yml_file.read()


def test_update_remote_system_redirected_incident_close_out_skipped(mocker):
    """
    Given: an XSOAR incident closed because its Microsoft incident was redirected (close_out on).
    When: running update-remote-system with only the close delta.
    Then: no PATCH is sent (no status or close comment for a redirected incident), and the skip is logged.
    """
    http_mock = _patch_http(mocker)
    debug_mock = mocker.patch.object(demisto, "debug")
    delta = {"closeReason": "Resolved", "closeNotes": "Redirected in Microsoft Defender to incident 999."}
    args = _update_args(INCIDENT_ID, delta, "incident", status=2)
    args["data"]["status"] = "redirected"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH") == []
    debug_mock.assert_any_call(f"[Mirroring] Incident {INCIDENT_ID} is redirected; skipping status update.")


@pytest.mark.parametrize(
    "delta, inc_status",
    [
        ({"closeReason": "", "closeNotes": "", "description": "new"}, 1),
        ({"closeReason": "Resolved", "closeNotes": "notes", "description": "new"}, 2),
        ({"status": "active", "description": "new"}, 1),
    ],
    ids=["reopen", "close", "status-field"],
)
def test_update_remote_system_redirected_incident_sends_other_fields_only(mocker, delta, inc_status):
    """
    Given: a redirected incident with a status change (reopen, close, or status field) and a description change.
    When: running update-remote-system with close_out on.
    Then: only the description is PATCHed, with no status.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, delta, "incident", status=inc_status)
    args["data"]["status"] = "redirected"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"description": "new"}


def test_update_remote_system_non_redirected_incident_close_out_sends_status(mocker):
    """
    Given: a closed XSOAR incident whose Microsoft incident is active (not redirected), close_out on.
    When: running update-remote-system with the close delta.
    Then: status=resolved is still sent (the redirected guard doesn't apply).
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {"closeReason": "Resolved", "closeNotes": "done"}, "incident", status=2)
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]["status"] == "resolved"


@pytest.mark.parametrize(
    "delta",
    [
        {"closeReason": "Resolved", "closeNotes": "done", "resolvingComment": "done"},
        {"resolvingComment": "done"},
    ],
    ids=["close-with-mapped-close-notes", "mapped-close-notes-only"],
)
def test_update_remote_system_close_out_disabled(mocker, delta):
    """
    Given: a closed XSOAR incident with close_out off, and a close in the delta that includes resolvingComment (the
        outgoing-mapped closeNotes).
    When: running update-remote-system.
    Then: no PATCH is sent at all: no status and no resolvingComment, since nothing else changed.
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=2), {"close_out": False})
    assert _http_calls(http_mock, "PATCH") == []


@pytest.mark.parametrize(
    "mirror_type, remote_id, other_change, expected_body, expected_comment_url",
    [
        (
            "incident",
            INCIDENT_ID,
            {"resolvingComment": "done", "description": "new"},
            {"description": "new"},
            f"security/incidents/{INCIDENT_ID}/comments",
        ),
        (
            "alert",
            ALERT_ID,
            {"assignedTo": "x", "customDetails": ["owner: SOC"]},
            {"customDetails": {"owner": "SOC"}},
            f"security/alerts_v2/{ALERT_ID}/comments",
        ),
    ],
)
@pytest.mark.parametrize("close_out", [False, "false"])
def test_update_remote_system_close_out_off_sends_other_fields_and_entries(
    mocker, mirror_type, remote_id, other_change, expected_body, expected_comment_url, close_out
):
    """
    Given: a closed XSOAR incident (status DONE) with close_out off, a close in the delta (for incidents including
        resolvingComment, the outgoing-mapped closeNotes), another field change and an entry tagged with the outgoing
        comment tag.
    When: running update-remote-system.
    Then: the PATCH holds only the other field change (no status, no resolvingComment), no close notes comment is
          posted, and the tagged entry is still mirrored out as a comment.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    delta = {"closeReason": "Resolved", "closeNotes": "done", "closingUserId": "admin", **other_change}
    entries = [{"id": "1", "contents": "note", "tags": ["CommentToMicrosoftGraphSecurity"], "user": "admin"}]
    args = _update_args(remote_id, delta, mirror_type, status=2, entries=entries)
    params = {**MIRROR_PARAMS, "close_out": close_out}
    assert update_remote_system_command(client_mocker, args, params) == remote_id
    patches = _http_calls(http_mock, "PATCH")
    assert len(patches) == 1
    assert patches[0].kwargs["json_data"] == expected_body
    assert "status" not in patches[0].kwargs["json_data"]
    assert "resolvingComment" not in patches[0].kwargs["json_data"]
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert posts[0].kwargs["url_suffix"] == expected_comment_url
    comment = posts[0].kwargs["json_data"]["comment"]
    assert "(admin): note" in comment
    assert "done" not in comment


def test_update_remote_system_close_out_off_close_only_posts_entries_no_patch(mocker):
    """
    Given: a closed XSOAR alert (status DONE) with close_out off, only close fields in the delta, and a tagged entry.
    When: running update-remote-system.
    Then: no PATCH is sent (nothing else changed), and the tagged entry is still posted as a comment.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    delta = {"closeReason": "Resolved", "closeNotes": "done"}
    entries = [{"id": "1", "contents": "note", "tags": ["CommentToMicrosoftGraphSecurity"], "user": "admin"}]
    args = _update_args(ALERT_ID, delta, "alert", status=2, entries=entries)
    update_remote_system_command(client_mocker, args, {**MIRROR_PARAMS, "close_out": False})
    assert _http_calls(http_mock, "PATCH") == []
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert "(admin): note" in posts[0].kwargs["json_data"]["comment"]


def test_get_remote_data_close_incident_param_missing(mocker):
    """
    Given: a resolved alert and params without the close_incident key (missing rather than None).
    When: running get-remote-data.
    Then: close_incident defaults to off: no error and no close entry.
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("alert", comments=[]))
    params = {key: value for key, value in MIRROR_PARAMS.items() if key != "close_incident"}
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "0"}, params)
    assert res.mirrored_object["in_mirror_error"] == ""
    assert res.entries == []


def test_update_remote_system_close_out_param_missing(mocker):
    """
    Given: params without the close_out key (missing rather than None), and a displayName and resolvingComment
        (the outgoing-mapped closeNotes) change.
    When: running update-remote-system.
    Then: close_out defaults to off: displayName is PATCHed and resolvingComment is dropped.
    """
    http_mock = _patch_http(mocker)
    params = {key: value for key, value in MIRROR_PARAMS.items() if key != "close_out"}
    delta = {"displayName": "x", "resolvingComment": "done"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), params)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"displayName": "x"}


def test_update_remote_system_redirected_incident_does_not_read_close_out(mocker):
    """
    Given: a redirected incident with a status and description change, and close_out=None.
    When: running update-remote-system.
    Then: the redirect check runs before close_out is read, so the description is PATCHed without a status.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {"status": "active", "description": "new"}, "incident")
    args["data"]["status"] = "redirected"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS | {"close_out": None})
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"description": "new"}


@pytest.mark.parametrize(
    "mirror_type, remote_id, expected_status", [("incident", INCIDENT_ID, "active"), ("alert", ALERT_ID, "new")]
)
def test_update_remote_system_reopen_out(mocker, mirror_type, remote_id, expected_status):
    """
    Given: a reopened XSOAR incident (the close fields are cleared in the delta), and the remote object is resolved.
    When: running update-remote-system.
    Then: the remote object is reopened (incident=active, alert=new).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {"closeReason": "", "closeNotes": "", "closingUserId": ""}
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type, status=1), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": expected_status}


@pytest.mark.parametrize(
    "mirror_type, remote_id, status_key, delta_status, expected_status",
    [
        # An explicit non-resolved status set in the same delta is kept.
        ("incident", INCIDENT_ID, "status", "inProgress", "inProgress"),
        ("incident", INCIDENT_ID, "status", "awaitingAction", "awaitingAction"),
        ("alert", ALERT_ID, "status", "inProgress", "inProgress"),
        # The raw XSOAR status field (renamed to `status` by to_graph_delta_keys) behaves the same.
        ("incident", INCIDENT_ID, "microsoftgraphsecurityincidentstatus", "inProgress", "inProgress"),
        ("alert", ALERT_ID, "microsoftgraphsecurityalertstatus", "inProgress", "inProgress"),
        # A resolved / empty / unknownFutureValue status is replaced with the default reopen status.
        ("incident", INCIDENT_ID, "status", "resolved", "active"),
        ("alert", ALERT_ID, "status", "resolved", "new"),
        ("incident", INCIDENT_ID, "status", "", "active"),
        ("alert", ALERT_ID, "status", "unknownFutureValue", "new"),
    ],
)
def test_update_remote_system_reopen_keeps_explicit_status(
    mocker, mirror_type, remote_id, status_key, delta_status, expected_status
):
    """
    Given: a reopened XSOAR incident (close fields cleared) whose delta also holds a status, and a resolved remote object.
    When: running update-remote-system with close_out on.
    Then: an explicit non-resolved status is kept (not overwritten by the default reopen status); a resolved, empty or
        unknownFutureValue status is replaced with the default reopen status (incident=active, alert=new).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {"closeReason": "", "closeNotes": "", "closingUserId": "", status_key: delta_status}
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type, status=1), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": expected_status}


def test_update_remote_system_reopen_with_explicit_status_logs_kept(mocker):
    """
    Given: a reopened XSOAR incident whose delta holds closeReason="", closingUserId="", resolvingComment="" and
        status=inProgress, and a resolved remote incident.
    When: running update-remote-system with close_out on.
    Then: status=inProgress is sent (not active), resolvingComment is not cleared, and the kept status is logged.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    debug_mock = mocker.patch.object(demisto, "debug")
    delta = {"closeReason": "", "closingUserId": "", "resolvingComment": "", "status": "inProgress"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=1), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "inProgress"}
    assert any("keeping the explicit status 'inProgress'" in c.args[0] for c in debug_mock.call_args_list)


@pytest.mark.parametrize(
    "mirror_type, remote_id, remote_status",
    [
        ("incident", INCIDENT_ID, "inProgress"),
        ("incident", INCIDENT_ID, "awaitingAction"),
        ("alert", ALERT_ID, "inProgress"),
    ],
)
def test_reopen_echo_of_remote_reopen_sends_nothing(mocker, mirror_type, remote_id, remote_status):
    """
    Given: a Microsoft analyst reopened a resolved remote object to a non-resolved status, the incoming mirror reopened the
        XSOAR incident, and the server echoes the reopen outgoing with only cleared close fields (no `status` in the delta).
    When: running update-remote-system with close_out on.
    Then: the remote status is checked, it is already open, so no PATCH is sent (the Microsoft status is not overwritten)
        and the skip is logged.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http(remote_status))
    debug_mock = mocker.patch.object(demisto, "debug")
    delta = {"closeReason": "", "closeNotes": "", "closingUserId": ""}
    args = _update_args(remote_id, delta, mirror_type, status=1)
    args["data"]["status"] = remote_status
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert len(_http_calls(http_mock, "GET")) == 1
    assert _http_calls(http_mock, "PATCH") == []
    assert any("is already open in Microsoft" in str(c.args[0]) for c in debug_mock.call_args_list)


@pytest.mark.parametrize(
    "mirror_type, remote_id, data_status, expected_status",
    [
        ("incident", INCIDENT_ID, "resolved", "active"),
        ("alert", ALERT_ID, "resolved", "new"),
        ("incident", INCIDENT_ID, "unknownFutureValue", "active"),
        ("alert", ALERT_ID, "", "new"),
    ],
)
def test_reopen_after_resolve_sends_default_reopen_status(mocker, mirror_type, remote_id, data_status, expected_status):
    """
    Given: a real XSOAR reopen after a resolve: the delta clears the close fields and data.status is resolved (or empty /
        unknownFutureValue), and the remote object is resolved.
    When: running update-remote-system with close_out on.
    Then: the default reopen status is sent (incident=active, alert=new).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    args = _update_args(remote_id, {"closeReason": "", "closeNotes": "", "closingUserId": ""}, mirror_type, status=1)
    args["data"]["status"] = data_status
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": expected_status}


@pytest.mark.parametrize(
    "mirror_type, remote_id, delta, expected_status",
    [
        ("incident", INCIDENT_ID, {"closeNotes": "", "closingUserId": ""}, "active"),
        ("incident", INCIDENT_ID, {"closingUserId": ""}, "active"),
        ("alert", ALERT_ID, {"closeNotes": "", "closingUserId": ""}, "new"),
        ("alert", ALERT_ID, {"closingUserId": ""}, "new"),
    ],
    ids=["incident-with-notes", "incident-no-notes", "alert-with-notes", "alert-no-notes"],
)
def test_reopen_after_close_without_reason_reopens_remote(mocker, mirror_type, remote_id, delta, expected_status):
    """
    Given: an XSOAR incident closed without a close reason (the remote object was resolved with the default comment) and
        then reopened, so the delta clears closingUserId but holds no closeReason, and the remote object is resolved.
    When: running update-remote-system with close_out on.
    Then: the remote object is reopened (incident=active, alert=new).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    args = _update_args(remote_id, delta, mirror_type, status=1)
    args["data"]["status"] = "resolved"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": expected_status}


@pytest.mark.parametrize(
    "mirror_type, remote_id, expected_status", [("incident", INCIDENT_ID, "active"), ("alert", ALERT_ID, "new")]
)
def test_reopen_remote_status_get_fails_reopens_anyway(mocker, mirror_type, remote_id, expected_status):
    """
    Given: a reopened XSOAR incident (closingUserId cleared), and the GET of the remote status fails (not HTTP 429).
    When: running update-remote-system with close_out on.
    Then: the remote object is reopened anyway (as the close-out does on a failed GET), and the failure is logged.
    """
    http_mock = mocker.patch.object(
        client_mocker.ms_client, "http_request", side_effect=_remote_status_http(get_error=DemistoException("boom"))
    )
    debug_mock = mocker.patch.object(demisto, "debug")
    args = _update_args(remote_id, {"closeReason": "", "closingUserId": ""}, mirror_type, status=1)
    args["data"]["status"] = "resolved"
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": expected_status}
    assert any("reopening anyway" in str(c.args[0]) for c in debug_mock.call_args_list)


def test_reopen_remote_status_get_rate_limited(mocker):
    """
    Given: a reopened XSOAR incident (closingUserId cleared), a tagged entry, and the GET of the remote status fails with
        HTTP 429.
    When: running update-remote-system with close_out on.
    Then: the "API rate limit" error is raised, so the server retries; nothing is PATCHed and no entry is POSTed.
    """
    http_mock = mocker.patch.object(
        client_mocker.ms_client, "http_request", side_effect=_remote_status_http(get_error=_rate_limit_error())
    )
    mocker.patch.object(demisto, "debug")
    args = _update_args(INCIDENT_ID, {"closeReason": "", "closingUserId": ""}, "incident", status=1, entries=[TAGGED_ENTRY])
    with pytest.raises(DemistoException, match="API rate limit"):
        update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH") == []
    assert _http_calls(http_mock, "POST") == []


@pytest.mark.parametrize("close_out", [False, "false"])
def test_reopen_close_out_off_sends_nothing(mocker, close_out):
    """
    Given: a reopened XSOAR incident (closingUserId cleared) and close_out off.
    When: running update-remote-system.
    Then: the remote status is not checked and nothing is sent.
    """
    http_mock = _patch_http(mocker)
    args = _update_args(INCIDENT_ID, {"closeReason": "", "closingUserId": ""}, "incident", status=1)
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS | {"close_out": close_out})
    assert http_mock.call_count == 0


def test_update_remote_system_mirror_out_entries(mocker):
    """
    Given: one entry tagged with the comment tag and one untagged entry.
    When: running update-remote-system for an incident with no field changes.
    Then: only the tagged entry is POSTed, as a comment with the marker.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    entries = [
        {"id": "1", "contents": "tagged note", "tags": ["CommentToMicrosoftGraphSecurity"], "user": "admin"},
        {"id": "2", "contents": "untagged", "tags": []},
    ]
    args = _update_args(INCIDENT_ID, {}, "incident", entries=entries, changed=False)
    res = update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert res == INCIDENT_ID
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert posts[0].kwargs["url_suffix"] == f"security/incidents/{INCIDENT_ID}/comments"
    comment = posts[0].kwargs["json_data"]["comment"]
    assert "(admin): tagged note" in comment
    assert MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR in comment
    assert _http_calls(http_mock, "PATCH") == []


def test_update_remote_system_skips_entry_with_incoming_tag_only(mocker):
    """
    Given: an entry tagged only with the incoming tag (a comment that was mirrored in from Microsoft).
    When: running update-remote-system.
    Then: the entry is not POSTed back to Microsoft.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    entries = [{"id": "1", "contents": "from Defender", "tags": ["CommentFromMicrosoftGraphSecurity"], "user": "admin"}]
    args = _update_args(INCIDENT_ID, {}, "incident", entries=entries, changed=False)
    assert update_remote_system_command(client_mocker, args, MIRROR_PARAMS) == INCIDENT_ID
    assert _http_calls(http_mock, "POST") == []


def test_update_remote_system_empty_outgoing_tag_posts_nothing(mocker):
    """
    Given: the outgoing comment tag param is empty (there are no code defaults) and a tagged entry.
    When: running update-remote-system.
    Then: nothing is POSTed, an error is logged, and the remote ID is still returned.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={})
    error_mock = mocker.patch.object(demisto, "error")
    entries = [{"id": "1", "contents": "note", "tags": ["CommentToMicrosoftGraphSecurity"], "user": "admin"}]
    args = _update_args(INCIDENT_ID, {}, "incident", entries=entries, changed=False)
    params = {**MIRROR_PARAMS, "comment_tag": ""}
    assert update_remote_system_command(client_mocker, args, params) == INCIDENT_ID
    assert _http_calls(http_mock, "POST") == []
    assert "parameter is empty" in error_mock.call_args[0][0]


def test_update_remote_system_patch_error_raises(mocker):
    """
    Given: the PATCH request fails with HTTP 400.
    When: running update-remote-system.
    Then: the PATCH error is raised as is (not swallowed).
    """
    error = DemistoException("Error in API call [400] - Bad Request", res=SimpleNamespace(status_code=400, headers={}))
    mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=error)
    with pytest.raises(DemistoException, match=r"\[400\] - Bad Request"):
        update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, {"displayName": "x"}, "incident"), MIRROR_PARAMS)


def _fail_on(method: str):
    """Returns an http_request side effect that raises for the given HTTP method and returns {} otherwise."""

    def side_effect(*args, **kwargs):
        if kwargs.get("method") == method:
            raise DemistoException(f"{method} failed")
        return {}

    return side_effect


def test_update_remote_system_patch_fails_raises_no_entries_posted(mocker):
    """
    Given: a field delta whose PATCH fails, and one entry tagged with the comment tag.
    When: running update-remote-system.
    Then: the PATCH error is raised and the tagged entry is not POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_fail_on("PATCH"))
    args = _update_args(INCIDENT_ID, {"displayName": "x"}, "incident", entries=[TAGGED_ENTRY])
    with pytest.raises(DemistoException, match="PATCH failed"):
        update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert len(_http_calls(http_mock, "PATCH")) == 1
    assert _http_calls(http_mock, "POST") == []


def test_update_remote_system_patch_rate_limited_raises_no_entries_posted(mocker):
    """
    Given: a field delta whose PATCH fails with HTTP 429, and one tagged entry.
    When: running update-remote-system.
    Then: the 429 error is raised as is and no comment is POSTed.
    """
    error = _rate_limit_error()
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=error)
    args = _update_args(INCIDENT_ID, {"displayName": "x"}, "incident", entries=[TAGGED_ENTRY])
    with pytest.raises(DemistoException) as exc_info:
        update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert exc_info.value is error
    assert _http_calls(http_mock, "POST") == []


def test_update_remote_system_comment_post_rate_limited_raises(mocker):
    """
    Given: a tagged entry whose comment POST fails with HTTP 429.
    When: running update-remote-system.
    Then: the 429 error is raised as is.
    """
    error = _rate_limit_error()
    mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=error)
    args = _update_args(INCIDENT_ID, {}, "incident", entries=[TAGGED_ENTRY], changed=False)
    with pytest.raises(DemistoException) as exc_info:
        update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert exc_info.value is error


def test_update_remote_system_first_entry_fails_raises_second_not_posted(mocker):
    """
    Given: two tagged entries, where the POST of the first one fails.
    When: running update-remote-system.
    Then: the POST error is raised and the second entry is not POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=[DemistoException("POST failed"), {}])
    entries = [
        {"id": "e1", "contents": "first", "tags": ["CommentToMicrosoftGraphSecurity"]},
        {"id": "e2", "contents": "second", "tags": ["CommentToMicrosoftGraphSecurity"]},
    ]
    args = _update_args(INCIDENT_ID, {}, "incident", entries=entries, changed=False)
    with pytest.raises(DemistoException, match="POST failed"):
        update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    posts = _http_calls(http_mock, "POST")
    assert len(posts) == 1
    assert "first" in posts[0].kwargs["json_data"]["comment"]


def test_update_remote_system_alert_close_out_patch_fails_raises_no_notes_posted(mocker):
    """
    Given: a closed XSOAR incident mirrored to an alert, with close notes, close_out on, and a failing PATCH.
    When: running update-remote-system.
    Then: the PATCH error is raised and the close notes comment is not POSTed.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_fail_on("PATCH"))
    delta = {"closeReason": "False Positive", "closeNotes": "not malicious"}
    with pytest.raises(DemistoException, match="PATCH failed"):
        update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "POST") == []


def test_create_alert_comment_command_body_unchanged(mocker):
    """
    Given: the manual msg-create-alert-comment command.
    When: running it.
    Then: the request body stays {"comment": ...} (the existing behavior isn't changed by mirroring).
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={"value": []})
    create_alert_comment_command(client_mocker, {"alert_id": "a1", "comment": "hi"})
    assert http_mock.call_args.kwargs["json_data"] == {"comment": "hi"}


""" CUSTOM DETAILS <-> ADDITIONAL DATA """


@pytest.mark.parametrize(
    "custom_details, expected",
    [
        (
            {"threatIntelligenceVerdict": "KnownMalicious", "iocTypeMatched": "IPAddress"},
            ["threatIntelligenceVerdict: KnownMalicious", "iocTypeMatched: IPAddress"],
        ),
        ({"owner": "SOC", "xsoarTags": "malware, urgent"}, ["owner: SOC", "malware", "urgent"]),
        ({"xsoarTags": ""}, []),
        ({}, []),
        (None, []),
        ("not a dict", []),
    ],
)
def test_custom_details_to_list(custom_details, expected):
    """
    Given: an alert customDetails value.
    When: converting it to Additional Data items.
    Then: entries become "key: value", and the reserved xsoarTags value is split into plain items.
    """
    assert custom_details_to_list(custom_details) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (["owner: SOC team", "url: https://fake-url.com/a"], {"owner": "SOC team", "url": "https://fake-url.com/a"}),
        (["ticket:INC-123"], {"xsoarTags": "ticket:INC-123"}),
        (["owner: SOC", "malware", "urgent"], {"owner": "SOC", "xsoarTags": "malware, urgent"}),
        (["xsoarTags: a, b", "c"], {"xsoarTags": "a, b, c"}),
        (["k: 1", "k: 2"], {"k": "2"}),
        (["", None, "  "], {}),
        (": no key", {"xsoarTags": ": no key"}),
        ("owner: SOC", {"owner": "SOC"}),
        ('{"a": "1", "b": 2, "c": null}', {"a": "1", "b": "2", "c": ""}),
        ('["a: 1", "plain"]', {"a": "1", "xsoarTags": "plain"}),
        ({"a": 1}, {"a": "1"}),
        ([], {}),
        (None, {}),
    ],
)
def test_additional_data_to_custom_details(value, expected):
    """
    Given: an outgoing Additional Data value (list, single string, JSON object/list string, dict or empty).
    When: converting it to customDetails.
    Then: "key: value" items split on the first ": ", plain items go to xsoarTags, and all values are strings.
    """
    result = additional_data_to_custom_details(value)
    assert result == expected
    assert all(isinstance(v, str) for v in result.values())


@pytest.mark.parametrize(
    "item, expected",
    [
        ("key: value", {"key": "value"}),
        ("url: https://example.com/a:b", {"url": "https://example.com/a:b"}),
        ("time: 10:30", {"time": "10:30"}),
        ("  owner  :   SOC  ", {"owner": "SOC"}),
        ("key:", {"key": ""}),
        ("key: ", {"key": ""}),
        # No ": " separator: the item is plain and goes to xsoarTags as-is (colons inside are not split).
        ("https://example.com", {"xsoarTags": "https://example.com"}),
        ("10:30", {"xsoarTags": "10:30"}),
        ("key=value", {"xsoarTags": "key=value"}),
        ("url=https://fake-url.com", {"xsoarTags": "url=https://fake-url.com"}),
        ("malware", {"xsoarTags": "malware"}),
        ("", {}),
        ("   ", {}),
    ],
)
def test_additional_data_item_separator(item, expected):
    """
    Given: a single Additional Data item, including values with ":" and items without a ": " separator.
    When: converting it to customDetails.
    Then: only the first ": " splits key from value, so URLs and times keep their colons; items without ": "
          (including "key=value", "https://fake-url.com" and "10:30") go to xsoarTags unchanged; blank items are skipped.
    """
    assert additional_data_to_custom_details([item]) == expected


def test_custom_details_round_trip():
    """
    Given: customDetails with a value containing ":" and a reserved xsoarTags entry.
    When: converting to Additional Data items and back.
    Then: the original dictionary is restored.
    """
    custom_details = {"sourceUrl": "https://fake-url.com/a:b", "time": "10:30", "xsoarTags": "malware, urgent"}
    assert additional_data_to_custom_details(custom_details_to_list(custom_details)) == custom_details


def test_additional_data_plain_item_logged(mocker):
    """
    Given: an Additional Data item without a separator.
    When: converting it to customDetails.
    Then: it is added to xsoarTags and a debug message is logged.
    """
    debug_mock = mocker.patch.object(demisto, "debug")
    assert additional_data_to_custom_details(["malware"]) == {"xsoarTags": "malware"}
    assert any("xsoarTags" in str(c.args[0]) for c in debug_mock.call_args_list)


def test_fetch_alerts_adds_custom_details_list(mocker):
    """
    Given: a fetched alert with customDetails.
    When: running fetch_alerts.
    Then: the raw JSON has customDetailsList as "key: value" items, and customDetails is kept untouched.
    """
    mocker.patch("MicrosoftGraphSecurity.parse_date_range", return_value=("2020-04-19T08:14:21.000000Z", "x"))
    mocker.patch.object(demisto, "integrationInstance", return_value="instance_1")
    custom_details = {"iocTypeMatched": "IPAddress", "xsoarTags": "malware"}
    mocker.patch.object(
        client_mocker,
        "search_alerts",
        return_value={"value": [{"id": "a1", "createdDateTime": "2020-04-20T10:00:00Z", "customDetails": custom_details}]},
    )
    alerts, _ = fetch_alerts(client_mocker, "1 hour", 10, "", "", {}, params=MIRROR_PARAMS)
    raw = json.loads(alerts[0]["rawJSON"])
    assert raw["customDetailsList"] == ["iocTypeMatched: IPAddress", "malware"]
    assert raw["customDetails"] == custom_details


def test_get_remote_data_alert_adds_custom_details_list(mocker):
    """
    Given: a remote alert with customDetails.
    When: running get-remote-data.
    Then: the mirrored object has customDetailsList, and customDetails is kept untouched.
    """
    alert = _remote_object("alert", customDetails={"threatIntelligenceVerdict": "KnownMalicious"})
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=alert)
    res = get_remote_data_command(client_mocker, {"id": ALERT_ID, "lastUpdate": "0"}, {})
    assert res.mirrored_object["customDetailsList"] == ["threatIntelligenceVerdict: KnownMalicious"]
    assert res.mirrored_object["customDetails"] == {"threatIntelligenceVerdict": "KnownMalicious"}


def test_get_remote_data_incident_no_custom_details_list(mocker):
    """
    Given: a remote incident.
    When: running get-remote-data.
    Then: customDetailsList is not added (alerts only).
    """
    mocker.patch.object(client_mocker.ms_client, "http_request", return_value=_remote_object("incident"))
    res = get_remote_data_command(client_mocker, {"id": INCIDENT_ID, "lastUpdate": "0"}, {})
    assert "customDetailsList" not in res.mirrored_object


def test_update_remote_system_alert_custom_details(mocker):
    """
    Given: an alert delta with the Additional Data list mapped to customDetails.
    When: running update-remote-system.
    Then: the PATCH body has customDetails as a dict of strings, with plain items under xsoarTags.
    """
    http_mock = _patch_http(mocker)
    delta = {"customDetails": ["owner: SOC team", "url: https://fake-url.com/a", "malware", "urgent"]}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert"), MIRROR_PARAMS)
    patch_call = _http_calls(http_mock, "PATCH")[0]
    assert patch_call.kwargs["url_suffix"] == f"security/alerts_v2/{ALERT_ID}"
    assert patch_call.kwargs["json_data"] == {
        "customDetails": {"owner": "SOC team", "url": "https://fake-url.com/a", "xsoarTags": "malware, urgent"}
    }


def test_build_patch_body_alert_unusable_custom_details_cleared(mocker):
    """
    Given: an alert delta whose customDetails value has no usable items.
    When: building the PATCH body.
    Then: the key was in the delta, so it counts as a clear: customDetails is sent as {} and a debug message is logged.
    """
    debug_mock = mocker.patch.object(demisto, "debug")
    assert build_patch_body({"customDetails": ["  "], "status": "new"}, "alert") == {"status": "new", "customDetails": {}}
    assert any("sending an empty customDetails" in str(c.args[0]) for c in debug_mock.call_args_list)


@pytest.mark.parametrize(
    "delta, mirror_type, expected",
    [
        ({"customTags": ""}, "incident", {"customTags": []}),
        ({"customTags": []}, "incident", {"customTags": []}),
        ({"customTags": None}, "incident", {"customTags": []}),
        ({"customTags": [""]}, "incident", {"customTags": []}),
        ({"description": ""}, "incident", {"description": ""}),
        ({"customDetails": []}, "alert", {"customDetails": {}}),
        ({"customDetails": ""}, "alert", {"customDetails": {}}),
        ({"customDetails": None}, "alert", {"customDetails": {}}),
        ({"severity": 3, "customTags": []}, "incident", {"severity": "high", "customTags": []}),
    ],
)
def test_build_patch_body_cleared_fields_sent(delta, mirror_type, expected):
    """
    Given: a delta where the analyst cleared a clearable field (customTags/description for incidents, customDetails for alerts).
    When: building the PATCH body.
    Then: the typed empty value is sent, so the value is cleared in Microsoft.
    """
    assert build_patch_body(delta, mirror_type) == expected


@pytest.mark.parametrize(
    "delta, mirror_type, expected",
    [
        ({"severity": 3}, "incident", {"severity": "high"}),
        ({"status": ""}, "incident", {}),
        ({"classification": ""}, "incident", {}),
        ({"severity": ""}, "incident", {}),
        ({"severity": None}, "incident", {}),
        ({"displayName": ""}, "incident", {}),
        ({"status": ""}, "alert", {}),
        ({"classification": None}, "alert", {}),
        ({"classification": "", "determination": ""}, "alert", {}),
        ({"description": ""}, "alert", {}),
        ({"customTags": []}, "alert", {}),
        ({"customDetails": []}, "incident", {}),
    ],
)
def test_build_patch_body_non_clearable_empty_dropped(delta, mirror_type, expected):
    """
    Given: a delta with a non-clearable empty key, a key not accepted by the object type, or no clearable key at all.
    When: building the PATCH body.
    Then: the empty value is dropped, and a key absent from the delta (never set) is not sent.
    """
    assert build_patch_body(delta, mirror_type) == expected


def test_update_remote_system_reopen_does_not_clear_resolving_comment(mocker):
    """
    Given: a reopened XSOAR incident (closeReason, closeNotes and closingUserId cleared, status not DONE), a resolved
        remote incident, and close_out on.
    When: running update-remote-system.
    Then: the incident is reopened (status=active), and resolvingComment is not sent, so Microsoft's resolution comment is kept.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {"closeReason": "", "closeNotes": "", "closingUserId": ""}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=1), MIRROR_PARAMS)
    body = _http_calls(http_mock, "PATCH")[0].kwargs["json_data"]
    assert "resolvingComment" not in body
    assert body == {"status": "active"}


def test_update_remote_system_logs_cleared_keys(mocker):
    """
    Given: an incident delta that clears the tags and the description.
    When: running update-remote-system.
    Then: the PATCH clears both keys, and a debug log lists the cleared key names.
    """
    http_mock = _patch_http(mocker)
    debug_mock = mocker.patch.object(demisto, "debug")
    delta = {"customTags": "", "description": ""}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"customTags": [], "description": ""}
    assert any("['customTags', 'description']" in str(c.args[0]) for c in debug_mock.call_args_list)


@pytest.mark.parametrize("status", ["active", "resolved", "redirected", "inProgress", "awaitingAction"])
def test_build_patch_body_incident_sends_all_statuses(status):
    """
    Given: an incident delta with a Graph incidentStatus value.
    When: building the PATCH body.
    Then: the status is sent unchanged (assumed accepted by the Graph PATCH, to be verified on a tenant).
    """
    assert build_patch_body({"status": status}, "incident") == {"status": status}


@pytest.mark.parametrize(
    "mirror_type, remote_id, delta, expected_body",
    [
        ("incident", INCIDENT_ID, {"microsoftgraphsecurityincidenttags": ["a", "b"]}, {"customTags": ["a", "b"]}),
        ("incident", INCIDENT_ID, {"microsoftgraphsecurityincidentstatus": "inProgress"}, {"status": "inProgress"}),
        ("incident", INCIDENT_ID, {"name": "New name"}, {"displayName": "New name"}),
        (
            "incident",
            INCIDENT_ID,
            {"microsoftgraphsecurityclassification": "True positive - Malware"},
            {"classification": "truePositive", "determination": "malware"},
        ),
        ("alert", ALERT_ID, {"microsoftgraphsecurityalertstatus": "inProgress"}, {"status": "inProgress"}),
        ("alert", ALERT_ID, {"additionaldata": ["k: v"]}, {"customDetails": {"k": "v"}}),
        (
            "alert",
            ALERT_ID,
            {"microsoftgraphsecurityclassification": "False positive - Not malicious"},
            {"classification": "falsePositive", "determination": "notMalicious"},
        ),
    ],
    ids=[
        "incident-tags",
        "incident-status",
        "incident-name",
        "incident-classification",
        "alert-status",
        "alert-additional-data",
        "alert-classification",
    ],
)
def test_update_remote_system_raw_field_names_renamed(mocker, mirror_type, remote_id, delta, expected_body):
    """
    Given: a delta that holds raw XSOAR field names instead of the outgoing-mapped Graph keys.
    When: running update-remote-system.
    Then: the fields are sent under their Graph keys.
    """
    http_mock = _patch_http(mocker)
    update_remote_system_command(client_mocker, _update_args(remote_id, delta, mirror_type), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == expected_body


def test_update_remote_system_cleared_raw_tags_field_reopen(mocker):
    """
    Given: the tenant delta of a reopened incident with its tags cleared, under the raw field name, and a resolved remote.
    When: running update-remote-system with close_out on.
    Then: the PATCH reopens the incident and clears customTags.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("resolved"))
    delta = {"closeReason": "", "closingUserId": "", "microsoftgraphsecurityincidenttags": [], "runStatus": ""}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident", status=1), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "active", "customTags": []}


def test_to_graph_delta_keys_mapped_key_wins():
    """
    Given: a delta holding both the raw field name and its Graph key.
    When: renaming the delta keys.
    Then: the Graph key value is kept, the raw field is removed, and the input isn't mutated.
    """
    delta = {"customTags": ["mapped"], "microsoftgraphsecurityincidenttags": ["raw"], "severity": 3}
    assert to_graph_delta_keys(delta, "incident") == {"customTags": ["mapped"], "severity": 3}
    assert "microsoftgraphsecurityincidenttags" in delta


def _outgoing_mapper_source(rule: dict) -> str:
    """Returns the XSOAR source field of an outgoing mapper rule, for both simple and complex mappings."""
    return rule.get("simple") or rule["complex"]["root"]


def test_outgoing_mapper_custom_tags_is_simple_mapping():
    """
    Given: the outgoing mapper's Incident customTags entry.
    When: a user clears all tags in XSOAR, so the field value becomes [].
    Then: the entry is a simple (direct) mapping of microsoftgraphsecurityincidenttags.
          With a complex mapping, the server's applyFilters turns [] into nil and drops the key from the delta,
          so the cleared tags would never reach update-remote-system or be mirrored to Graph customTags.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    assert mapping["Graph Security Incident"]["internalMapping"]["customTags"] == {
        "complex": None,
        "simple": "microsoftgraphsecurityincidenttags",
    }


def test_outgoing_mapper_custom_details_is_simple_mapping():
    """
    Given: the outgoing mapper's Alert customDetails entry.
    When: a user clears the Additional Data field in XSOAR, so the field value becomes [].
    Then: the entry is a simple (direct) mapping of additionaldata.
          With a complex mapping, the server's applyFilters turns [] into nil and drops the key from the mapped delta.
          A clear on its own was only mirrored through the server's raw-delta fallback (mapped result empty), and a
          clear saved together with another mapped change (e.g. a status change) never reached Graph customDetails.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    assert mapping["Graph Security Alert"]["internalMapping"]["customDetails"] == {
        "complex": None,
        "simple": "additionaldata",
    }


def test_update_remote_system_alert_clears_custom_details_with_status_change(mocker):
    """
    Given: an alert delta (simple-mapped) that clears customDetails and changes the status in the same save.
    When: running update-remote-system.
    Then: the PATCH sends the new status and an empty customDetails dict, so Microsoft's customDetails are cleared.
    """
    http_mock = _patch_http(mocker)
    delta = {"customDetails": [], "status": "inProgress"}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert"), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "inProgress", "customDetails": {}}


def test_update_remote_system_alert_close_out_clears_custom_details(mocker):
    """
    Given: an alert close (close_out on) whose delta also clears customDetails.
    When: running update-remote-system.
    Then: the PATCH sends the resolved status and an empty customDetails dict, and the close comment is posted.
    """
    http_mock = _patch_http(mocker)
    delta = {"closeReason": "Resolved", "closeNotes": "handled", "customDetails": []}
    update_remote_system_command(client_mocker, _update_args(ALERT_ID, delta, "alert", status=2), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"status": "resolved", "customDetails": {}}
    assert "Comment: handled" in _http_calls(http_mock, "POST")[0].kwargs["json_data"]["comment"]


def test_xsoar_field_to_graph_key_matches_outgoing_mapper():
    """
    Given: the outgoing mapper.
    When: comparing it to XSOAR_FIELD_TO_GRAPH_KEY.
    Then: every renamed mapper field is listed (except closeNotes and same-name fields), so the two stay in sync.
    """
    with open("../../Classifiers/classifier-mapper-outgoing-Graph_Security.json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]
    for section, mirror_type in (("Graph Security Incident", "incident"), ("Graph Security Alert", "alert")):
        expected = {
            _outgoing_mapper_source(rule): graph_key
            for graph_key, rule in mapping[section]["internalMapping"].items()
            if _outgoing_mapper_source(rule) not in (graph_key, "closeNotes")
        }
        assert expected == XSOAR_FIELD_TO_GRAPH_KEY[mirror_type]


def test_update_remote_system_incident_never_sends_custom_details(mocker):
    """
    Given: an incident delta with customDetails.
    When: running update-remote-system.
    Then: customDetails is never sent for incidents.
    """
    http_mock = _patch_http(mocker)
    delta = {"customDetails": ["owner: SOC"], "displayName": "x"}
    update_remote_system_command(client_mocker, _update_args(INCIDENT_ID, delta, "incident"), MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == {"displayName": "x"}


@pytest.mark.parametrize("mirror_type", ["incident", "alert"])
@pytest.mark.parametrize("xsoar_severity", [4, "4", 4.0])
def test_build_patch_body_drops_unsupported_xsoar_severity(xsoar_severity, mirror_type):
    """
    Given: an XSOAR severity with no Graph equivalent (4, Critical: Graph alerts and incidents have no such severity and
        it is never mirrored in).
    When: building the alert/incident PATCH body.
    Then: severity isn't sent.
    """
    assert build_patch_body({"severity": xsoar_severity}, mirror_type) == {}


@pytest.mark.parametrize(
    "inc_status, expected",
    [(None, False), ("", False), (0, False), (1, False), (2, True), ("2", True), (3, False)],
)
def test_is_xsoar_incident_closed(inc_status, expected):
    """
    Given: an update-remote-system `status` arg (None means open).
    When: checking whether the XSOAR incident is closed.
    Then: only IncidentStatus.DONE (2 or "2") is closed.
    """
    assert is_xsoar_incident_closed(inc_status) is expected


@pytest.mark.parametrize(
    "delta, expected",
    [
        ({}, False),
        ({"closeReason": "", "closeNotes": None, "displayName": "x"}, False),
        ({"closeReason": "Resolved"}, True),
        ({"closeNotes": "notes"}, True),
        # closingUserId holds no close text (only who closed it), so it is not a close field.
        ({"closingUserId": "admin"}, False),
        ({"resolvingComment": "comment"}, True),
    ],
)
def test_has_close_fields(delta, expected):
    """
    Given: an outgoing delta.
    When: checking for close fields.
    Then: True only when a CLOSE_OUT_KEYS value (close text: reason, notes, resolvingComment) is non-empty.
    """
    assert has_close_fields(delta) is expected


@pytest.mark.parametrize(
    "mirror_type, remote_id, expected_patch, expected_comments",
    [
        ("incident", INCIDENT_ID, {"status": "resolved", "resolvingComment": "Closed in Cortex XSOAR."}, []),
        ("alert", ALERT_ID, {"status": "resolved"}, ["Closed in Cortex XSOAR."]),
    ],
)
def test_close_without_reason_with_mapped_closing_user_sends_default_comment(
    mocker, mirror_type, remote_id, expected_patch, expected_comments
):
    """
    Given: an XSOAR close without a close reason or close notes. closingUserId is mapped in the outgoing mapper, so the
        delta holds only {"closingUserId": "admin"}, and the remote object is still open.
    When: running update-remote-system with close_out on.
    Then: the remote object is resolved with the default close comment (incident resolvingComment, alert comment) -
        closingUserId alone doesn't count as close text, so the default close-out is used.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", side_effect=_remote_status_http("active"))
    args = _update_args(remote_id, {"closingUserId": "admin"}, mirror_type, status=2)
    update_remote_system_command(client_mocker, args, MIRROR_PARAMS)
    assert _http_calls(http_mock, "PATCH")[0].kwargs["json_data"] == expected_patch
    comments = [c.kwargs["json_data"]["comment"] for c in _http_calls(http_mock, "POST")]
    assert [add_mirror_marker(text) for text in expected_comments] == comments


@pytest.mark.parametrize(
    "status, expected",
    [(None, False), ("", False), ("resolved", False), ("unknownFutureValue", False), ("inProgress", True), ("new", True)],
)
def test_is_open_graph_status(status, expected):
    """
    Given: a Graph status.
    When: checking whether it is an explicit open (non-resolved) status.
    Then: empty, resolved and unknownFutureValue are not open; any other status is.
    """
    assert is_open_graph_status(status) is expected


@pytest.mark.parametrize(
    "delta, expected",
    [
        ({}, None),
        ({"closeNotes": "", "resolvingComment": ""}, ""),
        ({"resolvingComment": "comment"}, "comment"),
        ({"closeNotes": "notes", "resolvingComment": "comment"}, "notes"),
    ],
)
def test_get_delta_close_notes(delta, expected):
    """
    Given: an outgoing delta.
    When: getting the close notes.
    Then: closeNotes wins, else resolvingComment (the falsy value of resolvingComment is returned as-is).
    """
    assert get_delta_close_notes(delta) == expected


def test_get_alert_by_id_request(mocker):
    """
    Given: an alert ID.
    When: calling MsGraphClient.get_alert_by_id.
    Then: one GET is sent to security/alerts_v2/{id}, with the Prefer header, the mirror timeout and no params.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={"id": "da123"})
    assert client_mocker.get_alert_by_id("da123") == {"id": "da123"}
    http_mock.assert_called_once_with(
        method="GET",
        url_suffix="security/alerts_v2/da123",
        headers={"Prefer": "include-unknown-enum-members"},
        timeout=60,
    )


@pytest.mark.parametrize(
    "expand_alerts, expected_url",
    [(False, "security/incidents/42"), (True, "security/incidents/42?$expand=alerts")],
)
def test_get_incident_by_id_request(mocker, expand_alerts, expected_url):
    """
    Given: an incident ID, and whether to expand alerts.
    When: calling MsGraphClient.get_incident_by_id.
    Then: one GET is sent to the expected URL, with the Prefer header, the mirror timeout and no params.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={"id": "42"})
    assert client_mocker.get_incident_by_id("42", expand_alerts=expand_alerts) == {"id": "42"}
    http_mock.assert_called_once_with(
        method="GET",
        url_suffix=expected_url,
        headers={"Prefer": "include-unknown-enum-members"},
        timeout=60,
    )


@pytest.mark.parametrize(
    "method_name, expected_url",
    [("update_alert_by_id", "security/alerts_v2/id1"), ("update_incident_by_id", "security/incidents/id1")],
)
def test_update_alert_or_incident_by_id_request(mocker, method_name, expected_url):
    """
    Given: an alert/incident ID and a PATCH body.
    When: calling MsGraphClient.update_alert_by_id / update_incident_by_id.
    Then: one PATCH is sent to the expected URL with the body, a text response type and the mirror timeout.
    """
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value="")
    getattr(client_mocker, method_name)("id1", {"status": "resolved"})
    http_mock.assert_called_once_with(
        method="PATCH", url_suffix=expected_url, json_data={"status": "resolved"}, resp_type="text", timeout=60
    )


def test_create_incident_comment_request(mocker):
    """
    Given: an incident ID and a comment body.
    When: calling MsGraphClient.create_incident_comment.
    Then: one POST is sent to security/incidents/{id}/comments with the body, and the response is returned.
    """
    body = {"@odata.type": "microsoft.graph.security.alertComment", "comment": "hello"}
    http_mock = mocker.patch.object(client_mocker.ms_client, "http_request", return_value={"value": []})
    assert client_mocker.create_incident_comment("id1", body) == {"value": []}
    http_mock.assert_called_once_with(method="POST", url_suffix="security/incidents/id1/comments", json_data=body)
