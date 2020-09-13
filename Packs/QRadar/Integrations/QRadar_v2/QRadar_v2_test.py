from CommonServerPython import DemistoException
import demistomock as demisto
import pytest
import json
import QRadar_v2  # import module separately for mocker
from QRadar_v2 import (
    QRadarClient,
    FetchMode,
    search_command,
    get_search_command,
    get_search_results_command,
    get_assets_command,
    get_asset_by_id_command,
    get_closing_reasons_command,
    create_note_command,
    get_note_command,
    fetch_incidents_long_running_no_events,
    fetch_incidents_long_running_events,
    enrich_offense_with_events,
    try_create_search_with_retry,
    try_poll_offense_events_with_retry
)

with open("TestData/commands_outputs.json", "r") as f:
    COMMAND_OUTPUTS = json.load(f)
with open("TestData/raw_responses.json", "r") as f:
    RAW_RESPONSES = json.load(f)


command_tests = [
    ("qradar-searches", search_command, {"query_expression": "SELECT sourceip AS 'MY Source IPs' FROM events"},),
    ("qradar-get-search", get_search_command, {"search_id": "6212b614-074e-41c1-8fcf-1492834576b8"},),
    ("qradar-get-search-results", get_search_results_command, {"search_id": "6212b614-074e-41c1-8fcf-1492834576b8"},),
    ("qradar-get-assets", get_assets_command, {"range": "0-1"}),
    ("qradar-get-asset-by-id", get_asset_by_id_command, {"asset_id": "1928"}),
    ("qradar-get-closing-reasons", get_closing_reasons_command, {}),
    (
        "qradar-create-note",
        create_note_command,
        {"offense_id": "450", "note_text": "XSOAR has the best documentation!"},
    ),
    ("qradar-get-note", get_note_command, {"offense_id": "450", "note_id": "1232"}),
]


@pytest.mark.parametrize("command,command_func,args", command_tests)
def test_commands(command, command_func, args, mocker):
    """
    Test a set of commands given input->output
    tested commands:
      * qradar-searches
      * qradar-get-search
      * qradar-get-search-results
      * qradar-get-assets
      * qradar-get-asset-by
      * qradar-get-closing-reasons
      * qradar-create-note
      * qradar-get-note

    Given:
        - command - command name
        - command_func - function of command
        - args - arguments for command
    When:
        - Command `command` is being called
    Then:
        - Assert the entryContext matches the COMMAND_OUTPUTS map entry value (expected output)
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    mocker.patch.object(client, "send_request", return_value=RAW_RESPONSES[command])
    res = command_func(client, **args)
    assert COMMAND_OUTPUTS[command] == res.get("EntryContext")


def test_fetch_incidents_long_running_no_events(mocker):
    """
    Assert fetch_incidents_long_running_no_events updates integration context with the expected id and samples

    Given:
        - Fetch incidents is set to: FetchMode.no_events
        - There is an offense to fetch: 450
    When:
        - Fetch loop is triggered
    Then:
        - Assert integration context id is set correctly
        - Assert integration context samples is set with correct length
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    mocker.patch.object(QRadar_v2, "get_integration_context", return_value={})
    mocker.patch.object(QRadar_v2, "fetch_raw_offenses", return_value=[RAW_RESPONSES["fetch-incidents"]])
    mocker.patch.object(demisto, "createIncidents")
    mocker.patch.object(demisto, "debug")
    sic_mock = mocker.patch.object(QRadar_v2, "set_integration_context")

    fetch_incidents_long_running_no_events(client, user_query="", ip_enrich=False, asset_enrich=False)

    assert sic_mock.call_args[0][0]['id'] == 450
    assert len(sic_mock.call_args[0][0]['samples']) == 1


def test_fetch_incidents_long_running_events(mocker):
    """
    Assert fetch_incidents_long_running_events updates integration context with the expected id, samples and events

    Given:
        - Fetch incidents is set to: FetchMode.all_events
        - There is an offense to fetch: 450
    When:
        - Fetch loop is triggered
    Then:
        - Assert integration context id is set correctly
        - Assert integration context samples is set with correct length
        - Assert integration context events is set with correct value
    """
    expected_events = "assert ok"

    def mock_enrich_offense_with_events(client, offense, fetch_mode, events_columns, events_limit):
        offense['events'] = expected_events
        return offense

    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    fetch_mode = FetchMode.all_events
    mocker.patch.object(QRadar_v2, "get_integration_context", return_value={})
    mocker.patch.object(QRadar_v2, "fetch_raw_offenses", return_value=[RAW_RESPONSES["fetch-incidents"]])
    QRadar_v2.enrich_offense_with_events = mock_enrich_offense_with_events
    mocker.patch.object(demisto, "createIncidents")
    mocker.patch.object(demisto, "debug")
    sic_mock = mocker.patch.object(QRadar_v2, "set_integration_context")

    fetch_incidents_long_running_events(client, "", False, False, fetch_mode, "", "")

    assert sic_mock.call_args[0][0]['id'] == 450
    assert len(sic_mock.call_args[0][0]['samples']) == 1
    incident_raw_json = json.loads(sic_mock.call_args[0][0]['samples'][0]['rawJSON'])
    assert incident_raw_json['events'] == expected_events


def test_enrich_offense_with_events__correlations(mocker):
    """
    Assert enrich_offense_with_events adds an additional WHERE query when FetchMode.correlations_only

    Given:
        - Fetch incidents is set to: FetchMode.correlations_only
    When:
        - Event fetch query is built via in enrich_offense_with_event
    Then:
        - Assert search is created with additional WHERE query
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense = RAW_RESPONSES["fetch-incidents"]
    fetch_mode = FetchMode.correlations_only
    events_cols = ""
    events_limit = ""

    poee_mock = mocker.patch.object(QRadar_v2, "perform_offense_events_enrichment", return_value=offense)
    enrich_offense_with_events(client, offense, fetch_mode, events_cols, events_limit)
    assert poee_mock.call_args[0][1] == "AND LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine'"


def test_enrich_offense_with_events__all_events(mocker):
    """
    Assert enrich_offense_with_events doesn't add an additional WHERE query when FetchMode.all_events

    Given:
        - Fetch incidents is set to: FetchMode.all_events
    When:
        - Event fetch query is built via in enrich_offense_with_event
    Then:
        - Assert search is created without additional WHERE query
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense = RAW_RESPONSES["fetch-incidents"]
    fetch_mode = FetchMode.all_events
    events_cols = ""
    events_limit = ""

    poee_mock = mocker.patch.object(QRadar_v2, "perform_offense_events_enrichment", return_value=offense)
    enrich_offense_with_events(client, offense, fetch_mode, events_cols, events_limit)
    assert poee_mock.call_args[0][1] == ""


def test_try_create_search_with_retry__semi_happy(mocker):
    """
    Create an event search with a connection error first, and succesful try after

    Given:
        - Event fetch is to be created via the qradar client
    When:
        - Search first returns ConnectionError
        - Search then returns search object
    Then:
        - Assert search is created with id and status
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    events_query = ""
    offense = RAW_RESPONSES["fetch-incidents"]
    max_retries = 3

    mocker.patch.object(client, "search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-searches"]])

    actual_status, actual_id = try_create_search_with_retry(client, events_query, offense, max_retries)
    assert actual_status == "EXECUTE"
    assert actual_id == "a135f4cb-c22a-4b3a-aa7d-83058c219d33"


def test_try_create_search_with_retry__sad(mocker):
    """
    Create an event search with a connection error first, and succesful try after

    Given:
        - Event fetch is to be created via the qradar client
    When:
        - Search first returns ConnectionError
        - Search then returns search object
    Then:
        - Assert search is created with id and status
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    events_query = ""
    offense = RAW_RESPONSES["fetch-incidents"]
    max_retries = 0
    exception_raised = False
    mocker.patch.object(client, "search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-searches"]])

    try:
        try_create_search_with_retry(client, events_query, offense, max_retries)
    except DemistoException:
        exception_raised = True
    assert exception_raised


def test_try_poll_offense_events_with_retry__semi_happy(mocker):
    """
    Poll event with a failure, recovery and success flow

    Given:
        - Event fetch is to be polled via the qradar client
    When:
        - Search first returns ConnectionError
        - Search then returns search is COMPLETED
    Then:
        - Assert events are fetched correctly
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense_id = 450
    query_status = "EXECUTE"
    search_id = "1"
    max_retries = 3
    expected = [{'MY Source IPs': '8.8.8.8'}]

    mocker.patch.object(QRadar_v2, "is_reset_triggered", return_value=False)
    mocker.patch.object(client, "get_search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-get-search"]])
    mocker.patch.object(client, "get_search_results", return_value=RAW_RESPONSES["qradar-get-search-results"])
    mocker.patch.object(demisto, "debug")

    actual = try_poll_offense_events_with_retry(client, offense_id, query_status, search_id, max_retries)
    assert actual == expected


def test_try_poll_offense_events_with_retry__reset(mocker):
    """
    Poll event with when reset is set

    Given:
        - Event fetch is to be polled via the qradar client
    When:
        - Reset trigger is waiting
    Then:
        - Stop fetch and return empty list
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense_id = 450
    query_status = "EXECUTE"
    search_id = "1"
    max_retries = 3

    mocker.patch.object(QRadar_v2, "is_reset_triggered", return_value=True)
    mocker.patch.object(client, "get_search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-get-search"]])
    mocker.patch.object(client, "get_search_results", return_value=RAW_RESPONSES["qradar-get-search-results"])
    mocker.patch.object(demisto, "debug")

    actual = try_poll_offense_events_with_retry(client, offense_id, query_status, search_id, max_retries)
    assert actual == []


def test_try_poll_offense_events_with_retry__sad(mocker):
    """
    Poll event with a failure

    Given:
        - Event fetch is to be polled via the qradar client
    When:
        - Search first returns ConnectionError
        - Recovery is set to 0
    Then:
        - Stop fetch and return empty list
    """
    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    offense_id = 450
    query_status = "EXECUTE"
    search_id = "1"
    max_retries = 0

    mocker.patch.object(QRadar_v2, "is_reset_triggered", return_value=False)
    mocker.patch.object(client, "get_search", side_effect=[ConnectionError, RAW_RESPONSES["qradar-get-search"]])
    mocker.patch.object(demisto, "debug")

    actual = try_poll_offense_events_with_retry(client, offense_id, query_status, search_id, max_retries)
    assert actual == []
