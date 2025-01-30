from unittest.mock import Mock
from demisto_sdk.commands.common.handlers import JSON_Handler
import pytest
import Dynatrace as dyn
from CommonServerPython import *
from unittest.mock import call
import demistomock as demisto

CLIENT = dyn.DynatraceClient(
    base_url="https://AAAAA.dynatrace.com",
    token="AAAAAAAAA.AAAAAAA.AAAAAAA",
    verify=True,
    proxy=None
    )


def test_get_audit_logs_events(mocker):
    """
    Given: A query
    When: calling get_audit_logs_events function
    Then: the http request is called with "GET" arg and with the right url.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.get_audit_logs_events(query="?querykey=queryarg")
    assert http_request.call_args[0][0] == "GET"
    assert http_request.call_args[0][1] == "/api/v2/auditlogs?querykey=queryarg"
    
    
def test_get_APM_events(mocker):
    """
    Given: A query
    When: calling get_APM_events function
    Then: the http request is called with "GET" arg and with the right url.
    """
    http_request = mocker.patch.object(CLIENT, '_http_request', return_value=[])
    CLIENT.get_APM_events(query="?querykey=queryarg")
    assert http_request.call_args[0][0] == "GET"
    assert http_request.call_args[0][1] == "/api/v2/events?querykey=queryarg"
    
    
@pytest.mark.parametrize(
    "events_to_fetch, audit_max, apm_max, expected_exception, expected_message",
    [
        # Valid token configuration
        (["APM"], 25000, 5000, None, None),
        
        # Invalid: No event types specified
        ([], 25000, 5000, DemistoException, "Please specify at least one event type"),
        
        # Invalid: audit_max out of range (too high)
        (["Audit logs"], 30000, 5000, DemistoException, "The maximum number of audit logs events"),
        
        # Invalid: audit_max out of range (negative)
        (["Audit logs"], -1, 5000, DemistoException, "The maximum number of audit logs events"),
        
        # Invalid: apm_max out of range (too high)
        (["APM"], 25000, 8000, DemistoException, "The maximum number of APM events"),
        
        # Invalid: apm_max out of range (negative)
        (["APM"], 25000, -1, DemistoException, "The maximum number of APM events"),
    ],
)
def test_validate_params(events_to_fetch, audit_max, apm_max, expected_exception, expected_message):
    """
    Given: all instance params
    When: Calling validate_params function
    Then: The function doesn't raise an error when params are valid and raises the right exception when params are invalid
    """
    from Dynatrace import validate_params
    if expected_exception:
        with pytest.raises(expected_exception) as excinfo:
            validate_params(
                events_to_fetch=events_to_fetch,
                audit_max=audit_max,
                apm_max=apm_max,
            )
        assert expected_message in str(excinfo.value)
    else:
        validate_params(
            events_to_fetch=events_to_fetch,
            audit_max=audit_max,
            apm_max=apm_max,
        )
        
        
@pytest.mark.parametrize(
    "events, event_type, expected",
    [
        # Test case 1: Audit logs
        (
            [{"timestamp": 1640995200000}],
            "Audit logs",
            [{"timestamp": 1640995200000, "SOURCE_LOG_TYPE": "Audit", "_time": 1640995200000}],
        ),
        # Test case 2: APM
        (
            [{"startTime": 1640995200000}],
            "APM",
            [{"startTime": 1640995200000, "SOURCE_LOG_TYPE": "APM", "_time": 1640995200000}],
        ),
        # Test case 3: Multiple Audit logs events
        (
            [
                {"timestamp": 1640995200000},
                {"timestamp": 1640995300000},
            ],
            "Audit logs",
            [
                {"timestamp": 1640995200000, "SOURCE_LOG_TYPE": "Audit", "_time": 1640995200000},
                {"timestamp": 1640995300000, "SOURCE_LOG_TYPE": "Audit", "_time": 1640995300000},
            ],
        ),
        # Test case 4: Empty events
        (
            [],
            "APM",
            [],
        ),
    ],
)
def test_add_fields_to_events(events, event_type, expected):
    """
    Given: events and event_type
    When: Calling add_fields_to_events function
    Then: The function retrieves the events with the expected added fields.
    """
    from Dynatrace import add_fields_to_events
    assert add_fields_to_events(events, event_type) == expected
    
    
def test_events_query__APM(mocker):
    """
    Given: args and event_type=APM
    When: Calling the events_query function
    Then: The get_APM_events is called with the right query.
    """
    from Dynatrace import events_query
    request = mocker.patch.object(CLIENT, 'get_APM_events', return_value=[])
    events_query(CLIENT, {"apm_limit": "100", "apm_from": "1640995200000"}, "APM")
    assert request.call_args[0][0] == '?pageSize=100&from=1640995200000'
    
    
def test_events_query__audit(mocker):
    """
    Given: args and event_type=Audit logs
    When: Calling the events_query function
    Then: The get_audit_events is called with the right query.
    """
    from Dynatrace import events_query
    request = mocker.patch.object(CLIENT, 'get_audit_logs_events', return_value=[])
    events_query(CLIENT, {"audit_limit": "100", "audit_from": "1640995200000"}, "Audit logs")
    assert request.call_args[0][0] == '?pageSize=100&from=1640995200000'
    

def test_fetch_events(mocker):
    """
    Given: events_to_fetch=["APM", "Audit logs"], audit_limit and apm_limit
    When: Running fetch-events command
    Then: The fetch_events function calls all expected functions to be called with the right arguments.
    """
    from Dynatrace import fetch_events
    apm_mock = mocker.patch("Dynatrace.fetch_apm_events", return_value=[])
    audit_mock = mocker.patch("Dynatrace.fetch_audit_log_events", return_value=[])
    send_events_to_xsiam_mock = mocker.patch("Dynatrace.send_events_to_xsiam")
    
    fetch_events(CLIENT, ["APM", "Audit logs"], {"APM": 100, "Audit logs": 200})
    
    assert apm_mock.call_args.args[1] == 100
    assert audit_mock.call_args.args[1] == 200
    send_events_to_xsiam_mock.assert_called_once_with([], "Dynatrace", "Platform")
    
    
def test_get_events_command__APM(mocker):
    """
    Given: args = {"events_types_to_get": "APM", "should_push_events": True} and no events are received.
    When: executing the dynatrace-get-events command
    Then:
        - events_query function and send_events_to_xsiam are called once with the right arguments.
        - The human readable returned is "No events were received".
    """
    from Dynatrace import get_events_command
    events_query_mock = mocker.patch("Dynatrace.events_query", return_value={"events": []})
    add_fields_to_events_mock = mocker.patch("Dynatrace.add_fields_to_events", return_value=[])
    send_events_to_xsiam_mock = mocker.patch("Dynatrace.send_events_to_xsiam")
    
    res = get_events_command(CLIENT, {"events_types_to_get": "APM", "should_push_events": True})
    
    events_query_mock.assert_called_once_with(CLIENT, {"events_types_to_get": "APM", "should_push_events": True}, "APM")
    add_fields_to_events_mock.assert_called_once_with([], "APM")
    send_events_to_xsiam_mock.assert_called_once_with(events=[], vendor="Dynatrace", product="Platform")
    assert "No events were received" in res.readable_output
    
    
def test_get_events_command__Audit_logs(mocker):
    """
    Given: args = {"events_types_to_get": "Audit logs", "should_push_events": False} and events are received.
    When: executing the dynatrace-get-events command
    Then:
        - events_query function is called with the right arguments.
        - send_events_to_xsiam function is not called.
        - The human readable includes the received events.
    """
    from Dynatrace import get_events_command
    events_query_mock = mocker.patch("Dynatrace.events_query", return_value={"auditLogs": [{"timestamp": 1640995200000}]})
    add_fields_to_events_mock = mocker.patch("Dynatrace.add_fields_to_events",
                                             return_value=[{"timestamp": 1640995200000, "SOURCE_LOG_TYPE": "Audit logs events"}])
    send_events_to_xsiam_mock = mocker.patch("Dynatrace.send_events_to_xsiam")
    
    res = get_events_command(CLIENT, {"events_types_to_get": "Audit logs", "should_push_events": False})
    
    events_query_mock.assert_called_once_with(CLIENT,
                                              {"events_types_to_get": "Audit logs", "should_push_events": False}, "Audit logs")
    add_fields_to_events_mock.assert_called_once_with([{"timestamp": 1640995200000}], "Audit logs")
    send_events_to_xsiam_mock.assert_not_called()
    assert "1640995200000" in res.readable_output
    
    
events_query_expected_calls_apm = [
    (CLIENT, {"apm_limit": 100, "apm_from": 1000}, "APM"),
    (CLIENT, {"apm_limit": 97, "apm_from": 1000}, "APM"),
    (CLIENT, {"apm_limit": 96, "apm_next_page_key": "AAAA"}, "APM"),
    (CLIENT, {"apm_limit": 93, "apm_from": 1002}, "APM"),
    (CLIENT, {"apm_limit": 92, "apm_from": 1002}, "APM"),
]
events_query_responses_apm = [
    # No next page key
    {"events": [{"startTime": 1000, "eventId": "id3"}, {"startTime": 1000, "eventId": "id2"},
                {"startTime": 999, "eventId": "id1"}], "totalCount": 3},
    # 2 events deduped, nextPageKey exists
    {"events": [{"startTime": 1001, "eventId": "id4"}, {"startTime": 1000, "eventId": "id3"},
                {"startTime": 1000, "eventId": "id2"}], "totalCount": 3, "nextPageKey": "AAAA"},
    # No events deduped, no nextPageKey
    {"events": [{"startTime": 1002, "eventId": "id6"}, {"startTime": 1002, "eventId": "id5"},
                {"startTime": 1001, "eventId": "id0"}], "totalCount": 3},
    # 2 events deduped, no nextPageKey
    {"events": [{"startTime": 1002, "eventId": "id7"}, {"startTime": 1002, "eventId": "id6"},
                {"startTime": 1002, "eventId": "id5"}], "totalCount": 3},
    # All events deduped, no nextPageKey, while loop breaks
    {"events": [{"startTime": 1002, "eventId": "id7"}, {"startTime": 1002, "eventId": "id6"},
                {"startTime": 1002, "eventId": "id5"}], "totalCount": 3},
]
add_fields_to_events_expected_calls_apm = [
    ([{"startTime": 1000, "eventId": "id3"}, {"startTime": 1000, "eventId": "id2"},
                {"startTime": 999, "eventId": "id1"}], "APM"),
    ([{"startTime": 1001, "eventId": "id4"}], "APM"),
    ([{"startTime": 1002, "eventId": "id6"}, {"startTime": 1002, "eventId": "id5"},
                {"startTime": 1001, "eventId": "id0"}], "APM"),
    ([{"startTime": 1002, "eventId": "id7"}], "APM")
    ]
add_fields_to_events_responses_apm = [
    [{"startTime": 1000, "eventId": "id3"}, {"startTime": 1000, "eventId": "id2"},
                {"startTime": 999, "eventId": "id1"}],
    [{"startTime": 1001, "eventId": "id4"}],
    [{"startTime": 1002, "eventId": "id6"}, {"startTime": 1002, "eventId": "id5"},
                {"startTime": 1001, "eventId": "id0"}],
    [{"startTime": 1002, "eventId": "id7"}],
    ]
def test_fetch_apm_events(mocker):
    """
    Given: A client, a higher limit then events to be returned and a fetch_start_time
    When: calling fetch_apm_events function
    Then:
        - The function receives exactly all the relevant events.
        - The events_query function is called 5 times every time with the right arguments
        - the add_fields_to_events function is called 4 times every time with the right arguments
        - The set_integration_context function is called with the right cnx to set.
        
    This test checks these use cases: (next test will check other use cases)
        - First response from api has no nexPgaKey
        - Limit of events isn't reached
        - Last iteration dedupes all events
        - Some events are deduped
        - No events are deduped(cause got a nextPagekey in the last run)
    """
    from Dynatrace import fetch_apm_events
    mocker.patch("Dynatrace.demisto.getIntegrationContext", return_value={})
    events_query_mock = mocker.patch("Dynatrace.events_query", side_effect=events_query_responses_apm)
    add_fields_to_events_mock = mocker.patch("Dynatrace.add_fields_to_events", side_effect=add_fields_to_events_responses_apm)
    set_integration_context_mock = mocker.patch("Dynatrace.set_integration_context")
    fetch_apm_events(CLIENT, 100, 1000)
    assert events_query_mock.call_count == 5
    assert [events_query_mock.call_args_list[i][0] for i in range(5)] == events_query_expected_calls_apm
    assert add_fields_to_events_mock.call_count == 4
    assert [add_fields_to_events_mock.call_args_list[i][0] for i in range(4)] == add_fields_to_events_expected_calls_apm
    set_integration_context_mock.assert_called_with({'last_apm_run': {'last_timestamp': 1002, 'nextPageKey': None, "last_events_ids": ["id7", "id6", "id5"]}})
    

events_query_expected_calls_audit = [ #"audit_next_page_key"
   (CLIENT, {"audit_limit": 100, "audit_from": 1000}, "Audit logs"),
   (CLIENT, {"audit_limit": 97, "audit_from": 1000}, "Audit logs"),
   (CLIENT, {"audit_limit": 96, "audit_next_page_key": "AAAA"}, "Audit logs"),
   (CLIENT, {"audit_limit": 93, "audit_from": 1002}, "Audit logs"),
   (CLIENT, {"audit_limit": 92, "audit_from": 1002}, "Audit logs")
]
events_query_responses_audit = [
    # No next page key
    {"auditLogs": [{"timestamp": 1000, "logId": "id3"}, {"timestamp": 1000, "logId": "id2"},
                {"timestamp": 999, "logId": "id1"}], "totalCount": 3},
    # 2 events deduped, nextPageKey exists
    {"auditLogs": [{"timestamp": 1001, "logId": "id4"}, {"timestamp": 1000, "logId": "id3"},
                {"timestamp": 1000, "logId": "id2"}], "totalCount": 3, "nextPageKey": "AAAA"},
    # No events deduped, no nextPageKey
    {"auditLogs": [{"timestamp": 1002, "logId": "id6"}, {"timestamp": 1002, "logId": "id5"},
                {"timestamp": 1001, "logId": "id0"}], "totalCount": 3},
    # 2 events deduped, no nextPageKey
    {"auditLogs": [{"timestamp": 1002, "logId": "id7"}, {"timestamp": 1002, "logId": "id6"},
                {"timestamp": 1002, "logId": "id5"}], "totalCount": 3},
    # All events deduped, no nextPageKey, while loop breaks
    {"auditLogs": [{"timestamp": 1002, "logId": "id7"}, {"timestamp": 1002, "logId": "id6"},
                {"timestamp": 1002, "logId": "id5"}], "totalCount": 3},
]
add_fields_to_events_responses_audit = [
    ([{"timestamp": 1000, "logId": "id3"}, {"timestamp": 1000, "logId": "id2"},
                {"timestamp": 999, "logId": "id1"}], "APM"),
    ([{"timestamp": 1001, "logId": "id4"}], "APM"),
    ([{"timestamp": 1002, "logId": "id6"}, {"timestamp": 1002, "logId": "id5"},
                {"timestamp": 1001, "logId": "id0"}], "APM"),
    ([{"timestamp": 1002, "logId": "id7"}], "APM")
    ]
add_fields_to_events_expected_calls_audit = [
    ([{"timestamp": 1000, "logId": "id3"}, {"timestamp": 1000, "logId": "id2"},
                {"timestamp": 999, "logId": "id1"}], "Audit logs"),
    ([{"timestamp": 1001, "logId": "id4"}], "Audit logs"),
    ([{"timestamp": 1002, "logId": "id6"}, {"timestamp": 1002, "logId": "id5"},
                {"timestamp": 1001, "logId": "id0"}], "Audit logs"),
    ([{"timestamp": 1002, "logId": "id7"}], "Audit logs")]
def test_fetch_audit_log_events(mocker):
    """
    Given: A client, a higher limit then events to be returned and a fetch_start_time
    When: calling fetch_audit_log_events function
    Then:
        - The function receives exactly all the relevant events.
        - The events_query function is called 5 times every time with the right arguments
        - the add_fields_to_events function is called 5 times every time with the right arguments
        - The set_integration_context function is called with the right cnx to set.
        
        This test checks the same use cases as the test_fetch_apm_events test but for audit logs events
    """
    from Dynatrace import fetch_audit_log_events
    mocker.patch("Dynatrace.demisto.getIntegrationContext", return_value={})
    events_query_mock = mocker.patch("Dynatrace.events_query", side_effect=events_query_responses_audit)
    add_fields_to_events_mock = mocker.patch("Dynatrace.add_fields_to_events", side_effect=add_fields_to_events_responses_audit)
    set_integration_context_mock = mocker.patch("Dynatrace.set_integration_context")
    fetch_audit_log_events(CLIENT, 100, 1000)
    assert events_query_mock.call_count == 5
    assert [events_query_mock.call_args_list[i][0] for i in range(5)] == events_query_expected_calls_audit
    assert add_fields_to_events_mock.call_count == 4
    assert [add_fields_to_events_mock.call_args_list[i][0] for i in range(4)] == add_fields_to_events_expected_calls_audit
    set_integration_context_mock.assert_called_with({'last_audit_run': {'last_timestamp': 1002, 'nextPageKey': None, "last_events_ids": ["id7", "id6", "id5"]}})

add_fields_return_value = [
            {"timestamp": 1000, "logId": "id3"},
            {"timestamp": 1000, "logId": "id2"},
            {"timestamp": 1000, "logId": "id1"}
            ]
events_query_mock_return_value = {
    "auditLogs":
        [
            {"timestamp": 1000, "logId": "id3"},
            {"timestamp": 1000, "logId": "id2"},
            {"timestamp": 1000, "logId": "id1"}
            ],
        "totalCount": 3
        }
def test_fetch_events__limit_is_reached(mocker):
    """
    Given: A limit
    When: fetching audit logs events and the first response returns amount of events as the limit
    Then: The events_query function is called only once and len(events returned) == given limit
    """
    from Dynatrace import fetch_audit_log_events
    mocker.patch("Dynatrace.demisto.getIntegrationContext", return_value={})
    events_query_mock = mocker.patch("Dynatrace.events_query", return_value=events_query_mock_return_value)
    mocker.patch("Dynatrace.add_fields_to_events", return_value=add_fields_return_value)
    mocker.patch("Dynatrace.set_integration_context")
    res = fetch_audit_log_events(CLIENT, 3, 1000)
    events_query_mock.assert_called_once()
    assert len(res) == 3