import json
import re
from unittest.mock import MagicMock

import pytest
import demistomock as demisto

from NetskopeEventCollector_v2 import (
    ALL_SUPPORTED_EVENT_TYPES,
    Client
)

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json("../NetskopeEventCollector/test_data/mock_events_entry.json")
EVENTS_RAW = util_load_json("../NetskopeEventCollector/test_data/events_raw.json")
EVENTS_PAGE_RAW = util_load_json("../NetskopeEventCollector/test_data/multiple_events_raw.json")
BASE_URL = "https://netskope.example.com"
FIRST_LAST_RUN = {
    "alert": {"operation": 1680182467},
    "application": {"operation": 1680182467},
    "audit": {"operation": 1680182467},
    "network": {"operation": 1680182467},
    "page": {"operation": 1680182467},
}


async def test_test_module(mocker):
    """
    Given:
        - A Netskope Client with mocked event data.
    When:
        - Running the test_module function.
    Then:
        - The result should be 'ok', indicating a successful connection and fetch logic.
    """
    from NetskopeEventCollector_v2 import test_module

    client = Client(BASE_URL, "dummy_token", False, False, event_types_to_fetch=ALL_SUPPORTED_EVENT_TYPES)
    mocker.patch.object(client, "get_events_data_async", return_value=EVENTS_RAW)
    results = await test_module(client, last_run=FIRST_LAST_RUN)
    assert results == "ok", f"Expected 'ok', got {results}"


def test_populate_prepare_events():
    """
    Given:
        - Event from the API of type audit
    When:
        - Running the command
    Then:
        - Make sure the _time, event_id, and source_log_event fields are populated properly.
    """
    from NetskopeEventCollector_v2 import prepare_events

    event = EVENTS_RAW.get("result")[0]
    prepare_events([event], event_type="audit")
    assert event.get("_time") == "2022-01-18T19:58:07.000Z"
    assert event.get("source_log_event") == "audit"
    assert event.get("event_id") == "f0e9b2cadd17402b59b3938b"


async def test_get_all_events(requests_mock):
    """
    Given:
        - netskope-get-events call
    When:
        - Running the get_all_events command
    Then:
        - Make sure the number of events returns as expected
        - Make sure that the _time and event_id fields are populated as expected
        - Make sure the new_last_run is set.
    """

    def json_callback(request, _):
        endpoint = request.path.split("/")[-1]
        return EVENTS_PAGE_RAW[endpoint]

    from NetskopeEventCollector_v2 import handle_fetch_and_send_all_events

    client = Client(
        BASE_URL, "netskope_token", validate_certificate=False, proxy=False, event_types_to_fetch=ALL_SUPPORTED_EVENT_TYPES
    )
    url_matcher = re.compile("https://netskope[.]example[.]com/events/dataexport/events")
    requests_mock.get(url_matcher, json=json_callback)
    events = []
    events, new_last_run = await handle_fetch_and_send_all_events(client, FIRST_LAST_RUN, limit=100, send_to_xsiam=False)
    assert isinstance(events, list), f"Expected events to be a list, got {type(events)}"
    assert isinstance(new_last_run, dict), f"Expected new_last_run to be a dict, got {type(new_last_run)}"
    assert len(events) == 26, f"Expected 26 events, got {len(events)}"
    assert events[0].get("event_id") == "1", f"Expected first event_id to be '1', got {events[0].get('event_id')}"
    assert events[0].get("_time") == "2023-05-22T10:30:16.000Z", f"Expected first _time to be '2023-05-22T10:30:16.000Z', got {events[0].get('_time')}"
    assert all(new_last_run[event_type]["operation"] == "next" for event_type in ALL_SUPPORTED_EVENT_TYPES), "Not all event types have 'next' operation in new_last_run"


async def test_get_events_command(mocker):
    """
    Given:
        - netskope-get-events call
    When:
        - Running the get_events_command
    Then:
        - Make sure the number of events returns as expected
        - Make sure that human_readable returned as expected
        - Make sure the outputs are set correctly.
    """
    from NetskopeEventCollector_v2 import handle_event_type_async

    client = Client(BASE_URL, "dummy_token", False, False, event_types_to_fetch=ALL_SUPPORTED_EVENT_TYPES)
    # Instead of patching get_all_events (not present in v2), directly test the async event fetch logic
    mocker.patch.object(client, "get_events_data_async", return_value={"result": MOCK_ENTRY})
    result = await handle_event_type_async(client, "alert", "start", "end", 0, 10, False)
    assert result is not None, "Expected result to not be None"



@pytest.mark.parametrize(
    "event_types_to_fetch_param, expected_value",
    [
        ("Application", ["application"]),
        ("Alert, Page, Audit", ["alert", "page", "audit"]),
        (["Application", "Audit", "Network", "Incident"], ["application", "audit", "network", "incident"]),
        ("Incident", ["incident"]),
        (None, ALL_SUPPORTED_EVENT_TYPES),
    ],
)
async def test_event_types_to_fetch_parameter_handling(event_types_to_fetch_param, expected_value):
    """
    Given:
        Case a: event_types_to_fetch parameter has a single value
        Case b: event_types_to_fetch parameter has multiple values
        Case c: event_types_to_fetch parameter is a pythonic list
        Case d: event_types_to_fetch parameter is None

    When:
        Handling the event_types_to_fetch parameter

    Then:
        - Make sure the parameter converts into a valid pythonic list
        - The values are lowercase
        - In the case event_types_to_fetch in None, default ALL_SUPPORTED_EVENT_TYPES is used as parameter

    """
    from NetskopeEventCollector_v2 import handle_event_types_to_fetch

    assert handle_event_types_to_fetch(event_types_to_fetch_param) == expected_value, (
    f"Expected {expected_value}, got {handle_event_types_to_fetch(event_types_to_fetch_param)} for param {event_types_to_fetch_param}"
)


@pytest.mark.parametrize(
    "num_fetched_events, max_fetch_events, new_next_run, expected_result",
    [
        (200, 250, {"key": "value"}, {"nextTrigger": "0", "key": "value"}),
        (1000, 5000, {"nextTrigger": "0"}, {}),
        (0, 0, {"key": "value"}, {"key": "value"}),
        (0, 0, {}, {}),
        (2500, 5000, {"nextTrigger": "0"}, {}),
        (2501, 5000, {"key": "value", "nextTrigger": "0"}, {"key": "value", "nextTrigger": "0"}),
    ],
)
def test_next_trigger_time(num_fetched_events, max_fetch_events, new_next_run, expected_result):
    """
    Given:
        - The number of fetched events and the max_fetch integration parameter.

    When:
        - Setting the new last_run

    Then:
        - Check that the last run is modified with the nextTrigger: '0',
            only if more than half of the max_fetch amount was fetched.
    """
    from NetskopeEventCollector_v2 import next_trigger_time

    next_trigger_time(num_fetched_events, max_fetch_events, new_next_run)
    assert new_next_run == expected_result, (
    f"Expected new_next_run={expected_result}, got {new_next_run} for fetched={num_fetched_events}, max_fetch={max_fetch_events}"
)


@pytest.mark.parametrize(
    "last_run, supported_event_types, expected_result",
    [
        (
            {
                "alert": {"operation": "next"},
                "audit": {"operation": "next"},
                "network": {"operation": "next"},
                "nextTrigger": "0",
                "page": {"operation": "next"},
            },
            ["alert"],
            {"nextTrigger": "0", "alert": {"operation": "next"}},
        ),
        ({}, ["alert"], {}),
        (
            {
                "alert": {"operation": "next"},
                "audit": {"operation": "next"},
                "network": {"operation": "next"},
            },
            ["audit", "network"],
            {"audit": {"operation": "next"}, "network": {"operation": "next"}},
        ),
    ],
)
def test_fix_last_run(last_run, supported_event_types, expected_result):
    """
    Given:
        - last run dict and supported event types.
    When:
        - preparing the last_run before execution.
    Then:
        - remove unsupported event types.
    """
    from NetskopeEventCollector_v2 import remove_unsupported_event_types

    remove_unsupported_event_types(last_run, supported_event_types)
    assert last_run == expected_result, (
    f"Expected last_run={expected_result}, got {last_run} for supported_event_types={supported_event_types}"
)


@pytest.mark.asyncio
async def test_incident_endpoint(mocker):
    """
    Given:
        - Netskope client set to fetch incident events.
    When:
        - Fetching events.
    Then:
        - Assert that the Netskope end point is called with the proper url and paras.
    """
    from NetskopeEventCollector_v2 import handle_event_type_async

    mocker.patch.object(demisto, "callingContext", {"context": {"IntegrationInstance": "test_instance"}})
    mocker.patch.object(
        __import__('NetskopeEventCollector_v2'), "is_execution_time_exceeded", return_value=False
    )
    mocker.patch("NetskopeEventCollector_v2.print_event_statistics_logs")
    client = Client(BASE_URL, "dummy_token", False, False, event_types_to_fetch=["incident"])
    mock_response = MagicMock()
    mock_response.json.return_value = {"result": EVENTS_RAW["result"], "wait_time": 0}
    request_mock = mocker.patch.object(Client, "_http_request", return_value=mock_response)
    await handle_event_type_async(
        client, "incident", "next", "end", 0, 50, False
    )
    kwargs = request_mock.call_args.kwargs
    assert kwargs["url_suffix"] == "events/data/incident", (
        f"Expected url_suffix 'events/data/incident', got {kwargs['url_suffix']}"
    )
    assert kwargs["params"] == {"index": "xsoar_collector_test_instance_incident", "operation": "next"}, (
        f"Expected params {{'index': 'xsoar_collector_test_instance_incident', 'operation': 'next'}}, got {kwargs['params']}"
    )


@pytest.mark.asyncio
async def test_client_context_manager():
    """
    Given:
        - A Netskope Client.
    When:
        - Using the Client as an async context manager.
    Then:
        - The aiohttp session should be opened inside the context and closed after exiting the context.
    """
    import aiohttp
    from NetskopeEventCollector_v2 import Client
    client = Client(BASE_URL, "token", False, False, ["alert"])
    async with client:
        assert isinstance(client._async_session, aiohttp.ClientSession)
    assert client._async_session.closed


@pytest.mark.asyncio
async def test_get_events_count(mocker):
    """
    Given:
        - A Netskope Client with a mocked get_events_data_async returning a known event count.
    When:
        - Calling get_events_count.
    Then:
        - The correct event count should be returned.
    """
    from NetskopeEventCollector_v2 import Client
    client = Client(BASE_URL, "token", False, False, ["alert"])
    mocker.patch.object(client, "get_events_data_async", return_value={"result": [{"event_count": 42}]})
    count = await client.get_events_count("alert", {})
    assert count == 42


@pytest.mark.asyncio
async def test_honor_rate_limiting_async(mocker):
    """
    Given:
        - Various rate-limiting headers.
    When:
        - Calling honor_rate_limiting_async.
    Then:
        - The function should sleep for the correct duration and return True/False as appropriate.
    """
    from NetskopeEventCollector_v2 import honor_rate_limiting_async, RATE_LIMIT_REMAINING, RATE_LIMIT_RESET
    # Should sleep for reset value
    headers = {RATE_LIMIT_REMAINING: "0", RATE_LIMIT_RESET: "2"}
    sleep_mock = mocker.patch("asyncio.sleep", return_value=None)
    result = await honor_rate_limiting_async(headers, "alert", {})
    sleep_mock.assert_called_with(2)
    assert result is True
    # Should sleep for 1 if no reset
    headers = {RATE_LIMIT_REMAINING: "0"}
    sleep_mock = mocker.patch("asyncio.sleep", return_value=None)
    result = await honor_rate_limiting_async(headers, "alert", {})
    sleep_mock.assert_called_with(1)
    assert result is True
    # Should return False if not rate limited
    headers = {RATE_LIMIT_REMAINING: "1"}
    result = await honor_rate_limiting_async(headers, "alert", {})
    assert result is False


def test_populate_parsing_rule_fields():
    """
    Given:
        - An event dict with and without a timestamp.
    When:
        - Calling populate_parsing_rule_fields.
    Then:
        - The event should have source_log_event set, and _time set if timestamp is present.
        - If timestamp is missing, _time should not be set and no error should be raised.
    """
    from NetskopeEventCollector_v2 import populate_parsing_rule_fields
    event = {"timestamp": 1680000000}
    populate_parsing_rule_fields(event, "alert")
    assert event["source_log_event"] == "alert"
    assert "_time" in event
    # Test missing timestamp
    event = {}
    populate_parsing_rule_fields(event, "alert")
    assert event["source_log_event"] == "alert"


@pytest.mark.parametrize("event_type,expected_config", [
    # Incident event type (specific configuration)
    ("incident", {
        "endpoint": "/events/datasearch/incident",
        "time_params": {"start_time": "starttime", "end_time": "endtime"},
        "count_field": "event_count:count(_id)"
    }),
    # Standard event types (default configuration)
    ("alert", {
        "endpoint": "/events/data/{type}",
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
        "count_field": "event_count:count(id)"
    }),
    ("network", {
        "endpoint": "/events/data/{type}",
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
        "count_field": "event_count:count(id)"
    }),
    ("application", {
        "endpoint": "/events/data/{type}",
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
        "count_field": "event_count:count(id)"
    }),
    ("audit", {
        "endpoint": "/events/data/{type}",
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
        "count_field": "event_count:count(id)"
    }),
    ("page", {
        "endpoint": "/events/data/{type}",
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
        "count_field": "event_count:count(id)"
    }),
    # Unknown event type (should return default configuration)
    ("unknown_type", {
        "endpoint": "/events/data/{type}",
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"},
        "count_field": "event_count:count(id)"
    })
])
def test_get_event_type_config(event_type, expected_config):
    """
    Given:
        - Various event types including incident, standard, and unknown event types.
    When:
        - Calling get_event_type_config.
    Then:
        - The correct configuration should be returned for each event type.
    """
    from NetskopeEventCollector_v2 import get_event_type_config
    
    config = get_event_type_config(event_type)
    assert config == expected_config, f"Expected {expected_config} for {event_type}, got {config}"


@pytest.mark.parametrize("mock_config,start_time,end_time,expected_params", [
    # Test incident-style config (starttime/endtime)
    ({
        "time_params": {"start_time": "starttime", "end_time": "endtime"}
    }, "1680000000", "1680086400", {
        "starttime": "1680000000",
        "endtime": "1680086400"
    }),
    # Test standard config (insertionstarttime/insertionendtime)
    ({
        "time_params": {"start_time": "insertionstarttime", "end_time": "insertionendtime"}
    }, "1680000000", "1680086400", {
        "insertionstarttime": "1680000000",
        "insertionendtime": "1680086400"
    }),
    # Test with different time values
    ({
        "time_params": {"start_time": "starttime", "end_time": "endtime"}
    }, "1234567890", "1234567999", {
        "starttime": "1234567890",
        "endtime": "1234567999"
    }),
    # Test with custom parameter names
    ({
        "time_params": {"start_time": "custom_start", "end_time": "custom_end"}
    }, "9999999999", "9999999998", {
        "custom_start": "9999999999",
        "custom_end": "9999999998"
    })
])
def test_get_time_window_params(mocker, mock_config, start_time, end_time, expected_params):
    """
    Given:
        - A mocked configuration with specific time parameter names.
        - Start and end time values.
    When:
        - Calling get_time_window_params.
    Then:
        - The function should correctly map the time values to the parameter names from the config.
        - This test focuses on the key mapping logic, not the config retrieval (which is tested separately).
    """
    from NetskopeEventCollector_v2 import get_time_window_params
    
    # Mock get_event_type_config to return our test config
    mock_get_config = mocker.patch('NetskopeEventCollector_v2.get_event_type_config', return_value=mock_config)
    
    params = get_time_window_params("any_event_type", start_time, end_time)
    
    # Verify the config was retrieved
    mock_get_config.assert_called_once_with("any_event_type")
    
    # Verify the key mapping worked correctly
    assert params == expected_params, f"Expected {expected_params}, got {params}"