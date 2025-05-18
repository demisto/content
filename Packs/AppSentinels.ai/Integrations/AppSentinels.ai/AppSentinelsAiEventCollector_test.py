import pytest
from CommonServerPython import *
from freezegun import freeze_time
import json
from typing import Dict, Any, List
from datetime import datetime, timedelta

from demisto_sdk.commands.common.handlers import JSON_Handler

import json

MOCK_BASEURL = "https://example.com"
MOCK_USER_KEY = "dummy_user_key"
MOCK_API_KEY = "dummy_api_key"
MOCK_ORGANIZATION = "dummy_org"
MOCK_APPLICATION = "dummy_app"

from AppSentinelsAiEventCollector import (
    Client,
    BASE_EVENT_BODY,
    DATE_FORMAT,
    remove_first_run_params,
    fetch_events,
    get_events
)


@pytest.fixture
def client():
    """
    A dummy client fixture for testing.
    """
    return Client(
        base_url=MOCK_BASEURL,
        user_key=MOCK_USER_KEY,
        api_key=MOCK_API_KEY,
        organization=MOCK_ORGANIZATION,
        application=MOCK_APPLICATION,
        verify=False,
        use_proxy=False,
        base_event_body=BASE_EVENT_BODY,  # Corrected variable name
    )


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class TestHelperFunctions:
    @pytest.mark.parametrize(
        "input_params, expected_params",
        [
            ({"from_timestamp": "2024-01-01", "to_timestamp": "2024-01-31", "other": 1}, {"other": 1}),
            ({"from_timestamp": "2024-01-01", "other": 1}, {"other": 1}),
            ({"to_timestamp": "2024-01-31", "other": 1}, {"other": 1}),
            ({"other": 1}, {"other": 1}),
            ({}, {}),
        ],
    )
    def test_remove_first_run_params(self, input_params: Dict[str, Any], expected_params: Dict[str, Any]):
        """
        Test remove_first_run_params function behavior.

        Given:
            - Valid HTTP request parameters.
            - Expected params at the end of the function run,

        When:
            - Removing first run params
        Then:
            - Make sure the request will be sent with right parameters.
        """
        params_copy = input_params.copy()  # Avoid modifying original test data
        remove_first_run_params(params_copy)
        assert params_copy == expected_params


class TestFetchEvents:
    @pytest.fixture
    def mock_response_data(self):
        """Provides sample API response data."""
        data = util_load_json("test_data/events-dummy-data.json")
        return {
            "data": data,
            "last_event_id": 22,
            "more_records": False,
        }

    @freeze_time("2023-10-26 10:05:00")  # Control the time for consistent testing
    def test_fetch_events_list_initial_fetch(self, client, mocker, mock_response_data):
        """
        Test fetch_events_list for the initial fetch (no last_event_id).

        Given:
            - Valid HTTP request parameters.
            - No last_run object
            - Valid response data

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make sure the 'from' aql parameter request is sent with the "current" time 2023-10-26T10:05:00.
            - Make sure the pagination logic performs as expected.
        """
        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {}
        events, _ = fetch_events(client, last_run)

        assert len(events) == len(mock_response_data["data"])
        assert last_run == {"last_event_id": mock_response_data["last_event_id"]}
        client.get_events_request.assert_called_once()  # Check if the API call was made

        current_time = get_current_time()
        start_time = (current_time - timedelta(minutes=1)).strftime(DATE_FORMAT)
        end_time = current_time.strftime(DATE_FORMAT)

        # Check the parameters of the API call
        expected_params = {
            "from_timestamp": start_time,
            "to_timestamp": end_time,
        }
        client.get_events_request.assert_called_with(params=expected_params)

        # Check _TIME and source_log_type
        for event in events:
            assert event["_TIME"] == event["timestamp"]
            assert event["source_log_type"] == "event"

    def test_fetch_events_list_subsequent_fetch(self, client, mocker, mock_response_data):
        """
        Test fetch_events_list for subsequent fetches (with last_event_id).

        Given:
            - Valid HTTP request parameters.
            - last_run argument.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make sure the 'from' aql parameter request is sent with the correct id.
            - Make sure that XSIAM entries were added correctly.
        """
        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {"last_event_id": 10}  # Simulate a previous fetch
        events, _ = fetch_events(client, last_run)

        assert len(events) == len(mock_response_data["data"])
        assert last_run == {"last_event_id": mock_response_data["last_event_id"]}
        client.get_events_request.assert_called_once()
        expected_params = {"last_event_id": 10}
        client.get_events_request.assert_called_with(params=expected_params)

        # Check _TIME and source_log_type
        for event in events:
            assert event["_TIME"] == event["timestamp"]
            assert event["source_log_type"] == "event"

    def test_fetch_events_list_fetch_limit(self, client, mocker, mock_response_data):
        """
        Test fetch_events_list with a fetch_limit.

        Given:
            - Valid HTTP request parameters.
            - Fetch limit.

        When:
            - Fetching events.
        Then:
            - Make Sure the number of events are according to the limit.
            - Make sure the pagination logic performs as expected.
        """
        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {"last_event_id": 0}
        fetch_limit = 2
        events, _ = fetch_events(client, last_run, fetch_limit)

        assert len(events) == fetch_limit
        assert last_run == {"last_event_id": mock_response_data["data"][1]["eventid"]}
        client.get_events_request.assert_called_once()

    def test_fetch_events_list_multiple_pages(self, client, mocker):
        """
        Test fetch_events_list with multiple pages of results.

        Given:
            - Valid HTTP request parameters.
            - Two different request response data.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make sure the pagination logic performs as expected.
        """
        mock_response_page1 = {
            "data": [
                {"eventid": 1, "timestamp": "2023-10-26T10:00:00Z"},
                {"eventid": 2, "timestamp": "2023-10-26T10:01:00Z"}
            ],
            "last_event_id": 2,
            "more_records": True,
        }
        mock_response_page2 = {
            "data": [
                {"eventid": 3, "timestamp": "2023-10-26T10:02:00Z"},
                {"eventid": 4, "timestamp": "2023-10-26T10:03:00Z"}
            ],
            "last_event_id": 4,
            "more_records": False,
        }
        mocker.patch.object(client, "get_events_request", side_effect=[mock_response_page1, mock_response_page2])
        last_run = {"last_event_id": 0}
        events, _ = fetch_events(client, last_run)

        assert len(events) == 4
        assert last_run == {"last_event_id": 4}
        assert client.get_events_request.call_count == 2

    def test_fetch_events_list_no_events(self, client, mocker):
        """
        Test fetch_events_list when the API returns no events.

        Given:
            - Valid HTTP request parameters.
            - Empty response

        When:
            - Fetching events.
        Then:
            - Make sure the pagination logic performs as expected.
            - Make sure the request is returning with right parameters for last_run.
        """
        mocker.patch.object(client, "get_events_request", return_value={"data": [], "last_event_id": 0, "more_records": False})
        last_run = {}
        events, _ = fetch_events(client, last_run)

        assert not events
        assert last_run == {}  # last_run should not be updated if no events are returned

    def test_fetch_events_list_with_fetch_limit_smaller_than_page_size(self, client, mocker):
        """
        Test fetch_events_list with fetch_limit smaller than the events returned.

        Given:
            - Valid HTTP request parameters.
            - Fetch limit smaller than response.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make Sure the number of events are according to the limit.
            - Make sure the pagination logic performs as expected.
        """
        mock_response_data = {
            "data": [
                {"eventid": 1, "timestamp": "2023-10-26T10:00:00Z"},
                {"eventid": 2, "timestamp": "2023-10-26T10:01:00Z"},
                {"eventid": 3, "timestamp": "2023-10-26T10:02:00Z"},
            ],
            "last_event_id": 3,
            "more_records": False
        }
        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {}
        fetch_limit = 2
        events, _ = fetch_events(client, last_run, fetch_limit)

        assert len(events) == fetch_limit
        assert last_run == {"last_event_id": 2}

    def test_fetch_events_list_with_fetch_limit_larger_than_total_events(self, client, mocker):
        """
        Test fetch_events_list with fetch_limit larger than the total number of events.

        Given:
            - Valid HTTP request parameters.
            - Fetch limit smaller larger than response.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make Sure the number of events are according to the limit.
            - Make sure the pagination logic performs as expected.
        """

        mock_response_data = {
            "data": [
                {"eventid": 1, "timestamp": "2023-10-26T10:00:00Z"},
                {"eventid": 2, "timestamp": "2023-10-26T10:01:00Z"},
            ],
            "last_event_id": 2,
            "more_records": False
        }
        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {}
        fetch_limit = 5
        events, _ = fetch_events(client, last_run, fetch_limit)

        assert len(events) == 2
        assert last_run == {"last_event_id": 2}


class TestGetEvents:
    @pytest.fixture
    def mock_client_get_events_request(self, mocker):
        """Mocks the Client's get_events_request method."""
        return mocker.patch.object(Client, "get_events_request")

    def test_get_events_no_events(self, client, mock_client_get_events_request):
        """
        Test get_events when the API returns no events.

        Given:
            - Valid HTTP request parameters.
            - Empty Response.

        When:
            - Fetching events.
        Then:
            - Make sure that correct output is returned
        """
        mock_client_get_events_request.return_value = {"data": []}
        args = {}  # Empty args
        result = get_events(client, args)

        assert result.outputs == []
        assert result.readable_output == "### AppSentinels.ai Record(s)\n**No entries.**\n"

    def test_get_events_with_events(self, client, mock_client_get_events_request):
        """
        Test get_events with events returned.

        Given:
            - Valid HTTP request parameters.
            - Valid http response data.

        When:
            - Fetching events.
        Then:
            - Make sure the request output is the data given as the response.
            - Make sure the readable output looks as expected.
        """
        dummy_data = util_load_json("test_data/events-dummy-data.json")
        mock_events_data = {
            "data": dummy_data
        }
        mock_client_get_events_request.return_value = mock_events_data
        args = {}
        result = get_events(client, args)

        assert result.outputs == mock_events_data["data"]
        assert result.outputs_prefix == "AppSentinels.ai."
        # Basic check for table format, more detailed checks could be added
        assert "ID" in result.readable_output
        assert "Action" in result.readable_output

    def test_get_events_with_limit(self, client, mock_client_get_events_request):
        """
        Test get_events with a limit argument.

        Given:
            - Valid HTTP request parameters.
            - Fetch limit.

        When:
            - Fetching events.
        Then:
            - Make Sure the number of events are according to the limit.
        """
        mock_data = util_load_json("test_data/events-dummy-data.json")
        mock_events_data = {
            "data": mock_data
        }
        mock_client_get_events_request.return_value = mock_events_data
        args = {"limit": 2}
        result = get_events(client, args)
        assert len(result.outputs) == 2

    @freeze_time("2025-01-15 12:00:00")
    def test_get_events_with_first_fetch(self, client, mock_client_get_events_request):
        """
        Test get_events with a first_fetch argument.

        Given:
            - Valid HTTP request parameters.
            - First fetch date.

        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
        """
        mock_events_data = {"data": []}
        mock_client_get_events_request.return_value = mock_events_data
        first_fetch_time = "1 Days"
        args = {"first_fetch": first_fetch_time}
        get_events(client, args)
        mock_client_get_events_request.assert_called_once()
        expected_params = {"from_timestamp": "2025-01-14T12:00:00.000000Z"}
        mock_client_get_events_request.assert_called_with(params=expected_params)
