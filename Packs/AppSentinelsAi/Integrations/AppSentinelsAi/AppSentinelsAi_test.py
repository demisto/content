import pytest
from CommonServerPython import *
from freezegun import freeze_time
from typing import Any
from datetime import timedelta

import json

MOCK_BASEURL = "https://example.com"
MOCK_USER_KEY = "dummy_user_key"
MOCK_API_KEY = "dummy_api_key"
MOCK_ORGANIZATION = "dummy_org"
EMPTY_RESPONSE = {"data": [], "pagination": 1, "total": 0}

from AppSentinelsAi import (
    Client,
    DATE_FORMAT,
    remove_first_run_params,
    fetch_events,
    get_events,
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
        verify=False,
        use_proxy=False,
    )


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class TestHelperFunctions:
    @pytest.mark.parametrize(
        "input_params, expected_params",
        [
            ({"from_date": "2024-01-01", "to_date": "2024-01-31", "other": 1}, {"other": 1}),
            ({"from_date": "2024-01-01", "other": 1}, {"other": 1}),
            ({"to_date": "2024-01-31", "other": 1}, {"other": 1}),
            ({"other": 1}, {"other": 1}),
            ({}, {}),
        ],
    )
    def test_remove_first_run_params(self, input_params: dict[str, Any], expected_params: dict[str, Any]):
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
        response = util_load_json("test_data/events-dummy-data.json")
        return response

    @freeze_time("2023-10-26 10:05:00")  # Control the time for consistent testing
    def test_fetch_events_list_initial_fetch(self, client, mocker, mock_response_data):
        """
        Test fetch_events_list for the initial fetch (no last_log_id).

        Given:
            - Valid HTTP request parameters
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
        assert last_run == {"last_log_id": mock_response_data["data"][-1]["id"]}
        client.get_events_request.assert_called_once()  # Check if the API call was made

        current_time = get_current_time()
        start_time = (current_time - timedelta(minutes=1)).strftime(DATE_FORMAT)
        end_time = current_time.strftime(DATE_FORMAT)

        # Check the parameters of the API call
        expected_body = {
            "from_date": start_time,
            "to_date": end_time,
        }
        client.get_events_request.assert_called_with(body=expected_body, params_update={})

        # Check _TIME and source_log_type
        for event in events:
            assert event["_TIME"] == event["timestamp"]
            assert event["source_log_type"] == "auditlog"

    def test_fetch_events_list_subsequent_fetch(self, client, mocker, mock_response_data):
        """
        Test fetch_events_list for subsequent fetches (with last_log_id).

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
        last_run = {"last_log_id": 0}  # Simulate a previous fetch
        events, _ = fetch_events(client, last_run)

        assert len(events) == len(mock_response_data["data"])
        assert last_run == {"last_log_id": mock_response_data["data"][-1]["id"]}
        client.get_events_request.assert_called_once()
        expected_body = {"last_log_id": 0}
        client.get_events_request.assert_called_with(body=expected_body, params_update={})

        # Check _TIME and source_log_type
        for event in events:
            assert event["_TIME"] == event["timestamp"]
            assert event["source_log_type"] == "auditlog"

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
        last_run = {"last_log_id": 2}
        fetch_limit = 2
        events, _ = fetch_events(client, last_run, fetch_limit)

        assert len(events) == fetch_limit
        assert last_run == {"last_log_id": mock_response_data["data"][1]["id"]}
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
            "data": [{"id": 1, "timestamp": "2023-10-26T10:00:00Z"}, {"id": 2, "timestamp": "2023-10-26T10:01:00Z"}],
            "pagination": 2,
            "total": 4,
        }
        mock_response_page2 = {
            "data": [{"id": 3, "timestamp": "2023-10-26T10:02:00Z"}, {"id": 4, "timestamp": "2023-10-26T10:03:00Z"}],
            "pagination": 2,
            "total": 2,
        }
        mocker.patch.object(client, "get_events_request", side_effect=[mock_response_page1, mock_response_page2])
        last_run = {"last_log_id": 0}
        events, _ = fetch_events(client, last_run)

        expected_body_1 = {"last_log_id": 0}
        expected_params_2 = {"page": 1}

        first_call_args = client.get_events_request.call_args_list[0][1]  # kwargs of first call
        second_call_args = client.get_events_request.call_args_list[1][1]  # kwargs of second call

        assert first_call_args["body"] == expected_body_1
        assert second_call_args["body"] == expected_body_1
        assert second_call_args["params_update"] == expected_params_2

        assert len(events) == 4
        assert last_run == {"last_log_id": 4}
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
        mocker.patch.object(client, "get_events_request", return_value={"data": [], "pagination": 1, "total": 0})
        last_run = {}
        events, _ = fetch_events(client, last_run)

        assert not events
        assert last_run == {}  # last_run should not be updated if no events are returned

    def test_fetch_events_list_with_fetch_limit_smaller_than_page_size(self, client, mocker, mock_response_data):
        """
        Test fetch_events_list with fetch_limit smaller than the events returned.

        Given:
            - Valid HTTP request parameters.
            - Fetch limit smaller than response.

        When:
            - Fetching events.
        Then:
            - Make Sure the number of events are according to the limit.
            - Make sure the last_run is updated correctly.
        """
        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {}
        fetch_limit = 2
        events, _ = fetch_events(client, last_run, fetch_limit)

        assert len(events) == fetch_limit
        assert last_run == {"last_log_id": 2}

    def test_fetch_events_list_with_fetch_limit_larger_than_total_events(self, client, mocker, mock_response_data):
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

        mocker.patch.object(client, "get_events_request", return_value=mock_response_data)
        last_run = {}
        fetch_limit = 5
        events, _ = fetch_events(client, last_run, fetch_limit)

        assert len(events) == 4
        assert last_run == {"last_log_id": 4}


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
        mock_client_get_events_request.return_value = {"data": [], "pagination": 1, "total": 0}
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
        mock_client_get_events_request.return_value = dummy_data
        args = {}
        result = get_events(client, args)

        assert result.outputs == dummy_data["data"]
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
        dummy_data = util_load_json("test_data/events-dummy-data.json")
        mock_client_get_events_request.return_value = dummy_data

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
        mock_events_data = EMPTY_RESPONSE
        mock_client_get_events_request.return_value = mock_events_data
        first_fetch_time = "1 Days"
        args = {"first_fetch": first_fetch_time}
        get_events(client, args)
        mock_client_get_events_request.assert_called_once()
        expected_body = {"from_date": "2025-01-14 12:00"}
        mock_client_get_events_request.assert_called_with(body=expected_body, params_update={})
