import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

from Docusign import (
    get_customer_events,
    CustomerEventsClient,
    DEFAULT_SERVER_DEV_URL,
    add_fields_to_customer_events
)


class TestGetCustomerEvents:
    def test_get_customer_events_basic_success(self, mocker):
        """
        Given:
            - last_run contains a previous cursor
            - API returns endCursor and two events
        When:
            - get_customer_events is called
        Then:
            - It should return the events and update last_run["cursor"] to endCursor
        """

        example_response = { # note: each item includes partial data, those are not the full event data (There are more fields)
            "endCursor": "aa_638553500560000000_638553500560000000_0",
            "data": [
                {
                    "timestamp": "2024-06-30T07:08:06.3038365Z",
                    "eventId": "11111111-1111-1111-1111-111111111111",
                    "accountId": "11111111-1111-1111-1111-111111111111",
                    "userId": "11111111-1111-1111-1111-111111111111",
                },
                {
                    "timestamp": "2024-06-30T06:44:26.8948106Z",
                    "eventId": "22222222-2222-2222-2222-222222222222",
                    "accountId": "22222222-2222-2222-2222-222222222222",
                    "userId": "22222222-2222-2222-2222-222222222222",
                },
            ],
        }

        mock_http = mocker.patch("Docusign.BaseClient._http_request", return_value=example_response)
        mocker.patch.object(demisto, "debug")

        client = CustomerEventsClient(server_url=DEFAULT_SERVER_DEV_URL, proxy=False, verify=True)
        last_run = {"cursor": "prev_cursor"}
        token = "test_token"
        limit = 200

        # Act
        events, updated_last_run = get_customer_events(last_run, limit, client, token)

        # Assert
        assert len(events) == 2
        assert updated_last_run["cursor"] == example_response["endCursor"]

        # Validate HTTP call parameters
        assert mock_http.call_count == 1
        _, kwargs = mock_http.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["headers"]["Authorization"] == f"Bearer {token}"
        assert kwargs["params"]["cursor"] == "prev_cursor"
        assert kwargs["params"]["limit"] == limit
        

    def test_get_customer_events_returns_empty_list(self, mocker):
        """
        Given:
            - last_run has a cursor
        When:
            - API returns empty data but a new endCursor
        Then:
            - It should return an empty list and update last_run["cursor"]
        """

        response = {"endCursor": "c2", "data": []}
        mocker.patch("Docusign.BaseClient._http_request", return_value=response)
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")

        client = CustomerEventsClient(server_url=DEFAULT_SERVER_DEV_URL, proxy=False, verify=True)
        last_run = {"cursor": "c1"}

        events, updated_last_run = get_customer_events(last_run, limit=100, client=client, access_token="tok")

        assert events == []
        assert updated_last_run["cursor"] == "c2"

    def test_get_customer_events_first_fetch_cursor_empty_in_last_run(self, mocker):
        """
        Given:
            - last_run is empty (no cursor)
        When:
            - get_customer_events is called
        Then:
            - It should use timestamp_to_datestring(time.time() - 60) as the cursor (which is it one_minute_ago variable)
        """

        # Force the default cursor string
        mocker.patch("Docusign.timestamp_to_datestring", return_value="one_minute_ago")

        # Return any valid response
        example_response = {"endCursor": "next_cursor", "data": []}
        mock_http = mocker.patch("Docusign.BaseClient._http_request", return_value=example_response)
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")

        client = CustomerEventsClient(server_url=DEFAULT_SERVER_DEV_URL, proxy=False, verify=True)

        events, updated_last_run = get_customer_events({}, limit=50, client=client, access_token="tok")

        assert events == []
        assert updated_last_run["cursor"] == "next_cursor"

        # Verify the cursor used in the request params
        _, kwargs = mock_http.call_args
        assert kwargs["params"]["cursor"] == "one_minute_ago"

    def test_add_fields_to_customer_events(self, mocker):
        """
        Given:
            - A list of customer events
        When:
            - add_fields_to_customer_events is called
        Then:
            - It should add source_log_type and _time fields to each event
        """
        
        events = [{"timestamp": "2024-06-30T07:08:06.3038365Z"}, {"timestamp": "2024-06-30T06:44:26.8948106Z"}]
        
        add_fields_to_customer_events(events)
        
        assert events[0]["source_log_type"] == "customerevent"
        assert events[0]["_time"] == "2024-06-30T07:08:06Z"
        assert events[1]["source_log_type"] == "customerevent"
        assert events[1]["_time"] == "2024-06-30T06:44:26Z"
