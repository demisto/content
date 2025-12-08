from unittest.mock import MagicMock
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

from Docusign import (
    get_customer_events,
    CustomerEventsClient,
    DEFAULT_SERVER_DEV_URL,
    add_fields_to_customer_events,
    get_user_data,
    fetch_audit_user_data,
    UserDataClient,
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
        # Note: each item contains partial data; these are not the full event records (additional fields exist)
        example_response = {
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


class TestGetUserData:
    """
    - limit ≤ per_page -> per_page = limit -> fetch full page, remaining logs mechanism is not used.
    - limit > per_page -> per_page = max_users_per_page -> fetch partial page, remaining logs mechanism is used.

    CRITICAL: per_page is ALWAYS constant during all the fetch user data runs.
    """

    def test_get_user_data_with_continuing_fetch_when_limit_less_than_max_logs_per_page(self, mocker):
        """
        Given:
            - assume maximum audit users per fetch = 10
            - limit = 8
            - next_page is not None (next_page=2)
        When:
            get_user_data is called with per_page=limit=8
        Then:
            It should fetch exactly 8 users in one request and set continuing_fetch_info for remaining logs.
            full page fetched because the limit is less than the max users per page-> no remaining logs from fetched partial page.
        """
        limit = 8
        mock_params = {
            "url": "url",
        }
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        # --- FIRST FETCH: no continuing fetch mechanism ---
        # Mock 8 users from first page (per_page=8, but more users available)
        users_1 = [  # note: "id" key is the only relevant key, this is a partial response (each user includes more fields)
            {"id": "11111111-1111-1111-1111-111111111111", "user_name": "user1"},
            {"id": "22222222-2222-2222-2222-222222222222", "user_name": "user2"},
            {"id": "33333333-3333-3333-3333-333333333333", "user_name": "user3"},
            {"id": "44444444-4444-4444-4444-444444444444", "user_name": "user4"},
            {"id": "55555555-5555-5555-5555-555555555555", "user_name": "user5"},
            {"id": "66666666-6666-6666-6666-666666666666", "user_name": "user6"},
            {"id": "77777777-7777-7777-7777-777777777777", "user_name": "user7"},
            {"id": "88888888-8888-8888-8888-888888888888", "user_name": "user8"},
        ]

        next_url = "next_url_1"
        paging = {
            "result_set_size": 8,
            "result_set_start_position": 0,
            "result_set_end_position": 7,
            "total_set_size": 1000,
            "next": next_url,
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"users": users_1, "paging": paging}

        # Create a mock UserClient
        mock_client = mocker.MagicMock()
        mock_client.get_users_first_request.return_value = (mock_response.json(), "request_url")

        # Initial state - first fetch
        initial_last_run = {}

        result_logs, result_last_run = get_user_data(
            initial_last_run, limit=limit, users_per_page=limit, client=mock_client, access_token="tok"
        )

        assert len(result_logs) == limit
        assert result_last_run["continuing_fetch_info"] is not None  # More pages available
        assert result_last_run["continuing_fetch_info"]["url"] == next_url

        # Verify only 1 request was made (limit reached after one request)
        assert mock_client.get_users_first_request.call_count == 1

        # Verify request used per_page = limit
        assert mock_client.get_users_first_request.call_args[0][1]["take"] == limit

        # --- SECOND FETCH: Continuing fetch mechanism, page=2---
        # Mock page 2 users - 8 more users
        users_2 = [
            {"id": "99999999-9999-9999-9999-999999999999", "user_name": "user9"},
            {"id": "10101010-1010-1010-1010-101010101010", "user_name": "user10"},
            {"id": "11111111-1111-1111-1111-111111111111", "user_name": "user11"},
            {"id": "12121212-1212-1212-1212-121212121212", "user_name": "user12"},
            {"id": "13131313-1313-1313-1313-131313131313", "user_name": "user13"},
            {"id": "14141414-1414-1414-1414-141414141414", "user_name": "user14"},
            {"id": "15151515-1515-1515-1515-151515151515", "user_name": "user15"},
            {"id": "16161616-1616-1616-1616-161616161616", "user_name": "user16"},
        ]
        next_url = "next_url_2"
        paging = {
            "result_set_size": 8,
            "result_set_start_position": 8,
            "result_set_end_position": 15,
            "total_set_size": 1000,
            "next": next_url,
        }

        mock_response_page2 = MagicMock()
        mock_response_page2.status_code = 200
        mock_response_page2.json.return_value = {"users": users_2, "paging": paging}

        # Reset mock to return page 2 response
        mock_client.get_users_request.return_value = mock_response_page2.json()
        mock_client.reset_mock()

        continuing_last_run = result_last_run
        result_logs_2, result_last_run_2 = get_user_data(
            continuing_last_run, limit, limit, client=mock_client, access_token="tok"
        )

        assert len(result_logs_2) == limit

        assert result_last_run_2["continuing_fetch_info"] is not None  # More pages available
        assert result_last_run_2["continuing_fetch_info"]["url"] == next_url
        assert mock_client.get_users_request.call_count == 1

    def test_fetch_audit_user_data_with_remaining_logs_mechanism(self, mocker):
        """
        Test the complete remaining logs mechanism using fetch_audit_logs function.

        Given:
            - max_user_events_per_fetch = 8 (limit)
            - MAX_USER_DATA_PER_PAGE = 5 (per_page)
            - Available logs: 12 total (more than limit)

        When:
            fetch_audit_logs is called with limit > per_page

        Then:
            It should:
            1. First call: fetch 5 logs (per_page=5), remaining=3
            2. Second call: fetch 5 logs (per_page=5), but only use 3 to reach limit=8
            3. Set excess_logs_info for the 2 unused logs from second call
            4. Return exactly 8 logs total
        """
        limit = 8
        per_page = 5

        mocker.patch("Docusign.MAX_USER_DATA_PER_PAGE", per_page)
        mocker.patch("Docusign.MAX_USER_DATA_PER_FETCH", limit)

        mock_params = {
            "url": "server_url",
            "max_user_events_per_fetch": limit,
        }
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        # --- FIRST FETCH - FIRST API CALL: Page 1, fetch 5 users ---
        users_1 = [
            {"id": "1", "user_name": "user1"},
            {"id": "2", "user_name": "user2"},
            {"id": "3", "user_name": "user3"},
            {"id": "4", "user_name": "user4"},
            {"id": "5", "user_name": "user5"},
        ]

        # --- FIRST FETCH - SECOND API CALL: Page 2, fetch 5 users (but only need 3) ---
        users_2 = [
            {"id": "6", "user_name": "user6"},
            {"id": "7", "user_name": "user7"},
            {"id": "8", "user_name": "user8"},
            {"id": "9", "user_name": "user9"},  # Excess log 1
            {"id": "10", "user_name": "user10"},  # Excess log 2
        ]

        # --- SECOND FETCH - THIRD API CALL: Page 3, fetch 5 users
        users_3 = [
            {"id": "11", "user_name": "user11"},
            {"id": "12", "user_name": "user12"},
            {"id": "13", "user_name": "user13"},
            {"id": "14", "user_name": "user14"},
            {"id": "15", "user_name": "user15"},
        ]

        # --- SECOND FETCH - FOURTH API CALL: Page 4, fetch 5 users (but only need 1)---
        users_4 = [
            {"id": "16", "user_name": "user16"},
            {"id": "17", "user_name": "user17"},  # Excess log 1
            {"id": "18", "user_name": "user18"},  # Excess log 2
            {"id": "19", "user_name": "user19"},  # Excess log 3
            {"id": "20", "user_name": "user20"},  # Excess log 4
        ]

        users_5 = [
            {"id": "21", "user_name": "user21"},
            {"id": "22", "user_name": "user22"},
        ]

        # Mock responses for both API calls
        mock_response_page1 = MagicMock()
        mock_response_page1.status_code = 200
        mock_response_page1.json.return_value = {"users": users_1, "paging": {"next": "next_url_1"}}

        mock_response_page2 = MagicMock()
        mock_response_page2.status_code = 200
        mock_response_page2.json.return_value = {"users": users_2, "paging": {"next": "next_url_2"}}

        mock_response_page3 = MagicMock()
        mock_response_page3.status_code = 200
        mock_response_page3.json.return_value = {"users": users_3, "paging": {"next": "next_url_3"}}

        mock_response_page4 = MagicMock()
        mock_response_page4.status_code = 200
        mock_response_page4.json.return_value = {"users": users_4, "paging": {"next": "next_url_4"}}

        mock_response_page1_1 = MagicMock()
        mock_response_page1_1.status_code = 200
        mock_response_page1_1.json.return_value = {"users": users_5, "paging": {"next": None}}

        mock_first_request = mocker.patch(
            "Docusign.UserDataClient.get_users_first_request",
            side_effect=[(mock_response_page1.json(), "next_url_1")],
        )
        # Configure mock to return different responses for each call
        mock_requests_get = mocker.patch(
            "Docusign.UserDataClient.get_users_request",
            side_effect=[
                mock_response_page2.json(),
                mock_response_page2.json(),
                mock_response_page3.json(),
                mock_response_page4.json(),
                mock_response_page4.json(),
                mock_response_page1_1.json(),
            ],
        )

        mock_timestamp_to_datestring = mocker.patch("Docusign.timestamp_to_datestring")
        mock_timestamp_to_datestring.return_value = "2024-06-03T15:00:00.000Z"

        user_data_client = UserDataClient(
            account_id="account_id", organization_id="organization_id", env="dev", proxy=False, verify=True
        )
        mocker.patch("Docusign.initiate_user_data_client", return_value=user_data_client)

        # create a mock for auth client
        mock_auth_client = mocker.MagicMock()
        mock_auth_client.access_token = "access_token"

        # Initial state - first fetch
        initial_last_run = {}
        result_last_run, users = fetch_audit_user_data(initial_last_run, mock_auth_client, test_mode=True)

        assert len(users) == limit
        assert result_last_run["continuing_fetch_info"].get("url") == "next_url_2"

        # Should contain logs from both pages (first 5 + first 3 from second page)
        expected_users_ids = ["1", "2", "3", "4", "5", "6", "7", "8"]
        actual_users_ids = [user["id"] for user in users]
        assert actual_users_ids == expected_users_ids

        # Should make exactly 2 API calls (5 logs from page 1 + 3 logs from page 2)
        assert mock_requests_get.call_count + mock_first_request.call_count == 2

        # Should set excess_users_info for unused users from page 2
        assert result_last_run["excess_users_info"].get("offset") == 3
        assert result_last_run["excess_users_info"].get("url") == "next_url_1"

        # --- SECOND CALL TO fetch_audit_user_data: Process excess users from previous fetch before fetching new page ---

        # Second fetch using last_run from first fetch
        result_last_run_2, users_2 = fetch_audit_user_data(result_last_run, mock_auth_client, test_mode=True)

        assert len(users_2) == limit

        # Should contain excess users first (9, 10), then new users (11-16)
        expected_users_ids_2 = ["9", "10", "11", "12", "13", "14", "15", "16"]  # 2 excess + 6 new
        actual_users_ids_2 = [user["id"] for user in users_2]
        assert actual_users_ids_2 == expected_users_ids_2

        # Second fetch should make exactly 3 API calls(2 users from page 2 + 5 users from page 3 + 1 user from page 4)
        # (First fetch made 2 API calls)
        assert mock_requests_get.call_count + mock_first_request.call_count == 5
        # Should set excess_users_info for unused users from page 4
        assert result_last_run_2["excess_users_info"] is not None
        excess_info = result_last_run_2["excess_users_info"]
        assert excess_info["offset"] == 1  # Only first 1 log from page 4 were used
        assert excess_info["url"] == "next_url_3"

        # Third fetch using last_run from second fetch
        result_last_run_3, users_3 = fetch_audit_user_data(result_last_run_2, mock_auth_client, test_mode=True)

        # Should return exactly 6 users
        assert len(users_3) == 6
        expected_users_ids_3 = ["17", "18", "19", "20", "21", "22"]
        actual_users_ids_3 = [user["id"] for user in users_3]
        assert actual_users_ids_3 == expected_users_ids_3

        # Third fetch should make exactly 1 API call (4 users remaining from page 5)
        # (First fetch made 2 API calls, second fetch made 3 API calls)
        assert mock_requests_get.call_count + mock_first_request.call_count == 7

        # Should remove excess_users_info from last run (already fetched remaining users)
        assert result_last_run_3["excess_users_info"] is None
        # Should remove continuing_fetch_info from last run (next page is none, next fetch will start a new fetch window)
        assert result_last_run_3["continuing_fetch_info"] is None
