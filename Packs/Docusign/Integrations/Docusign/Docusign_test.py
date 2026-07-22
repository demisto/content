from unittest.mock import MagicMock
import pytest
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
    AuthClient,
    get_events_command,
    fetch_events,
    get_scopes_per_type,
    get_env_from_server_url,
    is_access_token_expired,
    is_required_scopes_set,
    remove_duplicate_users,
    generate_consent_url,
    validate_configuration_params,
    test_module,
    reset_access_token,
    initiate_auth_client,
    CUSTOMER_EVENTS_SCOPE,
    USER_DATA_SCOPE,
    CUSTOMER_EVENTS_TYPE,
    USER_DATA_TYPE,
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
        result_last_run, users = fetch_audit_user_data(initial_last_run, mock_auth_client, limit=limit, test_mode=True)

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
        result_last_run_2, users_2 = fetch_audit_user_data(result_last_run, mock_auth_client, limit=limit, test_mode=True)

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
        result_last_run_3, users_3 = fetch_audit_user_data(result_last_run_2, mock_auth_client, limit=limit, test_mode=True)

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


class TestGetEventsCommand:
    def test_get_events_command_customer_events(self, mocker):
        """
        Given:
            - event_type is 'Customer events' and limit is 2
        When:
            - get_events_command is called
        Then:
            - It should call fetch_customer_events and return the events as CommandResults
        """
        mock_events = [
            {
                "timestamp": "2024-06-30T07:08:06.3038365Z",
                "eventId": "event-1",
                "source_log_type": "customerevent",
                "_time": "2024-06-30T07:08:06Z",
            },
            {
                "timestamp": "2024-06-30T06:44:26.8948106Z",
                "eventId": "event-2",
                "source_log_type": "customerevent",
                "_time": "2024-06-30T06:44:26Z",
            },
        ]

        mocker.patch.object(demisto, "args", return_value={"event_type": CUSTOMER_EVENTS_TYPE, "limit": "2"})
        mocker.patch.object(demisto, "params", return_value={"url": DEFAULT_SERVER_DEV_URL})
        mocker.patch.object(demisto, "debug")

        mock_fetch = mocker.patch("Docusign.fetch_customer_events", return_value=({}, mock_events))

        mock_auth_client = mocker.MagicMock()
        mock_auth_client.access_token = "test_token"

        result = get_events_command(mock_auth_client)

        assert "fetched 2" in result.readable_output
        assert result.raw_response == mock_events
        mock_fetch.assert_called_once_with(last_run={}, access_token="test_token", limit=2)

    def test_get_events_command_audit_users(self, mocker):
        """
        Given:
            - event_type is 'Audit Users' and limit is 3
        When:
            - get_events_command is called
        Then:
            - It should call fetch_audit_user_data and return the events as CommandResults
        """
        mock_users = [
            {"id": "user-1", "user_name": "alice"},
            {"id": "user-2", "user_name": "bob"},
            {"id": "user-3", "user_name": "charlie"},
        ]

        mocker.patch.object(demisto, "args", return_value={"event_type": USER_DATA_TYPE, "limit": "3"})
        mocker.patch.object(demisto, "params", return_value={"url": DEFAULT_SERVER_DEV_URL})
        mocker.patch.object(demisto, "debug")

        mock_fetch = mocker.patch("Docusign.fetch_audit_user_data", return_value=({}, mock_users))

        mock_auth_client = mocker.MagicMock()
        mock_auth_client.access_token = "test_token"

        result = get_events_command(mock_auth_client)

        assert "fetched 3" in result.readable_output
        assert result.raw_response == mock_users
        mock_fetch.assert_called_once_with(last_run={}, auth_client=mock_auth_client, limit=3, test_mode=True)

    def test_get_events_command_unknown_event_type(self, mocker):
        """
        Given:
            - event_type is an unknown value
        When:
            - get_events_command is called
        Then:
            - It should raise a DemistoException
        """
        mocker.patch.object(demisto, "args", return_value={"event_type": "InvalidType", "limit": "10"})
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "debug")

        mock_auth_client = mocker.MagicMock()

        import pytest

        with pytest.raises(DemistoException, match="Unknown event type"):
            get_events_command(mock_auth_client)


class TestScopes:
    """Regression tests for XSUP-70500: the JWT Grant requires the 'impersonation' scope
    for every fetch type, otherwise DocuSign returns 400 {"error": "consent_required"}.
    """

    def test_baseline_jwt_scopes_in_all_scope_sets(self):
        """
        Given:
            - The scope lists used to build the consent URL and the JWT.
        When:
            - Inspecting each fetch type's scopes.
        Then:
            - The DocuSign JWT Grant baseline scopes 'signature' and 'impersonation'
              must be present in both, since all flows use the JWT Bearer grant.
        """
        for scope_set in (CUSTOMER_EVENTS_SCOPE, USER_DATA_SCOPE):
            assert "signature" in scope_set
            assert "impersonation" in scope_set

    def test_get_scopes_per_type_audit_users_includes_impersonation(self):
        """
        Given:
            - Only the 'Audit Users' fetch type is selected.
        When:
            - get_scopes_per_type resolves the required scopes.
        Then:
            - The resolved scopes include 'impersonation' (the XSUP-70500 regression).
        """
        scopes = get_scopes_per_type(USER_DATA_TYPE)
        assert "impersonation" in scopes
        assert "organization_read" in scopes
        assert "user_read" in scopes
        assert "signature" in scopes

    def test_get_scopes_per_type_customer_events(self):
        scopes = get_scopes_per_type(CUSTOMER_EVENTS_TYPE)
        assert "impersonation" in scopes
        assert "signature" in scopes

    def test_get_scopes_per_type_both_types(self):
        scopes = get_scopes_per_type(f"{CUSTOMER_EVENTS_TYPE},{USER_DATA_TYPE}")
        for expected in ("signature", "impersonation", "organization_read", "user_read"):
            assert expected in scopes

    def test_get_scopes_per_type_none_selected(self):
        assert get_scopes_per_type("") == []


class TestEnvFromServerUrl:
    def test_dev_host(self):
        assert get_env_from_server_url("https://account-d.docusign.com") == "dev"

    def test_prod_host(self):
        assert get_env_from_server_url("https://account.docusign.com") == "prod"

    def test_unknown_host_defaults_to_prod(self):
        assert get_env_from_server_url("https://example.com") == "prod"


class TestTokenScopeHelpers:
    def test_is_access_token_expired_true(self, mocker):
        mocker.patch.object(demisto, "debug")
        assert is_access_token_expired("2000-01-01T00:00:00Z") is True

    def test_is_access_token_expired_false(self, mocker):
        mocker.patch.object(demisto, "debug")
        assert is_access_token_expired("2999-01-01T00:00:00Z") is False

    def test_is_required_scopes_set_true(self):
        assert is_required_scopes_set(["a", "b"], ["a", "b", "c"]) is True

    def test_is_required_scopes_set_false(self):
        assert is_required_scopes_set(["a", "z"], ["a", "b", "c"]) is False


class TestRemoveDuplicateUsers:
    def test_removes_matching_id_and_time(self):
        users = [
            {"id": "1", "_time": "t1"},
            {"id": "2", "_time": "t1"},
            {"id": "3", "_time": "t2"},
        ]
        result = remove_duplicate_users(users, ids_to_remove=["1"], time_to_remove="t1")
        assert {u["id"] for u in result} == {"2", "3"}

    def test_keeps_when_time_differs(self):
        users = [{"id": "1", "_time": "t2"}]
        result = remove_duplicate_users(users, ids_to_remove=["1"], time_to_remove="t1")
        assert result == users

    def test_empty_inputs_returns_original(self):
        users = [{"id": "1", "_time": "t1"}]
        assert remove_duplicate_users(users, ids_to_remove=[], time_to_remove="t1") == users
        assert remove_duplicate_users([], ids_to_remove=["1"], time_to_remove="t1") == []


class TestAuthClientValidatePrivateKey:
    def _client(self, mocker):
        mocker.patch.object(AuthClient, "get_access_token", return_value="tok")
        mocker.patch.object(demisto, "debug")
        return AuthClient(
            server_url="https://account-d.docusign.com",
            integration_key="key",
            user_id="user",
            private_key_pem="-----BEGIN RSA PRIVATE KEY-----\nAAAA BBBB CCCC\n-----END RSA PRIVATE KEY-----",
        )

    def test_validate_private_key_normalizes(self, mocker):
        client = self._client(mocker)
        assert client.private_key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----\n")
        assert client.private_key_pem.endswith("\n-----END RSA PRIVATE KEY-----")
        assert "AAAABBBBCCCC" in client.private_key_pem.replace("\n", "")

    def test_validate_private_key_bad_prefix(self, mocker):
        mocker.patch.object(AuthClient, "get_access_token", return_value="tok")
        mocker.patch.object(demisto, "debug")
        with pytest.raises(DemistoException, match="must start with"):
            AuthClient(
                server_url="https://account-d.docusign.com",
                integration_key="key",
                user_id="user",
                private_key_pem="not a key",
            )


class TestAuthClientToken:
    def _make_client(self, mocker):
        mocker.patch.object(AuthClient, "get_access_token", return_value="tok")
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "error")
        return AuthClient(
            server_url="https://account-d.docusign.com",
            integration_key="key",
            user_id="user",
            private_key_pem="-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
        )

    def test_exchange_jwt_success(self, mocker):
        client = self._make_client(mocker)
        mocker.patch.object(
            client,
            "_http_request",
            return_value={"access_token": "abc", "expires_in": 3600, "scope": "signature impersonation"},
        )
        access_token, expired_at, scope = client.exchange_jwt_to_access_token("jwt")
        assert access_token == "abc"
        assert scope == "signature impersonation"
        assert expired_at

    def test_exchange_jwt_missing_token_raises(self, mocker):
        client = self._make_client(mocker)
        mocker.patch.object(client, "_http_request", return_value={"scope": "signature"})
        with pytest.raises(DemistoException, match="Token exchange failed"):
            client.exchange_jwt_to_access_token("jwt")

    def test_exchange_jwt_consent_required_propagates(self, mocker):
        """consent_required from DocuSign must propagate (XSUP-70500 symptom)."""
        client = self._make_client(mocker)
        mocker.patch.object(
            client,
            "_http_request",
            side_effect=DemistoException('Error in API call [400] - Bad Request {"error": "consent_required"}'),
        )
        with pytest.raises(DemistoException, match="consent_required"):
            client.exchange_jwt_to_access_token("jwt")

    def test_get_user_info(self, mocker):
        client = self._make_client(mocker)
        mocker.patch.object(client, "_http_request", return_value={"accounts": [{"account_id": "a1"}]})
        assert client.get_user_info("tok")["accounts"][0]["account_id"] == "a1"

    def test_get_base_uri_from_context(self, mocker):
        client = self._make_client(mocker)
        mocker.patch("Docusign.get_integration_context", return_value={"base_uri": "https://cached"})
        assert client.get_base_uri("tok", "a1") == "https://cached"

    def test_get_base_uri_fetches_and_caches(self, mocker):
        client = self._make_client(mocker)
        mocker.patch("Docusign.get_integration_context", return_value={})
        set_ctx = mocker.patch("Docusign.set_integration_context")
        mocker.patch.object(
            client,
            "get_user_info",
            return_value={"accounts": [{"account_id": "a1", "base_uri": "https://fetched"}]},
        )
        assert client.get_base_uri("tok", "a1") == "https://fetched"
        set_ctx.assert_called_once()

    def test_get_base_uri_account_not_found(self, mocker):
        client = self._make_client(mocker)
        mocker.patch("Docusign.get_integration_context", return_value={})
        mocker.patch.object(client, "get_user_info", return_value={"accounts": [{"account_id": "other"}]})
        with pytest.raises(DemistoException, match="missing configuration account id"):
            client.get_base_uri("tok", "a1")


class TestGenerateConsentUrl:
    def test_includes_impersonation_for_audit_users(self, mocker):
        """XSUP-70500: the consent URL for Audit Users must request the 'impersonation' scope."""
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "event_types": USER_DATA_TYPE,
                "url": "https://account-d.docusign.com",
                "integration_key": "key",
                "redirect_url": "https://localhost",
            },
        )
        mocker.patch.object(demisto, "debug")
        mocker.patch("Docusign.get_integration_context", return_value={})
        mocker.patch("Docusign.set_integration_context")

        result = generate_consent_url()
        assert "impersonation" in result.readable_output
        assert "signature" in result.readable_output

    def test_all_scopes_already_consented(self, mocker):
        mocker.patch.object(demisto, "params", return_value={"event_types": USER_DATA_TYPE})
        mocker.patch.object(demisto, "debug")
        mocker.patch("Docusign.get_integration_context", return_value={"consent_scopes": list(USER_DATA_SCOPE)})

        result = generate_consent_url()
        assert "already set" in result.readable_output

    def test_no_event_types_selected_raises(self, mocker):
        mocker.patch.object(demisto, "params", return_value={"event_types": ""})
        mocker.patch.object(demisto, "debug")
        with pytest.raises(DemistoException, match="select Event Types"):
            generate_consent_url()

    def test_missing_auth_params_raises(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={"event_types": USER_DATA_TYPE, "url": "", "integration_key": "", "redirect_url": ""},
        )
        mocker.patch.object(demisto, "debug")
        mocker.patch("Docusign.get_integration_context", return_value={})
        with pytest.raises(DemistoException, match="Server URL, Integration Key and Redirect URL"):
            generate_consent_url()


class TestValidateConfigurationParams:
    def test_ok(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "u",
                "redirect_url": "r",
                "integration_key": "k",
                "user_id": "uid",
                "credentials": {"password": "pem"},
                "event_types": CUSTOMER_EVENTS_TYPE,
            },
        )
        assert validate_configuration_params() == "ok"

    def test_missing_auth(self, mocker):
        mocker.patch.object(demisto, "params", return_value={"url": "", "event_types": ""})
        assert "authentication flow" in validate_configuration_params()

    def test_missing_audit_user_params(self, mocker):
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "u",
                "redirect_url": "r",
                "integration_key": "k",
                "user_id": "uid",
                "credentials": {"password": "pem"},
                "event_types": USER_DATA_TYPE,
            },
        )
        assert "Account ID and Organization ID" in validate_configuration_params()


class TestModuleAndReset:
    def test_test_module_validation_fails(self, mocker):
        mocker.patch("Docusign.validate_configuration_params", return_value="some error")
        assert test_module() == "some error"

    def test_test_module_success(self, mocker):
        mocker.patch("Docusign.validate_configuration_params", return_value="ok")
        mock_client = mocker.MagicMock()
        mock_client.access_token = "tok"
        mocker.patch("Docusign.initiate_auth_client", return_value=mock_client)
        mocker.patch.object(demisto, "debug")
        assert test_module() == "Test completed successfully."
        mock_client.get_user_info.assert_called_once_with("tok")

    def test_reset_access_token(self, mocker):
        mocker.patch(
            "Docusign.get_integration_context",
            return_value={"access_token": "x", "expired_at": "y", "access_token_scopes": ["s"], "base_uri": "keep"},
        )
        set_ctx = mocker.patch("Docusign.set_integration_context")
        result = reset_access_token()
        assert "deleted successfully" in result.readable_output
        saved = set_ctx.call_args[0][0]
        assert "access_token" not in saved
        assert saved.get("base_uri") == "keep"


class TestInitiateAuthClient:
    def test_missing_required_params_raises(self, mocker):
        mocker.patch.object(demisto, "params", return_value={"url": "u"})
        mocker.patch.object(demisto, "debug")
        with pytest.raises(DemistoException, match="Integration Key, User ID"):
            initiate_auth_client()


class TestFetchEvents:
    """Covers the fetch-events command entry point (fetch_events) across all branches."""

    def _auth_client(self, mocker):
        client = mocker.MagicMock()
        client.access_token = "tok"
        return client

    def test_only_customer_events(self, mocker):
        """
        Given:
            - event_types includes only Customer events.
        When:
            - fetch_events runs.
        Then:
            - Only fetch_customer_events is called; audit users is NOT called; events returned.
        """
        mocker.patch.object(demisto, "params", return_value={"event_types": CUSTOMER_EVENTS_TYPE})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")

        customer_events = [{"eventId": "c1"}]
        mock_customer = mocker.patch("Docusign.fetch_customer_events", return_value=({"cursor": "next"}, customer_events))
        mock_audit = mocker.patch("Docusign.fetch_audit_user_data")

        last_run, events = fetch_events(self._auth_client(mocker))

        assert events == customer_events
        mock_customer.assert_called_once()
        mock_audit.assert_not_called()
        assert last_run[CUSTOMER_EVENTS_TYPE] == {"cursor": "next"}

    def test_only_audit_users(self, mocker):
        """
        Given:
            - event_types includes only Audit Users.
        When:
            - fetch_events runs.
        Then:
            - Only fetch_audit_user_data is called; customer events is NOT called.
        """
        mocker.patch.object(demisto, "params", return_value={"event_types": USER_DATA_TYPE})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")

        user_events = [{"id": "u1"}]
        mock_customer = mocker.patch("Docusign.fetch_customer_events")
        mock_audit = mocker.patch("Docusign.fetch_audit_user_data", return_value=({"latest_modifiedDate": "t"}, user_events))

        last_run, events = fetch_events(self._auth_client(mocker))

        assert events == user_events
        mock_audit.assert_called_once()
        mock_customer.assert_not_called()
        assert last_run[USER_DATA_TYPE] == {"latest_modifiedDate": "t"}

    def test_both_event_types(self, mocker):
        """
        Given:
            - event_types includes both Customer events and Audit Users.
        When:
            - fetch_events runs.
        Then:
            - Both fetchers are called and their events are merged.
        """
        mocker.patch.object(demisto, "params", return_value={"event_types": f"{CUSTOMER_EVENTS_TYPE},{USER_DATA_TYPE}"})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")

        mock_customer = mocker.patch("Docusign.fetch_customer_events", return_value=({}, [{"eventId": "c1"}]))
        mock_audit = mocker.patch("Docusign.fetch_audit_user_data", return_value=({}, [{"id": "u1"}]))

        last_run, events = fetch_events(self._auth_client(mocker))

        assert {"eventId": "c1"} in events
        assert {"id": "u1"} in events
        assert len(events) == 2
        mock_customer.assert_called_once()
        mock_audit.assert_called_once()
        assert CUSTOMER_EVENTS_TYPE in last_run
        assert USER_DATA_TYPE in last_run

    def test_empty_last_run_initialization(self, mocker):
        """
        Given:
            - demisto.getLastRun returns an empty object and both event types are selected.
        When:
            - fetch_events runs.
        Then:
            - It initializes a fresh last_run with both type keys and passes empty per-type state.
        """
        mocker.patch.object(demisto, "params", return_value={"event_types": f"{CUSTOMER_EVENTS_TYPE},{USER_DATA_TYPE}"})
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "info")

        mock_customer = mocker.patch("Docusign.fetch_customer_events", return_value=({}, []))
        mock_audit = mocker.patch("Docusign.fetch_audit_user_data", return_value=({}, []))

        last_run, events = fetch_events(self._auth_client(mocker))

        # Per-type state passed to each fetcher should start empty.
        assert mock_customer.call_args[0][0] == {}
        assert mock_audit.call_args[0][0] == {}
        assert events == []
        assert set(last_run.keys()) == {CUSTOMER_EVENTS_TYPE, USER_DATA_TYPE}
