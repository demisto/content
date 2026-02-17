import pytest
from iManageThreatManager import (
    Client,
    get_events_command,
    fetch_events_command,
    validate_credentials_for_event_types,
    _add_fields_to_events,
    _deduplicate_events,
    _fetch_events_with_pagination,
    _update_next_run_state,
    BEHAVIOR_ANALYTICS,
    ADDRESSABLE_ALERTS,
    DETECT_AND_PROTECT_ALERTS,
    EVENT_TYPE_CONFIG,
)
from CommonServerPython import DemistoException


BASE_URL = "https://test-instance.tm-cloudimanage.com"


@pytest.fixture
def client():
    """
    Given:
        - Base URL and authentication credentials
    When:
        - Creating a Client instance
    Then:
        - Ensure the client is properly initialized
    """
    return Client(
        base_url=BASE_URL,
        verify=True,
        proxy=False,
        username="test_user",
        password="test_password",
        token="test_token",
        secret="test_secret",
    )


class TestValidateCredentialsForEventTypes:
    """Tests for validate_credentials_for_event_types function"""

    def test_validate_credentials_behavior_analytics_success(self, client):
        """
        Given:
            - Client with valid token and secret
            - Behavior Analytics event type
        When:
            - Calling validate_credentials_for_event_types
        Then:
            - Ensure no exception is raised
        """
        validate_credentials_for_event_types(client, [BEHAVIOR_ANALYTICS])

    def test_validate_credentials_addressable_alerts_success(self, client):
        """
        Given:
            - Client with valid username and password
            - Addressable Alerts event type
        When:
            - Calling validate_credentials_for_event_types
        Then:
            - Ensure no exception is raised
        """
        validate_credentials_for_event_types(client, [ADDRESSABLE_ALERTS])

    def test_validate_credentials_missing_token_secret(self):
        """
        Given:
            - Client without token and secret
            - Behavior Analytics event type
        When:
            - Calling validate_credentials_for_event_types
        Then:
            - Ensure DemistoException is raised
        """
        client_no_token = Client(base_url=BASE_URL, verify=True, proxy=False, username="user", password="pass")
        with pytest.raises(DemistoException, match="Token and Secret"):
            validate_credentials_for_event_types(client_no_token, [BEHAVIOR_ANALYTICS])

    def test_validate_credentials_missing_username_password(self):
        """
        Given:
            - Client without username and password
            - Addressable Alerts event type
        When:
            - Calling validate_credentials_for_event_types
        Then:
            - Ensure DemistoException is raised
        """
        client_no_creds = Client(base_url=BASE_URL, verify=True, proxy=False, token="token", secret="secret")
        with pytest.raises(DemistoException, match="Username and Password"):
            validate_credentials_for_event_types(client_no_creds, [ADDRESSABLE_ALERTS])

    def test_validate_credentials_multiple_event_types(self, client):
        """
        Given:
            - Client with all credentials
            - Multiple event types
        When:
            - Calling validate_credentials_for_event_types
        Then:
            - Ensure no exception is raised
        """
        validate_credentials_for_event_types(client, [BEHAVIOR_ANALYTICS, ADDRESSABLE_ALERTS, DETECT_AND_PROTECT_ALERTS])


class TestDeduplicateEvents:
    """Tests for _deduplicate_events function"""

    def test_deduplicate_events_no_duplicates(self):
        """
        Given:
            - Events with unique IDs
            - Empty last_run_ids
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure all events are returned
        """
        events = [
            {"id": "1", "alert_time": 1000},
            {"id": "2", "alert_time": 900},
            {"id": "3", "alert_time": 800},
        ]
        result = _deduplicate_events(events, [], 700)
        assert len(result) == 3

    def test_deduplicate_events_with_duplicates(self):
        """
        Given:
            - Events with some duplicate IDs from last run
            - All events are newer than last_fetch_time
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure all events are returned (newer events bypass ID check)
        """
        events = [
            {"id": "1", "alert_time": 1000},
            {"id": "2", "alert_time": 900},
            {"id": "3", "alert_time": 800},
        ]
        last_run_ids = ["2"]
        # All events are newer than 700, so ID check is bypassed
        result = _deduplicate_events(events, last_run_ids, 700)
        assert len(result) == 3

    def test_deduplicate_events_with_duplicates_same_time(self):
        """
        Given:
            - Events at or before last_fetch_time
            - Some IDs are duplicates from last run
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure duplicates are removed
        """
        events = [
            {"id": "1", "alert_time": 700},
            {"id": "2", "alert_time": 700},
            {"id": "3", "alert_time": 700},
        ]
        last_run_ids = ["2"]
        result = _deduplicate_events(events, last_run_ids, 700)
        assert len(result) == 2
        assert result[0]["id"] == "1"
        assert result[1]["id"] == "3"

    def test_deduplicate_events_newer_than_last_fetch(self):
        """
        Given:
            - Events newer than last_fetch_time
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure all newer events are returned without checking IDs
        """
        events = [
            {"id": "1", "alert_time": 1000},
            {"id": "2", "alert_time": 900},
        ]
        result = _deduplicate_events(events, ["1", "2"], 800)
        assert len(result) == 2

    def test_deduplicate_events_without_ids(self):
        """
        Given:
            - Events without ID field
        When:
            - Calling _deduplicate_events
        Then:
            - Ensure events are kept (cannot deduplicate)
        """
        events = [
            {"alert_time": 1000},
            {"alert_time": 900},
        ]
        result = _deduplicate_events(events, [], 700)
        assert len(result) == 2


class TestUpdateNextRunState:
    """Tests for _update_next_run_state function"""

    def test_no_new_events_keeps_old_state(self):
        """
        Given:
            - Empty events list
            - Previous fetch time and IDs
        When:
            - Calling _update_next_run_state
        Then:
            - Ensure old timestamp and IDs are preserved
        """
        events = []
        last_fetch_time = 1000
        last_run_ids = ["id1", "id2"]

        new_time, new_ids = _update_next_run_state(events, last_fetch_time, last_run_ids)

        assert new_time == 1000
        assert new_ids == ["id1", "id2"]

    def test_new_events_with_newer_timestamp_replaces_ids(self):
        """
        Given:
            - Events with timestamp newer than last_fetch_time
            - Previous fetch time and IDs
        When:
            - Calling _update_next_run_state
        Then:
            - Ensure timestamp is updated and old IDs are replaced with new ones
        """
        events = [
            {"id": "new1", "alert_time": 2000},
            {"id": "new2", "alert_time": 2000},
            {"id": "old1", "alert_time": 1500},
        ]
        last_fetch_time = 1000
        last_run_ids = ["id1", "id2"]

        new_time, new_ids = _update_next_run_state(events, last_fetch_time, last_run_ids)

        assert new_time == 2000
        assert set(new_ids) == {"new1", "new2"}
        assert "id1" not in new_ids
        assert "id2" not in new_ids

    def test_new_events_with_same_timestamp_combines_ids(self):
        """
        Given:
            - Events with same timestamp as last_fetch_time
            - Previous fetch time and IDs
        When:
            - Calling _update_next_run_state
        Then:
            - Ensure timestamp stays same and old and new IDs are combined
        """
        events = [
            {"id": "new1", "alert_time": 1000},
            {"id": "new2", "alert_time": 1000},
        ]
        last_fetch_time = 1000
        last_run_ids = ["id1", "id2"]

        new_time, new_ids = _update_next_run_state(events, last_fetch_time, last_run_ids)

        assert new_time == 1000
        assert set(new_ids) == {"id1", "id2", "new1", "new2"}

    def test_new_events_with_same_timestamp_avoids_duplicate_ids(self):
        """
        Given:
            - Events with same timestamp as last_fetch_time
            - Some IDs overlap with previous run
        When:
            - Calling _update_next_run_state
        Then:
            - Ensure IDs are combined without duplicates
        """
        events = [
            {"id": "id1", "alert_time": 1000},  # Duplicate
            {"id": "new1", "alert_time": 1000},
        ]
        last_fetch_time = 1000
        last_run_ids = ["id1", "id2"]

        new_time, new_ids = _update_next_run_state(events, last_fetch_time, last_run_ids)

        assert new_time == 1000
        assert set(new_ids) == {"id1", "id2", "new1"}
        assert len(new_ids) == 3  # No duplicates

    def test_unexpected_older_timestamp_keeps_old_state(self):
        """
        Given:
            - Events with timestamp older than last_fetch_time (unexpected scenario)
            - Previous fetch time and IDs
        When:
            - Calling _update_next_run_state
        Then:
            - Ensure old state is preserved
        """
        events = [
            {"id": "old1", "alert_time": 500},
        ]
        last_fetch_time = 1000
        last_run_ids = ["id1", "id2"]

        new_time, new_ids = _update_next_run_state(events, last_fetch_time, last_run_ids)

        assert new_time == 1000
        assert new_ids == ["id1", "id2"]


class TestAddFieldsToEvents:
    """Tests for _add_fields_to_events function"""

    def test_add_fields_to_events_with_update_time(self):
        """
        Given:
            - Events with update_time
            - Source log type parameter
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure _time and _source_log_type fields are added with correct format
        """
        events = [
            {"update_time": 1609459200000, "id": "1"},  # 2021-01-01 00:00:00 UTC
            {"update_time": 1609545600000, "id": "2"},  # 2021-01-02 00:00:00 UTC
        ]
        _add_fields_to_events(events, "BehaviorAnalytics")
        assert "_time" in events[0]
        assert "_time" in events[1]
        assert events[0]["_time"] == "2021-01-01T00:00:00Z"
        assert events[1]["_time"] == "2021-01-02T00:00:00Z"
        assert events[0]["_source_log_type"] == "BehaviorAnalytics"
        assert events[1]["_source_log_type"] == "BehaviorAnalytics"

    def test_add_fields_to_events_entry_status_new(self):
        """
        Given:
            - Events where update_time equals alert_time
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure _ENTRY_STATUS is set to 'new'
        """
        events = [
            {"update_time": 1609459200000, "alert_time": 1609459200000, "id": "1"},
        ]
        _add_fields_to_events(events, "BehaviorAnalytics")
        assert events[0]["_ENTRY_STATUS"] == "new"

    def test_add_fields_to_events_entry_status_modified(self):
        """
        Given:
            - Events where update_time is greater than alert_time
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure _ENTRY_STATUS is set to 'modified'
        """
        events = [
            {"update_time": 1609545600000, "alert_time": 1609459200000, "id": "1"},
        ]
        _add_fields_to_events(events, "BehaviorAnalytics")
        assert events[0]["_ENTRY_STATUS"] == "modified"

    def test_add_fields_to_events_without_update_time(self):
        """
        Given:
            - Events without update_time field
            - Source log type parameter
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure _time field is not added but _source_log_type is added
        """
        events = [{"id": "1"}]
        _add_fields_to_events(events, "AddressableAlerts")
        assert events[0].get("_time") is None
        assert events[0]["_source_log_type"] == "AddressableAlerts"

    def test_add_fields_to_events_empty_list(self):
        """
        Given:
            - Empty events list
            - Source log type parameter
        When:
            - Calling _add_fields_to_events
        Then:
            - Ensure no error is raised
        """
        events = []
        _add_fields_to_events(events, "BehaviorAnalytics")
        assert events == []


class TestFetchEventsWithPagination:
    """Tests for _fetch_events_with_pagination function"""

    def test_pagination_single_page(self, client, requests_mock):
        """
        Given:
            - Limit of 50 events
            - API returns 30 events (less than page size)
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure pagination stops after first page
        """
        mock_response = {"results": [{"id": str(i), "alert_time": 1000 - i} for i in range(30)]}
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_response)

        events = _fetch_events_with_pagination(client, BEHAVIOR_ANALYTICS, 500, 1000, 50)
        assert len(events) == 30

    def test_pagination_multiple_pages(self, client, mocker):
        """
        Given:
            - Limit of 200 events
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure _fetch_alerts is called 3 times with page_size: 90, 90, 20
        """
        # Mock _fetch_alerts to return dummy data
        mock_fetch = mocker.patch.object(
            client,
            "_fetch_alerts",
            side_effect=[
                [{"id": f"1-{i}", "alert_time": 1000 - i} for i in range(90)],
                [{"id": f"2-{i}", "alert_time": 910 - i} for i in range(90)],
                [{"id": f"3-{i}", "alert_time": 820 - i} for i in range(90)],
            ],
        )

        _fetch_events_with_pagination(client, BEHAVIOR_ANALYTICS, 500, 1000, 200)

        assert mock_fetch.call_count == 3
        # Verify page_size parameter in each call
        assert mock_fetch.call_args_list[0][0][3] == 90  # First call
        assert mock_fetch.call_args_list[1][0][3] == 90  # Second call
        assert mock_fetch.call_args_list[2][0][3] == 20  # Third call

    def test_pagination_with_deduplication_at_boundary(self, client, mocker):
        """
        Given:
            - Events with same alert_time at page boundary
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure duplicates at boundary are removed
        """
        # First page: last 3 events have alert_time=910
        page1 = [{"id": f"1-{i}", "alert_time": 1000 - i} for i in range(87)]
        page1.extend(
            [
                {"id": "dup-1", "alert_time": 910},
                {"id": "dup-2", "alert_time": 910},
                {"id": "dup-3", "alert_time": 910},
            ]
        )

        # Second page: includes the same 3 duplicate events plus new ones
        page2 = [
            {"id": "dup-1", "alert_time": 910},
            {"id": "dup-2", "alert_time": 910},
            {"id": "dup-3", "alert_time": 910},
        ]
        page2.extend([{"id": f"2-{i}", "alert_time": 909 - i} for i in range(50)])

        mocker.patch.object(client, "_fetch_alerts", side_effect=[page1, page2])

        events = _fetch_events_with_pagination(client, BEHAVIOR_ANALYTICS, 500, 1000, 200)

        # Should have 90 from page1 + 50 new from page2 = 140 (3 duplicates removed)
        assert len(events) == 140
        # Verify no duplicate IDs
        event_ids = [e["id"] for e in events]
        assert len(event_ids) == len(set(event_ids))

    def test_pagination_stops_when_limit_reached(self, client, mocker):
        """
        Given:
            - Limit of 100 events
        When:
            - Calling _fetch_events_with_pagination
        Then:
            - Ensure pagination stops at limit with page_size: 90, 10
        """
        mock_fetch = mocker.patch.object(
            client,
            "_fetch_alerts",
            side_effect=[
                [{"id": f"1-{i}", "alert_time": 1000 - i} for i in range(90)],  # Page 1: 90 events
                [{"id": f"2-{i}", "alert_time": 910 - i} for i in range(10)],  # Page 2: 10 events
            ],
        )

        events = _fetch_events_with_pagination(client, BEHAVIOR_ANALYTICS, 500, 1000, 100)

        assert mock_fetch.call_count == 2
        assert mock_fetch.call_args_list[0][0][3] == 90  # First call: page_size=90
        assert mock_fetch.call_args_list[1][0][3] == 10  # Second call: page_size=10 (remaining)
        assert len(events) == 100


class TestClient:
    """Tests for Client class methods"""

    def test_get_access_token_from_token_secret(self, client, requests_mock, mocker):
        """
        Given:
            - Valid token and secret
        When:
            - Calling get_access_token_from_token_secret
        Then:
            - Ensure access token is returned
        """
        # Mock to bypass caching
        mocker.patch.object(client, "_get_cached_token", return_value=None)
        mocker.patch.object(client, "_cache_token")

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "test_access_token"})
        token = client.get_access_token_from_token_secret()
        assert token == "test_access_token"
        assert client._access_token == "test_access_token"

    def test_get_access_token_force_new(self, client, requests_mock, mocker):
        """
        Given:
            - Client with existing cached token
            - force_new=True parameter
        When:
            - Calling get_access_token_from_token_secret with force_new=True
        Then:
            - Ensure new token is generated bypassing cache
        """
        # Set existing token
        client._access_token = "old_token"
        mocker.patch.object(client, "_cache_token")

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "new_token"})
        token = client.get_access_token_from_token_secret(force_new=True)
        assert token == "new_token"
        assert client._access_token == "new_token"

    def test_get_access_token_from_username_password(self, client, requests_mock):
        """
        Given:
            - Valid username and password
        When:
            - Calling get_access_token_from_username_password
        Then:
            - Ensure access token is returned
        """
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "test_user_access_token"})
        token = client.get_access_token_from_username_password()
        assert token == "test_user_access_token"
        assert client._user_access_token == "test_user_access_token"

    def test_fetch_alerts_with_retry_on_429(self, client, requests_mock, mocker):
        """
        Given:
            - API returns HTTP 429 (Too Many Requests) on first attempt
            - API succeeds on second attempt
        When:
            - Calling _fetch_alerts
        Then:
            - Ensure retry mechanism works and events are returned
        """
        mocker.patch("time.sleep")  # Mock sleep to speed up test
        mocker.patch.object(client, "_get_cached_token", return_value=None)
        mocker.patch.object(client, "_cache_token")

        call_count = [0]

        def login_matcher(request, context):
            return {"access_token": f"token_{call_count[0]}"}

        def alerts_matcher(request, context):
            call_count[0] += 1
            if call_count[0] == 1:
                # First attempt: return 429
                context.status_code = 429
                return {"error": "Too Many Requests"}
            # Second attempt: success
            return {"results": [{"id": "1", "alert_time": 1000}]}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json=login_matcher)
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=alerts_matcher)

        alerts = client._fetch_alerts(BEHAVIOR_ANALYTICS, 500, 1000, 10)
        assert len(alerts) == 1
        assert call_count[0] == 2  # Should have made 2 attempts

    def test_fetch_alerts_with_retry_on_401(self, client, requests_mock, mocker):
        """
        Given:
            - API returns HTTP 401 (Unauthorized - token expired) on first attempt
            - API succeeds on second attempt with new token
        When:
            - Calling _fetch_alerts
        Then:
            - Ensure token is regenerated and request succeeds
        """
        mocker.patch("time.sleep")
        mocker.patch.object(client, "_get_cached_token", return_value=None)
        mocker.patch.object(client, "_cache_token")

        call_count = [0]

        def login_matcher(request, context):
            return {"access_token": f"token_{call_count[0]}"}

        def alerts_matcher(request, context):
            call_count[0] += 1
            if call_count[0] == 1:
                # First attempt: token expired
                context.status_code = 401
                return {"error": "Unauthorized"}
            # Second attempt: success with new token
            return {"results": [{"id": "1", "alert_time": 1000}]}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json=login_matcher)
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=alerts_matcher)

        alerts = client._fetch_alerts(BEHAVIOR_ANALYTICS, 500, 1000, 10)
        assert len(alerts) == 1
        assert call_count[0] == 2

    def test_fetch_alerts_retry_exhausted(self, client, requests_mock, mocker, capfd):
        """
        Given:
            - API returns HTTP 429 on all attempts
        When:
            - Calling _fetch_alerts
        Then:
            - Ensure exception is raised after max retries
        """
        mocker.patch("time.sleep")
        mocker.patch.object(client, "_get_cached_token", return_value=None)
        mocker.patch.object(client, "_cache_token")

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", status_code=429, json={"error": "Too Many Requests"})

        with capfd.disabled(), pytest.raises(DemistoException):
            client._fetch_alerts(BEHAVIOR_ANALYTICS, 500, 1000, 10)

    def test_fetch_alerts_no_retry_on_other_errors(self, client, requests_mock, mocker):
        """
        Given:
            - API returns HTTP 500 (Server Error)
        When:
            - Calling _fetch_alerts
        Then:
            - Ensure no retry is attempted and exception is raised immediately
        """
        mocker.patch.object(client, "_get_cached_token", return_value=None)

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", status_code=500, text="Server Error")

        with pytest.raises(DemistoException):
            client._fetch_alerts(BEHAVIOR_ANALYTICS, 500, 1000, 10)


class TestTestModuleCommand:
    """Tests for test_module_command function"""

    def test_test_module_success_behavior_analytics(self, client, requests_mock, freezer):
        """
        Given:
            - Valid client with token and secret
            - Behavior Analytics event type
        When:
            - Calling test_module_command
        Then:
            - Ensure 'ok' is returned
        """
        from iManageThreatManager import test_module_command

        freezer.move_to("2021-01-10T00:00:00Z")
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json={"results": []})

        result = test_module_command(client, {}, [BEHAVIOR_ANALYTICS])
        assert result == "ok"

    def test_test_module_success_addressable_alerts(self, client, requests_mock, freezer):
        """
        Given:
            - Valid client with username and password
            - Addressable Alerts event type
        When:
            - Calling test_module_command
        Then:
            - Ensure 'ok' is returned
        """
        from iManageThreatManager import test_module_command

        freezer.move_to("2021-01-10T00:00:00Z")
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "user_token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAddressableAlerts", json={"results": []})

        result = test_module_command(client, {}, [ADDRESSABLE_ALERTS])
        assert result == "ok"

    def test_test_module_auth_error(self, client, requests_mock, mocker, capfd):
        """
        Given:
            - Invalid credentials
        When:
            - Calling test_module_command
        Then:
            - Ensure authorization error message is returned
        """
        from iManageThreatManager import test_module_command

        mocker.patch("time.sleep")
        mocker.patch.object(client, "_get_cached_token", return_value=None)
        mocker.patch.object(client, "_cache_token")

        def login_matcher(request, context):
            return {"access_token": "token"}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json=login_matcher)
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", status_code=401, text="Unauthorized")

        with capfd.disabled():
            result = test_module_command(client, {}, [BEHAVIOR_ANALYTICS])
            assert "Authorization Error" in result


class TestGetEventsCommand:
    """Tests for get_events_command function"""

    def test_get_events_command_behavior_analytics(self, client, requests_mock, freezer):
        """
        Given:
            - Valid client and Behavior Analytics event type
        When:
            - Calling get_events_command
        Then:
            - Ensure events are returned
        """
        freezer.move_to("2021-01-10T00:00:00Z")
        mock_response = {"results": [{"id": "1", "alert_time": 1609459200000, "update_time": 1609459200000}]}
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_response)

        events, results = get_events_command(client, {"event_type": BEHAVIOR_ANALYTICS, "limit": "10"})
        assert len(events) == 1
        assert events[0]["id"] == "1"

    def test_get_events_command_with_pagination(self, client, requests_mock, freezer):
        """
        Given:
            - Limit of 150 events
            - API returns events in multiple pages
        When:
            - Calling get_events_command
        Then:
            - Ensure all events are fetched via pagination
        """
        freezer.move_to("2021-01-10T00:00:00Z")
        page1 = {"results": [{"id": f"1-{i}", "alert_time": 1000 - i} for i in range(90)]}
        page2 = {"results": [{"id": f"2-{i}", "alert_time": 910 - i} for i in range(60)]}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})

        call_count = [0]

        def custom_matcher(request, context):
            call_count[0] += 1
            return page1 if call_count[0] == 1 else page2

        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=custom_matcher)

        events, results = get_events_command(client, {"event_type": BEHAVIOR_ANALYTICS, "limit": "150"})
        assert len(events) == 150


class TestFetchEventsCommand:
    """Tests for fetch_events_command function"""

    def test_fetch_events_first_run(self, client, requests_mock, freezer):
        """
        Given:
            - Empty last_run (first fetch)
            - Behavior Analytics event type
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events are fetched and next_run is set correctly
        """
        # Freeze time to a known value (2021-01-10 00:00:00 UTC = 1610236800000 ms)
        freezer.move_to("2021-01-10T00:00:00Z")

        mock_response = {"results": [{"id": "1", "alert_time": 1609459200000, "update_time": 1609459200000}]}
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_response)

        next_run, events = fetch_events_command(
            client=client, last_run={}, event_types=[BEHAVIOR_ANALYTICS], max_events_per_type=10
        )

        assert len(events) == 1
        assert events[0]["_source_log_type"] == EVENT_TYPE_CONFIG[BEHAVIOR_ANALYTICS]["source_log_type"]
        assert "last_fetch_BehaviorAnalytics" in next_run
        assert next_run["last_fetch_BehaviorAnalytics"] == 1609459200000

    def test_fetch_events_with_pagination(self, client, requests_mock, freezer):
        """
        Given:
            - max_events_per_type of 200
            - API returns events in multiple pages
        When:
            - Calling fetch_events_command
        Then:
            - Ensure pagination is used to fetch all events
        """
        freezer.move_to("2021-01-10T00:00:00Z")
        page1 = {"results": [{"id": f"1-{i}", "alert_time": 1000 - i, "update_time": 1000 - i} for i in range(90)]}
        page2 = {"results": [{"id": f"2-{i}", "alert_time": 910 - i, "update_time": 910 - i} for i in range(90)]}
        page3 = {"results": [{"id": f"3-{i}", "alert_time": 820 - i, "update_time": 820 - i} for i in range(20)]}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})

        call_count = [0]

        def custom_matcher(request, context):
            call_count[0] += 1
            if call_count[0] == 1:
                return page1
            elif call_count[0] == 2:
                return page2
            else:
                return page3

        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=custom_matcher)

        next_run, events = fetch_events_command(
            client=client, last_run={}, event_types=[BEHAVIOR_ANALYTICS], max_events_per_type=200
        )

        assert len(events) == 200

    def test_fetch_events_multiple_types(self, client, requests_mock, freezer):
        """
        Given:
            - Multiple event types configured
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events from all types are fetched
        """
        freezer.move_to("2021-01-10T00:00:00Z")
        mock_behavior = {"results": [{"id": "1", "alert_time": 1609459200000, "update_time": 1609459200000}]}
        mock_addressable = {"results": [{"id": "2", "alert_time": 1609545600000, "update_time": 1609545600000}]}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "user_token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_behavior)
        requests_mock.post(f"{BASE_URL}/tm-api/getAddressableAlerts", json=mock_addressable)

        next_run, events = fetch_events_command(
            client=client, last_run={}, event_types=[BEHAVIOR_ANALYTICS, ADDRESSABLE_ALERTS], max_events_per_type=10
        )

        assert len(events) == 2
        assert events[0]["_source_log_type"] == EVENT_TYPE_CONFIG[BEHAVIOR_ANALYTICS]["source_log_type"]
        assert events[1]["_source_log_type"] == EVENT_TYPE_CONFIG[ADDRESSABLE_ALERTS]["source_log_type"]

    def test_fetch_events_no_new_events(self, client, requests_mock, freezer):
        """
        Given:
            - Last run with previous fetch time
            - No new events available
        When:
            - Calling fetch_events_command
        Then:
            - Ensure empty events list and updated next_run
        """
        freezer.move_to("2021-01-10T00:00:00Z")
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json={"results": []})

        last_run = {"last_fetch_BehaviorAnalytics": 1609459200000}
        next_run, events = fetch_events_command(
            client=client, last_run=last_run, event_types=[BEHAVIOR_ANALYTICS], max_events_per_type=10
        )

        assert len(events) == 0
        assert "last_fetch_BehaviorAnalytics" in next_run

    def test_fetch_events_with_error(self, client, requests_mock, mocker, capfd, freezer):
        """
        Given:
            - API error during fetch
        When:
            - Calling fetch_events_command
        Then:
            - Ensure error is handled and last_run is preserved
        """
        freezer.move_to("2021-01-10T00:00:00Z")
        mocker.patch.object(client, "_get_cached_token", return_value=None)

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", status_code=500, text="Server Error")

        last_run = {"last_fetch_BehaviorAnalytics": 1609459200000}

        with capfd.disabled():
            next_run, events = fetch_events_command(
                client=client, last_run=last_run, event_types=[BEHAVIOR_ANALYTICS], max_events_per_type=10
            )

        # Should preserve last_run on error
        assert next_run["last_fetch_BehaviorAnalytics"] == 1609459200000
        assert len(events) == 0
