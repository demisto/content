import pytest
from iManageThreatManager import (
    Client,
    test_module_command,
    get_events_command,
    fetch_events_command,
    validate_credentials_for_event_types,
    add_fields_to_events,
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
        secret="test_secret"
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
        # Should not raise any exception
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
        # Should not raise any exception
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
        client_no_token = Client(
            base_url=BASE_URL,
            verify=True,
            proxy=False,
            username="user",
            password="pass"
        )
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
        client_no_creds = Client(
            base_url=BASE_URL,
            verify=True,
            proxy=False,
            token="token",
            secret="secret"
        )
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
        # Should not raise any exception
        validate_credentials_for_event_types(
            client,
            [BEHAVIOR_ANALYTICS, ADDRESSABLE_ALERTS, DETECT_AND_PROTECT_ALERTS]
        )




class TestAddFieldsToEvents:
    """Tests for add_fields_to_events function"""

    def test_add_fields_to_events_with_update_time(self):
        """
        Given:
            - Events with update_time
            - Source log type parameter
        When:
            - Calling add_fields_to_events
        Then:
            - Ensure _time and _source_log_type fields are added with correct format
        """
        events = [
            {"update_time": 1609459200000, "id": "1"},  # 2021-01-01 00:00:00 UTC
            {"update_time": 1609545600000, "id": "2"},  # 2021-01-02 00:00:00 UTC
        ]
        add_fields_to_events(events, "BehaviorAnalytics")
        assert "_time" in events[0]
        assert "_time" in events[1]
        assert events[0]["_time"] == "2021-01-01T00:00:00Z"
        assert events[1]["_time"] == "2021-01-02T00:00:00Z"
        assert events[0]["_source_log_type"] == "BehaviorAnalytics"
        assert events[1]["_source_log_type"] == "BehaviorAnalytics"

    def test_add_fields_to_events_without_update_time(self):
        """
        Given:
            - Events without update_time field
            - Source log type parameter
        When:
            - Calling add_fields_to_events
        Then:
            - Ensure _time field is not added but _source_log_type is added
        """
        events = [{"id": "1"}]
        add_fields_to_events(events, "AddressableAlerts")
        # Event should not have _time or it should be None
        assert events[0].get("_time") is None
        assert events[0]["_source_log_type"] == "AddressableAlerts"

    def test_add_fields_to_events_empty_list(self):
        """
        Given:
            - Empty events list
            - Source log type parameter
        When:
            - Calling add_fields_to_events
        Then:
            - Ensure no error is raised
        """
        events = []
        add_fields_to_events(events, "BehaviorAnalytics")
        assert events == []

    def test_add_fields_to_events_none(self):
        """
        Given:
            - None as events
            - Source log type parameter
        When:
            - Calling add_fields_to_events
        Then:
            - Ensure no error is raised
        """
        add_fields_to_events(None, "BehaviorAnalytics")


class TestClient:
    """Tests for Client class methods"""

    def test_get_access_token_from_token_secret(self, client, requests_mock):
        """
        Given:
            - Valid token and secret
        When:
            - Calling get_access_token_from_token_secret
        Then:
            - Ensure access token is returned
        """
        requests_mock.post(
            f"{BASE_URL}/tm-api/v2/login/api_token",
            json={"access_token": "test_access_token"}
        )
        token = client.get_access_token_from_token_secret()
        assert token == "test_access_token"
        assert client._access_token == "test_access_token"

    def test_get_access_token_from_username_password(self, client, requests_mock):
        """
        Given:
            - Valid username and password
        When:
            - Calling get_access_token_from_username_password
        Then:
            - Ensure access token is returned
        """
        requests_mock.post(
            f"{BASE_URL}/tm-api/v2/login",
            json={"access_token": "test_user_access_token"}
        )
        token = client.get_access_token_from_username_password()
        assert token == "test_user_access_token"
        assert client._user_access_token == "test_user_access_token"



class TestTestModuleCommand:
    """Tests for test_module_command function"""

    def test_test_module_success_behavior_analytics(self, client, requests_mock):
        """
        Given:
            - Valid client with token and secret
            - Behavior Analytics event type
        When:
            - Calling test_module_command
        Then:
            - Ensure 'ok' is returned
        """
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json={"results": []})

        result = test_module_command(client, {}, [BEHAVIOR_ANALYTICS])
        assert result == "ok"

    def test_test_module_success_addressable_alerts(self, client, requests_mock):
        """
        Given:
            - Valid client with username and password
            - Addressable Alerts event type
        When:
            - Calling test_module_command
        Then:
            - Ensure 'ok' is returned
        """
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "user_token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAddressableAlerts", json={"results": []})

        result = test_module_command(client, {}, [ADDRESSABLE_ALERTS])
        assert result == "ok"


    def test_test_module_auth_error(self, client, requests_mock):
        """
        Given:
            - Invalid credentials
        When:
            - Calling test_module_command
        Then:
            - Ensure authorization error message is returned
        """
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", status_code=401, text="Unauthorized")

        result = test_module_command(client, {}, [BEHAVIOR_ANALYTICS])
        assert "Authorization Error" in result


class TestGetEventsCommand:
    """Tests for get_events_command function"""

    def test_get_events_command_behavior_analytics(self, client, requests_mock):
        """
        Given:
            - Valid client and Behavior Analytics event type
        When:
            - Calling get_events_command
        Then:
            - Ensure events are returned
        """
        mock_response = {
            "results": [
                {"id": "1", "update_time": 1609459200000}
            ]
        }
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_response)

        events, results = get_events_command(
            client,
            {"event_type": BEHAVIOR_ANALYTICS, "limit": "10"}
        )
        assert len(events) == 1
        assert events[0]["id"] == "1"

    def test_get_events_command_addressable_alerts(self, client, requests_mock):
        """
        Given:
            - Valid client and Addressable Alerts event type
        When:
            - Calling get_events_command
        Then:
            - Ensure events are returned
        """
        mock_response = {
            "results": [
                {"id": "2", "update_time": 1609459200000}
            ]
        }
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "user_token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAddressableAlerts", json=mock_response)

        events, results = get_events_command(
            client,
            {"event_type": ADDRESSABLE_ALERTS, "limit": "10"}
        )
        assert len(events) == 1
        assert events[0]["id"] == "2"

    def test_get_events_command_detect_and_protect(self, client, requests_mock):
        """
        Given:
            - Valid client and Detect and Protect event type
        When:
            - Calling get_events_command
        Then:
            - Ensure events are returned
        """
        mock_response = {
            "results": [
                {"id": "3", "update_time": 1609459200000}
            ]
        }
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "user_token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getDetectAndProtectAlerts", json=mock_response)

        events, results = get_events_command(
            client,
            {"event_type": DETECT_AND_PROTECT_ALERTS, "limit": "10"}
        )
        assert len(events) == 1
        assert events[0]["id"] == "3"


class TestFetchEventsCommand:
    """Tests for fetch_events_command function"""

    def test_fetch_events_first_run(self, client, requests_mock):
        """
        Given:
            - Empty last_run (first fetch)
            - Behavior Analytics event type
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events are fetched and next_run is set correctly
        """
        mock_response = {
            "results": [
                {"id": "1", "update_time": 1609459200000}
            ]
        }
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_response)

        next_run, events = fetch_events_command(
            client=client,
            last_run={},
            event_types=[BEHAVIOR_ANALYTICS],
            max_events_per_type=10
        )

        assert len(events) == 1
        assert events[0]["_source_log_type"] == EVENT_TYPE_CONFIG[BEHAVIOR_ANALYTICS]["source_log_type"]
        assert "last_fetch_BehaviorAnalytics" in next_run
        assert next_run["last_fetch_BehaviorAnalytics"] == 1609459200000

    def test_fetch_events_multiple_types(self, client, requests_mock):
        """
        Given:
            - Multiple event types configured
        When:
            - Calling fetch_events_command
        Then:
            - Ensure events from all types are fetched
        """
        mock_behavior = {"results": [{"id": "1", "update_time": 1609459200000}]}
        mock_addressable = {"results": [{"id": "2", "update_time": 1609545600000}]}

        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login", json={"access_token": "user_token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json=mock_behavior)
        requests_mock.post(f"{BASE_URL}/tm-api/getAddressableAlerts", json=mock_addressable)

        next_run, events = fetch_events_command(
            client=client,
            last_run={},
            event_types=[BEHAVIOR_ANALYTICS, ADDRESSABLE_ALERTS],
            max_events_per_type=10
        )

        assert len(events) == 2
        assert events[0]["_source_log_type"] == EVENT_TYPE_CONFIG[BEHAVIOR_ANALYTICS]["source_log_type"]
        assert events[1]["_source_log_type"] == EVENT_TYPE_CONFIG[ADDRESSABLE_ALERTS]["source_log_type"]

    def test_fetch_events_no_new_events(self, client, requests_mock):
        """
        Given:
            - Last run with previous fetch time
            - No new events available
        When:
            - Calling fetch_events_command
        Then:
            - Ensure empty events list and updated next_run
        """
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", json={"results": []})

        last_run = {"last_fetch_BehaviorAnalytics": 1609459200000}
        next_run, events = fetch_events_command(
            client=client,
            last_run=last_run,
            event_types=[BEHAVIOR_ANALYTICS],
            max_events_per_type=10
        )

        assert len(events) == 0
        assert "last_fetch_BehaviorAnalytics" in next_run

    def test_fetch_events_with_error(self, client, requests_mock):
        """
        Given:
            - API error during fetch
        When:
            - Calling fetch_events_command
        Then:
            - Ensure error is handled and last_run is preserved
        """
        requests_mock.post(f"{BASE_URL}/tm-api/v2/login/api_token", json={"access_token": "token"})
        requests_mock.post(f"{BASE_URL}/tm-api/getAlertList", status_code=500, text="Server Error")

        last_run = {"last_fetch_BehaviorAnalytics": 1609459200000}
        next_run, events = fetch_events_command(
            client=client,
            last_run=last_run,
            event_types=[BEHAVIOR_ANALYTICS],
            max_events_per_type=10
        )

        # Should preserve last_run on error
        assert next_run["last_fetch_BehaviorAnalytics"] == 1609459200000
        assert len(events) == 0
