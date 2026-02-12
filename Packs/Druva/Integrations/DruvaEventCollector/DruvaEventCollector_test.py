from datetime import datetime

import demistomock as demisto
import pytest
import requests
from CommonServerPython import DemistoException
from DruvaEventCollector import (
    DATE_FORMAT_FOR_TOKEN,
    MAX_FETCH,
    Client,
    fetch_events,
    get_events,
)
from DruvaEventCollector import (
    test_module as run_test_module,
)
from freezegun import freeze_time

RESPONSE_WITH_EVENTS_1 = {
    "events": [
        {
            "eventID": 0,
            "eventType": "Backup",
            "profileName": "Default",
            "inSyncUserName": "user name",
            "clientVersion": "7.5.0r(23c42be5)",
            "clientOS": "Office 365 Exchange Online",
            "ip": "",
            "inSyncUserEmail": "test@test.com",
            "eventDetails": "",
            "timestamp": "2024-05-25T18:52:48Z",
            "inSyncUserID": 0,
            "profileID": 0,
            "initiator": None,
            "inSyncDataSourceID": 0,
            "eventState": "Backed up with Errors",
            "inSyncDataSourceName": "Exchange Online",
            "severity": 4,
            "facility": 23,
        }
    ],
    "nextPageExists": False,
    "tracker": "xxxx",
}

RESPONSE_CYBERSECURITY_EVENTS = {
    "events": [
        {
            "id": 1178203423,
            "productID": 8193,
            "globalID": "e65b5695-4ef4-453b-90c6-3a31b0e6b159",
            "category": "EVENT",
            "feature": "Alerts And Notifications",
            "type": "Alert",
            "timeStamp": "2024-05-25T18:52:48Z",
            "details": {"eventID": 36832945, "ip": None, "clientOS": None},
        }
    ],
    "nextPageToken": "cybertoken123",
}
RESPONSE_WITH_EVENTS_2 = {
    "events": [
        {
            "eventID": 1,
            "eventType": "Backup",
            "profileName": "Default",
            "inSyncUserName": "user name",
            "clientVersion": "7.5.0r(23c42be5)",
            "clientOS": "Office 365 Exchange Online",
            "ip": "",
            "inSyncUserEmail": "test@test.com",
            "eventDetails": "",
            "timestamp": "2024-05-25T18:52:48Z",
            "inSyncUserID": 1,
            "profileID": 1,
            "initiator": None,
            "inSyncDataSourceID": 1,
            "eventState": "Backed up with Errors",
            "inSyncDataSourceName": "Exchange Online",
            "severity": 4,
            "facility": 23,
        }
    ],
    "nextPageExists": False,
    "tracker": "yyyy",
}
RESPONSE_WITHOUT_EVENTS = {"events": [], "nextPageExists": False, "tracker": "xxxx"}
INVALID_RESPONSE = {
    "events": [
        {
            "eventID": 0,
            "eventType": "Backup",
            "profileName": "Default",
            "inSyncUserName": "user name",
            "clientVersion": "7.5.0r(23c42be5)",
            "clientOS": "Office 365 Exchange Online",
            "ip": "",
            "inSyncUserEmail": "test@test.com",
            "eventDetails": "",
            "timestamp": "2024-05-25T18:52:48Z",
            "inSyncUserID": 0,
            "profileID": 0,
            "initiator": None,
            "inSyncDataSourceID": 0,
            "eventState": "Backed up with Errors",
            "inSyncDataSourceName": "Exchange Online",
            "severity": 4,
            "facility": 23,
        }
    ],
    "nextPageExists": False,
}


@pytest.fixture()
def mock_client(mocker) -> Client:
    mocker.patch.object(Client, "login", return_value="DUMMY_TOKEN")
    client = Client(
        base_url="test",
        client_id="client_id",
        secret_key="secret_key",
        max_fetch=MAX_FETCH,
        verify=False,
        proxy=False,
    )
    client._set_headers("DUMMY_TOKEN")
    return client


def test_test_module_command(mocker, mock_client):
    """
    Given:
    - test module command
    - an empty (yet valid) response from Druva

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    mocker.patch.object(
        mock_client,
        "search_events",
        return_value={"events": [], "tracker": "DUMMY_TRACKER"},
    )
    result = run_test_module(client=mock_client, event_types=["InSync events"])
    assert result == "ok"


def test_test_module_command_failure(mocker, mock_client):
    """
    Given:
    - test module command

    When:
    - Pressing test button

    Then:
    - Test module failed
    """
    mocker.patch.object(
        mock_client,
        "_http_request",
        side_effect=DemistoException(message="Error: invalid_grant"),
    )
    with pytest.raises(DemistoException):
        run_test_module(client=mock_client, event_types=["InSync events"])


@pytest.mark.parametrize(
    "event_type,mock_response,expected_tracker,expected_event_count,expected_event_id_field",
    [
        ("InSync events", RESPONSE_WITH_EVENTS_1, "xxxx", 1, "eventID"),
    ],
)
def test_get_events_command(
    mocker, mock_client, event_type, mock_response, expected_tracker, expected_event_count, expected_event_id_field
):
    """
    Given:
    - get_events command for InSync events

    When:
    - running get events command

    Then:
    - Ensure events and tracker are returned as expected
    """
    mocker.patch.object(mock_client, "search_events", return_value=mock_response)
    events, tracker = get_events(client=mock_client, event_type=event_type)

    assert tracker == expected_tracker
    assert len(events) == expected_event_count
    assert expected_event_id_field in events[0]


def test_search_events_cybersecurity_normalization(mocker, mock_client):
    """
    Given:
    - Cybersecurity events API response with nextPageToken

    When:
    - running search_events method with event_type="Cybersecurity events"

    Then:
    - Ensure nextPageToken is normalized to tracker in the response
    """
    mocker.patch.object(mock_client, "_http_request", return_value=RESPONSE_CYBERSECURITY_EVENTS)
    response = mock_client.search_events(event_type="Cybersecurity events")

    # Verify normalization: tracker should be added with same value as nextPageToken
    assert response["tracker"] == "cybertoken123"
    assert response["nextPageToken"] == "cybertoken123"


def test_get_events_command_failure(mocker, mock_client):
    """
    Given:
    - a mocked client
    - mocked response: invalid response structure, since it does not have the 'tracker' key as expected

    When:
    - running get events command

    Then:
    - Ensure KeyError exception was thrown due to invalid response

    """
    mocker.patch.object(mock_client, "search_events", return_value=INVALID_RESPONSE)
    with pytest.raises(KeyError):
        get_events(client=mock_client, event_type="InSync events")


def test_refresh_access_token(mocker, mock_client):
    """
    Given:
    - a mock client

    When:
    - running _refresh_access_token method

    Then:
    - Ensure exception is thrown
    - Ensure informative message was shown
    """
    response = requests.Response()
    response.status_code = 400

    mocker.patch.object(
        mock_client,
        "_http_request",
        side_effect=DemistoException(message="invalid_grant", res=response),
    )

    error_message = "Error in test-module: Make sure Server URL, Client ID and Secret Key are correctly entered."

    with pytest.raises(DemistoException, match=error_message):
        mock_client._refresh_access_token()


@pytest.mark.parametrize(
    "event_type,tracker,expected_url_suffix,mock_response",
    [
        ("InSync events", "xxxx", "/insync/eventmanagement/v2/events?tracker=xxxx", RESPONSE_WITHOUT_EVENTS),
        ("InSync events", None, "/insync/eventmanagement/v2/events", RESPONSE_WITHOUT_EVENTS),
        (
            "Cybersecurity events",
            "token123",
            "/platform/eventmanagement/v3/events?pageToken=token123",
            RESPONSE_CYBERSECURITY_EVENTS,
        ),
        ("Cybersecurity events", None, "/platform/eventmanagement/v3/events?pageSize=500", RESPONSE_CYBERSECURITY_EVENTS),
    ],
)
def test_search_events_called_with(mocker, mock_client, event_type, tracker, expected_url_suffix, mock_response):
    """
    Given:
    - a mock client
    - different event types and tracker scenarios

    When:
    - running search_events method with various parameters

    Then:
    - Ensure correct URL is constructed for each scenario
    """
    http_mock = mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    mock_client.search_events(tracker=tracker, event_type=event_type)
    http_mock.assert_called_with(
        method="GET",
        url_suffix=expected_url_suffix,
        headers={"Authorization": "Bearer DUMMY_TOKEN", "accept": "application/json"},
    )


def test_search_events_failure(mocker, mock_client):
    """
    Given:
    - a mock client

    When:
    - running search_events method

    Then:
    -  Ensure an exception was thrown due to invalid tracker
    """

    mocker.patch.object(
        mock_client,
        "_http_request",
        side_effect=DemistoException(message="Error: Invalid tracker"),
    )
    with pytest.raises(DemistoException):
        mock_client.search_events(tracker="xxxx")


def test_fetch_events_command(mocker, mock_client):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and the next run, match the response data
    """
    # First fetch
    mocker.patch.object(mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_1)
    first_run = {}
    events, tracker_for_second_run = fetch_events(
        client=mock_client, last_run=first_run, max_fetch=MAX_FETCH, event_types=["InSync events"]
    )

    assert len(events) == 1
    assert tracker_for_second_run["tracker_InSync events"] == "xxxx"
    assert events[0]["eventID"] == 0

    # Second fetch
    mock_search_events = mocker.patch.object(mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_2)
    events, tracker_for_third_run = fetch_events(
        client=mock_client, last_run=tracker_for_second_run, max_fetch=MAX_FETCH, event_types=["InSync events"]
    )
    # The second fetch uses the tracker from first fetch result (xxxx)
    mock_search_events.assert_called_with("xxxx", "InSync events")
    assert len(events) == 1
    assert tracker_for_third_run["tracker_InSync events"] == "yyyy"
    assert events[0]["eventID"] == 1


@freeze_time(datetime(2022, 2, 28, 11, 10))
@pytest.mark.parametrize(
    "integration_context",
    [
        ({}),
        (
            {
                "Token": "DUMMY TOKEN",
                "expiration_time": datetime(2022, 2, 28, 10, 50).strftime(DATE_FORMAT_FOR_TOKEN),
            }
        ),
    ],
)
def test_login_invalid_token(mocker, integration_context):
    """
    Given:
    - An IntegrationContext without a Token or one that has expired

    When:
    - Build a client (for checking login)

    Then:
    - Ensure a new token is generated
    """
    mocker.patch.object(demisto, "getIntegrationContext", return_value=integration_context)
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_refresh_access_token = mocker.patch.object(Client, "_refresh_access_token", return_value=("", 0))
    Client(
        base_url="test",
        client_id="client_id",
        secret_key="secret_key",
        max_fetch=MAX_FETCH,
        verify=False,
        proxy=False,
    )
    mock_refresh_access_token.assert_called_once_with()


@freeze_time(datetime(2022, 2, 28, 11, 00))
def test_login_valid_token(mocker):
    """
    Given:
    - An IntegrationContext with valid Access Token

    When:
    - Build a client (for checking login)

    Then:
    - Ensure a new token is not generated
    """
    mocker.patch.object(
        demisto,
        "getIntegrationContext",
        return_value={
            "Token": "DUMMY TOKEN",
            "expiration_time": datetime(2022, 2, 28, 11, 10).strftime(DATE_FORMAT_FOR_TOKEN),
        },
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_refresh_access_token = mocker.patch.object(Client, "_refresh_access_token", return_value=("DUMMY_TOKEN", 1800))
    Client(
        base_url="test",
        client_id="client_id",
        secret_key="secret_key",
        max_fetch=MAX_FETCH,
        verify=False,
        proxy=False,
    )
    assert not mock_refresh_access_token.called


def test_max_fetch_validation():
    """
    Given:
    - invalid max_fetch (more than 10,000)

    When:
    - init the client

    Then:
    - DemistoException is thrown with an appropriate message
    """

    with pytest.raises(DemistoException, match=f"The maximum number of events per fetch should be between 1 - {MAX_FETCH}"):
        Client(
            base_url="test",
            client_id="client_id",
            secret_key="secret_key",
            max_fetch=(MAX_FETCH + 1),
            verify=False,
            proxy=False,
        )


def test_fetch_events_invalid_tracker(mocker, mock_client):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command
    - Mocking the second fetch to throw an exception to Invalid tracker

    Then:
    - Ensure exception is caught
    - Ensure same tracker is returned (as we got at the previous call)
    - Ensure no events are returned
    """
    # First fetch
    mocker.patch.object(mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_1)
    events, tracker_for_second_run = fetch_events(
        client=mock_client, last_run={}, max_fetch=MAX_FETCH, event_types=["InSync events"]
    )

    # Second fetch
    mocker.patch.object(mock_client, "search_events", side_effect=Exception("Invalid tracker"))
    events, tracker_for_third_run = fetch_events(
        client=mock_client, last_run=tracker_for_second_run, max_fetch=MAX_FETCH, event_types=["InSync events"]
    )

    # same tracker should be returned when "Invalid tracker" exception is thrown and no events
    assert tracker_for_third_run["tracker_InSync events"] == tracker_for_second_run["tracker_InSync events"]
    assert events == []


@pytest.mark.parametrize(
    "event_types,expected_tracker_keys,mock_responses",
    [
        (["InSync events"], ["tracker_InSync events"], {"InSync events": RESPONSE_WITH_EVENTS_1}),
        (["Cybersecurity events"], ["tracker_Cybersecurity events"], {"Cybersecurity events": RESPONSE_CYBERSECURITY_EVENTS}),
        (
            ["InSync events", "Cybersecurity events"],
            ["tracker_InSync events", "tracker_Cybersecurity events"],
            {"InSync events": RESPONSE_WITH_EVENTS_1, "Cybersecurity events": RESPONSE_CYBERSECURITY_EVENTS},
        ),
    ],
)
def test_fetch_events_multiple_types(mocker, mock_client, event_types, expected_tracker_keys, mock_responses):
    """
    Given:
    - fetch events command with different event type configurations

    When:
    - Running fetch-events command with single or multiple event types

    Then:
    - Ensure correct trackers are stored for each event type
    - Ensure _time and source_log_type fields are added to events
    """

    def mock_search(tracker=None, event_type="InSync events"):
        return mock_responses.get(event_type, RESPONSE_WITH_EVENTS_1)

    mocker.patch.object(mock_client, "search_events", side_effect=mock_search)
    events, next_run = fetch_events(client=mock_client, last_run={}, max_fetch=MAX_FETCH, event_types=event_types)

    # Verify all expected tracker keys are present
    for key in expected_tracker_keys:
        assert key in next_run

    # Verify event count matches number of event types
    assert len(events) == len(event_types)

    # Verify _time and source_log_type fields are added
    for event in events:
        assert "_time" in event
        assert "source_log_type" in event
        # Verify source_log_type has correct value
        assert event["source_log_type"] in ["insync_events", "cybersecurity_events"]
