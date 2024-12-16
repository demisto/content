from CommonServerPython import DemistoException
from DruvaEventCollector import (
    Client,
    test_module as run_test_module,
    get_events,
    fetch_events,
    DATE_FORMAT_FOR_TOKEN, MAX_FETCH,
)
import pytest
import demistomock as demisto
import requests
from freezegun import freeze_time
from datetime import datetime

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
    result = run_test_module(client=mock_client)
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
        run_test_module(client=mock_client)


def test_get_events_command(mocker, mock_client):
    """
    Given:
    - get_events command

    When:
    - running get events command

    Then:
    - events and tracker as expected
    """
    mocker.patch.object(
        mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_1
    )
    events, tracker = get_events(client=mock_client)

    assert tracker == "xxxx"
    assert len(events) == 1


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
        get_events(client=mock_client)


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


def test_search_events_called_with(mocker, mock_client):
    """
    Given:
    - a mock client

    When:
    - running search_events method

    Then:
    -  Ensure all arguments were sent to the api call as expected
    """

    http_mock = mocker.patch.object(
        mock_client, "_http_request", return_value=RESPONSE_WITHOUT_EVENTS
    )

    mock_client.search_events(tracker="xxxx")
    http_mock.assert_called_with(
        method="GET",
        url_suffix="/insync/eventmanagement/v2/events?tracker=xxxx",
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
    mocker.patch.object(
        mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_1
    )
    first_run = {}
    events, tracker_for_second_run = fetch_events(
        client=mock_client, last_run=first_run, max_fetch=MAX_FETCH
    )

    assert len(events) == 1
    assert tracker_for_second_run["tracker"] == "xxxx"
    assert events[0]["eventID"] == 0

    # Second fetch
    mock_search_events = mocker.patch.object(
        mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_2
    )
    events, tracker_for_third_run = fetch_events(
        client=mock_client, last_run=tracker_for_second_run, max_fetch=MAX_FETCH
    )
    mock_search_events.assert_called_with(tracker_for_second_run.get("tracker"))
    assert len(events) == 1
    assert tracker_for_third_run["tracker"] == "yyyy"
    assert events[0]["eventID"] == 1


@freeze_time(datetime(2022, 2, 28, 11, 10))
@pytest.mark.parametrize(
    "integration_context",
    [
        ({}),
        (
            {
                "Token": "DUMMY TOKEN",
                "expiration_time": datetime(2022, 2, 28, 10, 50).strftime(
                    DATE_FORMAT_FOR_TOKEN
                ),
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
    mocker.patch.object(
        demisto, "getIntegrationContext", return_value=integration_context
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_refresh_access_token = mocker.patch.object(
        Client,
        "_refresh_access_token",
        return_value=("", 0)
    )
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
            "expiration_time": datetime(2022, 2, 28, 11, 10).strftime(
                DATE_FORMAT_FOR_TOKEN
            ),
        },
    )
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_refresh_access_token = mocker.patch.object(
        Client, "_refresh_access_token", return_value=("DUMMY_TOKEN", 1800)
    )
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
    mocker.patch.object(
        mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_1
    )
    events, tracker_for_second_run = fetch_events(
        client=mock_client, last_run={}, max_fetch=MAX_FETCH
    )

    # Second fetch
    mocker.patch.object(mock_client, "search_events", side_effect=Exception("Invalid tracker"))
    events, tracker_for_third_run = fetch_events(
        client=mock_client, last_run=tracker_for_second_run, max_fetch=MAX_FETCH
    )

    # same tracker should be returned when "Invalid tracker" exception is thrown and no events
    assert tracker_for_third_run["tracker"] == tracker_for_second_run["tracker"]
    assert events == []
