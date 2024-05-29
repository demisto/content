from CommonServerPython import DemistoException
from DruvaEventCollector import Client, test_module as run_test_module, get_events, fetch_events
import pytest

import requests

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
            "facility": 23
        }
    ],
    "nextPageExists": False,
    "tracker": "xxxx"
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
            "facility": 23
        }
    ],
    "nextPageExists": False,
    "tracker": "yyyy"
}
RESPONSE_WITHOUT_EVENTS = {
    "events": [],
    "nextPageExists": False,
    "tracker": "xxxx"
}
INVALID_RESPONSE = {
    "events": [{
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
        "facility": 23
    }],
    "nextPageExists": False
}


@pytest.fixture()
def mock_client() -> Client:
    return Client(base_url="test", verify=False, proxy=False, headers={'Authorization': 'Bearer DUMMY_TOKEN'})


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
    mocker.patch.object(mock_client, "search_events", return_value={})
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
    mocker.patch.object(mock_client, "_http_request", side_effect=DemistoException(message='Error: invalid_grant'))
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
    mocker.patch.object(mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_1)
    events, tracker = get_events(client=mock_client)

    assert tracker == 'xxxx'
    assert len(events) == 1


def test_get_events_command_failure(mocker, mock_client):
    """
    Given:
    - get_events command

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
    - running refresh_access_token method

    Then:
    - Ensure exception is thrown
    - Ensure informative message was shown
    """
    response = requests.Response()
    response.status_code = 400

    mocker.patch.object(mock_client, "_http_request", return_value=response)

    error_message = "Error in test-module: Make sure Server URL, Client ID and Secret Key are correctly entered."

    with pytest.raises(DemistoException, match=error_message):
        mock_client.refresh_access_token(credentials="test")


def test_search_events_called_with(mocker, mock_client):
    """
    Given:
    - a mock client

    When:
    - running search_events method

    Then:
    -  Ensure all arguments were sent to the api call as expected
    """

    http_mock = mocker.patch.object(mock_client, "_http_request", return_value=RESPONSE_WITHOUT_EVENTS)

    mock_client.search_events(tracker='xxxx')
    http_mock.assert_called_with(method='GET', url_suffix='/insync/eventmanagement/v2/events?tracker=xxxx',
                                 headers={'Authorization': 'Bearer DUMMY_TOKEN', 'accept': 'application/json'})


def test_search_events_failure(mocker, mock_client):
    """
    Given:
    - a mock client

    When:
    - running search_events method

    Then:
    -  Ensure an exception was thrown due to invalid tracker
    """

    mocker.patch.object(mock_client, "_http_request", side_effect=DemistoException(message='Error: Invalid tracker'))
    with pytest.raises(DemistoException):
        mock_client.search_events(tracker='xxxx')


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
    events, second_run = fetch_events(
        client=mock_client,
        last_run=first_run
    )

    assert len(events) == 1
    assert second_run['tracker'] == "xxxx"
    assert events[0]['eventID'] == 0

    # Second fetch
    mock_search_events = mocker.patch.object(mock_client, "search_events", return_value=RESPONSE_WITH_EVENTS_2)
    events, third_run = fetch_events(
        client=mock_client,
        last_run=second_run
    )
    mock_search_events.assert_called_with(second_run.get('tracker'))
    assert len(events) == 1
    assert third_run['tracker'] == "yyyy"
    assert events[0]['eventID'] == 1
