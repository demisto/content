from CommonServerPython import DemistoException
from DruvaEventCollector import Client, test_module as run_test_module, get_events, fetch_events
import pytest


@pytest.fixture()
def mock_client() -> Client:
    return Client(base_url="test", verify=False, proxy=False)


def test_test_module_command(mocker, mock_client):
    """
    Given:
    - test module command

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


EVENT_1 = {
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


def test_get_events_command(mocker, mock_client):
    """
    Given:
    - get_events command

    When:
    - running get events command

    Then:
    - events and tracker as expected
    """
    mocker.patch.object(mock_client, "search_events", return_value=EVENT_1)
    events, tracker = get_events(client=mock_client)

    assert tracker == 'xxxx'
    assert len(events) == 1


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
    client = Client(base_url="client_test")
    mocker.patch.object(client, "_http_request", side_effect=DemistoException(message='Error: invalid_grant'))
    with pytest.raises(DemistoException, match="Make sure Server URL, Client ID and Secret Key are correctly entered."):
        client.refresh_access_token(encoded_credentials=b"test")


EVENT_2 = {
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


def test_fetch_events_command(mocker, mock_client):
    """
    Given:
    - fetch events command

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and next run fields
    """
    # First fetch
    mocker.patch.object(mock_client, "search_events", return_value=EVENT_1)
    first_run = {}
    events, second_run = fetch_events(
        client=mock_client,
        last_run=first_run
    )

    assert len(events) == 1
    assert second_run['tracker'] == "xxxx"
    assert events[0]['eventID'] == 0

    # Second fetch
    mock_search_events = mocker.patch.object(mock_client, "search_events", return_value=EVENT_2)
    events, third_run = fetch_events(
        client=mock_client,
        last_run=second_run
    )
    mock_search_events.assert_called_with(second_run.get('tracker'))
    assert len(events) == 1
    assert third_run.get('tracker') == "yyyy"
    assert events[0].get('eventID') == 1
