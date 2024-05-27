from CommonServerPython import DemistoException
from DruvaEventCollector import Client, test_module, get_events, fetch_events
import pytest


@pytest.fixture()
def mock_client() -> Client:
    return Client(base_url="test", verify=False, proxy=False, headers=None)


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
    result = test_module(client=mock_client)
    assert result == "ok"


@pytest.mark.parametrize(
    "return_value, expected_result",
    [
        (DemistoException(message='Forbidden'),
         'Authorization Error: make sure Server URL, Client ID and Secret Key are correctly entered.'),
        (DemistoException(message='Error: Request failed with status code 404'), 'Error: Request failed with status code 404')
    ]
)
def test_test_module_command_failures(mocker, mock_client, return_value, expected_result):
    """
    Given:
    - test module command

    When:
    - Pressing test button

    Then:
    - Test module failed with Authorization Error
    - Test module failed with any other exception
    """
    mocker.patch.object(mock_client, "search_events", side_effect=return_value)
    try:
        result = test_module(client=mock_client)
    except DemistoException as exp:
        assert expected_result == exp.message
    else:
        assert expected_result == result


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
    tracker, events = get_events(client=mock_client)

    assert tracker == 'xxxx'
    assert len(events) == 1


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
    second_run, events = fetch_events(
        client=mock_client,
        last_run=first_run
    )

    assert len(events) == 1
    assert second_run.get('tracker') == "xxxx"
    assert events[0].get('eventID') == 0

    # Second fetch
    mock_search_events = mocker.patch.object(mock_client, "search_events", return_value=EVENT_2)
    third_run, events = fetch_events(
        client=mock_client,
        last_run=second_run
    )
    mock_search_events.assert_called_with(second_run.get('tracker'))
    assert len(events) == 1
    assert third_run.get('tracker') == "yyyy"
    assert events[0].get('eventID') == 1

