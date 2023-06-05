import demistomock as demisto
import pytest
from IronscalesEventCollector import (
    arg_to_datetime,
    fetch_events_command,
    get_events_command,
    incident_to_events,
    main,
    Client,
    DATEPARSER_SETTINGS,
)


@pytest.fixture
def client(mocker):
    def mock_get_incident(inc_id):
        return {
            "incident_id": inc_id,
            "first_reported_date": f"{4 - inc_id} days ago",
            "reports": [
                {
                    "name": "first_name",
                }
            ]
        }
    mocked_client = mocker.Mock()
    mocked_client.get_open_incident_ids.return_value = [0, 1, 3, 4]
    mocked_client.get_incident.side_effect = mock_get_incident
    return mocked_client


def test_fetch_events_by_fetch_time(client):
    """
    Given: A mock Ironscales client.
    When: Running fetch-events, where `max_fetch` param is 1 and `first_fetch` param is "2 days ago".
    Then: Ensure only the first event that occured up to 2 days ago is returned.
    """
    events, last_id = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=1,
    )
    assert len(events) == 1
    assert events[0]["incident_id"] == 3
    assert last_id == 3


def test_fetch_events_by_last_id(client):
    """
    Given: A mock Ironscales client.
    When: Running fetch-events, where `max_fetch` param is 10 and the last fetched incident id is 1.
    Then: Ensure incidents 3 and 4 are returned as events.
    """
    res, last_run = fetch_events_command(
        client,
        first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
        max_fetch=10,
        last_id=1
    )
    assert res[0]["incident_id"] == 3
    assert res[-1]["incident_id"] == 4


def test_get_events(client):
    """
    Given: A mock Ironscales client.
    When: Running get-events with a limit of 1, while there are four open incidents.
    Then: Ensure only one event is returned.
    """
    _, events = get_events_command(client, {"limit": 1})
    assert len(events) == 1
    assert events[0]["incident_id"] == 0


def test_incident_to_events():
    """
    Given: A mock Ironscales incident data that aggregates two reports.
    When: Calling incident_to_events().
    Then: Ensure there are two events returned, where each of them
        consists of the incident data and a single report data.
    """
    dummy_incident = {
        "incident_id": 1,
        "first_reported_date": "2023-05-11T11:39:53.104571Z",
        "reports": [
            {
                "name": "dummy name 1",
                "email": "test@paloaltonetworks.com",
                "headers": [
                    {
                        "name": "header1",
                        "value": "value1"
                    },
                ]
            },
            {
                "name": "dummy name 2",
                "email": "test2@paloaltonetworks.com",
                "headers": [
                    {
                        "name": "header2",
                        "value": "value2"
                    },
                ]
            }
        ],
        "links": [
            {
                "url": "http://www.ironscales.com/",
                "name": "tests"
            },
        ],
        "attachments": [
            {
                "file_name": "dummy file",
                "file_size": 1024,
                "md5": "a36544c75d1253d8dd32070908adebd0"
            }
        ]
    }
    events = incident_to_events(dummy_incident)
    assert len(events) == 2
    assert "reports" not in events[0]
    assert "reports" not in events[1]
    assert events[0]["incident_id"] == events[1]["incident_id"]
    assert events[0]["links"] == events[1]["links"]
    assert events[0]["attachments"] == events[1]["attachments"]
    assert events[0]["headers"][0]["name"] == "header1"
    assert events[1]["headers"][0]["name"] == "header2"
    assert events[0]["headers"][0]["value"] == "value1"
    assert events[1]["headers"][0]["value"] == "value2"


@pytest.mark.parametrize(
    "params, is_valid, result_msg",
    [
        (
            {"max_fetch": "1", "first_fetch": "", "url": ""},
            True,
            "ok"
        ),
        (
            {"max_fetch": "not a number", "first_fetch": "3 days", "url": ""},
            False,
            "\"not a number\" is not a valid number"
        ),
        (
            {"max_fetch": "1", "first_fetch": "not a date", "url": ""},
            False,
            "\"not a date\" is not a valid date"
        ),
    ]
)
def test_test_module(mocker, params, is_valid, result_msg):
    """
    Given: different assignments for integration parameters.
    When: Running test-module command.
    Then: Make sure the correct message is returned.
    """
    mocker.patch.object(Client, "get_jwt_token", return_value="mock_token")
    mocker.patch.object(Client, "get_open_incident_ids", return_value=[])
    mocker.patch.object(Client, "get_incident")
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value=params)
    demisto_result = mocker.patch.object(demisto, "results")
    return_error = mocker.patch('IronscalesEventCollector.return_error')
    main()
    result = (demisto_result if is_valid else return_error).call_args[0][0]
    assert result_msg in result
