from datetime import datetime

import dateparser

import demistomock as demisto
import pytest
from ForcepointEventCollector import (
    arg_to_datetime,
    fetch_events_command,
    get_events_command,
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
    mocked_client.get_incidents.return_value = [0, 1, 3, 4]
    mocked_client.get_incident.side_effect = mock_get_incident
    return mocked_client


def test_fetch_events_by_fetch_time(client):
    """
    Given: A mock Forcepoint DLP client.
    When: Running fetch-events, where `max_fetch` param is 1 and `first_fetch` param is "2 days ago".
    Then: Ensure only the first event that occurred up to 2 days ago is returned.
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
    Given: A mock Forcepoint DLP client.
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
    Given: A mock Forcepoint DLP client.
    When: Running get-events with a limit of 1, while there are four open incidents.
    Then: Ensure only one event is returned.
    """
    _, events = get_events_command(client, {"limit": 1})
    assert len(events) == 1
    assert events[0]["incident_id"] == 0


def test_incident_to_events():
    """
    Given: A mock Forcepoint DLP incident data that aggregates two reports.
    When: Calling incident_to_events().
    Then: Ensure there are two events returned, where each of them
        consists of the incident data and a single report data.
    """
    # FIXME
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
                "url": "https://server.com/",
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
    mocker.patch.object(Client, "get_access_token", return_value="mock_token")
    mocker.patch.object(Client, "get_open_incident_ids", return_value=[])
    mocker.patch.object(Client, "get_incident")
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value=params)
    demisto_result = mocker.patch.object(demisto, "results")
    return_error = mocker.patch('ForcepointEventCollector.return_error')
    main()
    result = (demisto_result if is_valid else return_error).call_args[0][0]
    assert result_msg in result


def generate_mocked_event(event_id):
    return {
            "action": "AUTHORIZED",
            "analyzed_by": "Policy Engine test.corp.service.com",
            "channel": "EMAIL",
            "destination": "John.Doe@test.com",
            "details": "SOS",
            "detected_by": "Forcepoint Email Security on test.corp.service.com",
            "event_id": "14070409734372476071",
            "event_time": "21/04/2023 09:55:52",
            "file_name": "MIME Data.txt - 337.8 KB; MIME Data.txt - 59.47 KB",
            "id": event_id,
            "ignored_incidents": False,
            "incident_time": "21/04/2023 09:56:35",
            "maximum_matches": 1,
            "partition_index": 20210213,
            "policies": "TTL",
            "released_incident": False,
            "severity": "LOW",
            "source": {
                "business_unit": "Excluded Resources",
                "department": "Quality Excellence",
                "email_address": "John.Doe@test.com",
                "login_name": "FooBar",
                "manager": "John Doe"
            },
            "status": "New",
            "transaction_size": 423151,
            "violation_triggers": 1
        }


@pytest.mark.parametrize(
    "first_fetch, utc_now, max_fetch, last_fetch_time, api_limit, last_id, incidents_per_time, ids, scenario, "
    "expected, expected_next_last_fetch_time",
    [
        (
            dateparser.parse("01/01/2020 00:00:00"),  # first fetch
            dateparser.parse("01/01/2020 00:01:01"),  # utc now
            10,  # max_fetch.
            None,  # last_fetch_time
            10,  # max API returned limit.
            None,  # last_id
            {  # incidents_per_time
                ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): list(range(1, 25)),
                ("01/01/2020 00:00:00", "01/01/2020 00:00:01"): [1, 2],
                ("01/01/2020 00:00:01", "01/01/2020 00:00:02"): [3, 4],
                ("01/01/2020 00:00:02", "01/01/2020 00:00:03"): [],
                ("01/01/2020 00:00:03", "01/01/2020 00:00:04"): [5, 6],
                ("01/01/2020 00:00:04", "01/01/2020 00:00:05"): [],
                ("01/01/2020 00:00:05", "01/01/2020 00:00:06"): [],
                ("01/01/2020 00:00:06", "01/01/2020 00:00:07"): [],
                ("01/01/2020 00:00:07", "01/01/2020 00:00:08"): [],
                ("01/01/2020 00:00:08", "01/01/2020 00:00:09"): [],
                ("01/01/2020 00:00:09", "01/01/2020 00:00:10"): [],

                ("01/01/2020 00:00:10", "01/01/2020 00:00:11"): [7],
                ("01/01/2020 00:00:11", "01/01/2020 00:00:12"): [8],
                ("01/01/2020 00:00:12", "01/01/2020 00:00:13"): [9],
                ("01/01/2020 00:00:13", "01/01/2020 00:00:14"): [10],
                ("01/01/2020 00:00:14", "01/01/2020 00:00:15"): [],
                ("01/01/2020 00:00:15", "01/01/2020 00:00:16"): [],
                ("01/01/2020 00:00:16", "01/01/2020 00:00:17"): [],
                ("01/01/2020 00:00:17", "01/01/2020 00:00:18"): [],
                ("01/01/2020 00:00:18", "01/01/2020 00:00:19"): [],
                ("01/01/2020 00:00:19", "01/01/2020 00:00:20"): [],

                ("01/01/2020 00:00:20", "01/01/2020 00:00:21"): [11, 12, 13, 14],
                ("01/01/2020 00:00:21", "01/01/2020 00:00:22"): [],
                ("01/01/2020 00:00:22", "01/01/2020 00:00:23"): [],
                ("01/01/2020 00:00:23", "01/01/2020 00:00:24"): [],
                ("01/01/2020 00:00:24", "01/01/2020 00:00:25"): [],
                ("01/01/2020 00:00:25", "01/01/2020 00:00:26"): [15, 16, 17],
                ("01/01/2020 00:00:26", "01/01/2020 00:00:27"): [],
                ("01/01/2020 00:00:27", "01/01/2020 00:00:28"): [18],
                ("01/01/2020 00:00:28", "01/01/2020 00:00:29"): [],
                ("01/01/2020 00:00:29", "01/01/2020 00:00:30"): [],

                ("01/01/2020 00:00:30", "01/01/2020 00:00:31"): [],
                ("01/01/2020 00:00:31", "01/01/2020 00:00:32"): [],
                ("01/01/2020 00:00:32", "01/01/2020 00:00:33"): [],
                ("01/01/2020 00:00:33", "01/01/2020 00:00:34"): [],
                ("01/01/2020 00:00:34", "01/01/2020 00:00:35"): [],
                ("01/01/2020 00:00:35", "01/01/2020 00:00:36"): [],
                ("01/01/2020 00:00:36", "01/01/2020 00:00:37"): [],
                ("01/01/2020 00:00:37", "01/01/2020 00:00:38"): [],
                ("01/01/2020 00:00:38", "01/01/2020 00:00:39"): [],
                ("01/01/2020 00:00:39", "01/01/2020 00:00:40"): [],

                ("01/01/2020 00:00:40", "01/01/2020 00:00:41"): [],
                ("01/01/2020 00:00:41", "01/01/2020 00:00:42"): [],
                ("01/01/2020 00:00:42", "01/01/2020 00:00:43"): [],
                ("01/01/2020 00:00:43", "01/01/2020 00:00:44"): [],
                ("01/01/2020 00:00:44", "01/01/2020 00:00:45"): [],
                ("01/01/2020 00:00:45", "01/01/2020 00:00:46"): [],
                ("01/01/2020 00:00:46", "01/01/2020 00:00:47"): [],
                ("01/01/2020 00:00:47", "01/01/2020 00:00:48"): [],
                ("01/01/2020 00:00:48", "01/01/2020 00:00:49"): [],
                ("01/01/2020 00:00:49", "01/01/2020 00:00:50"): [],

                ("01/01/2020 00:00:50", "01/01/2020 00:00:51"): [],
                ("01/01/2020 00:00:51", "01/01/2020 00:00:52"): [],
                ("01/01/2020 00:00:52", "01/01/2020 00:00:53"): [],
                ("01/01/2020 00:00:53", "01/01/2020 00:00:54"): [],
                ("01/01/2020 00:00:54", "01/01/2020 00:00:55"): [],
                ("01/01/2020 00:00:55", "01/01/2020 00:00:56"): [],
                ("01/01/2020 00:00:56", "01/01/2020 00:00:57"): [19],
                ("01/01/2020 00:00:57", "01/01/2020 00:00:58"): [20],
                ("01/01/2020 00:00:58", "01/01/2020 00:00:59"): [21, 22, 23, 24, 25],
                ("01/01/2020 00:00:59", "01/01/2020 00:01:00"): [],
            },
            [  # ids
            ],
            "scenario",
            list(range(1, 11)),  # expected
            "01/01/2020 00:00:14",  # expected_next_last_fetch_time
        ),
    ]
)
def test_fetch_events(mocker, first_fetch, utc_now, max_fetch, last_fetch_time, api_limit, last_id, incidents_per_time, ids,
                      scenario, expected, expected_next_last_fetch_time):


    def mock_get_incidents(from_date, to_date):
        from_date_str = from_date.strftime("%m/%d/%Y %H:%M:%S")
        to_date_str = to_date.strftime("%m/%d/%Y %H:%M:%S")
        incidents = [generate_mocked_event(event_id) for event_id in incidents_per_time.get((from_date_str, to_date_str))]
        return {
            "incidents": incidents[:api_limit],
            "total_count": len(incidents),
            "total_returned": min(len(incidents), api_limit)
        }
    def mock_get_incident_ids(event_ids):
        return {
            "incidents": [generate_mocked_event(event_id) for event_id in ids]
        }

    mocked_client = mocker.Mock()
    mocked_client.get_incidents.side_effect = mock_get_incidents
    mocked_client.get_incident_ids.side_effect = mock_get_incident_ids
    mocked_client.api_limit = api_limit
    mocked_client.utc_now = utc_now

    events, last_id, next_last_fetch_time = fetch_events_command(
        client=mocked_client,
        first_fetch=first_fetch,
        max_fetch=max_fetch,
        last_fetch_time=last_fetch_time,
        last_id=last_id,
    )
    assert list(map(lambda event: event["id"], events)) == expected, f"{scenario} event ids don't match"
    assert last_id == expected[-1], f"{scenario} last event id don't match {last_id}"
    assert next_last_fetch_time.strftime("%m/%d/%Y %H:%M:%S") == expected_next_last_fetch_time
