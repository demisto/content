import dateparser
import pytest

import demistomock as demisto
from ForcepointEventCollector import fetch_events, to_str_time, Client, get_events_command


def mock_client():
    return Client(
        base_url="https://test.com",
        verify=False,
        proxy=False,
        username="user_name",
        password="password",
        utc_now=dateparser.parse("2020-01-01T00:00:00Z"),
    )


def test_get_events_command(requests_mock, mocker):
    """Tests get-events command function.

    Checks the output of the command function with the expected output.
    """
    client = mock_client()
    since_time = "2022-12-26T00:00:00Z"
    mock_response = {
        "incidents": [generate_mocked_event(1, since_time), generate_mocked_event(1, since_time)],
        "total_count": 2,
        "total_returned": 2,
    }
    args = {"since_time": since_time, "limit": 2}
    mocker.patch.object(Client, "get_access_token", return_value={"access_token": "access_token"})
    requests_mock.post("https://test.com/incidents", json=mock_response)
    result, events = get_events_command(client, args)

    assert len(events) == mock_response.get("total_count")
    assert events == mock_response.get("incidents")


def generate_mocked_event(event_id, event_time):
    return {
        "_collector_source": "API",
        "action": "AUTHORIZED",
        "analyzed_by": "Policy Engine test.corp.service.com",
        "channel": "EMAIL",
        "destination": "John.Doe@test.com",
        "details": "SOS",
        "detected_by": "Forcepoint Email Security on test.corp.service.com",
        "event_id": "14070409734372476071",
        "event_time": event_time,
        "file_name": "MIME Data.txt - 337.8 KB; MIME Data.txt - 59.47 KB",
        "id": event_id,
        "ignored_incidents": False,
        "incident_time": event_time,
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
            "manager": "John Doe",
        },
        "status": "New",
        "transaction_size": 423151,
        "violation_triggers": 1,
    }


@pytest.mark.parametrize(
    "scenario, first_fetch, utc_now, max_fetch, last_fetch_time, api_limit, last_events_ids, incidents_per_time,"
    "returned_events_ids, forward_last_events_ids, forward_last_fetch, backward_done, backward_last_events_ids,"
    "backward_last_fetch, backward_to_time",
    [
        (
            "get all events between the timespan",  # scenario
            "01/01/2020 00:00:00",  # first fetch
            "01/01/2020 00:01:00",  # utc now
            10,  # max_fetch.
            "01/01/2020 00:00:00",  # last_fetch_time
            10,  # max API returned limit.
            [],  # last_events_ids
            {  # incidents_per_time
                ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): {
                    1: "01/01/2020 00:00:01",
                    2: "01/01/2020 00:00:02",
                    3: "01/01/2020 00:00:03",
                    4: "01/01/2020 00:00:04",
                    5: "01/01/2020 00:00:05",
                    6: "01/01/2020 00:00:06",
                    7: "01/01/2020 00:00:07",
                    8: "01/01/2020 00:00:08",
                    9: "01/01/2020 00:00:09",
                    10: "01/01/2020 00:00:10",
                },
            },
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # returned_events_ids
            [10],  # forward_last_events_ids
            "01/01/2020 00:00:10",  # forward_last_fetch
            False,  # backward_done
            [],  # backward_last_events_ids
            "01/01/2020 00:00:00",  # backward_last_fetch
            "01/01/2020 00:01:00",  # backward_to_time
        ),
        (
            "all events were already fetched, force move to next second",  # scenario
            "01/01/2020 00:00:00",  # first fetch
            "01/01/2020 00:01:00",  # utc now
            10,  # max_fetch.
            "01/01/2020 00:00:00",  # last_fetch_time
            10,  # max API returned limit.
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # last_events_ids
            {  # incidents_per_time
                ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): {
                    1: "01/01/2020 00:00:00",
                    2: "01/01/2020 00:00:00",
                    3: "01/01/2020 00:00:00",
                    4: "01/01/2020 00:00:00",
                    5: "01/01/2020 00:00:00",
                    6: "01/01/2020 00:00:00",
                    7: "01/01/2020 00:00:00",
                    8: "01/01/2020 00:00:00",
                    9: "01/01/2020 00:00:00",
                    10: "01/01/2020 00:00:00",
                },
            },
            [],  # returned_events_ids
            [],  # forward_last_events_ids
            "01/01/2020 00:00:01",  # forward_last_fetch
            False,  # backward_done
            [],  # backward_last_events_ids
            "01/01/2020 00:00:00",  # backward_last_fetch
            "01/01/2020 00:01:00",  # backward_to_time
        ),
        (
            "testing starting from a timestamp where we already have existing events in the last fetch (dedup)",  # scenario
            "01/01/2020 00:00:00",  # first fetch
            "01/01/2020 00:01:00",  # utc now
            10,  # max_fetch.
            "01/01/2020 00:00:09",  # last_fetch_time
            10,  # max API returned limit.
            [9, 10],  # last_events_ids
            {  # incidents_per_time
                ("01/01/2020 00:00:09", "01/01/2020 00:01:00"): {
                    9: "01/01/2020 00:00:09",
                    10: "01/01/2020 00:00:10",
                    11: "01/01/2020 00:00:11",
                },
            },
            [11],  # returned_events_ids
            [11],  # forward_last_events_ids
            "01/01/2020 00:00:11",  # forward_last_fetch
            False,  # backward_done
            [],  # backward_last_events_ids
            "01/01/2020 00:00:00",  # backward_last_fetch
            "01/01/2020 00:01:00",  # backward_to_time
        ),
    ],
)
def test_fetch_events(
    mocker,
    scenario,
    first_fetch,
    utc_now,
    max_fetch,
    last_fetch_time,
    api_limit,
    last_events_ids,
    incidents_per_time,
    returned_events_ids,
    forward_last_events_ids,
    forward_last_fetch,
    backward_done,
    backward_last_events_ids,
    backward_last_fetch,
    backward_to_time,
):

    def mock_get_incidents(from_date, to_date):
        from_date_str = to_str_time(from_date)
        to_date_str = to_str_time(to_date)
        incidents = [
            generate_mocked_event(event_id, event_time)
            for event_id, event_time in incidents_per_time.get((from_date_str, to_date_str)).items()
        ]
        return {
            "incidents": incidents[:api_limit],
            "total_count": len(incidents),
            "total_returned": min(len(incidents), api_limit),
        }

    mocked_client = mocker.Mock()
    mocked_client.get_incidents.side_effect = mock_get_incidents
    mocked_client.api_limit = api_limit
    mocked_client.utc_now = dateparser.parse(utc_now)

    mocked_send_events_to_xsiam = mocker.patch("ForcepointEventCollector.send_events_to_xsiam")
    mocked_demisto_set_last_run = mocker.patch.object(demisto, "setLastRun")

    last_run = {
        "forward": {
            "last_fetch": last_fetch_time,
            "last_events_ids": last_events_ids,
        }
    }

    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    fetch_events(
        client=mocked_client,
        first_fetch=first_fetch,
        max_fetch=max_fetch,
    )

    assert mocked_send_events_to_xsiam.called, f"{scenario} - send event to xsiam wasn't called"
    assert [
        event["id"] for event in mocked_send_events_to_xsiam.call_args.args[0]
    ] == returned_events_ids, f"{scenario} - event ids don't match"
    assert mocked_demisto_set_last_run.called, f"{scenario} - set last run wasn't called"
    assert mocked_demisto_set_last_run.call_args.args[0] == {
        "forward": {"last_events_ids": forward_last_events_ids, "last_fetch": forward_last_fetch}
    }, f"{scenario} - set last run doesn't match expected value"
