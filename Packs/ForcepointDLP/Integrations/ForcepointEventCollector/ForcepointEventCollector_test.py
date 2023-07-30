import dateparser
import pytest

import demistomock as demisto
from ForcepointEventCollector import (
    fetch_events,
    main,
    Client,
    to_str_time
)

#
# @pytest.fixture
# def client(mocker):
#     def mock_get_incident(inc_id):
#         return {
#             "incident_id": inc_id,
#             "first_reported_date": f"{4 - inc_id} days ago",
#             "reports": [
#                 {
#                     "name": "first_name",
#                 }
#             ]
#         }
#     mocked_client = mocker.Mock()
#     mocked_client.get_incidents.return_value = [0, 1, 3, 4]
#     mocked_client.get_incident.side_effect = mock_get_incident
#     return mocked_client
#
#
# def test_fetch_events_by_fetch_time(client):
#     """
#     Given: A mock Forcepoint DLP client.
#     When: Running fetch-events, where `max_fetch` param is 1 and `first_fetch` param is "2 days ago".
#     Then: Ensure only the first event that occurred up to 2 days ago is returned.
#     """
#     events, last_id = fetch_events(
#         client,
#         first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
#         max_fetch=1,
#     )
#     assert len(events) == 1
#     assert events[0]["incident_id"] == 3
#     assert last_id == 3
#
#
# def test_fetch_events_by_last_id(client):
#     """
#     Given: A mock Forcepoint DLP client.
#     When: Running fetch-events, where `max_fetch` param is 10 and the last fetched incident id is 1.
#     Then: Ensure incidents 3 and 4 are returned as events.
#     """
#     res, last_run = fetch_events(
#         client,
#         first_fetch=arg_to_datetime("2 days ago", settings=DATEPARSER_SETTINGS),  # type: ignore
#         max_fetch=10,
#     )
#     assert res[0]["incident_id"] == 3
#     assert res[-1]["incident_id"] == 4
#
#
# def test_get_events(client):
#     """
#     Given: A mock Forcepoint DLP client.
#     When: Running get-events with a limit of 1, while there are four open incidents.
#     Then: Ensure only one event is returned.
#     """
#     _, events = get_events_command(client, {"limit": 1})
#     assert len(events) == 1
#     assert events[0]["incident_id"] == 0


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


def generate_mocked_event(event_id, event_time):
    return {
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
            "manager": "John Doe"
        },
        "status": "New",
        "transaction_size": 423151,
        "violation_triggers": 1
    }


@pytest.mark.parametrize(
    "scenario, first_fetch, utc_now, max_fetch, last_fetch_time, api_limit, last_events_ids, incidents_per_time,"
    "returned_events_ids, forward_last_events_ids, forward_last_fetch, backward_done, backward_last_events_ids,"
    "backward_last_fetch, backward_to_time",
    [
        # (
        #     "get all events between the timespan",  # scenario
        #     "01/01/2020 00:00:00",  # first fetch
        #     "01/01/2020 00:01:00",  # utc now
        #     10,  # max_fetch.
        #     "01/01/2020 00:00:00",  # last_fetch_time
        #     10,  # max API returned limit.
        #     [],  # last_events_ids
        #     {  # incidents_per_time
        #         ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): {
        #             1: "01/01/2020 00:00:01",
        #             2: "01/01/2020 00:00:02",
        #             3: "01/01/2020 00:00:03",
        #             4: "01/01/2020 00:00:04",
        #             5: "01/01/2020 00:00:05",
        #             6: "01/01/2020 00:00:06",
        #             7: "01/01/2020 00:00:07",
        #             8: "01/01/2020 00:00:08",
        #             9: "01/01/2020 00:00:09",
        #             10: "01/01/2020 00:00:10",
        #         },
        #     },
        #     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # returned_events_ids
        #     [10],  # forward_last_events_ids
        #     "01/01/2020 00:00:10",  # forward_last_fetch
        #     False,  # backward_done
        #     [],  # backward_last_events_ids
        #     "01/01/2020 00:00:00",  # backward_last_fetch
        #     "01/01/2020 00:01:00",  # backward_to_time
        # ),
        # (
        #     "all events were already fetched, force move to next second",  # scenario
        #     "01/01/2020 00:00:00",  # first fetch
        #     "01/01/2020 00:01:00",  # utc now
        #     10,  # max_fetch.
        #     "01/01/2020 00:00:00",  # last_fetch_time
        #     10,  # max API returned limit.
        #     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # last_events_ids
        #     {  # incidents_per_time
        #         ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): {
        #             1: "01/01/2020 00:00:00",
        #             2: "01/01/2020 00:00:00",
        #             3: "01/01/2020 00:00:00",
        #             4: "01/01/2020 00:00:00",
        #             5: "01/01/2020 00:00:00",
        #             6: "01/01/2020 00:00:00",
        #             7: "01/01/2020 00:00:00",
        #             8: "01/01/2020 00:00:00",
        #             9: "01/01/2020 00:00:00",
        #             10: "01/01/2020 00:00:00",
        #         },
        #     },
        #     [],  # returned_events_ids
        #     [],  # forward_last_events_ids
        #     "01/01/2020 00:00:01",  # forward_last_fetch
        #     False,  # backward_done
        #     [],  # backward_last_events_ids
        #     "01/01/2020 00:00:00",  # backward_last_fetch
        #     "01/01/2020 00:01:00",  # backward_to_time
        # ),
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
    ]
)
def test_fetch_events(mocker, scenario, first_fetch, utc_now, max_fetch, last_fetch_time, api_limit, last_events_ids,
                      incidents_per_time, returned_events_ids, forward_last_events_ids, forward_last_fetch,
                      backward_done, backward_last_events_ids, backward_last_fetch, backward_to_time):

    def mock_get_incidents(from_date, to_date):
        from_date_str = to_str_time(from_date)
        to_date_str = to_str_time(to_date)
        incidents = [generate_mocked_event(event_id, event_time)
                     for event_id, event_time in incidents_per_time.get((from_date_str, to_date_str)).items()]
        return {
            "incidents": incidents[:api_limit],
            "total_count": len(incidents),
            "total_returned": min(len(incidents), api_limit)
        }

    mocked_client = mocker.Mock()
    mocked_client.get_incidents.side_effect = mock_get_incidents
    mocked_client.api_limit = api_limit
    mocked_client.utc_now = dateparser.parse(utc_now)

    mocked_send_events_to_xsiam = mocker.patch('ForcepointEventCollector.send_events_to_xsiam')
    mocked_demisto_set_last_run = mocker.patch.object(demisto, 'setLastRun')

    last_run = {
        "forward": {
            "last_fetch": last_fetch_time,
            "last_events_ids": last_events_ids,
        }
    }

    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)

    fetch_events(
        client=mocked_client,
        first_fetch=dateparser.parse(first_fetch),
        max_fetch=max_fetch,
    )

    assert mocked_send_events_to_xsiam.called, f"{scenario} - send event to xsiam wasn't called"
    assert [event["id"] for event in mocked_send_events_to_xsiam.call_args.args[0]] == returned_events_ids, \
        f"{scenario} - event ids don't match"
    assert mocked_demisto_set_last_run.called, f"{scenario} - set last run wasn't called"
    assert mocked_demisto_set_last_run.call_args.args[0] == {
        'forward': {
            'last_events_ids': forward_last_events_ids,
            'last_fetch': forward_last_fetch
        },
        'backward': {
            "done": backward_done,
            "last_events_ids": backward_last_events_ids,
            "last_fetch": backward_last_fetch,
            "to_time": backward_to_time
        },
    }, f"{scenario} - set last run doesn't match expected value"
