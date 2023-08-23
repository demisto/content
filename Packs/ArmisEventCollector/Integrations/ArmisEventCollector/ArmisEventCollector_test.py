from ArmisEventCollector import *
import pytest


@pytest.fixture
def dummy_client(mocker):
    """
    A dummy client fixture for testing.
    """
    mocker.patch.object(Client, 'is_valid_access_token', return_value=True)
    return Client(base_url='test_bae_url', api_key='test_api_key', access_token='test_access_token', verify=False, proxy=False)


class TestHelperFunction:

    # test_calculate_fetch_start_time & test_are_two_event_time_equal parametrize arguments
    date_1 = '2023-01-01T01:00:00'
    date_2 = '2023-01-01T02:00:00'
    datetime_1 = arg_to_datetime(date_1)
    datetime_2 = arg_to_datetime(date_2)

    @pytest.mark.parametrize(
        "last_fetch_time, fetch_start_time_param, expected_result", [
            (date_1, datetime_2, datetime_1), (None, datetime_2, datetime_2)]
    )
    def test_calculate_fetch_start_time(self, last_fetch_time, fetch_start_time_param, expected_result):
        """
            Given:
                - Case 1: last_fetch_time from last run exist
                - Case 2: last_fetch_time from last run does not exist (first fetch)
            When:
                - Calculating fetch start time from current fetch cycle.
            Then:
                - Case 1: Prefer last_fetch_time from last run and convert it to a valid datetime object.
                - Case 2: Use provided fetch_start_time_param (usually current time) datetime object.
            """
        assert calculate_fetch_start_time(last_fetch_time, fetch_start_time_param) == expected_result

    @pytest.mark.parametrize('x, y, expected_result', [(datetime_1, datetime_1, True), (datetime_1, datetime_2, False)])
    def test_are_two_event_time_equal(self, x, y, expected_result):
        """
            Given:
                - Case 1: first and last datetime objected from the API response are equal up to seconds attribute.
                - Case 2: first and last datetime objected from the API response are not equal.
            When:
                - Verifying if all events in the API response have the same time up to seconds.
            Then:
                - Case 1: Return True.
                - Case 2: Return False.
            """
        assert are_two_event_time_equal(x, y) == expected_result

    # test_dedup_events parametrize arguments
    case_all_events_with_same_time = ([
        {
            'unique_id': '1',
            'time': '2023-01-01T01:00:00.123456+00:00'
        },
        {
            'unique_id': '2',
            'time': '2023-01-01T01:00:00.123456+00:00'
        },
        {
            'unique_id': '3',
            'time': '2023-01-01T01:00:00.123456+00:00'
        }
    ], ['0', '1', '2'], 'unique_id', ([{
        'unique_id': '3',
        'time': '2023-01-01T01:00:00.123456+00:00'
    }], ['0', '1', '2', '3']))
    case_events_with_different_time = ([
        {
            'unique_id': '1',
            'time': '2023-01-01T01:00:10.123456+00:00'
        },
        {
            'unique_id': '2',
            'time': '2023-01-01T01:00:20.123456+00:00'
        },
        {
            'unique_id': '3',
            'time': '2023-01-01T01:00:30.123456+00:00'
        }
    ], ['2'], 'unique_id', ([{
        'unique_id': '1',
        'time': '2023-01-01T01:00:10.123456+00:00'
    }, {
        'unique_id': '3',
        'time': '2023-01-01T01:00:30.123456+00:00'
    }], ['1', '3']))
    case_empty_event_list: tuple = ([], ['1', '2', '3'], 'unique_id', ([], ['1', '2', '3']))

    @pytest.mark.parametrize('events, events_last_fetch_ids, unique_id_key, expected_result', [
        case_all_events_with_same_time,
        case_events_with_different_time,
        case_empty_event_list
    ])
    def test_dedup_events(self, events, events_last_fetch_ids, unique_id_key, expected_result):
        """
        Given:
            - Case 1: All events from the current fetch cycle have the same timestamp.
            - Case 2: Most recent event has later timestamp then other events in the response.
            - Case 3: Empty event list (no new events received from API response).
        When:
            - Using the dedup mechanism while fetching events.
        Then:
            - Case 1: Add the list of fetched events IDs to current 'events_last_fetch_ids' from last run,
                    return list of dedup event and updated list of 'events_last_fetch_ids' for next run.
            - Case 2: Return list of dedup event and new list of 'new_ids' for next run.
            - Case 3: Return empty list and the unchanged list of 'events_last_fetch_ids' for next run.
        """
        assert dedup_events(events, events_last_fetch_ids, unique_id_key) == expected_result

    def test_fetch_by_event_type(self, mocker, dummy_client):
        """
        Given:
            - a valid event type arguments for API request (unique_id_key, aql_query, type).
        When:
            - Iterating over which event types to fetch.
        Then:
            - Case 1: Perform fetch for the specific event type, update event list and update
                      last run dictionary for next fetch cycle.
        """
        event_type = {
            'unique_id_key': 'unique_id',
            'aql_query': 'example:query',
            'type': 'events'}
        events: list[dict] = []
        next_run: dict = {}
        last_run = {'events_last_fetch_time': '2023-01-01T02:00:00', 'events_last_fetch_ids': ['2', '3']}
        fetch_start_time_param = datetime.now()
        response = [
            {
                'unique_id': '1',
                'time': '2023-01-01T01:00:10.123456+00:00'
            },
            {
                'unique_id': '2',
                'time': '2023-01-01T01:00:20.123456+00:00'
            },
            {
                'unique_id': '3',
                'time': '2023-01-01T01:00:30.123456+00:00'
            }
        ]
        mocker.patch.object(Client, 'fetch_by_aql_query', return_value=response)

        fetch_by_event_type(event_type, events, next_run, dummy_client, 1, last_run, fetch_start_time_param)

        assert events == [{'unique_id': '1', 'time': '2023-01-01T01:00:10.123456+00:00'}]
        assert next_run == {'events_last_fetch_ids': ['1'], 'events_last_fetch_time': '2023-01-01T01:00:10.123456+00:00'}

    # test_add_time_to_events parametrize arguments
    case_one_event = (
        [{'time': '2023-01-01T01:00:10.123456+00:00', 'unique_id': '1'}
         ], [{'time': '2023-01-01T01:00:10.123456+00:00', '_time': '2023-01-01T01:00:10', 'unique_id': '1'}]
    )

    case_two_events = (
        [{'time': '2023-01-01T01:00:10.123456+00:00', 'unique_id': '1'},
            {'time': '2023-01-01T01:00:20.123456+00:00', 'unique_id': '2'}],
        [{'time': '2023-01-01T01:00:10.123456+00:00', '_time': '2023-01-01T01:00:10', 'unique_id': '1'},
         {'time': '2023-01-01T01:00:20.123456+00:00', '_time': '2023-01-01T01:00:20', 'unique_id': '2'}]
    )
    case_empty_event: tuple = (
        [], []
    )

    @pytest.mark.parametrize('events, expected_result', [
        case_one_event,
        case_two_events,
        case_empty_event,
    ])
    def test_add_time_to_events(self, events, expected_result):
        """
        Given:
            - Case 1: One event with valid time attribute.
            - Case 2: Two event with valid time attribute.
            - Case 3: Empty list og events.
        When:
            - Preparing to send fetched events to XSIAM.
        Then:
            - Add _time attribute to each event with a valid time attribute.
        """
        add_time_to_events(events)
        assert events == expected_result

    def test_events_to_command_results(self):
        """
        Given:
            - Case 1: Valid list of fetched events.
        When:
            - Using the 'armis-get-event' command.
        Then:
            - A command result with readable output will be printed to the war-room.
        """
        response_with_two_events = [{'time': '2023-01-01T01:00:10.123456+00:00',
                                     '_time': '2023-01-01T01:00:10',
                                     'unique_id': '1'},
                                    {'time': '2023-01-01T01:00:20.123456+00:00',
                                     '_time': '2023-01-01T01:00:20', 'unique_id': '2'}]
        expected_result = CommandResults(
            raw_response=response_with_two_events,
            readable_output=tableToMarkdown(name=f'{VENDOR} {PRODUCT} events', t=response_with_two_events, removeNull=True))
        assert events_to_command_results(response_with_two_events).readable_output == expected_result.readable_output


class TestFetch:
    ...
