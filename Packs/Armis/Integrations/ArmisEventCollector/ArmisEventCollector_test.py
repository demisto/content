from ArmisEventCollector import Client, datetime, DemistoException, arg_to_datetime, EVENT_TYPE, EVENT_TYPES
import pytest


@pytest.fixture
def dummy_client(mocker):
    """
    A dummy client fixture for testing.
    """
    mocker.patch.object(Client, 'is_valid_access_token', return_value=True)
    return Client(base_url='test_base_url', api_key='test_api_key', access_token='test_access_token', verify=False, proxy=False)


class TestClientFunctions:

    def test_fetch_by_aql_query(self, mocker, dummy_client):
        """
        Given:
            - A valid HTTP request parameters.
        When:
            - Fetching events.
        Then:
            - Make sure the request is sent with right parameters.
            - Make sure the pagination logic performs as expected.
        """
        first_response = {'data': {'next': 1, 'results': [{
            'unique_id': '1',
            'time': '2023-01-01T01:00:10.123456+00:00'
        }]}}

        second_response = {'data': {'next': None, 'results': [{
            'unique_id': '2',
            'time': '2023-01-01T01:00:20.123456+00:00'
        }]}}

        expected_result = [{
            'unique_id': '1',
            'time': '2023-01-01T01:00:10.123456+00:00'
        }, {
            'unique_id': '2',
            'time': '2023-01-01T01:00:20.123456+00:00'
        }]
        mocker.patch.object(Client, '_http_request', side_effect=[first_response, second_response])
        assert dummy_client.fetch_by_aql_query('example_query', 3) == expected_result


class TestHelperFunction:

    date_1 = '2023-01-01T01:00:00'
    date_2 = '2023-01-01T02:00:00'
    datetime_1 = arg_to_datetime(date_1)
    datetime_2 = arg_to_datetime(date_2)

    # test_calculate_fetch_start_time parametrize arguments
    case_last_run_exist = (date_1, datetime_2, datetime_1)
    case_from_date_parameter = (None, datetime_1, datetime_1)  # type: ignore
    case_first_fetch_no_from_date_parameter = (None, None, None)

    @pytest.mark.parametrize(
        "last_fetch_time, fetch_start_time_param, expected_result", [
            case_last_run_exist, case_from_date_parameter, case_first_fetch_no_from_date_parameter]
    )
    def test_calculate_fetch_start_time(self, last_fetch_time, fetch_start_time_param, expected_result):
        """
        Given:
            - Case 1: last_fetch_time exist in last_run, thus being prioritized (fetch-events / armis-get-events commands).
            - Case 2: last_run is empty & from_date parameter exist (armis-get-events command with from_date argument).
            - Case 3: first fetch in the instance (no last_run),
                      this will set the current date time (fetch-events / armis-get-events commands).
        When:
            - Calculating fetch start time from current fetch cycle.
        Then:
            - Case 1: Prefer last_fetch_time from last run and convert it to a valid datetime object.
            - Case 2: Use provided fetch_start_time_param (usually current time) datetime object.
            """
        from ArmisEventCollector import calculate_fetch_start_time
        assert calculate_fetch_start_time(last_fetch_time, fetch_start_time_param) == expected_result

    @pytest.mark.parametrize('x, y, expected_result', [(datetime_1, datetime_1, True), (datetime_1, datetime_2, False)])
    def test_are_two_event_time_equal(self, x, y, expected_result):
        """
        Given:
            - Case 1: First and last datetime objected from the API response are equal up to seconds attribute.
            - Case 2: First and last datetime objected from the API response are not equal.
        When:
            - Verifying if all events in the API response have the same time up to seconds.
        Then:
            - Case 1: Return True.
            - Case 2: Return False.
        """
        from ArmisEventCollector import are_two_datetime_equal_by_second
        assert are_two_datetime_equal_by_second(x, y) == expected_result

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
    }], ['3']))
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
        from ArmisEventCollector import dedup_events
        assert dedup_events(events, events_last_fetch_ids, unique_id_key) == expected_result

    def test_fetch_by_event_type(self, mocker, dummy_client):
        """
        Given:
            - A valid event type arguments for API request (unique_id_key, aql_query, type).
        When:
            - Iterating over which event types to fetch.
        Then:
            - Perform fetch for the specific event type, update event list and update
              last run dictionary for next fetch cycle.
        """
        from ArmisEventCollector import fetch_by_event_type
        event_type = EVENT_TYPE('unique_id', 'example:query', 'events')
        events: list[dict] = []
        next_run: dict = {}
        last_run = {'events_last_fetch_time': '2023-01-01T01:00:20', 'events_last_fetch_ids': ['1', '2']}
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

        assert events == [{'unique_id': '3', 'time': '2023-01-01T01:00:30.123456+00:00'}]
        assert next_run == {'events_last_fetch_ids': ['3'], 'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00'}

    # test_add_time_to_events parametrize arguments
    case_one_event = (
        [{'time': '2023-01-01T01:00:10.123456+00:00', 'unique_id': '1'}
         ], [{'time': '2023-01-01T01:00:10.123456+00:00', '_time': '2023-01-01T01:00:10.123456+00:00', 'unique_id': '1'}]
    )

    case_two_events = (
        [{'time': '2023-01-01T01:00:10.123456+00:00', 'unique_id': '1'},
            {'time': '2023-01-01T01:00:20.123456+00:00', 'unique_id': '2'}],
        [{'time': '2023-01-01T01:00:10.123456+00:00', '_time': '2023-01-01T01:00:10.123456+00:00', 'unique_id': '1'},
         {'time': '2023-01-01T01:00:20.123456+00:00', '_time': '2023-01-01T01:00:20.123456+00:00', 'unique_id': '2'}]
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
            - Case 3: Empty list of events.
        When:
            - Preparing to send fetched events to XSIAM.
        Then:
            - Add _time attribute to each event with a valid time attribute.
        """
        from ArmisEventCollector import add_time_to_events
        add_time_to_events(events)
        assert events == expected_result

    def test_events_to_command_results(self):
        """
        Given:
            - A valid list of fetched events.
        When:
            - Using the 'armis-get-event' command.
        Then:
            - A command result with readable output will be printed to the war-room.
        """
        from ArmisEventCollector import CommandResults, VENDOR, PRODUCT, events_to_command_results, tableToMarkdown
        response_with_two_events = [{'time': '2023-01-01T01:00:10.123456+00:00',
                                     '_time': '2023-01-01T01:00:10',
                                     'unique_id': '1'},
                                    {'time': '2023-01-01T01:00:20.123456+00:00',
                                     '_time': '2023-01-01T01:00:20', 'unique_id': '2'}]
        expected_result = CommandResults(
            raw_response=response_with_two_events,
            readable_output=tableToMarkdown(name=f'{VENDOR} {PRODUCT} events', t=response_with_two_events, removeNull=True))
        assert events_to_command_results(response_with_two_events).readable_output == expected_result.readable_output


class TestFetchFlow:

    fetch_start_time = arg_to_datetime('2023-01-01T01:00:00')

    events_with_different_time_1 = [
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
        }]
    events_with_different_time_2 = [
        {
            'unique_id': '4',
            'time': '2023-01-01T01:00:40.123456+00:00'
        },
        {
            'unique_id': '5',
            'time': '2023-01-01T01:00:50.123456+00:00'
        },
        {
            'unique_id': '6',
            'time': '2023-01-01T01:01:00.123456+00:00'
        },
        {
            'unique_id': '7',
            'time': '2023-01-01T01:01:00.123456+00:00'
        }]
    events_with_duplicated_from_1 = [
        {
            'unique_id': '1',
            'time': '2023-01-01T01:00:10.123456+00:00'
        },
        {
            'unique_id': '2',
            'time': '2023-01-01T01:00:20.123456+00:00'
        },
        {
            'unique_id': '6',
            'time': '2023-01-01T01:01:00.123456+00:00'
        },
        {
            'unique_id': '7',
            'time': '2023-01-01T01:01:00.123456+00:00'
        }]
    events_with_same_time = [  # type: ignore
        {
            'unique_id': '4',
            'time': '2023-01-01T01:00:30.123456+00:00'
        },
        {
            'unique_id': '5',
            'time': '2023-01-01T01:00:30.123456+00:00'
        },
        {
            'unique_id': '6',
            'time': '2023-01-01T01:00:30.123456+00:00'
        }]

    case_first_fetch = (  # type: ignore
        1000,
        {},
        fetch_start_time,
        ['Events'],
        events_with_different_time_1,
        events_with_different_time_1,
        {'events_last_fetch_ids': ['3'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'}
    )
    case_second_fetch = (  # type: ignore
        1000,
        {'events_last_fetch_ids': ['1', '2', '3'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'},
        fetch_start_time,
        ['Events'],
        events_with_different_time_2,
        events_with_different_time_2,
        {'events_last_fetch_ids': ['7', '6'],
            'events_last_fetch_time': '2023-01-01T01:01:00.123456+00:00', 'access_token': 'test_access_token'}
    )
    case_second_fetch_with_duplicates = (  # type: ignore
        1000,
        {'events_last_fetch_ids': ['1', '2', '3'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'},
        fetch_start_time,
        ['Events'],
        events_with_duplicated_from_1,
        [{
            'unique_id': '6',
            'time': '2023-01-01T01:01:00.123456+00:00'
        },
            {
            'unique_id': '7',
            'time': '2023-01-01T01:01:00.123456+00:00'
        }],
        {'events_last_fetch_ids': ['7', '6'],
            'events_last_fetch_time': '2023-01-01T01:01:00.123456+00:00', 'access_token': 'test_access_token'}
    )

    case_no_new_event_from_fetch = (  # type: ignore
        1000,
        {'events_last_fetch_ids': ['1', '2', '3'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'},
        fetch_start_time,
        ['Events'],
        [],
        [],
        {'events_last_fetch_ids': ['1', '2', '3'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'}
    )

    case_all_events_from_fetch_have_the_same_time = (  # type: ignore
        1000,
        {'events_last_fetch_ids': ['1', '2', '3'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'},
        fetch_start_time,
        ['Events'],
        events_with_same_time,
        events_with_same_time,
        {'events_last_fetch_ids': ['1', '2', '3', '4', '5', '6'],
            'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00', 'access_token': 'test_access_token'}
    )

    @ pytest.mark.parametrize('max_fetch, last_run, fetch_start_time, event_types_to_fetch, response, events, next_run', [
        case_first_fetch, case_second_fetch, case_second_fetch_with_duplicates,
        case_no_new_event_from_fetch, case_all_events_from_fetch_have_the_same_time
    ])
    def test_fetch_flow_cases(self, mocker, dummy_client, max_fetch, last_run,
                              fetch_start_time, event_types_to_fetch, response, events, next_run):
        """
        Given:
            - Case 1: First fetch, response has 3 events with different timestamps.
            - Case 2: Second fetch, response has 3 events with different timestamps.
            - Case 3: Second fetch with duplicated, some events in the response have same timestamps as last fetch.
            - Case 4: Second fetch with empty response (no new events from last fetch).
            - Case 5: Second fetch, all events have the same timestamp.
        When:
            - Fetching events.
        Then:
            - Case 1: Handle the fetch, validate events and next_run variables.
            - Case 2: Handle the fetch, validate events and next_run variables.
            - Case 3: Handle the fetch, validate dedup, validate events and next_run variables.
            - Case 4: Handle the fetch, validate dedup, validate events and next_run (same as last_run).
            - Case 5: Handle the fetch, validate dedup, validate events & last_run variable has IDs from current and last fetch.

        """
        from ArmisEventCollector import fetch_events
        mocker.patch.object(Client, 'fetch_by_aql_query', return_value=response)
        mocker.patch.dict(EVENT_TYPES, {'Events': EVENT_TYPE('unique_id', 'events_query', 'events')})
        assert fetch_events(dummy_client, max_fetch, last_run,
                            fetch_start_time, event_types_to_fetch) == (events, next_run)

    case_access_token_expires_in_runtime = ()

    def test_token_expires_in_runtime(self, mocker, dummy_client):
        """
        Given:
            - Access token has expired in runtime.
        When:
            - Fetching events.
        Then:
            - Catch the specific exception, updated the access token and perform a second attempt
              to fetch events for the current event type iteration.
        """
        from ArmisEventCollector import fetch_events
        events_with_different_time = [
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
            }]
        fetch_start_time = arg_to_datetime('2023-01-01T01:00:00')
        mocker.patch.object(Client, 'fetch_by_aql_query', side_effect=[DemistoException(
            message='Invalid access token'), events_with_different_time])
        mocker.patch.dict(EVENT_TYPES, {'Events': EVENT_TYPE('unique_id', 'events_query', 'events')})
        mocker.patch.object(Client, 'update_access_token')
        if fetch_start_time:
            last_run = {'events_last_fetch_ids': ['3'],
                        'events_last_fetch_time': '2023-01-01T01:00:30.123456+00:00',
                        'access_token': 'test_access_token'}
            assert fetch_events(dummy_client, 1000, {}, fetch_start_time, [
                'Events']) == (events_with_different_time, last_run)
