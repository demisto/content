import pytest
from CommonServerPython import DemistoException
import demistomock as demisto  # noqa: F401
from datetime import datetime, UTC
import json
from freezegun import freeze_time

BASE_URL = "https://api.zoom.us/v2/"
MAX_RECORDS_PER_PAGE = 300


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize("first_fetch_time, expected_result, expect_error", [
    ("3 days", "First fetch timestamp: 2023-03-29 00:00:00", False),
    ("6 months", "First fetch timestamp: 2022-10-02 00:00:00", False),
    ("7 months",
     "The First fetch time should fall within the last six months."
     " Please provide a valid date within the last six months.", True)
])
@freeze_time("2023-04-01 00:00:00")
def test_main(first_fetch_time, expected_result, expect_error, mocker):
    """
    Given:
        - 'first_fetch_time': A string representing the first fetch time to be used in the command.
        - 'expected_result': The expected result of the command function.
        - 'expect_error': A boolean indicating whether an error is expected to be raised.
    When:
        - Running the 'main' function.
    Then:
        If 'expect_error' is True: Checks that a 'DemistoException' is raised with a message that
         matches the 'expected_result'.
        If 'expect_error' is False:
            Checks that the output of the command function matches the 'expected_result'.
            Checks that the 'demisto.results' function was called once with the value 'ok'.
            Checks that the 'demisto.info' function was called with the appropriate output.
    """
    from ZoomEventCollector import main

    params = {
        "url": BASE_URL,
        "credentials": {"identifier": "test_id", "password": "test_secret"},
        "account_id": "test_account",
        "first_fetch": first_fetch_time,
    }
    args = {}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value=args)

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, 'results')
    mocker.patch('ZoomEventCollector.Client.get_oauth_token', return_value=('token', None))
    mocker.patch('ZoomEventCollector.Client.search_events', return_value={
        "from": "2023-03-31",
        "to": "2023-04-01",
        "page_size": 300,
        "next_page_token": "",
        "operation_logs": []
    })
    mocker_info = mocker.patch.object(demisto, "info")
    mock_return_error = mocker.patch('ZoomEventCollector.return_error')

    if expect_error:
        main()
        assert mock_return_error.called
        mock_return_error.assert_called_with(f'Failed to execute test-module command.\nError:\n{str(expected_result)}')
    else:
        main()

        output = mocker_info.call_args[0][0]

        assert output == expected_result
        assert demisto.results.call_count == 1
        assert demisto.results.call_args[0][0] == 'ok'
        assert mock_return_error.call_count == 0


@freeze_time("2023-03-30 00:00:00")
def test_fetch_events(mocker):
    """
    Tests the fetch_events function

    Given:
        - first_fetch_time
    When:
        - Running the 'fetch_events' function.
    Then:
        - Validates that the function generates the correct API requests with the expected parameters.
        - Validates that the function returns the expected events and next_run timestamps.
    """
    from ZoomEventCollector import fetch_events, Client

    first_fetch_time = datetime(2023, 3, 1).replace(tzinfo=UTC)

    http_request_mocker = mocker.patch.object(Client, "error_handled_http_request", side_effect=[
        util_load_json('test_data/fetch_events_operationlogs.json').get('fetch_events_month_before'),
        util_load_json('test_data/fetch_events_operationlogs.json').get('fetch_events'),
        util_load_json('test_data/fetch_events_activities.json').get('fetch_events_month_before'),
        util_load_json('test_data/fetch_events_activities.json').get('fetch_events'),
    ])

    mocker.patch('ZoomEventCollector.Client.get_oauth_token', return_value=('token', None))
    mocker.patch.object(Client, "generate_oauth_token")

    client = Client(base_url=BASE_URL)
    next_run, events = fetch_events(client, last_run={},
                                    first_fetch_time=datetime(2023, 2, 1).replace(tzinfo=UTC))

    mock_events = util_load_json('test_data/zoom_fetch_events.json')
    assert http_request_mocker.call_args_list[0][1].get("params") == {'page_size': 300, 'from': '2023-02-01',
                                                                      'to': '2023-03-01'}
    assert http_request_mocker.call_args_list[1][1].get("params") == {'page_size': 300, 'from': '2023-03-02',
                                                                      'to': '2023-03-30'}
    assert http_request_mocker.call_args_list[2][1].get("params") == {'page_size': 300, 'from': '2023-02-01',
                                                                      'to': '2023-03-01'}
    assert http_request_mocker.call_args_list[3][1].get("params") == {'page_size': 300, 'from': '2023-03-02',
                                                                      'to': '2023-03-30'}
    assert http_request_mocker.call_args_list[0][1].get("url_suffix") == 'report/operationlogs'
    assert http_request_mocker.call_args_list[2][1].get("url_suffix") == 'report/activities'

    assert events == mock_events
    assert next_run == {'activities': '2023-03-29T11:38:50Z', 'operationlogs': '2023-03-21T08:22:09Z'}

    # assert no new results when given the last_run:

    mocker.patch.object(Client, "error_handled_http_request", side_effect=[
        util_load_json('test_data/fetch_events_operationlogs.json').get('fetch_events'),
        util_load_json('test_data/fetch_events_activities.json').get('fetch_events')
    ])

    next_run, events = fetch_events(client, last_run={'activities': '2023-03-29T11:38:50Z',
                                                      'operationlogs': '2023-03-21T08:22:09Z'},
                                    first_fetch_time=first_fetch_time)
    assert events == []
    assert next_run == {'activities': '2023-03-29T11:38:50Z', 'operationlogs': '2023-03-21T08:22:09Z'}


@freeze_time("2023-03-30 00:00:00")
def test_fetch_events_with_last_run(mocker):
    """
    Tests the fetch_events function

    Given:
        - last run object
        - the first request returns next_page_token
        *NOTE* The test simulates a situation where next token is returned, in reality there is no reason why
        next_token would be returned if it is not over 300 results
    When:
        - Running the 'fetch_events' function.
    Then:
        - Ensure the events are returned as expected and the pagination is working as expected
    """
    from ZoomEventCollector import fetch_events, Client
    first_fetch_time = datetime(2023, 3, 1).replace(tzinfo=UTC)

    http_request_mocker = mocker.patch.object(Client, "error_handled_http_request", side_effect=[
        util_load_json('test_data/fetch_events_operationlogs.json').get('fetch_events_with_token'),
        util_load_json('test_data/fetch_events_operationlogs.json').get('fetch_events_with_token_next'),
        util_load_json('test_data/fetch_events_activities.json').get('fetch_events_with_token'),
        util_load_json('test_data/fetch_events_activities.json').get('fetch_events_with_token_next')
    ])

    mocker.patch('ZoomEventCollector.Client.get_oauth_token', return_value=('token', None))
    mocker.patch.object(Client, "generate_oauth_token")

    client = Client(base_url=BASE_URL)
    next_run, events = fetch_events(client, last_run={'activities': "2023-03-21T08:14:27Z",
                                                      'operationlogs': "2023-03-20T16:37:58Z"},
                                    first_fetch_time=first_fetch_time)

    mock_events = util_load_json('test_data/zoom_fetch_events_with_token.json')
    assert http_request_mocker.call_args_list[0][1].get("params") == {'page_size': 300, 'from': '2023-03-20',
                                                                      'to': '2023-03-30'}
    assert http_request_mocker.call_args_list[1][1].get("params") == {'page_size': 300, 'from': '2023-03-20',
                                                                      'to': '2023-03-30',
                                                                      'next_page_token': 'next_token_operationlogs'}
    assert http_request_mocker.call_args_list[2][1].get("params") == {'page_size': 300, 'from': '2023-03-21',
                                                                      'to': '2023-03-30'}
    assert http_request_mocker.call_args_list[3][1].get("params") == {'page_size': 300, 'from': '2023-03-21',
                                                                      'to': '2023-03-30',
                                                                      'next_page_token': 'next_token_activities'}
    assert http_request_mocker.call_args_list[0][1].get("url_suffix") == 'report/operationlogs'
    assert http_request_mocker.call_args_list[2][1].get("url_suffix") == 'report/activities'

    assert events == mock_events
    assert next_run == {'activities': '2023-03-29T11:38:50Z', 'operationlogs': '2023-03-21T08:22:09Z'}


@freeze_time("2023-03-30 00:00:00")
def test_get_events_command(mocker):
    """
    Tests the get-events command function.

        Given:
            - NetBox client and limit of events to fetch
        When:
            - Running the 'get_events' function.
        Then:
            - Checks that the events returned by the 'get_events' function match the expected events.
            - Checks that an exception is raised when the limit exceeds the maximum number of records per page.
    """
    from ZoomEventCollector import get_events, Client

    http_request_mocker = mocker.patch.object(Client, "error_handled_http_request", side_effect=[
        util_load_json('test_data/get_events_operationlogs.json'),
        util_load_json('test_data/get_events_activities.json')
    ])

    mocker.patch('ZoomEventCollector.Client.get_oauth_token', return_value=('token', None))
    mocker.patch.object(Client, "generate_oauth_token")

    client = Client(base_url=BASE_URL)
    events, results = get_events(client, limit=2,
                                 first_fetch_time=datetime(2023, 3, 1).replace(tzinfo=UTC))

    mock_events = util_load_json('test_data/zoom_get_events.json')
    assert http_request_mocker.call_args_list[0][1].get("params") == {'page_size': 2, 'from': '2023-03-01',
                                                                      'to': '2023-03-30'}
    assert http_request_mocker.call_args_list[1][1].get("params") == {'page_size': 2, 'from': '2023-03-01',
                                                                      'to': '2023-03-30'}
    assert http_request_mocker.call_args_list[0][1].get("url_suffix") == 'report/operationlogs'
    assert http_request_mocker.call_args_list[1][1].get("url_suffix") == 'report/activities'
    assert events == mock_events

    # Test limit > MAX_RECORDS_PER_PAGE
    with pytest.raises(DemistoException) as e:
        get_events(client, limit=MAX_RECORDS_PER_PAGE + 1,
                   first_fetch_time=datetime(2023, 3, 1).replace(tzinfo=UTC))
    assert e.value.message == f"The requested limit ({MAX_RECORDS_PER_PAGE + 1}) exceeds the maximum number of " \
                              f"records per page ({MAX_RECORDS_PER_PAGE}). Please reduce the limit and try again."


@pytest.mark.parametrize(
    "input_date, expected_output",
    [
        (datetime(2021, 12, 3), datetime(2022, 1, 3)),
        (datetime(2022, 1, 31), datetime(2022, 2, 28)),
        (datetime(2022, 2, 28), datetime(2022, 3, 28)),
        (datetime(2020, 2, 29), datetime(2020, 3, 29)),
    ],
)
def test_get_next_month(input_date: datetime, expected_output: datetime):
    """
    Given -
        input_date: A datetime object representing the input date.
        expected_output: A datetime object representing the date of the next month on the same day.

    When -
        The function get_next_month is called with the input_date.

    Then -
        Validate that the output of get_next_month is equal to expected_output.
    """
    from ZoomEventCollector import get_next_month

    assert get_next_month(input_date) == expected_output
