
import pytest
import json
import dateparser
from freezegun import freeze_time
from datetime import datetime, timedelta
import demistomock as demisto
from unittest.mock import MagicMock, patch
from DuoEventCollector import (Client, GetEvents, LogType, Params, parse_events, main,
                               parse_mintime, validate_request_order_array, calculate_window)
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


@pytest.fixture
def ret_fresh_client(ret_fresh_parameters):
    return Client(Params(**ret_fresh_parameters, mintime={}))   # type: ignore


@pytest.fixture
def ret_fresh_parameters():
    params = {
        "after": "1 month",
        "host": "api-a1fdb00d.duosecurity.com",
        "integration_key": "DI47EXXXXXXXWRYV2",
        "limit": "5",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "YK6mtSzXXXXXXXXXXX", "passwordChanged": False},
        "fetch_delay": "0"
    }
    calculate_window(params)
    return params


global_demisto_params = {
    "after": "1 month",
    "host": "api-a1fdb00d.duosecurity.com",
    "integration_key": "DI47EXXXXXXXWRYV2",
    "limit": "5",
    "proxy": False,
    "retries": "5",
    "secret_key": {"password": "YK6mtSzXXXXXXXXXXX", "passwordChanged": False},
    "fetch_delay": "0"
}

calculate_window(global_demisto_params)
client = Client(Params(**global_demisto_params, mintime={}))     # type: ignore

get_events = GetEvents(
    client=client,
    request_order=[LogType.AUTHENTICATION, LogType.ADMINISTRATION, LogType.TELEPHONY],
)


def load_json(file: str) -> dict:
    with open(file) as f:
        return json.load(f)


def test_rotate_request_order():
    get_events.rotate_request_order()
    assert get_events.request_order == [
        LogType.ADMINISTRATION,
        LogType.TELEPHONY,
        LogType.AUTHENTICATION,
    ]
    get_events.rotate_request_order()
    get_events.rotate_request_order()
    assert get_events.request_order == [
        LogType.AUTHENTICATION,
        LogType.ADMINISTRATION,
        LogType.TELEPHONY,
    ]


@pytest.mark.parametrize(
    "event, expected_res",
    [
        (
            [{"event1": "event1", "isotimestamp": "2020-01-23T16:18:58+00:00"}],
            [
                {
                    "event1": "event1",
                    "isotimestamp": "2020-01-23T16:18:58+00:00",
                    "_time": "2020-01-23T16:18:58+00:00",
                }
            ],
        ),
        ([], []),
    ],
)
def test_parse_events(event, expected_res):
    """
    Giver:
        A list of events from the api
    When:
        We want to prepare them for XSIAM
    Then:
        check that the _time field is added to the each event"""
    assert parse_events(event) == expected_res


def test_call():
    mock_admin_api = MagicMock()
    mock_response = load_json('./test_data/authenticationV2.json')
    mock_admin_api.get_authentication_log.return_value = mock_response
    client.admin_api = mock_admin_api
    client.params.mintime = {LogType.AUTHENTICATION: {'min_time': '16843543575', 'next_offset': []}}
    client.params.fetch_delay = '0'
    _, metadata = client.call([LogType.AUTHENTICATION])
    assert metadata == {
        "next_offset": ["1532951895000", "af0ba235-0b33-23c8-bc23-a31aa0231de8"],
        "total_objects": 1
    }


def test_setLastRun_when_no_new_events(ret_fresh_client, ret_fresh_parameters, mocker):
    """
    Given:
        receiving events from XSIAM for the first iteration and then no more events in the second call.
    When:
        running the whole fetch_events flow.
    Then:
        validate that the lastRun is being set to the last batch send from XSIAM.
    """
    client = ret_fresh_client
    event1 = load_json('./test_data/authenticationV2.json').get('authlogs', [])[0]
    mocker.patch.object(demisto, 'params', return_value=ret_fresh_parameters)
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(Client, 'call', side_effect=[([event1], {
        "next_offset": "1666714065304,5bf1a860-fe39-49e3-be29-217659663a74",
        "total_objects": 3
    }), ([], {})])
    mocker.patch('DuoEventCollector.send_events_to_xsiam', return_vaule=None)
    mock_get_events = GetEvents(client, [LogType.AUTHENTICATION])
    with patch('DuoEventCollector.GetEvents', return_value=mock_get_events):
        # call the main function
        main()
        assert mock_get_events.get_last_run().get('after') == {LogType.AUTHENTICATION: {
            "next_offset": "1666714065304,5bf1a860-fe39-49e3-be29-217659663a74"
        }}


def test_set_next_run_filter_v1(ret_fresh_client):
    """
    Given:
        a metadata response from the api v1 and authentication log type.
    When:
        We need to set the mintime parameter to prepare for the next run.
    Then:
        Assert that the min time for next run is correct.
    """
    client = ret_fresh_client
    client.set_next_run_filter_v1(LogType.ADMINISTRATION, 12345)
    assert client.params.mintime[LogType.ADMINISTRATION] == 12346


def test_set_next_run_filter_v2(ret_fresh_client):
    """
    Given:
        a metadata response from the api v2 and authentication log type.
    When:
        We need to set the next_offset parameter to prepare for the next run.
    Then:
        Assert that the min time for next run is correct.
    """
    client = ret_fresh_client
    metadata = {"metadata": {
        "next_offset": ["1532951895000", "af0ba235-0b33-23c8-bc23-a31aa0231de8"],
        "total_objects": 1
    }}
    client.set_next_run_filter_v2(LogType.AUTHENTICATION, metadata)
    assert client.params.mintime[LogType.AUTHENTICATION] == {'next_offset': metadata.get('next_offset')}


def test_parse_mintime():
    """
    Given:
        time a date in epocs
    When:
        calculating the first mintime
    Then:
        Validate that the v2 version returns as an int with 13 digits and v1 10 digits int
    """
    date_string = "May 10th, 2023+00:00"
    datetime_obj = dateparser.parse(date_string, settings={"TIMEZONE": "UTC"})
    epocs_time = datetime_obj.timestamp()
    mintime_v1, mintime_v2 = parse_mintime(epocs_time)
    assert mintime_v1 == 1683676800
    assert mintime_v2 == 1683676800000


@freeze_time("2024-01-24 17:00:00 UTC")
def test_handle_authentication_logs(ret_fresh_client):
    """
    Given:
        A call is being send to retrive authntication logs from duo
    When:
        Reciving the events
    Then:
        Validate that the events return are accessed properly
    """
    authentication_response = load_json('./test_data/authenticationV2.json')
    client: Client = ret_fresh_client
    client.params.mintime[LogType.AUTHENTICATION] = {"min_time": '1579878696'}
    with patch.object(client.admin_api, 'get_authentication_log', return_value=authentication_response):
        events, metadata = client.handle_authentication_logs()

    assert events == authentication_response.get('authlogs')
    assert metadata == authentication_response.get('metadata')


@freeze_time("2024-01-24 17:00:00 UTC")
def test_handle_v2_logs_no_events(mocker):
    """
    Given:
        A call is being send to get authentication and telephony logs from duo.
    When:
        getting the events.
    Then:
        Validate that no events are returned since we are not in the time window.
    """
    params = {
        "after": "1 minute",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2024-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "5"
    }
    client = Client(Params(**params, mintime={}))
    client.params.mintime[LogType.AUTHENTICATION] = {"min_time": '1706115540000'}
    client.params.mintime[LogType.TELEPHONY] = {"min_time": '1706115540000'}

    events_auth, metadata_auth = client.handle_authentication_logs()
    events_tel, metadata_tel = client.handle_telephony_logs_v2()
    assert not events_auth
    assert not metadata_auth
    assert not events_tel
    assert not metadata_tel


@freeze_time("2024-01-24 17:00:00 UTC")
def test_handle_v2_test_args(mocker):
    """
    Given:
        A call is being send to get authentication and telephony logs from duo.
    When:
        getting the events.
    Then:
        Validate that the correct arguments are being sent.
    """
    end_window: datetime = datetime.strptime("2024-01-24 16:55:00", DATE_FORMAT)
    params = {
        "after": "1 minute",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": end_window,
        "fetch_delay": "5"
    }
    client = Client(Params(**params, mintime={}))
    client.params.mintime[LogType.AUTHENTICATION] = {"min_time": '1706115240000'}
    client.params.mintime[LogType.TELEPHONY] = {"min_time": '1706115240000'}
    maxtime = '1706115300000'
    mintime = '1706115240000'

    # authentication , no next_offset
    request_1 = mocker.patch.object(client.admin_api, 'get_authentication_log')
    client.handle_authentication_logs()
    request_1.assert_called_with(mintime=mintime, api_version=2, limit='10', sort='ts:asc', maxtime=maxtime)
    # telephony no next_offset
    request_2 = mocker.patch.object(client.admin_api, 'get_telephony_log')
    client.handle_telephony_logs_v2()
    request_2.assert_called_with(mintime=mintime, api_version=2, limit='10', sort='ts:asc', maxtime=maxtime)

    next_offset_auth = ["1706115240000", "af0ba235-0b33-23c8-bc23-a31aa0231de8"]
    next_offset_tel = "1706115240000,af0ba235-0b33-23c8-bc23-a31aa0231de8"
    client.params.mintime[LogType.AUTHENTICATION] = {"min_time": '1706115540000', "next_offset": next_offset_auth}
    client.params.mintime[LogType.TELEPHONY] = {"min_time": '1706115540000', "next_offset": next_offset_tel}
    # authentication with next_offset
    request_3 = mocker.patch.object(client.admin_api, 'get_authentication_log')
    client.handle_authentication_logs()
    request_3.assert_called_with(next_offset=next_offset_auth, mintime=mintime, api_version=2,
                                 limit='10', sort='ts:asc', maxtime=maxtime)
    # telephony with next_offset
    request_4 = mocker.patch.object(client.admin_api, 'get_telephony_log')
    client.handle_telephony_logs_v2()
    request_4.assert_called_with(next_offset=next_offset_tel, mintime=mintime, api_version=2,
                                 limit='10', sort='ts:asc', maxtime=maxtime)


def test_handle_telephony_logs_v2(ret_fresh_client):
    """
    Given:
        A call is being send to retrive authntication logs from duo
    When:
        Reciving the events
    Then:
        Validate that the events return are accessed properly
    """
    telephony_response = load_json('./test_data/telephonyV2.json')
    client: Client = ret_fresh_client
    client.params.mintime[LogType.TELEPHONY] = {"min_time": '1579878696'}
    with patch.object(client.admin_api, 'get_telephony_log', return_value=telephony_response):
        events, metadata = client.handle_telephony_logs_v2()

    assert events == telephony_response.get('items')
    assert metadata == telephony_response.get('metadata')


def test_handle_telephony_logs_v1(ret_fresh_client):
    """
    Given:
        A call is being send to retrive authntication logs from duo
    When:
        Reciving the events
    Then:
        Validate that the events return are accessed properly
    """
    telephony_response = load_json('./test_data/telephonyV1.json')
    client: Client = ret_fresh_client
    client.params.mintime[LogType.TELEPHONY] = '1579878696'
    with patch.object(client.admin_api, 'get_telephony_log', return_value=telephony_response):
        ret_events = client.handle_telephony_logs_v1()

    assert telephony_response == ret_events


def test_handle_administration_logs(ret_fresh_client):
    """
    Given:
        A call is being send to retrive authntication logs from duo
    When:
        Reciving the events
    Then:
        Validate that the events return are accessed properly
    """
    administration_response = load_json('./test_data/administration.json')
    client: Client = ret_fresh_client
    client.params.mintime[LogType.ADMINISTRATION] = 12345
    with patch.object(client.admin_api, 'get_administrator_log', return_value=administration_response):
        ret_events = client.handle_administration_logs()

    assert administration_response == ret_events


@freeze_time("2024-01-24 17:00:00 UTC")
def test_handle_v1_logs_no_events(ret_fresh_client):
    """
    Given:
        A call is being send to get authentication logs from duo.
    When:
        getting the events.
    Then:
        Validate that no events are returned since we are not in the time window.
    """
    params = {
        "after": "1 minute",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2024-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "5"
    }
    client = Client(Params(**params, mintime={}))
    client.params.mintime[LogType.ADMINISTRATION] = '1706115540'
    client.params.mintime[LogType.TELEPHONY] = '1706115540'

    events_admin = client.handle_administration_logs()
    events_tel = client.handle_telephony_logs_v1()
    assert not events_admin
    assert not events_tel


@pytest.mark.parametrize('log_type_list, expected_res', [(['AUTHENTICATION'], True),
                                                         (['AUTHENTICATION', 'TELEPHONY'], True),
                                                         ([], True),
                                                         (['banana'], 'banana'),
                                                         (['AUTHENTICATION', 'TELEPONY'], 'TELEPONY'),
                                                         (['AUTHENTICATION', 'TELEPONY', 'ADMIN'], 'TELEPONY,ADMIN')])
def test_validate_request_order_array(log_type_list, expected_res):
    """
    Given:
        A list of log types from the user.
    When:
        calling a command.
    Then:
        Validate that the log types are spelled correctly.
    """
    assert expected_res == validate_request_order_array(log_type_list)


@freeze_time("2024-01-20 17:00:00 UTC")
def test_events_in_window_all_in():
    """ case d
    Given:
        A list of log/events.
    When:
        calling events_in_window.
    Then:
        Validate that the all events are returned.
    """
    input_events = load_json('./test_data/events_in_window_v1_administration.json')
    params = {
        "after": "1 month",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 16:55:00", DATE_FORMAT),
        "fetch_delay": "5"
    }

    client = Client(Params(**params, mintime={}))

    request_order = ['ADMINISTRATION']

    get_events_obj = GetEvents(client, request_order)
    output_events, reached_end_window = get_events_obj.events_in_window(input_events)
    assert len(output_events) == 9
    assert not reached_end_window


@freeze_time("2020-01-24 15:16:33 UTC")
def test_events_in_window_some_in():
    """ case c
    Given:
        A list of log/events.
    When:
        calling events_in_window.
    Then:
        Validate that some events are returned.
    """
    input_events = load_json('./test_data/events_in_window_v1_administration.json')
    params = {
        "after": "1 month",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "5"
    }

    client = Client(Params(**params, mintime={}))

    request_order = ['ADMINISTRATION']

    get_events_obj = GetEvents(client, request_order)
    output_events, reached_end_window = get_events_obj.events_in_window(input_events)
    assert len(output_events) == 6
    assert reached_end_window


@freeze_time("2020-01-24 15:16:33 UTC")
def test_events_in_window_none_in():
    """ case b
    Given:
        A list of log/events.
    When:
        calling events_in_window.
    Then:
        Validate that none of the events are returned.
    """
    input_events = load_json('./test_data/events_in_window_v1_administration.json')
    params = {
        "after": "1 month",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:09:33", DATE_FORMAT),
        "fetch_delay": "7"
    }

    client = Client(Params(**params, mintime={}))

    request_order = ['ADMINISTRATION']

    get_events_obj = GetEvents(client, request_order)
    output_events, reached_end_window = get_events_obj.events_in_window(input_events)
    assert len(output_events) == 0
    assert reached_end_window


@freeze_time("2020-01-24 15:16:33 UTC")
def test_events_in_window_all_no_delay():
    """ case a
    Given:
        A list of log/events.
    When:
        calling events_in_window.
    Then:
        Validate that all events are returned, because we don't want to apply a delay.
    """
    input_events = load_json('./test_data/events_in_window_v1_administration.json')
    params = {
        "after": "1 month",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "0"
    }

    client = Client(Params(**params, mintime={}))

    request_order = ['ADMINISTRATION']

    get_events_obj = GetEvents(client, request_order)
    output_events, reached_end_window = get_events_obj.events_in_window(input_events)
    assert len(output_events) == 9
    assert not reached_end_window


@freeze_time("2020-01-24 15:16:33 UTC")
def test_calculate_window():
    """ case a
    Given:
        A list of log/events.
    When:
        calling events_in_window.
    Then:
        Validate that the correct end_window value is set.
    """
    params = {
        "after": "1 month",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "fetch_delay": "5"
    }
    calculate_window(params)
    assert params['end_window'] == datetime.strptime("2020-01-24 15:11:33", DATE_FORMAT)


@freeze_time("2020-01-24 15:16:33 UTC")
def test_check_window_before_call_no_delay():
    """
    Given:
        mintime - a timestamp represents the minimum time from which to get events.
    When:
        calling check_window_before_call.
    Then:
        True is returned, the API call should be performed, we are in the time window.
    """
    params = {
        "after": "1 day",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:16:33", DATE_FORMAT),
        "fetch_delay": "0"
    }

    client = Client(Params(**params, mintime={}))

    mintime = datetime.now() - timedelta(days=1)
    result = client.check_window_before_call(mintime=mintime.timestamp())
    assert result


@freeze_time("2020-01-24 15:16:33 UTC")
def test_check_window_before_call_small_delay():
    """
    Given:
        mintime - a timestamp represents the minimum time from which to get events.
    When:
        calling check_window_before_call.
    Then:
        True is returned, the API call should be performed, we are in the time window..
    """
    params = {
        "after": "1 day",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "5"
    }

    client = Client(Params(**params, mintime={}))

    mintime = datetime.now() - timedelta(days=1)
    result = client.check_window_before_call(mintime=mintime.timestamp())
    assert result


@freeze_time("2022-10-25 16:16:45 UTC")
def test_check_window_before_call_v2_format():
    """
    Given:
        mintime - a timestamp represents the minimum time from which to get events in a v2 format (13 digits).
    When:
        calling check_window_before_call.
    Then:
        1. False is returned, no need to perform the API call.
        2. True is returned, the API call should be performed, we are in the time window.
    """
    params = {
        "after": "1 day",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2022-10-25 16:07:46", DATE_FORMAT),
        "fetch_delay": "9"
    }

    client = Client(Params(**params, mintime={}))

    result_no_fetch = client.check_window_before_call(mintime=1666714066000 / 1000)  # October 25, 2022 4:07:46 PM
    assert not result_no_fetch
    result_do_fetch = client.check_window_before_call(mintime=1666714060304 / 1000)  # October 25, 2022 4:07:45.304 PM
    assert result_do_fetch


@freeze_time("2020-01-24 15:16:33 UTC")
def test_check_window_before_call_not_in_window():
    """
    Given:
        mintime - a timestamp represents the minimum time from which to get events.
    When:
        calling check_window_before_call.
    Then:
        True is returned, the API call should be performed, we are in the time window.
    """
    params = {
        "after": "1 minute",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "5"
    }

    client = Client(Params(**params, mintime={}))

    mintime = datetime.now() - timedelta(minutes=1)
    result = client.check_window_before_call(mintime=mintime.timestamp())
    assert not result


@freeze_time("2020-01-24 15:16:33 UTC")
def test_check_window_before_call_5_sec_time_delta():
    """
    Given:
        mintime - a timestamp represents the minimum time from which to get events.
    When:
        calling check_window_before_call.
    Then:
        True is returned, the API call should be performed, we are in the time window.
    """
    params = {
        "after": "1 minute",
        "host": "api-host.duosecurity.com",
        "integration_key": "XXXXXXXXXXXXXXXX",
        "limit": "10",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "password", "passwordChanged": False},
        "end_window": datetime.strptime("2020-01-24 15:11:33", DATE_FORMAT),
        "fetch_delay": "5"
    }

    client = Client(Params(**params, mintime={}))
    # min time 3 sec less than the end time return false (less then 5 sec delta)
    mintime = datetime.strptime("2020-01-24 15:11:30", DATE_FORMAT)
    assert not client.check_window_before_call(mintime=mintime.timestamp())
    # min time 13 sec less than the end time return true (more then 5 sec delta)
    mintime = datetime.strptime("2020-01-24 15:11:20", DATE_FORMAT)
    assert client.check_window_before_call(mintime=mintime.timestamp())
