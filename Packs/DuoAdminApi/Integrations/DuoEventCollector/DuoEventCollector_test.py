import pytest
import json
import dateparser
import demistomock as demisto
from unittest.mock import MagicMock, patch
from DuoEventCollector import Client, GetEvents, LogType, Params, parse_events, main, parse_mintime, validate_request_order_array


@pytest.fixture
def ret_fresh_client(ret_fresh_parameters):
    return Client(Params(**ret_fresh_parameters, mintime={}))   # type: ignore


@pytest.fixture
def ret_fresh_parameters():
    return {
        "after": "1 month",
        "host": "api-a1fdb00d.duosecurity.com",
        "integration_key": "DI47EXXXXXXXWRYV2",
        "limit": "5",
        "proxy": False,
        "retries": "5",
        "secret_key": {"password": "YK6mtSzXXXXXXXXXXX", "passwordChanged": False},
    }


global_demisto_params = {
    "after": "1 month",
    "host": "api-a1fdb00d.duosecurity.com",
    "integration_key": "DI47EXXXXXXXWRYV2",
    "limit": "5",
    "proxy": False,
    "retries": "5",
    "secret_key": {"password": "YK6mtSzXXXXXXXXXXX", "passwordChanged": False},
}

client = Client(Params(**global_demisto_params, mintime={}))     # type: ignore

get_events = GetEvents(
    client=client,
    request_order=[LogType.AUTHENTICATION, LogType.ADMINISTRATION, LogType.TELEPHONY],
)


def load_json(file: str) -> dict:
    with open(file, 'r') as f:
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
    parse_events(event) == expected_res


def test_call():
    mock_admin_api = MagicMock()
    mock_response = load_json('./test_data/authenticationV2.json')
    mock_admin_api.get_authentication_log.return_value = mock_response
    client.admin_api = mock_admin_api
    client.params.mintime = {LogType.AUTHENTICATION: {'min_time': '16843543575', 'next_offset': []}}
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
    mocker.patch.object(demisto, 'params', return_value=ret_fresh_parameters)
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(Client, 'call', side_effect=[(['event1'], {
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
    client.params.mintime[LogType.AUTHENTICATION] = {}
    with patch.object(client.admin_api, 'get_authentication_log', return_value=authentication_response):
        events, metadata = client.handle_authentication_logs()

    assert events == authentication_response.get('authlogs')
    assert metadata == authentication_response.get('metadata')


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
    client.params.mintime[LogType.TELEPHONY] = {}
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
    client.params.mintime[LogType.TELEPHONY] = {}
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
