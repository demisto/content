import pytest
import json
from unittest.mock import MagicMock, patch
from DuoEventCollector import Client, GetEvents, LogType, Params, parse_events, main


@pytest.fixture
def ret_demisto_params():
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
global_demisto_params['params'] = Params(**global_demisto_params, mintime={})
client = Client(global_demisto_params)     # type: ignore

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
    mock_response = load_json('./test_data/telephonyV2.json')
    mock_admin_api.get_telephony_log.return_value = mock_response
    client.admin_api = mock_admin_api
    client.params.mintime = {LogType.TELEPHONY: {'min_time': '16843543575', 'next_offset': []}}
    _, metadata = client.call(['TELEPHONY'])
    assert metadata == {
        "next_offset": "1666714065304,5bf1a860-fe39-49e3-be29-217659663a74",
        "total_objects": 3
    }


def test_main():
    client = MagicMock(spec=Client)
    client.call.return_value = (['event1'], {
        "next_offset": "1666714065304,5bf1a860-fe39-49e3-be29-217659663a74",
        "total_objects": 3
    })
    mock_get_events = GetEvents(client, ['TELEPHONY'])
    with patch('DuoEventCollector.GetEvents', return_value=mock_get_events):
        # call the main function
        main()
        assert mock_get_events.get_last_run() == 'bla'


def test_set_next_run_filter_v1(ret_demisto_params):
    """
    Given:
        a metadata response from the api v1 and authentication log type.
    When:
        We need to set the mintime parameter to prepare for the next run.
    Then:
        Assert that the min time for next run is correct.
    """
    demisto_params = ret_demisto_params
    p = Params(**demisto_params, mintime={})
    demisto_params['params'] = p
    client = Client(demisto_params)
    client.set_next_run_filter_v1(12345)
    assert p.mintime[LogType.ADMINISTRATION] == 12346


def test_set_next_run_filter_v2(ret_demisto_params):
    """
    Given:
        a metadata response from the api v2 and authentication log type.
    When:
        We need to set the next_offset parameter to prepare for the next run.
    Then:
        Assert that the min time for next run is correct.
    """
    demisto_params = ret_demisto_params
    p = Params(**demisto_params, mintime={})
    demisto_params['params'] = p
    client = Client(demisto_params)
    metadata = {"metadata": {
        "next_offset": ["1532951895000", "af0ba235-0b33-23c8-bc23-a31aa0231de8"],
        "total_objects": 1
    }}
    client.set_next_run_filter_v2(LogType.AUTHENTICATION, metadata)
    assert p.mintime[LogType.AUTHENTICATION] == {'next_offset': metadata.get('next_offset')}
