import io
import json
import demistomock as demisto
from CommonServerPython import BaseClient
from FireEyeHXEventCollector import populate_modeling_rule_fields, fetch_events, get_events_command, Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


BASE_URL = 'https://example.com'
EVENTS_RES = util_load_json('test_data/events_res.json')
EVENTS_RAW = util_load_json('test_data/events_raw.json')


def test_populate_modeling_rule_fields():
    """
    Given
            List of FireEye alerts
    When
            Calling populate_modeling_rule_fields
    Then
            Make sure that the method updated the _time field with the value from event_at field as datestring
    """
    populate_modeling_rule_fields(EVENTS_RAW)
    assert EVENTS_RAW[0]['id'] == 4000


def test_fetch_events(mocker):
    """
    Given:
        - fireeye get events request
    When:
        - Running fetch_events
    Then:
        - Make sure all the events are returned
        - Make sure get_events_request method executes with the correct parameters
        - Make sure send_events_to_xsiam method executes with the correct parameters
        - Make sure demisto.lastrun contains the last alert id and time
    """
    client = Client(BASE_URL, 'username', 'password', False, False)
    get_events_request_mock = mocker.patch.object(client, 'get_events_request', return_value=EVENTS_RES)
    send_events_mocker = mocker.patch('FireEyeHXEventCollector.send_events_to_xsiam')
    demisto_set_last_run_mock = mocker.patch('demistomock.setLastRun')

    events = fetch_events(client=client, max_fetch='100', first_fetch='2023-02-01T11:21:12.135Z',
                          min_id='100', should_push_events=True)
    assert len(events) == 2
    assert get_events_request_mock.call_args.kwargs['min_id'] == '100'
    assert send_events_mocker.call_args.kwargs['events'] == events
    assert send_events_mocker.call_args.kwargs['vendor'] == 'FireEye'
    assert send_events_mocker.call_args.kwargs['product'] == 'HX'
    assert demisto_set_last_run_mock.call_args[0][0]['last_alert_id'] == '4001'


def test_http_request_token_already_created(mocker):
    """
    Given
            Integration context with token
    When
            Calling client.http_request
    Then
            Make sure that the method using the token from the context inside X-FeApi-Token header
    """
    client = Client(BASE_URL, 'username', 'password', False, False)
    demisto.setIntegrationContext({'token': 'TOKEN'})
    http_request = mocker.patch.object(BaseClient, '_http_request', return_value={})

    client.http_request('GET')
    assert http_request.call_args.kwargs['headers']['X-FeApi-Token'] == 'TOKEN'


def test_http_request_token_not_created(mocker):
    """
    Given
            Empty integration context
    When
            Calling client.http_request
    Then
            Make sure that the method call get_access_token and use the returned token inside X-FeApi-Token header
    """
    client = Client(BASE_URL, 'username', 'password', False, False)
    demisto.setIntegrationContext({})
    http_request = mocker.patch.object(BaseClient, '_http_request', return_value={})
    mocker.patch.object(Client, 'get_access_token', return_value='123456')

    client.http_request('GET')
    assert http_request.call_args.kwargs['headers']['X-FeApi-Token'] == '123456'


def test_get_events_request(mocker):
    """
    Given
            no params
    When
            Calling client.get_events_request
    Then
            Make sure http_request method executes with the correct parameters
    """
    client = Client(BASE_URL, 'username', 'password', False, False)
    http_request = mocker.patch.object(Client, 'http_request')
    client.get_events_request(min_id='100')
    assert http_request.call_args.kwargs['url_suffix'] == '/hx/api/v3/alerts'
    assert http_request.call_args.kwargs['params']['min_id'] == '100'


def test_get_events_command(mocker):
    """
    Given
            fireeye get events request
    When
            Calling get_events_command
    Then
            Make sure the command results are correct
    """
    mocker.patch('FireEyeHXEventCollector.fetch_events', return_value=EVENTS_RAW)
    res = get_events_command(None, '', '', False)
    assert res.raw_response == EVENTS_RAW
    assert res.outputs == EVENTS_RAW


def test_get_events_command_empty_res(mocker):
    """
    Given
            Empty alerts list
    When
            Calling get_events_command
    Then
            Make sure the command results is No events were found.
    """
    mocker.patch('FireEyeHXEventCollector.fetch_events', return_value=[])
    res = get_events_command(None, '', '', False)
    assert res == 'No events were found.'
