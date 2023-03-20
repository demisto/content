import io
import json
from datetime import datetime, timedelta
import demistomock as demisto
from CommonServerPython import BaseClient
from FireEyeHXEventCollector import populate_modeling_rule_fields, fetch_events,\
     get_events_command, Client, DATE_FORMAT


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

BASE_URL = 'https://example.com'
EVENTS_RES = util_load_json('test_data/events_res.json')
EVENTS_RAW = util_load_json('test_data/events_raw.json')


def test_populate_modeling_rule_fields():
    populate_modeling_rule_fields(EVENTS_RAW)
    assert EVENTS_RAW[0]['_time'] == '2023-03-14T21:27:51.000Z'


def test_fetch_events(mocker):
    client = Client(BASE_URL, 'username', 'password', False, False)
    get_events_request_mock = mocker.patch.object(client, 'get_events_request', return_value=EVENTS_RES)
    send_events_mocker =mocker.patch('FireEyeHXEventCollector.send_events_to_xsiam')

    to_date = (datetime.now() + timedelta(days=1)).strftime(DATE_FORMAT)
    filter_query = '{"operator": "between", "arg": ["2023-02-01T11:21:12.135Z",' \
                   ' "' + to_date + '"], "field": "reported_at"}'

    events = fetch_events(client=client, max_fetch='100', first_fetch='2023-02-01T11:21:12.135Z',
                          min_id='100', should_push_events=True)
    assert len(events) == 2
    assert get_events_request_mock.call_args.kwargs['filter_query'] == filter_query
    assert not get_events_request_mock.call_args.kwargs['resolution']
    assert get_events_request_mock.call_args.kwargs['min_id'] == '100'
    assert send_events_mocker.call_args.kwargs['events'] == events
    assert send_events_mocker.call_args.kwargs['vendor'] == 'FireEye'
    assert send_events_mocker.call_args.kwargs['product'] == 'HX'
    assert demisto.getLastRun()['last_alert_id'] == '3994'
    assert demisto.getLastRun()['last_alert_time'] == '2023-02-01T11:21:12.135Z'


def test_http_request_token_already_created(mocker):
    client = Client(BASE_URL, 'username', 'password', False, False)
    demisto.setIntegrationContext({'token': 'TOKEN'})
    http_request = mocker.patch.object(BaseClient, '_http_request', return_value={})

    client.http_request('GET')
    assert http_request.call_args.kwargs['headers']['X-FeApi-Token'] == 'TOKEN'


def test_http_request_token_not_created(mocker):
    client = Client(BASE_URL, 'username', 'password', False, False)
    demisto.setIntegrationContext({})
    http_request = mocker.patch.object(BaseClient, '_http_request', return_value={})
    mocker.patch.object(Client, 'get_access_token', return_value='123456')

    client.http_request('GET')
    assert http_request.call_args.kwargs['headers']['X-FeApi-Token'] == '123456'


def test_get_events_request(mocker):
    client = Client(BASE_URL, 'username', 'password', False, False)
    http_request = mocker.patch.object(Client, 'http_request')
    client.get_events_request(min_id='100', resolution='alert')
    assert http_request.call_args.kwargs['url_suffix'] == '/hx/api/v3/alerts'
    assert http_request.call_args.kwargs['params']['resolution'] == 'alert'
    assert http_request.call_args.kwargs['params']['min_id'] == '100'


def test_get_events_command(mocker):
    mocker.patch('FireEyeHXEventCollector.fetch_events', return_value=EVENTS_RAW)
    readable_output = ''
    res = get_events_command(None, '', '', False)
    with io.open('test_data/get_events_readable_outputs.md', mode='r', encoding='utf-8') as f:
        readable_output = f.read()

    assert res.raw_response == EVENTS_RAW
    assert res.readable_output == readable_output


def test_get_events_command_empty_res(mocker):
    mocker.patch('FireEyeHXEventCollector.fetch_events', return_value=[])

    res = get_events_command(None, '', '', False)
    assert res == 'No events were found.'
