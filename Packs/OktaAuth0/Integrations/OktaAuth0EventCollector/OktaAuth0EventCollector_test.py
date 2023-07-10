import json
import io
import pytest
import demistomock as demisto

from OktaAuth0EventCollector import Client, prepare_query_params
from requests import Session


CORE_URL = 'https://api.oktaauth0.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


MOCK_EVENTS = util_load_json('test_data/mock_events.json')


class MockResponse:
    def __init__(self, data: list):
        self.ok = True
        self.status_code = 200
        self.data = {'data': [self.create_mock_entry(**e) for e in data]}

    def create_mock_entry(self, **kwargs) -> dict:
        return kwargs

    def json(self):
        return self.data


@pytest.mark.parametrize('params, last_run, expected_params', [
    ({'limit': '1', 'since': '2022-08-01T09:00:00Z'}, {}, {'q': 'date:[2022-08-01T09:00:00Z TO *]',
                                                           'sort': 'date:1', 'per_page': 100}),
    ({'since': '2022-08-01T09:00:00Z'}, {'last_id': '11111'},
     {'from': '11111', 'sort': 'date:1', 'take': 100}),
])
def test_auth0_events_params_good(params, last_run, expected_params):
    """
    Given:
        - Various dictionary values.
    When:
        - preparing the parameters.
    Then:
        - Make sure they are parsed correctly.
    """
    assert prepare_query_params(params, last_run) == expected_params


def test_auth0_events_params_bad():
    """
    Given:
        - Various dictionary bad values.
    When:
        - preparing the parameters.
    Then:
        - Make sure an Exception is raised.
    """
    params = {'since': 'hello'}
    with pytest.raises(ValueError):
        prepare_query_params(params)


def test_test_module(mocker):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from OktaAuth0EventCollector import test_module_command

    mocker.patch.object(Session, 'request', return_value=MockResponse([]))
    assert test_module_command(Client(base_url='', client_id='', client_secret='', verify=False, proxy=False), {}) == 'ok'


def test_fetch_events(requests_mock):
    """
    Given:
        - fetch-events call, where first_id = 2 in LastRun obj.
    When:
        - Four events with ids 1, 2, 3 and 4 are retrieved from the API.
    Then:
        - Make sure only events 2, 3 and 4 are returned (1 should not).
    """
    from OktaAuth0EventCollector import fetch_events_command

    requests_mock.post(f'{CORE_URL}/oauth/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/v2/logs', json=MOCK_EVENTS)

    events, last_run = fetch_events_command(Client(base_url=CORE_URL, client_id='', client_secret='', verify=False, proxy=False),
                                            params={"since": "3 days", "limit": 3}, last_run={})

    assert len(events) == 3
    assert last_run['last_id'] == '3'


def test_fetch_events_with_iterations(mocker):
    """
    Given:
        - fetch-events command execution.
    When:
        - Limit parameter value is 10.
        - A single /events API call retrieves 4 events.
    Then:
        - Make sure the logs API is called 3 times.
    """
    from OktaAuth0EventCollector import fetch_events_command

    mocker.patch.object(Client, 'get_access_token', return_value='token')
    logs_mock = mocker.patch.object(Client, '_http_request', side_effect=[MOCK_EVENTS[:2], MOCK_EVENTS[2:-1], [MOCK_EVENTS[-1]]])

    client = Client(base_url=CORE_URL, client_id='', client_secret='', verify=False, proxy=False)
    defined_limit = 4

    events, last_run = fetch_events_command(client, {"limit": 4}, {})

    assert len(events) == defined_limit
    assert logs_mock.call_count == 3
    assert last_run['last_id'] == '4'


@pytest.mark.parametrize('int_context, expected_token', [
    ({}, 'new_token'),
    ({'access_token': 'token', 'expired_token_time': 1688852440}, 'token'),
    ({'access_token': 'token', 'expired_token_time': 1688852439}, 'new_token')
])
def test_get_access_token(mocker, requests_mock, int_context, expected_token):
    """
    Given:
        - fetch-events command execution.
    When:
        - Limit parameter value is 10.
        - A single /events API call retrieves 4 events.
    Then:
        - Make sure the logs API is called 3 times.
    """
    import time

    mocker.patch.object(time, 'time', return_value=1688935240)
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=int_context)

    def set_int_context(context):
        mocker.patch.object(demisto, 'getIntegrationContext', return_value=context)

    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_int_context)
    requests_mock.post(f'{CORE_URL}/oauth/token', json={"access_token": "new_token"})

    client = Client(base_url=CORE_URL, client_id='', client_secret='', verify=False, proxy=False)
    access_token = client.get_access_token()

    assert access_token == expected_token


def test_get_events(mocker, requests_mock):
    """
    Given:
        - okta-auth0-get-events call
    When:
        - Four events with ids 1, 2, 3 and 4 are retrieved from the API.
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
    """
    from OktaAuth0EventCollector import get_events_command

    response = MOCK_EVENTS
    requests_mock.get(f'{CORE_URL}/api/1/events', json=response)

    mocker.patch.object(Client, 'get_access_token_request')
    mocker.patch.object(Client, 'get_event_types_request')
    _, results = get_events_command(Client(base_url='', client_id='', client_secret='', verify=False, proxy=False), args={})

    assert len(results.raw_response.get('data', [])) == 4
    assert results.raw_response == response
