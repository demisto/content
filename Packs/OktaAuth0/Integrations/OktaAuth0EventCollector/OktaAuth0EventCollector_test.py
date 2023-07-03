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
MOCK_EVENT_TYPES = util_load_json('test_data/mock_event_types.json')


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
    ({'limit': '1'}, {}, {'limit': 1}),
    ({'since': '2022-08-01T09:00:00Z'}, {'q': 'date:[2022-09-01T09:00:00Z TO *]'},
     {'limit': 1000, 'q': 'date:[2022-09-01T09:00:00Z TO *]'}),
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
    query_params = prepare_query_params(params, last_run)

    if query_params['since']:
        assert query_params['since'] == '2022-09-01T09:00:00Z' if 'since' in last_run else \
            query_params['since'] == '2022-08-01T09:00:00Z'

    if query_params['after_cursor']:
        assert query_params['after_cursor'] == 'last_run_cursor' if 'after_cursor' in last_run else \
            query_params['after_cursor'] == 'param_cursor'

    assert expected_params.items() <= prepare_query_params(params, last_run).items()


@pytest.mark.parametrize('params', [
    {'limit': 'hello'},
    {'since': 'hello'},
])
def test_auth0_events_params_bad(params):
    """
    Given:
        - Various dictionary bad values.
    When:
        - preparing the parameters.
    Then:
        - Make sure an Exception is raised.
    """
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

    last_run = {'first_id': 2}

    requests_mock.post(f'{CORE_URL}/auth/oauth2/v2/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    requests_mock.get(f'{CORE_URL}/api/1/events', json=MOCK_EVENTS)

    events, _ = fetch_events_command(Client(base_url='', client_id='', client_secret='', verify=False, proxy=False),
                                     params={"limit": 3}, last_run=last_run)

    assert len(events) == 3
    assert events[0].get('id') == 2


def test_fetch_events_with_iterations(requests_mock):
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

    requests_mock.post(f'{CORE_URL}/auth/oauth2/v2/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    mock_request = requests_mock.get(f'{CORE_URL}/api/1/events', json=MOCK_EVENTS)

    events, _ = fetch_events_command(Client(base_url='', client_id='', client_secret='', verify=False, proxy=False),
                                     params={'limit': 10}, last_run={})

    assert len(events) == 10
    assert mock_request.call_count == 3


def test_fetch_events_with_last_event_ids(requests_mock):
    """
    Given:
        - fetch-events call, where first_id = 2 in LastRun obj.
    When:
        - Four events with ids 1, 2, 3 and 4 are retrieved from the API.
    Then:
        - Make sure only events 2, 3 and 4 are returned (1 should not).
    """
    from OktaAuth0EventCollector import fetch_events_command

    last_run = {'last_event_ids': [1, 2]}

    requests_mock.post(f'{CORE_URL}/auth/oauth2/v2/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    requests_mock.get(f'{CORE_URL}/api/1/events', json=MOCK_EVENTS)

    events, _ = fetch_events_command(Client(base_url='', client_id='', client_secret='', verify=False, proxy=False),
                                     params={"limit": 2}, last_run=last_run)

    assert len(events) == 2
    assert events[0].get('id') == 3


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
