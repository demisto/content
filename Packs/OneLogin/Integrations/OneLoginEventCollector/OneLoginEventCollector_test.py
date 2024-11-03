import json
import pytest
import demistomock as demisto

from OneLoginEventCollector import Client, prepare_query_params, check_response
from requests import Session


CORE_URL = 'https://api.onelogin.com'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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
    ({'since': '2022-08-01T09:00:00Z'}, {'since': '2022-09-01T09:00:00Z'}, {'limit': 1000, 'since': '2022-09-01T09:00:00Z'}),
    ({'since': '2022-08-01T09:00:00Z', 'after_cursor': 'param_cursor'}, {'after_cursor': 'last_run_cursor'},
     {'limit': 1000, 'since': '2022-08-01T09:00:00Z', 'after_cursor': 'last_run_cursor'}),
    ({'after_cursor': 'param_cursor'}, {}, {'limit': 1000, 'after_cursor': 'param_cursor'}),
])
def test_onelogin_events_params_good(params, last_run, expected_params):
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
    {'until': 'hello'}
])
def test_onelogin_events_params_bad(params):
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


@pytest.mark.parametrize('response, should_fail', [
    ({"status": {"error": False}}, False),
    ({"status": {"error": True, "code": 400}}, True),
    (MOCK_EVENTS, False)
])
def test_onelogin_check_response(mocker, response, should_fail):
    """
    Given:
        - An OneLogin API response.
    When:
        - Running the check_response to verify the response isn't an error.
    Then:
        - Make sure the method raises an exception if the response is an error.
    """
    mocker.patch.object(demisto, "error")

    if should_fail:
        with pytest.raises(Exception):
            check_response(response)
    else:
        check_response(response)


def test_test_module(mocker):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from OneLoginEventCollector import test_module_command

    mocker.patch.object(Session, 'request', return_value=MockResponse([]))
    assert test_module_command(Client(base_url='', headers={}), {}) == 'ok'


def test_fetch_events(requests_mock):
    """
    Given:
        - fetch-events call, where first_id = 2 in LastRun obj.
    When:
        - Four events with ids 1, 2, 3 and 4 are retrieved from the API.
    Then:
        - Make sure only events 2, 3 and 4 are returned (1 should not).
    """
    from OneLoginEventCollector import fetch_events_command

    last_run = {'first_id': 2}

    requests_mock.post(f'{CORE_URL}/auth/oauth2/v2/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    requests_mock.get(f'{CORE_URL}/api/1/events', json=MOCK_EVENTS)

    events, _ = fetch_events_command(Client(base_url=CORE_URL, headers={}),
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
    from OneLoginEventCollector import fetch_events_command

    requests_mock.post(f'{CORE_URL}/auth/oauth2/v2/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    mock_request = requests_mock.get(f'{CORE_URL}/api/1/events', json=MOCK_EVENTS)

    events, _ = fetch_events_command(Client(base_url=CORE_URL, headers={}),
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
    from OneLoginEventCollector import fetch_events_command

    last_run = {'last_event_ids': [1, 2]}

    requests_mock.post(f'{CORE_URL}/auth/oauth2/v2/token', json={"access_token": "token"})
    requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    requests_mock.get(f'{CORE_URL}/api/1/events', json=MOCK_EVENTS)

    events, _ = fetch_events_command(Client(base_url=CORE_URL, headers={}),
                                     params={"limit": 2}, last_run=last_run)

    assert len(events) == 2
    assert events[0].get('id') == 3


def test_get_events(mocker, requests_mock):
    """
    Given:
        - onelogin-get-events call
    When:
        - Four events with ids 1, 2, 3 and 4 are retrieved from the API.
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
    """
    from OneLoginEventCollector import get_events_command

    response = MOCK_EVENTS
    requests_mock.get(f'{CORE_URL}/api/1/events', json=response)

    mocker.patch.object(Client, 'get_access_token_request')
    mocker.patch.object(Client, 'get_event_types_request')
    _, results = get_events_command(Client(base_url=CORE_URL, headers={}), args={})

    assert len(results.raw_response.get('data', [])) == 4
    assert results.raw_response == response


@pytest.mark.parametrize('last_run, call_count', [
    ({'event_types': {'1': 'TYPE'}}, 0),
    ({}, 1)
])
def test_get_event_types_from_last_run(requests_mock, last_run, call_count):
    """
    Given:
        - LasRun object.
    When:
        - Trying tp get the events type using the client.get_event_types_from_last_run method.
    Then:
        - Verify a request is sent only if there are no event types in the LastRun.
    """

    request_mocker = requests_mock.get(f'{CORE_URL}/api/1/events/types', json={})
    client = Client(base_url=CORE_URL, headers={})
    client.get_event_types_from_last_run(last_run)

    assert request_mocker.call_count == call_count


@pytest.mark.parametrize('event, call_count, expected_name', [
    ({'event_type_id': 1}, 0, 'EVENT_TYPE_NUMBER_1'),
    ({'event_type_id': 3}, 1, 'EVENT_TYPE_NUMBER_3'),
    ({'event_type_id': 5}, 1, '')
])
def test_convert_type_id_to_name(requests_mock, event, call_count, expected_name):
    """
    Given:
        - An event from the API response.
        - Dict of event type names by IDs.
    When:
        - Trying to convert the event type id to its name.
    Then:
        - Verify the returned type name is as expected.
        - Verify An API request is called only if didn't find the type ID in the given types dict.
        - Verify LastRun object is updated with the new event types dict if a request was called.
    """

    request_mock = requests_mock.get(f'{CORE_URL}/api/1/events/types', json=MOCK_EVENT_TYPES)
    client = Client(base_url=CORE_URL, headers={})

    event_types = {'1': 'EVENT_TYPE_NUMBER_1', '2': 'EVENT_TYPE_NUMBER_2'}
    last_run = {'event_types': event_types}
    event_type_name = client.convert_type_id_to_name(event, event_types, last_run)

    assert event_type_name == expected_name
    assert request_mock.call_count == call_count
    if expected_name:
        assert str(event['event_type_id']) in last_run['event_types']
