import pytest

from GitLabEventCollector import Client, prepare_query_params
from requests import Session


class MockResponse:
    def __init__(self, data: list):
        self.ok = True
        self.status_code = 200
        self.data = data
        self.links = None

    def json(self):
        return self.data

    def raise_for_status(self):
        pass


""" Test methods """


@pytest.mark.parametrize('params, last_run, expected_params_url', [
    ({'after': '02/02/2022T15:00:00Z'}, {}, 'pagination=keyset&created_after=2022-02-02T15:00:00Z&per_page=100'),
    ({'after': '02/02/2022T15:01:00Z'},
     {'next_url': 'pagination=keyset&created_after=2022-02-02T15:00:00Z&per_page=100&cursor=examplecursor'},
     'pagination=keyset&created_after=2022-02-02T15:00:00Z&per_page=100&cursor=examplecursor')
])
def test_gitlab_events_params_good(params, last_run, expected_params_url):
    """
    Given:
        - Various params and LastRun dictionary values.
    When:
        - preparing the parameters.
    Then:
        - Make sure they are parsed correctly into the URL suffix.
    """
    assert expected_params_url == prepare_query_params(params, last_run)


def test_fetch_events(mocker):
    """
    Given:
        - fetch-events call, where last_id = 1
    When:
        - Three following results are retrieved from the API:
            1. id = 1, date_create = 1521214343
            2. id = 2, date_create = 1521214343
            3. id = 3, date_create = 1521214345
    Then:
        - Make sure only events 2 and 3 are returned (1 should not).
        - Verify the new lastRun is calculated correctly.
    """
    from GitLabEventCollector import fetch_events_command

    last_run = {'last_id': '1'}

    mock_response = MockResponse([
        {'id': '3', 'date_create': 1521214345},
        {'id': '2', 'date_create': 1521214343},
        {'id': '1', 'date_create': 1521214343},
    ])
    mocker.patch.object(Session, 'request', return_value=mock_response)
    events, new_last_run = fetch_events_command(Client(base_url=''), params={}, last_run=last_run)

    assert len(events) == 2
    assert events[0].get('id') != '1'
    assert new_last_run['last_id'] == '3'


def test_fetch_events_with_two_iterations(mocker):
    """
    Given:
        - fetch-events command execution.
    When:
        - Limit parameter value is 300.
        - A single logs API call retrieves 200 events.
    Then:
        - Make sure the logs API is called twice.
    """
    from GitLabEventCollector import fetch_events_command

    last_run = {}

    mock_response = MockResponse([{'id': '1', 'date_create': 1521214343}] * 200)
    mock_response.links = {'next': {'url': 'https://example.com?param=value'}}
    mock_request = mocker.patch.object(Session, 'request', return_value=mock_response)
    fetch_events_command(Client(base_url=''), params={'limit': 300}, last_run=last_run)
    assert mock_request.call_count == 2


def test_get_events(mocker):
    """
    Given:
        - gitlab-get-events call
    When:
        - Three following results are retrieved from the API:
            1. id = 1, date_create = 1521214343
            2. id = 2, date_create = 1521214343
            3. id = 3, date_create = 1521214345
    Then:
        - Make sure all of the events are returned as part of the CommandResult.
    """
    from GitLabEventCollector import get_events_command

    mock_response = MockResponse([
        {'id': '3', 'date_create': 1521214345},
        {'id': '2', 'date_create': 1521214343},
        {'id': '1', 'date_create': 1521214343},
    ])
    mocker.patch.object(Session, 'request', return_value=mock_response)
    _, results = get_events_command(Client(base_url=''), args={})

    assert len(results.raw_response) == 3
    assert results.raw_response == mock_response.json()


def test_test_module(mocker):
    """
    Given:
        - test-module call.
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned.
    """
    from GitLabEventCollector import test_module_command

    mocker.patch.object(Session, 'request', return_value=MockResponse([]))
    assert test_module_command(Client(base_url=''), {'url': ''}, {'groups_ids': [1, 2], 'projects_ids': [3, 4, 5]}) == 'ok'
