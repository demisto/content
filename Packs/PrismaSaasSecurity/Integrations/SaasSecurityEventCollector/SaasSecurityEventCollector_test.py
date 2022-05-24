"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import demistomock as demisto
import pytest
import json
import io
from SaasSecurityEventCollector import Client


@pytest.fixture
def mock_client():
    return Client(base_url='https://test.com/api', client_id='', client_secret='', verify=False, proxy=False)


class MockedResponse:

    def __init__(self, status_code, text='{}'):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    'mocked_response', [MockedResponse(status_code=200), MockedResponse(status_code=204)]
)
def test_module(mocker, mock_client, mocked_response):
    """
    Given
       - a response which indicates an event was found.
       - a response which indicates that an event is still being searched

    When -
        testing the module

    Then -
        make sure the test module returns the 'ok' response.
    """
    from SaasSecurityEventCollector import test_module
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)
    assert test_module(client=mock_client) == 'ok'


@pytest.mark.parametrize(
    'args, integration_context_mock', [
        (
            {"limit": "1"},
            {'events': '[{"1":"1"},{"2":"2"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            {"limit": "2"},
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"},{"4":"4"}]'}
        ),
        (
            {"limit": "5"},
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"}]'}
        ),
        (
            {"limit": "50"},
            {'events': '[{"1":"1"},{"2":"2"}]'}
        ),
        (
            {"limit": "22"},
            {'events': '[]'}
        )
    ]
)
def test_saas_security_get_events(mocker, args, integration_context_mock):
    """
    Given
       - events in the integration context
       - limit parameter

    When -
        executing the saas-security-get-events command

    Then
       - make sure the events that are returned the size of the limit or less
       - make sure the integration context is not being overridden.
       - make sure in case there are no events, a representing string will be returned
    """
    import SaasSecurityEventCollector

    limit = int(args.get("limit"))
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context_mock)

    set_context_mocker = mocker.patch.object(SaasSecurityEventCollector, 'set_to_integration_context_with_retries')

    expected_events = json.loads(integration_context_mock['events'])

    result = SaasSecurityEventCollector.saas_security_get_events_command(args=args)
    if expected_events:
        assert result.outputs == expected_events[:limit]
    else:
        assert result == 'No events were found.'
    assert not set_context_mocker.called



@pytest.mark.parametrize(
    'limit, integration_context_mock', [
        (
            1,
            {'events': '[{"1":"1"},{"2":"2"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            2,
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"},{"4":"4"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            5,
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            50,
            {'events': '[{"1":"1"},{"2":"2"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            22,
            {'events': '[]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            3,
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"},{"4":"4"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            4,
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"},{"4":"4"}]', 'access_token': 'test', 'time_issued': 'test'}
        ),
        (
            6,
            {'events': '[{"1":"1"},{"2":"2"},{"3":"3"},{"4":"4"},{"5":"5"},{"6":"6"},{"7":"7"},{"8":"8"}]',
             'access_token': 'test', 'time_issued': 'test'}
        ),
    ]
)
def test_fetch_events(mocker, limit, integration_context_mock):
    """
    Given
       - events in the integration context
       - limit parameter

    When -
        executing the fetch-events

    Then
       - make sure the events that are returned the size of the limit or less
       - make sure the integration context is being overridden with the correct events
    """
    import SaasSecurityEventCollector
    expected_integration_context = integration_context_mock.copy()

    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context_mock)
    set_context_mocker = mocker.patch.object(SaasSecurityEventCollector, 'set_to_integration_context_with_retries')

    expected_integration_context['events'] = json.loads(expected_integration_context['events'])

    actual_events = SaasSecurityEventCollector.fetch_events(max_fetch=limit)
    assert actual_events == expected_integration_context['events'][:limit]

    expected_integration_context['events'] = expected_integration_context['events'][limit:]
    assert set_context_mocker.called
    assert expected_integration_context == set_context_mocker.call_args.kwargs['context']
