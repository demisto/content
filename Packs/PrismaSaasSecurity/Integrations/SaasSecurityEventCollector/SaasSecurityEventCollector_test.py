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
import copy
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
            {'events': '[{"id":"1"},{"id":"2"}]'}
        ),
        (
            {"limit": "2"},
            {'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"}]'}
        ),
        (
            {"limit": "5"},
            {'events': '[{"id":"1"},{"id":"2"},{"id":"3"}]'}
        ),
        (
            {"limit": "50"},
            {'events': '[{"id":"1"},{"id":"2"}]'}
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


class TestFetchEvents:

    INTEGRATION_CONTEXT = {}

    def set_integration_context(self, **kwargs):
        from CommonServerPython import merge_lists
        events = kwargs.get('context').get('events')
        self.INTEGRATION_CONTEXT['events'] = json.dumps(
            merge_lists(original_list=json.loads(self.INTEGRATION_CONTEXT['events']), updated_list=events, key='id')
        )

    @pytest.mark.parametrize(
        'limit, expected_integration_context', [
            (
                1,
                {'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},{"id":"6"},{"id":"7"},{"id":"8"}]'}
            ),
            (
                2,
                {'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},{"id":"6"},{"id":"7"},{"id":"8"}]'}
            ),
            (
                10,
                {'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},{"id":"6"},{"id":"7"},{"id":"8"}]'}
            ),
            (
               3,
               {
                   'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},'
                             '{"id":"6"},{"id":"7"},{"id":"8"},{"id":"9"},{"id":"10"},'
                             '{"id":"11"},{"id":"12"},{"id":"13"},{"id":"14"},{"id":"15"},{"id":"16"}]'
               }
            ),
            (
                15,
                {
                    'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},'
                              '{"id":"6"},{"id":"7"},{"id":"8"},{"id":"9"},{"id":"10"},'
                              '{"id":"11"},{"id":"12"},{"id":"13"},{"id":"14"},{"id":"15"},{"id":"16"}]'
                }
            ),
            (
                16,
                {
                    'events': '[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},'
                              '{"id":"6"},{"id":"7"},{"id":"8"},{"id":"9"},{"id":"10"},'
                              '{"id":"11"},{"id":"12"},{"id":"13"},{"id":"14"},{"id":"15"},{"id":"16"}]'
                }
            )
        ]
    )
    def test_fetch_events(self, mocker, limit, expected_integration_context):
        """
        Given
           - events in the integration context
           - limit parameter

        When -
            executing the fetch-events command

        Then
           - make sure that if limit > len(events) - then all of the events will be returned and all of them will be
             deleted from the integration context
           - make sure that if limit < len(events), that the first 'limit' events will be fetched and deleted from
             the integration context
           - make sure that when setting the integration context, the events that should be deleted are passed
           - make sure that every time we call fetch events, then set integration context will be called as well.

        """
        import SaasSecurityEventCollector

        self.INTEGRATION_CONTEXT = copy.deepcopy(expected_integration_context)

        mocker.patch.object(demisto, 'getIntegrationContext', return_value=self.INTEGRATION_CONTEXT)
        set_context_mocker = mocker.patch.object(
            SaasSecurityEventCollector,
            'set_to_integration_context_with_retries',
            side_effect=self.set_integration_context
        )

        expected_integration_context['events'] = json.loads(expected_integration_context['events'])
        call_count = 1

        while len(json.loads(self.INTEGRATION_CONTEXT['events'])) > 0:
            actual_events = SaasSecurityEventCollector.fetch_events(max_fetch=limit)
            assert actual_events == expected_integration_context['events'][:limit]

            assert set_context_mocker.call_count == call_count
            call_count += 1
            for event in expected_integration_context['events'][:limit]:
                event['remove'] = True
            expected_events_removed = expected_integration_context['events'][:limit]
            assert {'events': expected_events_removed} == set_context_mocker.call_args.kwargs.get('context')
            expected_integration_context['events'] = expected_integration_context['events'][limit:]
