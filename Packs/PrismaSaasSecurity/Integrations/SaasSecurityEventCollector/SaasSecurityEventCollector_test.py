"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import demistomock as demisto
from CommonServerPython import *
import pytest
import json
import io
from SaasSecurityEventCollector import Client


@pytest.fixture
def mock_client():
    return Client(base_url='https://test.com/api', client_id='', client_secret='', verify=False, proxy=False)


def create_events(start_id=1, end_id=100, should_dump=True):
    events = {'events': [{'id': i} for i in range(start_id, end_id + 1)]}
    return json.dumps(events) if should_dump else events


class MockedResponse:

    def __init__(self, status_code, text='{}'):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_module(mocker, mock_client):
    """
    Given
       - a valid access token

    When -
        testing the module.

    Then
       - make sure the test module returns the 'ok' response.

    """
    from SaasSecurityEventCollector import test_module

    mocker.patch.object(Client, 'get_token_request')
    assert test_module(client=mock_client) == 'ok'


class TestFetchEvents:

    EVENTS_DATA = [
        (
            200,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=21, end_id=30))
            ],
            create_events(start_id=1, end_id=200, should_dump=False)
        ),
        (
            100,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=102)),
            ],
            create_events(start_id=1, end_id=100, should_dump=False)
        ),
        (
            100,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=8)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=8, should_dump=False)
        ),
        (
            100,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=54)),
                MockedResponse(status_code=204)
            ],
            create_events(start_id=1, end_id=54, should_dump=False)
        ),
        (
            100,
            [
                MockedResponse(status_code=204)
            ],
            create_events(start_id=2, end_id=1, should_dump=False)  # empty events response
        ),
        (
            200,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=204)
            ],
            create_events(start_id=1, end_id=100, should_dump=False)
        ),
        (
            300,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=204)
            ],
            create_events(start_id=1, end_id=200, should_dump=False)
        ),
        (
            1000,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
                MockedResponse(status_code=200, text=create_events(start_id=401, end_id=500)),
                MockedResponse(status_code=200, text=create_events(start_id=501, end_id=600)),
                MockedResponse(status_code=200, text=create_events(start_id=601, end_id=700)),
                MockedResponse(status_code=200, text=create_events(start_id=701, end_id=800)),
                MockedResponse(status_code=200, text=create_events(start_id=801, end_id=900)),
                MockedResponse(status_code=200, text=create_events(start_id=901, end_id=1000)),
                MockedResponse(status_code=200, text=create_events(start_id=1001, end_id=1050)),
            ],
            create_events(start_id=1, end_id=1000, should_dump=False)
        ),
        (
            300,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=280)),
                MockedResponse(status_code=204)
            ],
            create_events(start_id=1, end_id=280, should_dump=False)
        ),
        (
            400,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204)
            ],
            create_events(start_id=1, end_id=300, should_dump=False)
        ),
        (
            400,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400))
            ],
            create_events(start_id=1, end_id=300, should_dump=False)
        ),
        (
            None,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400))
            ],
            create_events(start_id=1, end_id=300, should_dump=False)
        ),
        (
            None,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
                MockedResponse(status_code=200, text=create_events(start_id=401, end_id=500)),
                MockedResponse(status_code=200, text=create_events(start_id=501, end_id=600)),
                MockedResponse(status_code=200, text=create_events(start_id=601, end_id=700)),
                MockedResponse(status_code=200, text=create_events(start_id=701, end_id=800)),
                MockedResponse(status_code=200, text=create_events(start_id=801, end_id=900)),
                MockedResponse(status_code=200, text=create_events(start_id=901, end_id=1000)),
                MockedResponse(status_code=200, text=create_events(start_id=1001, end_id=1100)),
                MockedResponse(status_code=200, text=create_events(start_id=1101, end_id=1200)),
                MockedResponse(status_code=200, text=create_events(start_id=1201, end_id=1300)),
                MockedResponse(status_code=200, text=create_events(start_id=1301, end_id=1400)),
                MockedResponse(status_code=200, text=create_events(start_id=1401, end_id=1500)),
                MockedResponse(status_code=200, text=create_events(start_id=1501, end_id=1600)),
                MockedResponse(status_code=200, text=create_events(start_id=1601, end_id=1700)),
                MockedResponse(status_code=200, text=create_events(start_id=1701, end_id=1800)),
                MockedResponse(status_code=200, text=create_events(start_id=1801, end_id=1900)),
                MockedResponse(status_code=200, text=create_events(start_id=1901, end_id=2000)),
                MockedResponse(status_code=200, text=create_events(start_id=2001, end_id=2043)),
                MockedResponse(status_code=204)
            ],
            create_events(start_id=1, end_id=2043, should_dump=False)
        ),
    ]

    @pytest.mark.parametrize('max_fetch, queue, expected_events', EVENTS_DATA)
    def test_fetch_events(self, mocker, mock_client, max_fetch, queue, expected_events):
        """
        Given
           - a queue of responses to fetch events.
           - max fetch limit

        When -
            fetching events.

        Then
          - make sure the correct events are fetched according to the queue and max fetch.
          - make sure in case max fetch is None that all available events will be fetched.

        """
        from SaasSecurityEventCollector import fetch_events_from_saas_security
        mocker.patch.object(Client, 'http_request', side_effect=queue)
        assert expected_events.get('events') == fetch_events_from_saas_security(client=mock_client, max_fetch=max_fetch)

    @pytest.mark.parametrize('max_fetch, queue, expected_events', EVENTS_DATA)
    def test_saas_security_get_events(self, mocker, mock_client, max_fetch, queue, expected_events):
        """
        Given
           - a queue of responses to fetch events.
           - a limit parameter.
           - a should push events parameter.

        When -
            executing the get security events command.

        Then
          - make sure the correct events are fetched according to the queue and max fetch.
          - make sure in case where there are no events to fetch, a proper message will be returned.
          - make sure that the send_events_to_xsiam was called in case should_push_events is True
          - make sure that the send_events_to_xsiam was not called in case should_push_events is False
          - make sure in case max fetch is empty that all available events will be fetched.
        """
        import SaasSecurityEventCollector

        should_push_events = True if max_fetch == 100 else False
        mocker.patch.object(Client, 'http_request', side_effect=queue)
        send_events_mocker = mocker.patch.object(SaasSecurityEventCollector, 'send_events_to_xsiam')

        result = SaasSecurityEventCollector.get_events_command(
            client=mock_client, args={'should_push_events': should_push_events}, max_fetch=max_fetch
        )

        if expected_events := expected_events.get('events'):
            assert expected_events == result.outputs
            assert send_events_mocker.called == should_push_events
        else:
            assert result == 'No events were found.'
            assert not send_events_mocker.called

    @pytest.mark.parametrize('max_fetch, queue, expected_events', EVENTS_DATA)
    def test_main_flow_fetch_events(self, mocker, max_fetch, queue, expected_events):
        """
        Given
           - a queue of responses to fetch events.
           - max fetch limit
           - integration parameters

        When -
            executing main to fetch events.

        Then
           - make sure the correct events are fetched according to the queue and max fetch.
           - make sure the send_events_to_xsiam was called with the correct events.
           - make sure in case max fetch is empty that all available events will be fetched.
        """
        import SaasSecurityEventCollector

        mocker.patch.object(Client, 'http_request', side_effect=queue)
        send_events_mocker = mocker.patch.object(SaasSecurityEventCollector, 'send_events_to_xsiam')
        mocker.patch.object(demisto, 'params', return_value={
            "url": "https://test.com/",
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_fetch": max_fetch
        })
        mocker.patch.object(demisto, 'command', return_value='fetch-events')
        SaasSecurityEventCollector.main()
        assert send_events_mocker.called
        assert send_events_mocker.call_args.kwargs.get('events') == expected_events.get('events')


@pytest.mark.parametrize(
    'time_mock, token_initiate_time, token_expiration_seconds, expected_result', [
        (17200.941587, 10000.941587, 7200, True),
        (16999.941587, 10000.941587, 7200, False),
        (20000.941587, 10000.941587, 9000, True),
        (12456.941587, 10000.941587, 9000, False),
        (300, 240, 120, True),
        (300.00001, 240, 120, True),
        (299.99999, 240, 120, False),
    ]
)
def test_is_token_expired(mocker, time_mock, token_initiate_time, token_expiration_seconds, expected_result):
    """
    Given
       - time which means the token expiration time has reached.
       - time which means the token expiration time has not reached yet.

    When -
        validating whether token has expired

    Then
      - make sure when token expiration time has reached, the is_token_expired will return True
      - make sure when token expiration time has not reached, the is_token_expired will return False
    """
    import time
    from SaasSecurityEventCollector import is_token_expired

    mocker.patch.object(time, 'time', return_value=time_mock)

    assert is_token_expired(
        token_initiate_time=token_initiate_time, token_expiration_seconds=token_expiration_seconds
    ) == expected_result


@pytest.mark.parametrize('limit', [126, 54, 23, 12, 45, 12, 3, 1, 76, 23, 101, 235, -1, -80])
def test_validate_limit(limit):
    """
    Given
       - a limit parameter which is not divisible by 100/negative limit.

    When -
        executing the validate limit

    Then
      - make sure an exception is raised
    """
    from SaasSecurityEventCollector import validate_limit

    with pytest.raises(DemistoException):
        validate_limit(limit)
