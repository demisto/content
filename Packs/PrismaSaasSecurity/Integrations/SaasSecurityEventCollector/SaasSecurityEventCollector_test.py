"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json

import demistomock as demisto
import pytest
from CommonServerPython import *
from SaasSecurityEventCollector import Client


@pytest.fixture
def mock_client():
    return Client(base_url="https://test.com/api", client_id="", client_secret="", verify=False, proxy=False)


def create_events(start_id=1, end_id=100, should_dump=True):
    events = {"events": [{"id": i} for i in range(start_id, end_id + 1)]}
    return json.dumps(events) if should_dump else events


class MockedResponse:
    def __init__(self, status_code, text="{}"):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
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

    mocker.patch.object(Client, "get_token_request")
    assert test_module(client=mock_client) == "ok"


def test_get_new_access_token(mocker, mock_client):
    mocker.patch.object(mock_client, "get_token_request", return_value=("123", "100"))
    access_token = mock_client.get_access_token()
    assert access_token == "123"


def test_get_existing_access_token(mocker, mock_client):
    mocker.patch.object(
        demisto,
        "getIntegrationContextVersioned",
        return_value={
            "context": {"access_token": "123", "token_initiate_time": "10000.941587", "token_expiration_seconds": "7200"}
        },
    )
    mocker.patch.object(time, "time", return_value=16999.941587)
    access_token = mock_client.get_access_token()
    assert access_token == "123"


class TestFetchEvents:
    EVENTS_DATA = [
        (
            200,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=21, end_id=30)),
            ],
            create_events(start_id=1, end_id=200, should_dump=False),
        ),
        (
            100,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=102)),
            ],
            create_events(start_id=1, end_id=100, should_dump=False),
        ),
        (
            100,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=8)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=8, should_dump=False),
        ),
        (
            100,
            [MockedResponse(status_code=200, text=create_events(start_id=1, end_id=54)), MockedResponse(status_code=204)],
            create_events(start_id=1, end_id=54, should_dump=False),
        ),
        (
            100,
            [MockedResponse(status_code=204)],
            create_events(start_id=2, end_id=1, should_dump=False),  # empty events response
        ),
        (
            200,
            [MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)), MockedResponse(status_code=204)],
            create_events(start_id=1, end_id=100, should_dump=False),
        ),
        (
            300,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=200, should_dump=False),
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
            create_events(start_id=1, end_id=1000, should_dump=False),
        ),
        (
            300,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=280)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=280, should_dump=False),
        ),
        (
            400,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=300, should_dump=False),
        ),
        (
            400,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
            ],
            create_events(start_id=1, end_id=300, should_dump=False),
        ),
        (
            10000,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=705)),
                MockedResponse(status_code=200, text=create_events(start_id=706, end_id=950)),
                MockedResponse(status_code=200, text=create_events(start_id=951, end_id=1678)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=1678, should_dump=False),
        ),
        (
            10000,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=1000)),
                MockedResponse(status_code=200, text=create_events(start_id=1001, end_id=2000)),
                MockedResponse(status_code=200, text=create_events(start_id=2001, end_id=3000)),
                MockedResponse(status_code=200, text=create_events(start_id=3001, end_id=4000)),
                MockedResponse(status_code=200, text=create_events(start_id=4001, end_id=4512)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=4512, should_dump=False),
        ),
        (
            None,
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
            ],
            create_events(start_id=1, end_id=300, should_dump=False),
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
                MockedResponse(status_code=200, text=create_events(start_id=901, end_id=950)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=950, should_dump=False),
        ),
    ]

    @pytest.mark.parametrize("max_fetch, queue, expected_events", EVENTS_DATA)
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

        mocker.patch.object(Client, "http_request", side_effect=queue)
        events, _, _ = fetch_events_from_saas_security(client=mock_client, max_fetch=max_fetch)

        assert expected_events.get("events") == events

    @pytest.mark.parametrize("max_fetch, queue, expected_events", EVENTS_DATA)
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

        should_push_events = max_fetch == 100
        mocker.patch.object(Client, "http_request", side_effect=queue)
        send_events_mocker = mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")

        result = SaasSecurityEventCollector.get_events_command(
            client=mock_client, args={"should_push_events": should_push_events}, max_fetch=max_fetch
        )

        if expected_events := expected_events.get("events"):
            assert expected_events == result.outputs
            assert send_events_mocker.called == should_push_events
        else:
            assert result == "No events were found."
            assert not send_events_mocker.called

    # For the main fetch-events flow the collector now drains the queue until a 204 is received
    # (bounded only by max_iterations), regardless of the configured max_fetch. Each queue below
    # therefore ends with a 204, and the expected result is the full set of events in the queue.
    MAIN_FLOW_DATA = [
        (
            1000,  # configured max_fetch (must NOT cap the live fetch anymore)
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=300, should_dump=False),
        ),
        (
            100,  # small max_fetch must NOT cap live fetch; full queue (500) should be drained
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
                MockedResponse(status_code=200, text=create_events(start_id=401, end_id=500)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=500, should_dump=False),
        ),
        (
            None,  # no max_fetch configured - drain everything until 204
            [
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=150)),
                MockedResponse(status_code=204),
            ],
            create_events(start_id=1, end_id=150, should_dump=False),
        ),
    ]

    @pytest.mark.parametrize("max_fetch, queue, expected_events", MAIN_FLOW_DATA)
    def test_main_flow_fetch_events(self, mocker, max_fetch, queue, expected_events):
        """
        Given
           - a queue of responses to fetch events that ends with a 204 (queue drained).
           - a configured max_fetch (possibly small, possibly None).
           - integration parameters.

        When -
            executing main to fetch events.

        Then
           - make sure ALL available events in the queue are fetched and sent to XSIAM,
             regardless of the configured max_fetch (max_fetch no longer throttles live fetch).
        """
        import SaasSecurityEventCollector

        mocker.patch.object(Client, "http_request", side_effect=queue)
        send_events_mocker = mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://test.com/",
                "credentials": {
                    "identifier": "1234",
                    "password": "1234",
                },
                "max_fetch": max_fetch,
            },
        )
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        SaasSecurityEventCollector.main()
        assert send_events_mocker.called
        assert send_events_mocker.call_args.kwargs.get("events") == expected_events.get("events")

    @pytest.mark.parametrize("max_fetch, queue, expected_events", MAIN_FLOW_DATA)
    def test_main_flow_fetch_events_saved_in_integration_context(self, mocker, max_fetch, queue, expected_events):
        """
        Given
           - a queue of responses to fetch events that ends with a 204.
           - integration parameters.

        When
           - executing main to fetch events.
           - send_events_to_xsiam raised an exception (destructive-read safety: events already pulled
             from the queue must not be lost).

        Then
           - make sure ALL the events pulled from the queue are saved in the integration context,
             so they are re-sent on the next run instead of being dropped.
        """
        import SaasSecurityEventCollector

        mocker.patch.object(Client, "http_request", side_effect=queue)
        mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam", side_effect=Exception("error"))
        set_integration_context_mock = mocker.patch.object(demisto, "setIntegrationContext")

        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://test.com/",
                "credentials": {
                    "identifier": "1234",
                    "password": "1234",
                },
                "max_fetch": max_fetch,
            },
        )
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        SaasSecurityEventCollector.main()

        assert set_integration_context_mock.call_args.args[0] == {"events": expected_events.get("events")}

    def test_main_flow_fetch_events_with_max_iterations(self, mocker):
        """
        Given
           - a queue of responses to fetch events.
           - max fetch limit
           - integration parameters
           - max iterations

        When
           - executing main to fetch events.

        Then
           - make sure that only the events will stop being fetched after the number of iterations has been reached.
        """
        import SaasSecurityEventCollector

        mocker.patch.object(
            Client,
            "http_request",
            side_effect=[
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
                MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
                MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
                MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
                MockedResponse(status_code=200, text=create_events(start_id=401, end_id=500)),
            ],
        )
        send_events_mocker = mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://test.com/",
                "credentials": {
                    "identifier": "1234",
                    "password": "1234",
                },
                "max_fetch": 10000,
                "max_iterations": 3,
            },
        )
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        SaasSecurityEventCollector.main()
        assert send_events_mocker.called
        assert send_events_mocker.call_args.kwargs.get("events") == create_events(start_id=1, end_id=300, should_dump=False).get(
            "events"
        )


@pytest.mark.parametrize(
    "time_mock, token_initiate_time, token_expiration_seconds, expected_result",
    [
        (17200.941587, 10000.941587, 7200, True),
        (16999.941587, 10000.941587, 7200, False),
        (20000.941587, 10000.941587, 9000, True),
        (12456.941587, 10000.941587, 9000, False),
        (300, 240, 120, True),
        (300.00001, 240, 120, True),
        (299.99999, 240, 120, False),
    ],
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

    mocker.patch.object(time, "time", return_value=time_mock)

    assert (
        is_token_expired(token_initiate_time=token_initiate_time, token_expiration_seconds=token_expiration_seconds)
        == expected_result
    )


@pytest.mark.parametrize(
    "limit, expected_limit",
    [
        (126, 120),
        (54, 50),
        (23, 20),
        (235, 230),
        (250, 250),
        (10000, 5000),
        (5000, 5000),
        (3, 10),
        (100, 100),
        (2000, 2000),
        (150, 150),
        (404, 400),
        (120, 120),
        (1, 10),
        (4, 10),
        (487, 480),
    ],
)
def test_max_fetch(limit, expected_limit):
    """
    Given
       - a limit parameter which is not divisible by 100/negative limit.

    When -
        executing get_max_fetch function

    Then
      - make sure the limit gets rounded to a number that is dividable by 10.
    """
    from SaasSecurityEventCollector import get_max_fetch

    assert get_max_fetch(limit) == expected_limit


def test_max_fetch_negative_number():
    """
    Given
      - a limit parameter that is negative

    When
      - executing validate_limit function

    Then
      - make sure an exception is raised
    """
    from SaasSecurityEventCollector import get_max_fetch

    with pytest.raises(DemistoException):
        get_max_fetch(-1)


def test_default_constants_match_api_reality():
    """
    Given
      - the SaaS Security /log_events_bulk API returns at most 100 events per call (verified against the API).

    When
      - inspecting the module-level constants.

    Then
      - MAX_EVENTS_PER_REQUEST reflects the real per-call cap (100), not the previous misleading 1000.
      - MAX_ITERATIONS default is raised to 150 so a single execution can drain up to 15,000 events,
        which (together with nextTrigger) keeps the collector ahead of high upstream rates.
    """
    import SaasSecurityEventCollector

    assert SaasSecurityEventCollector.MAX_EVENTS_PER_REQUEST == 100
    assert SaasSecurityEventCollector.MAX_ITERATIONS == 150


def test_get_events_request_uses_per_call_cap(mocker, mock_client):
    """
    Given
      - the client.

    When
      - calling get_events_request without an explicit size.

    Then
      - the request is sent with size equal to the real per-call cap (100).
    """
    from SaasSecurityEventCollector import MAX_EVENTS_PER_REQUEST

    http_mock = mocker.patch.object(Client, "http_request", return_value=MockedResponse(status_code=204))
    mock_client.get_events_request()
    assert http_mock.call_args.kwargs.get("params") == {"size": MAX_EVENTS_PER_REQUEST}


def test_fetch_drains_until_204_ignoring_small_max_fetch(mocker, mock_client):
    """
    Given
      - a queue with 500 events followed by a 204.

    When
      - fetching events with max_fetch=None (the live-fetch behavior).

    Then
      - all 500 events are drained until the 204, and queue_drained is True.
    """
    from SaasSecurityEventCollector import fetch_events_from_saas_security

    queue = [
        MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
        MockedResponse(status_code=200, text=create_events(start_id=101, end_id=200)),
        MockedResponse(status_code=200, text=create_events(start_id=201, end_id=300)),
        MockedResponse(status_code=200, text=create_events(start_id=301, end_id=400)),
        MockedResponse(status_code=200, text=create_events(start_id=401, end_id=500)),
        MockedResponse(status_code=204),
    ]
    mocker.patch.object(Client, "http_request", side_effect=queue)
    events, exception, queue_drained = fetch_events_from_saas_security(client=mock_client, max_fetch=None)

    assert exception is None
    assert queue_drained is True
    assert events == create_events(start_id=1, end_id=500, should_dump=False).get("events")


def test_fetch_not_drained_when_max_iterations_reached(mocker, mock_client):
    """
    Given
      - a queue that never returns 204 (more events than max_iterations can pull).

    When
      - fetching events with a small max_iterations and no max_fetch.

    Then
      - the loop stops at max_iterations and reports queue_drained=False
        (so the caller schedules an immediate nextTrigger follow-up).
    """
    from SaasSecurityEventCollector import fetch_events_from_saas_security

    queue = [MockedResponse(status_code=200, text=create_events(start_id=i * 100 + 1, end_id=i * 100 + 100)) for i in range(10)]
    mocker.patch.object(Client, "http_request", side_effect=queue)
    events, exception, queue_drained = fetch_events_from_saas_security(client=mock_client, max_fetch=None, max_iterations=3)

    assert exception is None
    assert queue_drained is False
    assert len(events) == 300


def test_main_sets_next_trigger_when_queue_not_drained(mocker):
    """
    Given
      - a queue that never drains within max_iterations.

    When
      - executing main to fetch events.

    Then
      - nextTrigger is set in last run so the next fetch fires immediately,
      - and the consecutive backlog counter is incremented.
    """
    import SaasSecurityEventCollector

    queue = [MockedResponse(status_code=200, text=create_events(start_id=i * 100 + 1, end_id=i * 100 + 100)) for i in range(5)]
    mocker.patch.object(Client, "http_request", side_effect=queue)
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://test.com/",
            "credentials": {"identifier": "1234", "password": "1234"},
            "max_iterations": 3,
        },
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    SaasSecurityEventCollector.main()

    last_run = set_last_run_mock.call_args.args[0]
    assert last_run.get("nextTrigger") == SaasSecurityEventCollector.NEXT_TRIGGER_VALUE
    assert last_run.get("consecutive_backlog_cycles") == 1


def test_main_clears_next_trigger_when_queue_drained(mocker):
    """
    Given
      - a queue that drains (ends with 204) and a prior backlog counter in last run.

    When
      - executing main to fetch events.

    Then
      - nextTrigger and the backlog counter are cleared so the next fetch uses the normal interval.
    """
    import SaasSecurityEventCollector

    queue = [
        MockedResponse(status_code=200, text=create_events(start_id=1, end_id=100)),
        MockedResponse(status_code=204),
    ]
    mocker.patch.object(Client, "http_request", side_effect=queue)
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={"nextTrigger": "1", "consecutive_backlog_cycles": 4})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://test.com/",
            "credentials": {"identifier": "1234", "password": "1234"},
        },
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    SaasSecurityEventCollector.main()

    last_run = set_last_run_mock.call_args.args[0]
    assert "nextTrigger" not in last_run
    assert "consecutive_backlog_cycles" not in last_run


def test_main_emits_backlog_warning_after_threshold(mocker):
    """
    Given
      - a queue that never drains within max_iterations.
      - a prior backlog counter just below the warning threshold.

    When
      - executing main to fetch events.

    Then
      - a high-visibility error is emitted so sustained ingestion backlog/lag is observable
        instead of failing silently.
    """
    import SaasSecurityEventCollector

    queue = [MockedResponse(status_code=200, text=create_events(start_id=i * 100 + 1, end_id=i * 100 + 100)) for i in range(5)]
    mocker.patch.object(Client, "http_request", side_effect=queue)
    mocker.patch.object(SaasSecurityEventCollector, "send_events_to_xsiam")
    mocker.patch.object(demisto, "setLastRun")
    error_mock = mocker.patch.object(demisto, "error")
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={"consecutive_backlog_cycles": SaasSecurityEventCollector.BACKLOG_WARNING_THRESHOLD - 1},
    )
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://test.com/",
            "credentials": {"identifier": "1234", "password": "1234"},
            "max_iterations": 3,
        },
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    SaasSecurityEventCollector.main()

    assert error_mock.called
