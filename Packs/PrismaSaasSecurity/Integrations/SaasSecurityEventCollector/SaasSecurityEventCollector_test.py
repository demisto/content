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

    @pytest.mark.parametrize("max_fetch, queue, expected_events", EVENTS_DATA)
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

    @pytest.mark.parametrize("max_fetch, queue, expected_events", EVENTS_DATA)
    def test_main_flow_fetch_events_saved_in_integration_context(self, mocker, max_fetch, queue, expected_events):
        """
        Given
           - a queue of responses to fetch events.
           - max fetch limit
           - integration parameters

        When
           - executing main to fetch events.
           - send_events_to_xsiam raised an exception

        Then
           - make sure all the events are saved in the integration context in such case.
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

        assert expected_events == set_integration_context_mock.call_args.args[0]

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


# Tests: hash_event


class TestHashEvent:
    """Tests for the hash_event helper function."""

    def test_hash_is_deterministic(self):
        """Hashing the same dict twice yields the same hash."""
        from SaasSecurityEventCollector import hash_event

        event = {"timestamp": "2025-01-01T00:00:00Z", "log_type": "audit", "user": "alice"}
        assert hash_event(event) == hash_event(event)

    def test_hash_is_key_order_independent(self):
        """Different dict insertion order produces the same hash (sort_keys=True)."""
        from SaasSecurityEventCollector import hash_event

        event_a = {"a": 1, "b": 2, "c": 3}
        event_b = {"c": 3, "b": 2, "a": 1}
        assert hash_event(event_a) == hash_event(event_b)

    def test_hash_differs_for_different_events(self):
        """Two events with different content produce different hashes."""
        from SaasSecurityEventCollector import hash_event

        event_a = {"id": "1", "user": "alice"}
        event_b = {"id": "2", "user": "alice"}
        assert hash_event(event_a) != hash_event(event_b)

    def test_hash_handles_nested_structures(self):
        """Nested dicts/lists hash deterministically regardless of key order."""
        from SaasSecurityEventCollector import hash_event

        event_a = {"meta": {"x": 1, "y": 2}, "tags": ["a", "b"]}
        event_b = {"tags": ["a", "b"], "meta": {"y": 2, "x": 1}}
        assert hash_event(event_a) == hash_event(event_b)

    def test_hash_handles_non_json_values(self):
        """Non-JSON-native values (e.g., datetime) are stringified, not raising."""
        from datetime import datetime

        from SaasSecurityEventCollector import hash_event

        event = {"timestamp": datetime(2025, 1, 1)}  # noqa: DTZ001
        assert hash_event(event) == hash_event(event)

    def test_hash_returns_hex_string(self):
        """The returned hash is a 64-character hex string (SHA-256)."""
        from SaasSecurityEventCollector import hash_event

        h = hash_event({"a": 1})
        assert isinstance(h, str)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# Tests: deduplicate_events


class TestDeduplicateEvents:
    """Tests for the deduplicate_events helper function."""

    def test_first_run_returns_all_events_and_their_hashes(self):
        """When no previous hashes exist, every event passes through and is hashed."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        events = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
        new_events, new_hashes = deduplicate_events(events, previous_hashes=[])

        assert new_events == events
        assert new_hashes == [hash_event(e) for e in events]

    def test_empty_events_preserves_previous_hashes(self):
        """Empty input must return previous_hashes unchanged so dedup state is preserved."""
        from SaasSecurityEventCollector import deduplicate_events

        new_events, new_hashes = deduplicate_events([], previous_hashes=["abc"])
        assert new_events == []
        assert new_hashes == ["abc"]

    def test_filters_out_duplicates(self):
        """Events whose hash matches a previous hash are removed; returned hashes
        contain only the new run's events (not the union with previous)."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        seen = {"id": "1", "user": "alice"}
        new = {"id": "2", "user": "bob"}
        events = [seen, new]
        previous_hashes = [hash_event(seen)]

        new_events, new_hashes = deduplicate_events(events, previous_hashes=previous_hashes)

        assert new_events == [new]
        assert new_hashes == [hash_event(new)]

    def test_preserves_event_order(self):
        """Surviving events retain their original order."""
        from SaasSecurityEventCollector import deduplicate_events

        events = [{"id": "1"}, {"id": "2"}, {"id": "3"}, {"id": "4"}]
        new_events, _ = deduplicate_events(events, previous_hashes=[])

        assert [e["id"] for e in new_events] == ["1", "2", "3", "4"]

    def test_no_duplicates_when_hashes_disjoint(self):
        """If no event matches any previous hash, all events pass through and
        returned hashes include only the new run's events."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        events = [{"id": "x"}, {"id": "y"}]
        previous_hashes = ["unrelated_hash"]
        new_events, new_hashes = deduplicate_events(events, previous_hashes=previous_hashes)

        assert new_events == events
        assert new_hashes == [hash_event(e) for e in events]

    def test_all_events_are_duplicates_returns_empty_hashes(self):
        """If every event matches a previous hash, no events and no hashes are returned."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        events = [{"id": "1"}, {"id": "2"}]
        previous_hashes = [hash_event(e) for e in events]

        new_events, new_hashes = deduplicate_events(events, previous_hashes=previous_hashes)

        assert new_events == []
        assert new_hashes == []

    def test_dedup_is_key_order_invariant(self):
        """An event sent with reordered keys is still detected as a duplicate."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        original = {"a": 1, "b": 2, "c": 3}
        reordered = {"c": 3, "a": 1, "b": 2}
        previous_hashes = [hash_event(original)]

        new_events, new_hashes = deduplicate_events([reordered], previous_hashes=previous_hashes)

        assert new_events == []
        assert new_hashes == []

    def test_intra_batch_duplicates_are_filtered(self):
        """If the same event appears multiple times within a single batch, only
        the first occurrence is kept (intra-batch dedup)."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        event = {"id": "x", "user": "alice"}
        events = [event, event, event]  # same event 3 times in one batch
        new_events, new_hashes = deduplicate_events(events, previous_hashes=[])

        assert new_events == [event]
        assert new_hashes == [hash_event(event)]

    def test_first_run_with_intra_batch_duplicates(self):
        """First-run path (empty previous_hashes) also dedups intra-batch."""
        from SaasSecurityEventCollector import deduplicate_events, hash_event

        events = [{"id": "1"}, {"id": "2"}, {"id": "1"}]  # event 1 appears twice
        new_events, new_hashes = deduplicate_events(events, previous_hashes=[])

        assert new_events == [{"id": "1"}, {"id": "2"}]
        assert new_hashes == [hash_event({"id": "1"}), hash_event({"id": "2"})]


# Tests: dedup integration in main() fetch-events flow


class TestMainFetchEventsDedup:
    """Tests for the dedup integration inside main()'s fetch-events branch."""

    PARAMS = {
        "url": "https://test.com/",
        "credentials": {"identifier": "1234", "password": "1234"},
        "max_fetch": 100,
    }

    def _common_mocks(self, mocker, last_run, queue):
        """Wire up common demisto + Client mocks used by every test in this class."""
        import SaasSecurityEventCollector

        mocker.patch.object(Client, "http_request", side_effect=queue)
        mocker.patch.object(demisto, "params", return_value=self.PARAMS)
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(demisto, "getLastRun", return_value=last_run)
        mocker.patch.object(demisto, "getIntegrationContext", return_value={})
        return SaasSecurityEventCollector

    def test_first_run_pushes_all_events_and_stores_hashes(self, mocker):
        """
        Given - last_run has no `hashed_recent_events` key (first run).
        When  - main() runs fetch-events with a queue of events.
        Then  - all fetched events are sent to XSIAM, and last_run is updated with
                hashes for every pushed event.
        """
        from SaasSecurityEventCollector import hash_event

        mod = self._common_mocks(
            mocker,
            last_run={},
            queue=[
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=3)),
                MockedResponse(status_code=204),
            ],
        )
        send_mock = mocker.patch.object(mod, "send_events_to_xsiam")
        set_last_run_mock = mocker.patch.object(demisto, "setLastRun")

        mod.main()

        sent_events = send_mock.call_args.kwargs.get("events")
        assert len(sent_events) == 3
        stored_last_run = set_last_run_mock.call_args.args[0]
        expected_hashes = [hash_event(e) for e in sent_events]
        assert stored_last_run["hashed_recent_events"] == expected_hashes

    def test_subsequent_run_filters_duplicates(self, mocker):
        """
        Given - last_run already contains hashes for some of the upcoming events.
        When  - main() runs fetch-events.
        Then  - duplicates are removed before pushing; only new events are sent;
                last_run is replaced with ONLY the current run's hashes (bounded by max_fetch).
        """
        from SaasSecurityEventCollector import hash_event

        # Pre-compute hashes for events 1 and 2 — they should be filtered out.
        already_seen = [{"id": 1}, {"id": 2}]
        previous_hashes = [hash_event(e) for e in already_seen]

        mod = self._common_mocks(
            mocker,
            last_run={"hashed_recent_events": previous_hashes},
            queue=[
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=4)),
                MockedResponse(status_code=204),
            ],
        )
        send_mock = mocker.patch.object(mod, "send_events_to_xsiam")
        set_last_run_mock = mocker.patch.object(demisto, "setLastRun")

        mod.main()

        sent_events = send_mock.call_args.kwargs.get("events")
        # Only events 3 and 4 should remain after dedup.
        assert sent_events == [{"id": 3}, {"id": 4}]
        stored_last_run = set_last_run_mock.call_args.args[0]
        # last_run is replaced with only the current run's hashes (no carryover).
        assert stored_last_run["hashed_recent_events"] == [hash_event(e) for e in sent_events]

    def test_hashes_not_stored_when_push_fails(self, mocker):
        """
        Given - last_run has previous hashes; XSIAM push raises an exception.
        When  - main() runs fetch-events.
        Then  - last_run["hashed_recent_events"] is NOT updated (still the previous
                hashes), so a re-fetch on the next invocation will not falsely treat
                the unsent events as duplicates.
        """
        from SaasSecurityEventCollector import hash_event

        previous_hashes = [hash_event({"id": 999})]  # unrelated to events about to fetch

        mod = self._common_mocks(
            mocker,
            last_run={"hashed_recent_events": previous_hashes},
            queue=[
                MockedResponse(status_code=200, text=create_events(start_id=1, end_id=2)),
                MockedResponse(status_code=204),
            ],
        )
        mocker.patch.object(mod, "send_events_to_xsiam", side_effect=Exception("xsiam down"))
        mocker.patch.object(demisto, "setIntegrationContext")
        set_last_run_mock = mocker.patch.object(demisto, "setLastRun")

        mod.main()

        stored_last_run = set_last_run_mock.call_args.args[0]
        # Hashes should remain unchanged (still the previous ones, not overwritten).
        assert stored_last_run["hashed_recent_events"] == previous_hashes
