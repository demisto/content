"""Unit tests for the Akamai Prolexic Event Collector.

Coverage target: ≥ 70%. Tests cover:

* ``test-module`` success and 401/404 failure mapping
* ``akamai-prolexic-get-events`` with and without ``should_push_events``
* ``fetch-events`` first run, subsequent run, dedup, multi-source
* Per-source ``max_events_per_fetch`` cap
* ``_ENTRY_STATUS`` annotation for critical events
* Account Switch Key propagation
"""

from __future__ import annotations

from typing import Any

import pytest

from AkamaiProlexic import (
    CRITICAL_EVENTS,
    DEFAULT_FIRST_FETCH,
    EVENTS,
    MAX_EVENTS_PER_FETCH_CEILING,
    Client,
    _parse_max_events_per_fetch,
    annotate_critical_event,
    extract_event_list,
    fetch_events,
    fetch_source_events,
    filter_and_dedup,
    get_events_command,
    make_event_id,
    normalize_event_timestamp,
    parse_first_fetch,
    push_events,
    run_test_module,
)


# --------------------------------------------------------------------------- #
# Test fixtures
# --------------------------------------------------------------------------- #


CRITICAL_RESPONSE: dict[str, Any] = {
    "criticalEvents": [
        {
            "id": "ce-1",
            "firstOccur": "2026-04-20T10:00:00Z",
            "recentOccur": "2026-04-20T10:00:00Z",
            "severity": "high",
            "description": "DDoS detected on policy A",
        },
        {
            "id": "ce-2",
            "firstOccur": "2026-04-20T11:30:00Z",
            "recentOccur": "2026-04-20T12:00:00Z",
            "severity": "critical",
            "description": "Volumetric attack on policy B",
        },
        {
            "id": "ce-3",
            "firstOccur": "2026-04-20T12:45:00Z",
            "recentOccur": "2026-04-20T12:45:00Z",
            "severity": "high",
            "description": "DDoS detected on policy C",
        },
    ]
}


EVENTS_RESPONSE: dict[str, Any] = {
    "events": [
        {
            "id": "e-1",
            "eventStartTime": "2026-04-20T09:00:00Z",
            "eventName": "Traffic anomaly",
            "policy": "policy-A",
        },
        {
            "id": "e-2",
            "eventStartTime": "2026-04-20T09:15:00Z",
            "eventName": "Traffic anomaly",
            "policy": "policy-B",
        },
    ]
}


EMPTY_RESPONSE: dict[str, Any] = {"events": [], "criticalEvents": []}


def _build_client() -> Client:
    """Build a Client without making any real network or signing calls."""
    return Client(
        base_url="https://akab-test.luna.akamaiapis.net",
        verify=False,
        proxy=False,
        client_token="ct",
        client_secret="cs",
        access_token="at",
        account_switch_key=None,
    )


# --------------------------------------------------------------------------- #
# Helper / utility tests
# --------------------------------------------------------------------------- #


class TestHelpers:
    def test_normalize_event_timestamp_iso(self):
        assert normalize_event_timestamp("2026-04-20T09:00:00Z") == "2026-04-20T09:00:00.000000Z"

    def test_normalize_event_timestamp_invalid(self):
        assert normalize_event_timestamp("not-a-date") is None

    def test_normalize_event_timestamp_none(self):
        assert normalize_event_timestamp(None) is None
        assert normalize_event_timestamp("") is None

    def test_parse_first_fetch_default(self):
        out = parse_first_fetch("")
        assert out.endswith("Z")
        assert "T" in out

    def test_parse_first_fetch_relative(self):
        out = parse_first_fetch("1 day")
        assert out.endswith("Z")
        assert "T" in out

    def test_make_event_id_includes_type_and_time(self):
        raw = {"id": "abc", "firstOccur": "2026-04-20T10:00:00Z"}
        out = make_event_id(CRITICAL_EVENTS, raw, "firstOccur")
        assert out == "Critical Events:abc:2026-04-20T10:00:00Z"

    def test_make_event_id_falls_back_to_alternative_id(self):
        raw = {"eventId": "xyz", "eventStartTime": "2026-04-20T11:00:00Z"}
        out = make_event_id(EVENTS, raw, "eventStartTime")
        assert out == "Events:xyz:2026-04-20T11:00:00Z"

    def test_extract_event_list_from_known_keys(self):
        assert len(extract_event_list({"events": [{"a": 1}, {"b": 2}]})) == 2
        assert len(extract_event_list({"criticalEvents": [{"x": 1}]})) == 1

    def test_extract_event_list_top_level_list(self):
        assert extract_event_list([{"a": 1}, "skip", {"b": 2}]) == [{"a": 1}, {"b": 2}]  # type: ignore[arg-type]

    def test_extract_event_list_unknown_response(self):
        assert extract_event_list({"foo": "bar"}) == []
        assert extract_event_list("nope") == []  # type: ignore[arg-type]

    def test_annotate_critical_event_new(self):
        ev = {"firstOccur": "2026-04-20T10:00:00Z", "recentOccur": "2026-04-20T10:00:00Z"}
        annotate_critical_event(ev)
        assert ev["_ENTRY_STATUS"] == "new"

    def test_annotate_critical_event_updated(self):
        ev = {"firstOccur": "2026-04-20T10:00:00Z", "recentOccur": "2026-04-20T11:00:00Z"}
        annotate_critical_event(ev)
        assert ev["_ENTRY_STATUS"] == "updated"

    def test_annotate_critical_event_no_first_occur(self):
        ev: dict[str, Any] = {"description": "no time"}
        annotate_critical_event(ev)
        assert "_ENTRY_STATUS" not in ev


# --------------------------------------------------------------------------- #
# Dedup / filter tests
# --------------------------------------------------------------------------- #


class TestFilterAndDedup:
    def test_filter_skips_events_before_high_water(self):
        raws = CRITICAL_RESPONSE["criticalEvents"]
        events, hw, ids = filter_and_dedup(
            raw_events=raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso="2026-04-20T11:00:00.000000Z",
            fetched_ids=set(),
            max_events=100,
        )
        # Only ce-2 and ce-3 are >= 11:00.
        assert {e["id"] for e in events} == {"ce-2", "ce-3"}
        # New high-water = ce-3 firstOccur normalised.
        assert hw == "2026-04-20T12:45:00.000000Z"
        assert ids == {make_event_id(CRITICAL_EVENTS, events[-1], "firstOccur")}

    def test_filter_dedups_already_fetched_ids(self):
        raws = CRITICAL_RESPONSE["criticalEvents"]
        previously_seen = {make_event_id(CRITICAL_EVENTS, raws[0], "firstOccur")}
        events, _, _ = filter_and_dedup(
            raw_events=raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso="2026-04-20T09:00:00.000000Z",
            fetched_ids=previously_seen,
            max_events=100,
        )
        assert "ce-1" not in {e["id"] for e in events}

    def test_filter_respects_max_events(self):
        raws = CRITICAL_RESPONSE["criticalEvents"]
        events, _, _ = filter_and_dedup(
            raw_events=raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso="2026-04-20T09:00:00.000000Z",
            fetched_ids=set(),
            max_events=2,
        )
        assert len(events) == 2

    def test_filter_skips_events_without_timestamp(self):
        bad_raws = [{"id": "x", "description": "no ts"}, *CRITICAL_RESPONSE["criticalEvents"]]
        events, _, _ = filter_and_dedup(
            raw_events=bad_raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso="2026-04-20T09:00:00.000000Z",
            fetched_ids=set(),
            max_events=100,
        )
        assert "x" not in {e["id"] for e in events}

    def test_critical_events_get_entry_status(self):
        raws = CRITICAL_RESPONSE["criticalEvents"]
        events, _, _ = filter_and_dedup(
            raw_events=raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso="2026-04-20T09:00:00.000000Z",
            fetched_ids=set(),
            max_events=100,
        )
        statuses = {e["id"]: e["_ENTRY_STATUS"] for e in events}
        assert statuses["ce-1"] == "new"
        assert statuses["ce-2"] == "updated"
        assert statuses["ce-3"] == "new"

    def test_events_have_source_log_type_and_event_type(self):
        events, _, _ = filter_and_dedup(
            raw_events=EVENTS_RESPONSE["events"],
            event_type=EVENTS,
            last_fetch_iso="2026-04-20T08:00:00.000000Z",
            fetched_ids=set(),
            max_events=100,
        )
        assert all(e["event_type"] == EVENTS for e in events)
        assert all(e["SOURCE_LOG_TYPE"] == "EVENTS" for e in events)
        assert all("_time" in e for e in events)

    def test_dedup_unions_when_cursor_does_not_advance(self):
        """Regression test for PR review (44059): when no NEW events arrive but the
        API re-emits previously-seen events at the same boundary timestamp, the
        prior dedup ids must be preserved (UNION) rather than replaced.
        """
        raws = CRITICAL_RESPONSE["criticalEvents"]
        # Seed last_run with the LAST event id so the cursor cannot advance.
        seeded_id = make_event_id(CRITICAL_EVENTS, raws[-1], "firstOccur")
        # Pretend we previously processed everything up to the latest timestamp.
        last_fetch_iso = "2026-04-20T12:45:00.000000Z"
        events, hw, retained = filter_and_dedup(
            raw_events=raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso=last_fetch_iso,
            fetched_ids={seeded_id},
            max_events=100,
        )
        # No fresh events accepted (ce-3 is dedup'd; ce-1/ce-2 are pre-cursor).
        assert events == []
        # High-water unchanged.
        assert hw == last_fetch_iso
        # Critical: prior id MUST survive into the next ``last_run``.
        assert seeded_id in retained

    def test_dedup_replaces_when_cursor_advances(self):
        """Counter-test for the union case: when the cursor DOES advance, only
        ids at the new boundary are retained (older ids cannot reappear)."""
        raws = CRITICAL_RESPONSE["criticalEvents"]
        # last_fetch_iso is well before everything; cursor will advance to ce-3.
        events, hw, retained = filter_and_dedup(
            raw_events=raws,
            event_type=CRITICAL_EVENTS,
            last_fetch_iso="2026-04-19T00:00:00.000000Z",
            fetched_ids=set(),
            max_events=100,
        )
        assert hw == "2026-04-20T12:45:00.000000Z"
        # Only ce-3 sits at the new high-water mark.
        assert retained == {make_event_id(CRITICAL_EVENTS, events[-1], "firstOccur")}


# --------------------------------------------------------------------------- #
# Source dispatch tests
# --------------------------------------------------------------------------- #


class TestFetchSourceEvents:
    def test_critical_events_first_run(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=CRITICAL_RESPONSE)
        events, next_run = fetch_source_events(
            client=client,
            event_type=CRITICAL_EVENTS,
            contract_id="C-1",
            source_last_run={},
            max_events=100,
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
        )
        assert {e["id"] for e in events} == {"ce-1", "ce-2", "ce-3"}
        assert next_run["last_fetch_ts"] == "2026-04-20T12:45:00.000000Z"
        assert next_run["fetched_ids"]

    def test_events_subsequent_run_dedups(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)
        already = make_event_id(EVENTS, EVENTS_RESPONSE["events"][0], "eventStartTime")
        events, _ = fetch_source_events(
            client=client,
            event_type=EVENTS,
            contract_id="C-1",
            source_last_run={
                "last_fetch_ts": "2026-04-20T08:00:00.000000Z",
                "fetched_ids": [already],
            },
            max_events=100,
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
        )
        assert {e["id"] for e in events} == {"e-2"}

    def test_unsupported_event_type_raises(self):
        client = _build_client()
        with pytest.raises(Exception):
            fetch_source_events(
                client=client,
                event_type="Bogus",
                contract_id="C-1",
                source_last_run={},
                max_events=10,
                first_fetch_iso="2026-04-19T00:00:00.000000Z",
            )


# --------------------------------------------------------------------------- #
# fetch-events end-to-end
# --------------------------------------------------------------------------- #


class TestFetchEvents:
    def test_first_run_both_sources(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=CRITICAL_RESPONSE)
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)
        events, next_run = fetch_events(
            client=client,
            contract_id="C-1",
            event_types=[CRITICAL_EVENTS, EVENTS],
            max_events_per_fetch=100,
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
            last_run={},
        )
        assert len(events) == 5
        assert "critical_events" in next_run
        assert "events" in next_run

    def test_subsequent_run_persists_state(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=CRITICAL_RESPONSE)
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)

        # Simulate state where ce-1 was already seen.
        seeded_id = make_event_id(CRITICAL_EVENTS, CRITICAL_RESPONSE["criticalEvents"][0], "firstOccur")
        last_run = {
            "critical_events": {
                "last_fetch_ts": "2026-04-20T09:00:00.000000Z",
                "fetched_ids": [seeded_id],
            }
        }
        events, _ = fetch_events(
            client=client,
            contract_id="C-1",
            event_types=[CRITICAL_EVENTS],
            max_events_per_fetch=100,
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
            last_run=last_run,
        )
        assert "ce-1" not in {e["id"] for e in events}

    def test_max_events_per_fetch_is_respected_per_source(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=CRITICAL_RESPONSE)
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)
        events, _ = fetch_events(
            client=client,
            contract_id="C-1",
            event_types=[CRITICAL_EVENTS, EVENTS],
            max_events_per_fetch=1,
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
            last_run={},
        )
        # 1 of each source.
        assert len(events) == 2
        assert {e["event_type"] for e in events} == {CRITICAL_EVENTS, EVENTS}

    def test_fetch_with_empty_response(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=EMPTY_RESPONSE)
        events, next_run = fetch_events(
            client=client,
            contract_id="C-1",
            event_types=[CRITICAL_EVENTS],
            max_events_per_fetch=100,
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
            last_run={},
        )
        assert events == []
        # Last fetch ts unchanged when nothing new.
        assert next_run["critical_events"]["last_fetch_ts"] == "2026-04-19T00:00:00.000000Z"


# --------------------------------------------------------------------------- #
# get-events command
# --------------------------------------------------------------------------- #


class TestGetEventsCommand:
    def test_get_events_returns_results_no_push(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=CRITICAL_RESPONSE)
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)
        push_spy = mocker.patch("AkamaiProlexic.send_events_to_xsiam")

        events, results = get_events_command(
            client=client,
            args={"limit": "100", "event_type": "Critical Events,Events", "should_push_events": "false"},
            contract_id="C-1",
            configured_types=[CRITICAL_EVENTS, EVENTS],
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
        )
        assert len(events) == 5
        assert results.readable_output  # tableToMarkdown produced output
        push_spy.assert_not_called()

    def test_get_events_push_invokes_xsiam(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=EMPTY_RESPONSE)
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)
        push_spy = mocker.patch("AkamaiProlexic.send_events_to_xsiam")

        events, _ = get_events_command(
            client=client,
            args={"limit": "100", "event_type": "Events", "should_push_events": "true"},
            contract_id="C-1",
            configured_types=[CRITICAL_EVENTS, EVENTS],
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
        )
        push_events(events)
        push_spy.assert_called_once()
        kwargs = push_spy.call_args.kwargs
        assert kwargs["vendor"] == "akamai"
        assert kwargs["product"] == "prolexic"
        assert len(kwargs["events"]) == 2

    def test_get_events_start_time_filters_old_events(self, mocker):
        """PR review (44059): ``get-events`` must accept a ``start_time`` arg
        that overrides the integration-level first-fetch.
        """
        client = _build_client()
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)

        # ``start_time`` later than e-1 (09:00) but before e-2 (09:15) → only e-2
        # should pass the filter.
        events, _ = get_events_command(
            client=client,
            args={
                "limit": "100",
                "event_type": "Events",
                "start_time": "2026-04-20T09:10:00Z",
                "should_push_events": "false",
            },
            contract_id="C-1",
            configured_types=[EVENTS],
            first_fetch_iso="2026-04-19T00:00:00.000000Z",
        )
        assert {e["id"] for e in events} == {"e-2"}


# --------------------------------------------------------------------------- #
# Configuration-parameter validation
# --------------------------------------------------------------------------- #


class TestParseMaxEventsPerFetch:
    """PR review (44059): ``max_events_per_fetch`` must reject 0 explicitly,
    not silently rewrite it to the default.
    """

    def test_default_when_unset(self):
        assert _parse_max_events_per_fetch(None) > 0
        assert _parse_max_events_per_fetch("") > 0

    def test_rejects_zero(self):
        with pytest.raises(Exception, match="Maximum events per fetch"):
            _parse_max_events_per_fetch("0")

    def test_rejects_negative(self):
        with pytest.raises(Exception, match="Maximum events per fetch"):
            _parse_max_events_per_fetch("-5")

    def test_rejects_non_numeric(self):
        # ``arg_to_number`` raises ``ValueError`` with a message containing
        # "is not a valid number" before our wrapper gets to relabel it.
        with pytest.raises(Exception, match="not a valid number|must be an integer"):
            _parse_max_events_per_fetch("abc")

    def test_rejects_above_ceiling(self):
        with pytest.raises(Exception, match="Maximum events per fetch"):
            _parse_max_events_per_fetch(str(MAX_EVENTS_PER_FETCH_CEILING + 1))

    def test_accepts_valid_integer(self):
        assert _parse_max_events_per_fetch("500") == 500


# --------------------------------------------------------------------------- #
# Default-first-fetch behaviour (PR review 44059)
# --------------------------------------------------------------------------- #


class TestDefaultFirstFetch:
    def test_default_is_now(self):
        """The default first-fetch value should be 'now' so we do not back-fill
        on the first run (XSIAM Event-Collector convention)."""
        assert DEFAULT_FIRST_FETCH == "now"

    def test_parse_first_fetch_now_returns_iso(self):
        out = parse_first_fetch("now")
        assert out.endswith("Z")
        assert "T" in out


# --------------------------------------------------------------------------- #
# test-module
# --------------------------------------------------------------------------- #


class TestTestModule:
    def test_test_module_success(self, mocker):
        client = _build_client()
        mocker.patch.object(client, "get_critical_events", return_value=CRITICAL_RESPONSE)
        mocker.patch.object(client, "get_events", return_value=EVENTS_RESPONSE)
        assert run_test_module(client, "C-1", [CRITICAL_EVENTS, EVENTS]) == "ok"

    def test_test_module_unauthorized(self, mocker):
        client = _build_client()
        from CommonServerPython import DemistoException

        class _Resp:
            status_code = 401

        mocker.patch.object(
            client,
            "get_critical_events",
            side_effect=DemistoException("unauthorized", res=_Resp()),
        )
        out = run_test_module(client, "C-1", [CRITICAL_EVENTS])
        assert "Authorization Error" in out

    def test_test_module_not_found(self, mocker):
        client = _build_client()
        from CommonServerPython import DemistoException

        class _Resp:
            status_code = 404

        mocker.patch.object(
            client,
            "get_critical_events",
            side_effect=DemistoException("nope", res=_Resp()),
        )
        out = run_test_module(client, "C-1", [CRITICAL_EVENTS])
        assert "Endpoint not found" in out

    def test_test_module_unknown_event_type(self):
        client = _build_client()
        out = run_test_module(client, "C-1", ["Bogus"])
        assert "Unknown event type" in out


# --------------------------------------------------------------------------- #
# Push events
# --------------------------------------------------------------------------- #


class TestPushEvents:
    def test_push_events_skips_when_empty(self, mocker):
        spy = mocker.patch("AkamaiProlexic.send_events_to_xsiam")
        push_events([])
        spy.assert_not_called()

    def test_push_events_uses_documented_dataset(self, mocker):
        spy = mocker.patch("AkamaiProlexic.send_events_to_xsiam")
        push_events([{"_time": "2026-04-20T10:00:00.000000Z", "event_type": EVENTS}])
        spy.assert_called_once_with(
            events=[{"_time": "2026-04-20T10:00:00.000000Z", "event_type": EVENTS}],
            vendor="akamai",
            product="prolexic",
        )


# --------------------------------------------------------------------------- #
# Account Switch Key behaviour
# --------------------------------------------------------------------------- #


class TestAccountSwitchKey:
    def test_switch_key_added_to_query_params(self, mocker):
        client = Client(
            base_url="https://akab-test.luna.akamaiapis.net",
            verify=False,
            proxy=False,
            client_token="ct",
            client_secret="cs",
            access_token="at",
            account_switch_key="ASK-123",
        )
        captured: dict[str, Any] = {}

        def _fake_request(*_, **kwargs):
            captured.update(kwargs)
            return {"events": []}

        mocker.patch.object(client, "_http_request", side_effect=_fake_request)
        client.get_events("C-1")
        assert captured["params"]["accountSwitchKey"] == "ASK-123"
        assert captured["params"]["extended"] == "true"

    def test_no_switch_key_omits_param(self, mocker):
        client = _build_client()
        captured: dict[str, Any] = {}

        def _fake_request(*_, **kwargs):
            captured.update(kwargs)
            return {"criticalEvents": []}

        mocker.patch.object(client, "_http_request", side_effect=_fake_request)
        client.get_critical_events("C-1")
        assert "accountSwitchKey" not in captured["params"]
