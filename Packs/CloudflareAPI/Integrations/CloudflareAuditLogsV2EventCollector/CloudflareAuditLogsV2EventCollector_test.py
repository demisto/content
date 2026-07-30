# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Cloudflare Audit Logs V2 Event Collector."""

import copy
import demistomock as demisto

import CloudflareAuditLogsV2EventCollector as collector


def _record(rec_id, time, description=None, **kw):
    r = {
        "id": rec_id,
        "account": {"id": "acct-1", "name": "Example"},
        "action": {"time": time, "type": "update", "result": "success", "description": description},
        "actor": {"type": "user"},
        "resource": {"type": "record", "product": "dns"},
    }
    for k, v in kw.items():
        r.setdefault(k, {})
        r[k] = {**r.get(k, {}), **v} if isinstance(v, dict) else v
    return r


class MockClient:
    """Serves canned cursor-paged responses without touching the network."""

    def __init__(self, pages):
        # pages: list of (records, cursor) tuples
        self.pages = pages
        self.calls: list[dict] = []

    def get_audit_logs(self, account_id, since, before, limit=100, cursor=None):
        self.calls.append({"account_id": account_id, "since": since, "before": before, "cursor": cursor})
        idx = 0 if cursor is None else next(
            (i + 1 for i, (_, c) in enumerate(self.pages) if c == cursor), len(self.pages)
        )
        if idx >= len(self.pages):
            return {"result": [], "result_info": {}}
        records, next_cursor = self.pages[idx]
        return {"result": copy.deepcopy(records), "result_info": {"cursor": next_cursor}}


# --------------------------------------------------------------------------- #
# Paging is by cursor, never by page number
# --------------------------------------------------------------------------- #


def test_cursor_walks_every_page():
    client = MockClient([
        ([_record("a", "2026-07-01T00:00:00Z")], "cur1"),
        ([_record("b", "2026-07-02T00:00:00Z")], "cur2"),
        ([_record("c", "2026-07-03T00:00:00Z")], None),
    ])
    got = collector.fetch_logs_for_account(client, "acct-1", "since", "before", 5000)
    assert [r["id"] for r in got] == ["a", "b", "c"]
    assert [c["cursor"] for c in client.calls] == [None, "cur1", "cur2"]


def test_paging_stops_when_cursor_absent():
    """The endpoint ignores page numbers, so an absent cursor is the only stop."""
    client = MockClient([([_record("a", "2026-07-01T00:00:00Z")], None)])
    got = collector.fetch_logs_for_account(client, "acct-1", "since", "before", 5000)
    assert len(got) == 1
    assert len(client.calls) == 1


def test_empty_page_terminates():
    client = MockClient([([], "cur1")])
    assert collector.fetch_logs_for_account(client, "acct-1", "since", "before", 5000) == []


def test_max_fetch_caps_collection():
    pages = [([_record(str(i), "2026-07-01T00:00:00Z")], f"cur{i}") for i in range(10)]
    client = MockClient(pages)
    got = collector.fetch_logs_for_account(client, "acct-1", "since", "before", 3)
    assert len(got) == 3


def test_since_and_before_are_both_sent():
    """The v2 endpoint returns 400 unless both bounds are supplied."""
    client = MockClient([([], None)])
    collector.fetch_logs_for_account(client, "acct-1", "2026-07-01T00:00:00Z", "2026-07-08T00:00:00Z", 10)
    assert client.calls[0]["since"] == "2026-07-01T00:00:00Z"
    assert client.calls[0]["before"] == "2026-07-08T00:00:00Z"


# --------------------------------------------------------------------------- #
# Flattening, so every column is queryable without parsing
# --------------------------------------------------------------------------- #


def test_nested_objects_are_flattened():
    rec = _record("a", "2026-07-01T00:00:00Z", description="LOGIN",
                  actor={"email": "user@example.com", "ip_address": "192.0.2.10", "context": "dash"})
    got = collector.flatten_event(rec, "acct-9")
    assert got["action_description"] == "LOGIN"
    assert got["actor_email"] == "user@example.com"
    assert got["actor_ip_address"] == "192.0.2.10"
    assert got["account_name"] == "Example"
    assert not [k for k, v in got.items() if isinstance(v, dict | list)]


def test_structured_subfields_become_json_strings():
    rec = _record("a", "2026-07-01T00:00:00Z")
    rec["resource"]["value"] = {"before": 1, "after": 2}
    got = collector.flatten_event(rec, "acct-1")
    assert isinstance(got["resource_value"], str)
    assert "after" in got["resource_value"]


def test_time_comes_from_the_action_not_ingest():
    rec = _record("a", "2026-07-01T12:00:00Z")
    got = collector.flatten_event(rec, "acct-1")
    assert got["_time"] == "2026-07-01T12:00:00Z" == got["action_time"]
    assert got["source_log_type"] == "audit_v2"
    assert got["cloudflare_account_id"] == "acct-1"


# --------------------------------------------------------------------------- #
# Time-series cursor behaviour
# --------------------------------------------------------------------------- #


def test_already_seen_ids_are_dropped():
    events = [collector.flatten_event(_record("a", "2026-07-01T00:00:00Z"), "x"),
              collector.flatten_event(_record("b", "2026-07-02T00:00:00Z"), "x")]
    new, ts, ids = collector.dedup_events(events, {"a"})
    assert [e["id"] for e in new] == ["b"]
    assert ts == "2026-07-02T00:00:00Z"
    assert ids == {"b"}


def test_ids_sharing_the_newest_timestamp_are_all_carried():
    events = [collector.flatten_event(_record("a", "2026-07-02T00:00:00Z"), "x"),
              collector.flatten_event(_record("b", "2026-07-02T00:00:00Z"), "x")]
    _, ts, ids = collector.dedup_events(events, set())
    assert ids == {"a", "b"}


def test_nothing_new_keeps_the_previous_cursor():
    events = [collector.flatten_event(_record("a", "2026-07-01T00:00:00Z"), "x")]
    new, ts, ids = collector.dedup_events(events, {"a"})
    assert new == []
    assert ts == ""
    assert ids == {"a"}


def test_a_failing_account_keeps_its_own_cursor_and_others_continue(mocker):
    # The collector logs this failure with demisto.error, which the demisto-sdk
    # harness treats as stdout and fails the run on. Production behaviour is
    # correct and stays as it is; the test simply must not let it leak.
    mocker.patch.object(demisto, "error")
    class Boom(MockClient):
        def get_audit_logs(self, account_id, since, before, limit=100, cursor=None):
            if account_id == "bad":
                raise Exception("boom")
            return super().get_audit_logs(account_id, since, before, limit, cursor)

    client = Boom([([_record("a", "2026-07-05T00:00:00Z")], None)])
    prior = {"bad": {"last_ts": "2026-07-01T00:00:00Z", "last_ids": ["z"]}}
    events, next_run = collector.fetch_events(client, ["bad", "good"], prior, "2026-06-01T00:00:00Z", 5000)

    # The failing account's cursor is untouched, so it does not re-read its window.
    assert next_run["bad"] == prior["bad"]
    assert [e["id"] for e in events] == ["a"]
    assert next_run["good"]["last_ts"] == "2026-07-05T00:00:00Z"


def test_login_events_survive_the_whole_pipeline():
    """The reason this collector exists: v1 carries no sign-in events."""
    rec = _record("login-1", "2026-07-27T21:44:57Z", description="LOGIN",
                  actor={"email": "user@example.com", "ip_address": "192.0.2.10",
                         "context": "api", "type": "user"})
    client = MockClient([([rec], None)])
    events, _ = collector.fetch_events(client, ["acct-1"], {}, "2026-07-01T00:00:00Z", 5000)
    assert len(events) == 1
    assert events[0]["action_description"] == "LOGIN"
    assert events[0]["action_result"] == "success"
    assert events[0]["actor_email"] == "user@example.com"
    assert events[0]["actor_ip_address"] == "192.0.2.10"
