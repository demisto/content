# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Portkey Audit Logs Event Collector."""

import inspect
import json

import PortkeyAuditLogsEventCollector as collector


class MockClient:
    """Serves canned pages keyed by the zero-based page number."""

    def __init__(self, pages, total=None):
        self.pages = pages
        self.total = total
        self.calls = 0
        self.requested_pages = []

    def get_audit_logs(self, start_time, end_time, current_page=0, page_size=100):
        self.calls += 1
        self.requested_pages.append(current_page)
        records = self.pages.get(current_page, [])
        return {"records": records, "total": self.total if self.total is not None else None}


def _rec(rid, timestamp, **kw):
    r = {
        "request_id": rid,
        "timestamp": timestamp,
        "method": "POST",
        "uri": "/v1/x",
        "organisation_id": "org-from-record",
    }
    r.update(kw)
    return r


def test_dedup_computes_cursor_and_boundary_ids():
    events = [
        _rec("a", "2026-07-20T10:00:00.000Z"),
        _rec("b", "2026-07-20T11:00:00.000Z"),
        _rec("c", "2026-07-20T11:00:00.000Z"),
    ]
    new, ts, ids = collector.dedup_events(events, set())
    assert ts == "2026-07-20T11:00:00.000Z"
    assert ids == {"b", "c"}
    assert len(new) == 3


def test_dedup_drops_seen_boundary_ids():
    events = [_rec("b", "2026-07-20T11:00:00.000Z"), _rec("d", "2026-07-20T12:00:00.000Z")]
    new, ts, ids = collector.dedup_events(events, {"b"})
    assert [e["request_id"] for e in new] == ["d"]
    assert ts == "2026-07-20T12:00:00.000Z"
    assert ids == {"d"}


def test_paging_starts_at_page_zero():
    """Portkey pages are zero-based; starting at page 1 silently skips the first page."""
    pages = {0: [_rec("a", "2026-07-20T10:00:00.000Z")]}
    client = MockClient(pages, total=1)
    events, _, _ = collector.fetch_audit_logs(client, "s", "e", 100, set(), 100)
    assert client.requested_pages[0] == 0
    assert [e["request_id"] for e in events] == ["a"]


def test_get_audit_logs_does_not_accept_organisation_id():
    """Sending organisation_id to the endpoint returns 403 AB03, so it must not be a parameter."""
    signature = inspect.signature(collector.Client.get_audit_logs)
    assert "organisation_id" not in signature.parameters


def test_fetch_paginates_until_short_page():
    pages = {
        0: [_rec(str(i), f"2026-07-20T10:0{i}:00.000Z") for i in range(3)],
        1: [_rec("x", "2026-07-20T10:05:00.000Z")],
    }
    client = MockClient(pages, total=None)
    events, _, _ = collector.fetch_audit_logs(client, "2026-07-19T00:00:00.000Z", "2026-07-21T00:00:00.000Z", 100, set(), 3)
    assert client.requested_pages == [0, 1]
    assert len(events) == 4


def test_fetch_stops_at_total():
    pages = {0: [_rec(str(i), f"2026-07-20T10:0{i}:00.000Z") for i in range(2)]}
    client = MockClient(pages, total=2)
    events, _, _ = collector.fetch_audit_logs(client, "s", "e", 100, set(), 100)
    assert client.calls == 1
    assert len(events) == 2


def test_fetch_caps_at_max_fetch():
    pages = {0: [_rec(str(i), f"2026-07-20T10:0{i}:00.000Z") for i in range(5)]}
    client = MockClient(pages, total=5)
    events, _, _ = collector.fetch_audit_logs(client, "s", "e", 3, set(), 100)
    assert len(events) == 3


def test_metadata_taken_from_the_record():
    pages = {0: [_rec("a", "2026-07-20T10:00:00.000Z")]}
    client = MockClient(pages, total=1)
    events, _, _ = collector.fetch_audit_logs(client, "s", "e", 100, set(), 100)
    e = events[0]
    assert e["_time"] == "2026-07-20T10:00:00.000Z"
    assert e["source_log_type"] == "audit"
    assert e["portkey_organisation_id"] == "org-from-record"


def test_empty_keeps_cursor():
    client = MockClient({0: []}, total=0)
    events, run = collector.fetch_events(client, {"last_ts": "2026-07-20T09:00:00.000Z", "last_ids": ["z"]}, "3 days", 100, 100)
    assert events == []
    assert run["last_ts"] == "2026-07-20T09:00:00.000Z"
    assert run["last_ids"] == ["z"]


# --------------------------------------------------------------------------- #
# LAW N17 -- credential material must not reach the dataset
# --------------------------------------------------------------------------- #


def test_an_integration_credential_is_redacted_before_ingestion():
    """Creating an integration POSTs the third party credential IN FULL.

    The vendor redacts some fields itself, which is what makes this dangerous: the
    body looks sanitised because an api key reads back as i2*****Wp4, while the
    credentials object beside it carries a live key in plaintext.
    """
    event = {
        "timestamp": 1,
        "organisation_id": "org-1",
        "request_body": json.dumps(
            {
                "organisation_id": "org-1",
                "integration_id": "int-1",
                "credentials": {"AIRS_API_KEY": "a-real-secret-value"},
            }
        ),
    }
    out = collector.add_fields_to_event(event)
    body = json.loads(out["request_body"])
    assert "a-real-secret-value" not in out["request_body"]
    assert body["credentials"]["AIRS_API_KEY"] == collector.REDACTED
    # The NAME survives: which provider was integrated is worth detecting on.
    assert "AIRS_API_KEY" in body["credentials"]
    # Everything that is not a secret is untouched.
    assert body["integration_id"] == "int-1"


def test_secret_bearing_keys_are_matched_by_substring_and_case():
    """api_key, apiKey and AIRS_API_KEY are one rule, not three."""
    for name in ("api_key", "apiKey", "AIRS_API_KEY", "Authorization", "client_secret", "PASSWORD"):
        out = collector.redact_request_body(json.dumps({name: "sensitive"}))
        assert "sensitive" not in out, f"{name} was not redacted"


def test_a_nested_secret_is_reached():
    """Secrets are not always at the top level."""
    out = collector.redact_request_body(
        json.dumps({"config": {"providers": [{"name": "openai", "credentials": {"token": "sensitive"}}]}})
    )
    assert "sensitive" not in out
    assert "openai" in out


def test_a_body_that_will_not_parse_is_dropped_not_passed_through():
    """An unparseable body cannot be inspected, so passing it on would defeat the check."""
    assert collector.redact_request_body("{not json") == collector.REDACTED


def test_a_body_with_no_secrets_is_left_alone():
    """Redaction must not damage the change detection built on this field."""
    original = json.dumps({"name": "k", "scopes": ["logs.list"], "usage_limits": None})
    out = collector.redact_request_body(original)
    assert json.loads(out) == json.loads(original)
