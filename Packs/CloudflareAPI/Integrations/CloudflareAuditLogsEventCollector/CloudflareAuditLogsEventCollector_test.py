# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Cloudflare Audit Logs Event Collector."""
import json
import os

import pytest

from CloudflareAuditLogsEventCollector import (
    Client,
    add_fields_to_event,
    dedup_events,
    fetch_events,
    fetch_audit_logs_for_account,
    get_events_command,
)
# Aliased so pytest does not collect the integration's ``test_module`` as a test case.
from CloudflareAuditLogsEventCollector import test_module as run_test_module

BASE_URL = "https://api.cloudflare.com/client/v4"
ACCOUNT_A = "023e105f4ecef8ad9ca31a8372d0c353"
ACCOUNT_B = "111e105f4ecef8ad9ca31a8372d0c999"


def load_test_data() -> dict:
    path = os.path.join(os.path.dirname(__file__), "test_data", "audit_logs.json")
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def data() -> dict:
    return load_test_data()


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_token="token", verify=False, proxy=False)


def test_add_fields_to_event():
    event = {"id": "1", "when": "2024-04-26T17:31:07Z"}
    enriched = add_fields_to_event(event, ACCOUNT_A)
    assert enriched["_time"] == "2024-04-26T17:31:07Z"
    assert enriched["source_log_type"] == "audit"
    assert enriched["cloudflare_account_id"] == ACCOUNT_A


def test_dedup_events_filters_seen_ids():
    events = [
        {"id": "1", "when": "2024-04-26T17:00:00Z"},
        {"id": "2", "when": "2024-04-26T18:00:00Z"},
    ]
    new_events, newest_ts, newest_ids = dedup_events(events, last_ids={"1"})
    assert [e["id"] for e in new_events] == ["2"]
    assert newest_ts == "2024-04-26T18:00:00Z"
    assert newest_ids == {"2"}


def test_dedup_events_all_seen_keeps_cursor():
    events = [{"id": "1", "when": "2024-04-26T17:00:00Z"}]
    new_events, newest_ts, newest_ids = dedup_events(events, last_ids={"1"})
    assert new_events == []
    assert newest_ts == ""
    assert newest_ids == {"1"}


def test_dedup_events_same_timestamp_tracks_all_ids():
    events = [
        {"id": "1", "when": "2024-04-26T18:00:00Z"},
        {"id": "2", "when": "2024-04-26T18:00:00Z"},
    ]
    _, newest_ts, newest_ids = dedup_events(events, last_ids=set())
    assert newest_ts == "2024-04-26T18:00:00Z"
    assert newest_ids == {"1", "2"}


def test_fetch_audit_logs_paginates(mocker, client, data):
    """Two pages are combined and metadata is attached."""
    mocker.patch.object(
        client, "get_audit_logs", side_effect=[data["page_1"], data["page_2"]]
    )
    events, newest_ts, newest_ids = fetch_audit_logs_for_account(
        client=client,
        account_id=ACCOUNT_A,
        since="2024-04-01T00:00:00Z",
        max_fetch=5000,
        last_ids=set(),
        hide_user_logs=False,
    )
    assert len(events) == 3
    assert newest_ts == "2024-04-26T18:05:30Z"
    assert newest_ids == {"ffffeeee-9999-8888-7777-666655554444"}
    assert all(e["source_log_type"] == "audit" for e in events)
    assert all(e["cloudflare_account_id"] == ACCOUNT_A for e in events)


def test_fetch_audit_logs_respects_max_fetch(mocker, client, data):
    mocker.patch.object(client, "get_audit_logs", return_value=data["page_1"])
    events, _, _ = fetch_audit_logs_for_account(
        client=client,
        account_id=ACCOUNT_A,
        since="2024-04-01T00:00:00Z",
        max_fetch=1,
        last_ids=set(),
        hide_user_logs=False,
    )
    assert len(events) == 1


def test_fetch_audit_logs_empty(mocker, client, data):
    mocker.patch.object(client, "get_audit_logs", return_value=data["empty"])
    events, newest_ts, newest_ids = fetch_audit_logs_for_account(
        client=client,
        account_id=ACCOUNT_A,
        since="2024-04-01T00:00:00Z",
        max_fetch=5000,
        last_ids={"x"},
        hide_user_logs=False,
    )
    assert events == []
    # Cursor is preserved when nothing new is returned.
    assert newest_ts == "2024-04-01T00:00:00Z"
    assert newest_ids == {"x"}


def test_fetch_events_per_account_lastrun_isolation(mocker, client, data):
    """Each account gets its own cursor and its own dedup id set."""
    calls = {"count": 0}

    def side_effect(**kwargs):
        # Account A returns page_1 then page_2; Account B returns empty.
        if kwargs["account_id"] == ACCOUNT_B:
            return data["empty"]
        calls["count"] += 1
        return data["page_1"] if calls["count"] == 1 else data["page_2"]

    mocker.patch.object(client, "get_audit_logs", side_effect=side_effect)

    last_run = {ACCOUNT_B: {"last_ts": "2024-04-20T00:00:00Z", "last_ids": ["old"]}}
    events, next_run = fetch_events(
        client=client,
        account_ids=[ACCOUNT_A, ACCOUNT_B],
        last_run=last_run,
        first_fetch="2024-04-01T00:00:00Z",
        max_fetch=5000,
        hide_user_logs=False,
    )
    assert len(events) == 3
    assert next_run[ACCOUNT_A]["last_ts"] == "2024-04-26T18:05:30Z"
    # Account B had no new events, so its cursor is preserved.
    assert next_run[ACCOUNT_B]["last_ts"] == "2024-04-20T00:00:00Z"
    assert next_run[ACCOUNT_B]["last_ids"] == ["old"]


def test_fetch_events_dedups_across_runs(mocker, client, data):
    """Events already seen on the previous run are not returned again."""
    mocker.patch.object(client, "get_audit_logs", return_value=data["page_1"])
    last_run = {
        ACCOUNT_A: {
            "last_ts": "2024-04-26T18:00:00Z",
            "last_ids": ["a1b2c3d4-0000-1111-2222-333344445555"],
        }
    }
    events, _ = fetch_events(
        client=client,
        account_ids=[ACCOUNT_A],
        last_run=last_run,
        first_fetch="2024-04-01T00:00:00Z",
        max_fetch=5000,
        hide_user_logs=False,
    )
    ids = {e["id"] for e in events}
    assert "a1b2c3d4-0000-1111-2222-333344445555" not in ids
    assert "d5b0f326-1232-4452-8858-1089bd7168ef" in ids


def test_get_events_command(mocker, client, data):
    mocker.patch.object(
        client, "get_audit_logs", side_effect=[data["page_1"], data["page_2"]]
    )
    args = {"account_ids": ACCOUNT_A, "since": "3 days", "limit": "10"}
    events, results = get_events_command(client, args, hide_user_logs=False)
    assert len(events) == 3
    assert "Cloudflare Audit Logs" in results.readable_output


def test_test_module_success(mocker, client, data):
    get = mocker.patch.object(client, "get_audit_logs", return_value=data["page_1"])
    assert run_test_module(client, [ACCOUNT_A, ACCOUNT_B], hide_user_logs=False) == "ok"
    assert get.call_count == 2


def test_test_module_propagates_error(mocker, client):
    mocker.patch.object(client, "get_audit_logs", side_effect=Exception("401 Unauthorized"))
    with pytest.raises(Exception, match="401 Unauthorized"):
        run_test_module(client, [ACCOUNT_A], hide_user_logs=False)
