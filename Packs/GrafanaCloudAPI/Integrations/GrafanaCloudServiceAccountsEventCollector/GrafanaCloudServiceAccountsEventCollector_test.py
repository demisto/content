# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Grafana Cloud Service Accounts Event Collector."""

import copy

import GrafanaCloudServiceAccountsEventCollector as collector


def _account(sa_id, **kw):
    a = {
        "id": sa_id,
        "uid": f"uid-{sa_id}",
        "name": f"sa-{sa_id}",
        "login": f"sa-1-sa-{sa_id}",
        "orgId": 1,
        "isDisabled": False,
        "isExternal": False,
        "role": "Viewer",
        "tokens": 1,
    }
    a.update(kw)
    return a


def _token(name="t1", **kw):
    t = {
        "id": 1,
        "name": name,
        "created": "2026-07-01T00:00:00Z",
        "lastUsedAt": None,
        "expiration": None,
        "hasExpired": False,
        "isRevoked": False,
    }
    t.update(kw)
    return t


class MockClient:
    """Serves canned paged responses without touching the network."""

    _base_url = "https://example.grafana.net"

    def __init__(self, pages=None, tokens=None, token_error=None):
        # pages is keyed by page NUMBER, so a test can prove which pages were asked for
        self.pages = pages or {}
        self.tokens = tokens or {}
        self.token_error = token_error
        self.pages_requested: list[int] = []
        self.token_calls: list[int] = []

    def search_service_accounts(self, page, per_page=100):
        self.pages_requested.append(page)
        return {"serviceAccounts": copy.deepcopy(self.pages.get(page, [])), "totalCount": 99}

    def get_tokens(self, service_account_id):
        self.token_calls.append(service_account_id)
        if self.token_error:
            raise self.token_error
        return copy.deepcopy(self.tokens.get(service_account_id, []))


# --------------------------------------------------------------------------- #
# Paging starts at ONE, and totalCount cannot be trusted
# --------------------------------------------------------------------------- #


def test_paging_starts_at_page_one_not_zero():
    """Page 0 and page 1 return identical records, so a zero-based loop double-reads."""
    client = MockClient(pages={1: [_account(1)], 2: []})
    collector.fetch_service_accounts(client, 5000)
    assert client.pages_requested[0] == 1
    assert 0 not in client.pages_requested


def test_paging_walks_until_an_empty_page():
    client = MockClient(pages={1: [_account(1)], 2: [_account(2)], 3: []})
    events = collector.fetch_service_accounts(client, 5000)
    assert [e["id"] for e in events] == [1, 2]
    assert client.pages_requested == [1, 2, 3]


def test_total_count_is_never_used_to_terminate():
    """totalCount stays populated past the end, so only an empty page stops the loop."""
    client = MockClient(pages={1: [_account(1)], 2: []})
    collector.fetch_service_accounts(client, 5000)
    assert client.pages_requested == [1, 2]


def test_max_fetch_caps_the_snapshot():
    client = MockClient(pages={1: [_account(i) for i in range(10)], 2: []})
    events = collector.fetch_service_accounts(client, 3)
    assert len(events) == 3
    # Tokens are only read for the accounts actually kept.
    assert len(client.token_calls) == 3


# --------------------------------------------------------------------------- #
# Token posture is the security payload
# --------------------------------------------------------------------------- #


def test_token_without_expiry_is_counted():
    got = collector.summarise_tokens([_token(expiration=None), _token(expiration="2027-01-01T00:00:00Z")])
    assert got["token_count"] == 2
    assert got["tokens_without_expiry"] == 1


def test_expired_revoked_and_unused_tokens_are_counted():
    got = collector.summarise_tokens(
        [
            _token("a", hasExpired=True),
            _token("b", isRevoked=True),
            _token("c", lastUsedAt="2026-07-02T00:00:00Z"),
        ]
    )
    assert got["tokens_expired"] == 1
    assert got["tokens_revoked"] == 1
    assert got["tokens_never_used"] == 2
    assert got["last_token_used_at"] == "2026-07-02T00:00:00Z"


def test_token_secrets_are_never_collected():
    """The API does not return a token's secret, and nothing may invent one."""
    got = collector.summarise_tokens([_token("k", key="SHOULD-NOT-APPEAR")])
    assert "SHOULD-NOT-APPEAR" not in str(got)
    assert got["token_names"] == "k"


def test_no_tokens_leaves_zeroed_counters():
    got = collector.summarise_tokens([])
    assert got["token_count"] == 0
    assert got["oldest_token_created"] is None


def test_malformed_tokens_are_skipped_not_fatal():
    got = collector.summarise_tokens([_token("ok"), "not a dict", None])
    assert got["token_count"] == 1


# --------------------------------------------------------------------------- #
# Robustness and ingestion metadata
# --------------------------------------------------------------------------- #


def test_an_account_whose_tokens_fail_is_still_inventoried():
    from CommonServerPython import DemistoException

    client = MockClient(pages={1: [_account(1)], 2: []}, token_error=DemistoException("[403] Forbidden"))
    events = collector.fetch_service_accounts(client, 5000)
    assert [e["id"] for e in events] == [1]
    assert events[0]["token_count"] == 0


def test_ingestion_metadata_added_and_nothing_nested():
    client = MockClient(pages={1: [_account(1)], 2: []}, tokens={1: [_token()]})
    event = collector.fetch_service_accounts(client, 5000)[0]
    assert event["_time"] == event["snapshot_at"]
    assert event["source_log_type"] == "service_account"
    assert event["grafana_instance"] == "https://example.grafana.net"
    assert not [k for k, v in event.items() if isinstance(v, dict | list)]


def test_empty_instance_returns_no_events():
    assert collector.fetch_service_accounts(MockClient(pages={1: []}), 5000) == []
