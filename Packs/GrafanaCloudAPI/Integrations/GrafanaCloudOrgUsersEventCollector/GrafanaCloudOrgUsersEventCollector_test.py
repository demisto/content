# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Grafana Cloud Organisation Users Event Collector."""

import copy

import GrafanaCloudOrgUsersEventCollector as collector


def _user(user_id, **kw):
    u = {
        "orgId": 1,
        "userId": user_id,
        "uid": f"uid-{user_id}",
        "email": f"user{user_id}@example.com",
        "name": "",
        "login": f"user{user_id}",
        "role": "Viewer",
        "lastSeenAt": "2026-07-28T20:41:28Z",
        "created": "2026-03-21T04:57:15Z",
        "lastSeenAtAge": "6 minutes",
        "isDisabled": False,
        "authLabels": [],
        "isExternallySynced": False,
        "isProvisioned": False,
    }
    u.update(kw)
    return u


class MockClient:
    """Serves a canned membership list without touching the network."""

    _base_url = "https://example.grafana.net"

    def __init__(self, users=None):
        self.users = users or []
        self.calls = 0

    def list_org_users(self):
        self.calls += 1
        return copy.deepcopy(self.users)


def test_requested_exactly_once():
    """The endpoint ignores paging, so a page loop would re-send the same records."""
    client = MockClient([_user(1), _user(2)])
    events = collector.fetch_org_users(client, 5000)
    assert client.calls == 1
    assert [e["userId"] for e in events] == [1, 2]


def test_max_fetch_caps_the_snapshot():
    assert len(collector.fetch_org_users(MockClient([_user(i) for i in range(8)]), 3)) == 3


def test_records_without_a_user_id_are_skipped():
    client = MockClient([_user(1), {"login": "no id"}])
    assert [e["userId"] for e in collector.fetch_org_users(client, 5000)] == [1]


def test_auth_labels_are_flattened_for_querying():
    client = MockClient([_user(1, authLabels=["grafana.com", "SAML"])])
    event = collector.fetch_org_users(client, 5000)[0]
    assert event["auth_labels"] == "SAML|grafana.com"
    assert event["auth_label_count"] == 2
    assert not [k for k, v in event.items() if isinstance(v, dict | list)]


def test_no_auth_labels_yields_an_empty_string_not_null():
    event = collector.fetch_org_users(MockClient([_user(1)]), 5000)[0]
    assert event["auth_labels"] == ""
    assert event["auth_label_count"] == 0


def test_last_seen_survives_because_dormancy_is_the_detection():
    event = collector.fetch_org_users(MockClient([_user(1, role="Admin")]), 5000)[0]
    assert event["lastSeenAt"] == "2026-07-28T20:41:28Z"
    assert event["role"] == "Admin"


def test_ingestion_metadata_added():
    event = collector.fetch_org_users(MockClient([_user(1)]), 5000)[0]
    assert event["_time"] == event["snapshot_at"]
    assert event["source_log_type"] == "org_user"
    assert event["grafana_instance"] == "https://example.grafana.net"


def test_empty_org_returns_no_events():
    assert collector.fetch_org_users(MockClient([]), 5000) == []
