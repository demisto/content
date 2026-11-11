# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the GitBook Organisation Members Event Collector."""

import GitBookOrgMembersEventCollector as collector


ORG = "org_test_1234"
NOW = "2026-08-02T00:00:00Z"


def _member(**overrides):
    base = {
        "object": "member",
        "id": "user_abc",
        "role": "admin",
        "disabled": False,
        "sso": False,
        "joinedAt": "2026-01-01T00:00:00.000Z",
        "lastSeenAt": "2026-08-01T00:00:00.000Z",
        "spaces": 3,
        "teams": 1,
        "sites": 2,
        "user": {
            "object": "user",
            "id": "user_abc",
            "displayName": "Example Person",
            "email": "person@example.com",
            "urls": {"location": "/users/user_abc"},
        },
    }
    base.update(overrides)
    return base


class _StubClient:
    """Returns canned pages so the cursor loop can be exercised without a network."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def _http_request(self, method, url_suffix, params=None):
        self.requested.append((params or {}).get("page"))
        return self.pages[len(self.requested) - 1]


def _client_with(pages):
    client = collector.Client.__new__(collector.Client)
    stub = _StubClient(pages)
    client._http_request = stub._http_request  # type: ignore[method-assign]
    client._stub = stub
    return client


def test_nested_user_object_is_flattened_into_columns():
    """The user object must become columns, not a blob a rule would have to parse."""
    event = collector.build_event(_member(), ORG, NOW)
    assert event["user_id"] == "user_abc"
    assert event["user_displayName"] == "Example Person"
    assert event["user_email"] == "person@example.com"
    assert all(not isinstance(v, dict | list) for v in event.values())


def test_privileged_and_sso_are_resolved_once():
    """The admin-without-SSO combination is resolved here rather than in every rule."""
    admin_no_sso = collector.build_event(_member(role="admin", sso=False), ORG, NOW)
    assert admin_no_sso["is_privileged_role"] is True
    assert admin_no_sso["uses_sso"] is False

    member_with_sso = collector.build_event(_member(role="member", sso=True), ORG, NOW)
    assert member_with_sso["is_privileged_role"] is False
    assert member_with_sso["uses_sso"] is True

    # Role matching must not depend on the casing the API happens to send.
    assert collector.build_event(_member(role="Owner"), ORG, NOW)["is_privileged_role"] is True


def test_snapshot_metadata_is_stamped_on_every_record():
    event = collector.build_event(_member(), ORG, NOW)
    assert event["_time"] == NOW
    assert event["snapshot_at"] == NOW
    assert event["source_log_type"] == "member"
    assert event["organization_id"] == ORG


def test_pagination_follows_the_opaque_cursor():
    """The page parameter is an identifier from the previous response, never constructed."""
    client = _client_with(
        [
            {"items": [_member(id="a")], "next": {"page": "CURSOR_2"}},
            {"items": [_member(id="b")], "next": {"page": "CURSOR_3"}},
            {"items": [_member(id="c")]},
        ]
    )
    members = client.list_members(ORG, 100)
    assert [m["id"] for m in members] == ["a", "b", "c"]
    assert client._stub.requested == [None, "CURSOR_2", "CURSOR_3"]


def test_pagination_stops_when_the_cursor_repeats():
    """A cursor that does not advance would otherwise re-request one page forever."""
    client = _client_with(
        [
            {"items": [_member(id="a")], "next": {"page": "SAME"}},
            {"items": [_member(id="b")], "next": {"page": "SAME"}},
        ]
    )
    members = client.list_members(ORG, 100)
    assert [m["id"] for m in members] == ["a", "b"]
    assert len(client._stub.requested) == 2


def test_pagination_honours_max_fetch():
    client = _client_with(
        [
            {"items": [_member(id="a"), _member(id="b")], "next": {"page": "CURSOR_2"}},
            {"items": [_member(id="c")]},
        ]
    )
    assert len(client.list_members(ORG, 1)) == 1


def test_records_without_an_id_are_dropped():
    class _Single:
        def list_members(self, organization_id, max_fetch):
            return [_member(), {"object": "member", "role": "admin"}, "not a dict"]

    events = collector.fetch_members(_Single(), ORG, 100)
    assert len(events) == 1


def test_empty_roster_is_not_an_error():
    client = _client_with([{"items": []}])
    assert client.list_members(ORG, 100) == []


def test_malformed_response_does_not_raise():
    client = _client_with(["not a dict"])
    assert client.list_members(ORG, 100) == []
