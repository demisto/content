# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the GitBook Link Invites Event Collector."""

import GitBookLinkInvitesEventCollector as collector


ORG = "org_test_1234"
NOW = "2026-08-02T00:00:00Z"


def _org_invite(**overrides):
    """An invite to the organisation itself, which carries a role."""
    base = {
        "object": "invite",
        "id": "invite_abc",
        "role": "admin",
        "redundant": False,
    }
    base.update(overrides)
    return base


def _space_invite(**overrides):
    """An invite to a single space, which carries a level and a nested target."""
    base = {
        "object": "invite",
        "id": "invite_space_1",
        "level": "edit",
        "redundant": False,
        "space": {
            "object": "space",
            "id": "space_xyz",
            "title": "Runbooks",
            "visibility": "private",
            "urls": {"location": "/spaces/space_xyz"},
        },
    }
    base.update(overrides)
    return base


def _collection_invite(**overrides):
    base = {
        "object": "invite",
        "id": "invite_coll_1",
        "level": "read",
        "redundant": False,
        "collection": {
            "object": "collection",
            "id": "coll_xyz",
            "title": "Internal",
            "urls": {"location": "/collections/coll_xyz"},
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


def test_nested_target_objects_are_flattened_into_columns():
    """A target object must become columns, not a blob a rule would have to parse."""
    event = collector.build_event(_space_invite(), ORG, NOW)
    assert event["space_id"] == "space_xyz"
    assert event["space_title"] == "Runbooks"
    assert event["space_visibility"] == "private"
    assert "space" not in event
    assert all(not isinstance(v, dict | list) for v in event.values())

    collection_event = collector.build_event(_collection_invite(), ORG, NOW)
    assert collection_event["collection_id"] == "coll_xyz"
    assert collection_event["collection_title"] == "Internal"
    assert "collection" not in collection_event
    assert all(not isinstance(v, dict | list) for v in collection_event.values())


def test_privileged_role_is_resolved_once():
    """An invite handing out an administrative role is resolved here, not in every rule."""
    assert collector.build_event(_org_invite(role="admin"), ORG, NOW)["is_privileged_role"] is True
    assert collector.build_event(_org_invite(role="read"), ORG, NOW)["is_privileged_role"] is False

    # Role matching must not depend on the casing the API happens to send.
    assert collector.build_event(_org_invite(role="Owner"), ORG, NOW)["is_privileged_role"] is True

    # The role is null for a guest invite, which must not raise and must not read as privileged.
    guest = collector.build_event(_org_invite(role=None), ORG, NOW)
    assert guest["is_privileged_role"] is False


def test_invite_target_distinguishes_the_three_shapes():
    assert collector.build_event(_org_invite(), ORG, NOW)["invite_target"] == "organization"
    assert collector.build_event(_space_invite(), ORG, NOW)["invite_target"] == "space"
    assert collector.build_event(_collection_invite(), ORG, NOW)["invite_target"] == "collection"


def test_snapshot_metadata_is_stamped_on_every_record():
    event = collector.build_event(_org_invite(), ORG, NOW)
    assert event["_time"] == NOW
    assert event["snapshot_at"] == NOW
    assert event["source_log_type"] == "link_invite"
    assert event["organization_id"] == ORG


def test_pagination_follows_the_opaque_cursor():
    """The page parameter is an identifier from the previous response, never constructed."""
    client = _client_with(
        [
            {"items": [_org_invite(id="a")], "next": {"page": "CURSOR_2"}},
            {"items": [_org_invite(id="b")], "next": {"page": "CURSOR_3"}},
            {"items": [_org_invite(id="c")]},
        ]
    )
    invites = client.list_link_invites(ORG, 100)
    assert [i["id"] for i in invites] == ["a", "b", "c"]
    assert client._stub.requested == [None, "CURSOR_2", "CURSOR_3"]


def test_pagination_stops_when_the_cursor_repeats():
    """A cursor that does not advance would otherwise re-request one page forever."""
    client = _client_with(
        [
            {"items": [_org_invite(id="a")], "next": {"page": "SAME"}},
            {"items": [_org_invite(id="b")], "next": {"page": "SAME"}},
        ]
    )
    invites = client.list_link_invites(ORG, 100)
    assert [i["id"] for i in invites] == ["a", "b"]
    assert len(client._stub.requested) == 2


def test_pagination_honours_max_fetch():
    client = _client_with(
        [
            {
                "items": [_org_invite(id="a"), _org_invite(id="b")],
                "next": {"page": "CURSOR_2"},
            },
            {"items": [_org_invite(id="c")]},
        ]
    )
    assert len(client.list_link_invites(ORG, 1)) == 1


def test_records_without_an_id_are_dropped():
    class _Single:
        def list_link_invites(self, organization_id, max_fetch):
            return [_org_invite(), {"object": "invite", "role": "admin"}, "not a dict"]

    events = collector.fetch_link_invites(_Single(), ORG, 100)
    assert len(events) == 1


def test_empty_invite_list_is_not_an_error():
    """An organisation with no standing invites is a valid answer, not a failure."""
    client = _client_with([{"items": [], "count": 0}])
    assert client.list_link_invites(ORG, 100) == []


def test_malformed_response_does_not_raise():
    assert _client_with(["not a dict"]).list_link_invites(ORG, 100) == []
    assert _client_with([{"items": "not a list"}]).list_link_invites(ORG, 100) == []
