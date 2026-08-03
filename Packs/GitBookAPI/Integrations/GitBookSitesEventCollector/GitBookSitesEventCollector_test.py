# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the GitBook Sites Event Collector."""

import GitBookSitesEventCollector as collector


ORG = "org_test_1234"
NOW = "2026-08-02T00:00:00Z"


def _site(**overrides):
    base = {
        "object": "site",
        "id": "site_abc",
        "type": "ultimate",
        "appliedType": "ultimate",
        "title": "Example Docs",
        "icon": "book",
        "basename": "example-docs",
        "visibility": "public",
        "defaultLevel": None,
        "published": False,
        "createdAt": "2026-01-01T00:00:00.000Z",
        "siteSpaces": 1,
        "features": ["a", "b", "c"],
        "permissions": {
            "view": True,
            "access": True,
            "admin": False,
            "installIntegration": False,
            "viewAdaptiveSchema": True,
            "editAdaptiveSchema": False,
        },
        "urls": {
            "location": "https://example.gitbook.io/docs",
            "app": "https://app.gitbook.com/o/org_test_1234/sites/site_abc",
            "preview": "https://example.gitbook.io/docs?preview=1",
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


def test_permissions_are_flattened_into_boolean_columns():
    """Each permission must become its own column, not a blob a rule would have to parse."""
    event = collector.build_event(_site(), ORG, NOW)
    assert event["permission_view"] is True
    assert event["permission_admin"] is False
    assert event["permission_editAdaptiveSchema"] is False
    assert "permissions" not in event


def test_every_column_is_a_scalar():
    """A dict or list in a column cannot be filtered on, so none may survive."""
    event = collector.build_event(_site(), ORG, NOW)
    assert all(not isinstance(v, dict | list) for v in event.values())
    # The features list and the urls object are dropped; only the app URL is lifted out.
    assert "features" not in event
    assert "urls" not in event
    assert event["urls_app"] == "https://app.gitbook.com/o/org_test_1234/sites/site_abc"


def test_public_visibility_is_resolved_and_published_is_kept_separate():
    """A site can be public in configuration while not yet published, so both are carried."""
    public_unpublished = collector.build_event(_site(visibility="public", published=False), ORG, NOW)
    assert public_unpublished["is_publicly_visible"] is True
    assert public_unpublished["published"] is False

    private_site = collector.build_event(_site(visibility="unlisted", published=True), ORG, NOW)
    assert private_site["is_publicly_visible"] is False
    assert private_site["published"] is True

    # Visibility matching must not depend on the casing the API happens to send.
    assert collector.build_event(_site(visibility="Public"), ORG, NOW)["is_publicly_visible"] is True
    # A missing visibility must not be read as public.
    assert collector.build_event(_site(visibility=None), ORG, NOW)["is_publicly_visible"] is False


def test_scalar_fields_are_carried_through():
    event = collector.build_event(_site(), ORG, NOW)
    assert event["basename"] == "example-docs"
    assert event["appliedType"] == "ultimate"
    assert event["siteSpaces"] == 1


def test_snapshot_metadata_is_stamped_on_every_record():
    event = collector.build_event(_site(), ORG, NOW)
    assert event["_time"] == NOW
    assert event["snapshot_at"] == NOW
    assert event["source_log_type"] == "site"
    assert event["organization_id"] == ORG


def test_pagination_follows_the_opaque_cursor():
    """The page parameter is an identifier from the previous response, never constructed."""
    client = _client_with(
        [
            {"items": [_site(id="a")], "next": {"page": "CURSOR_2"}},
            {"items": [_site(id="b")], "next": {"page": "CURSOR_3"}},
            {"items": [_site(id="c")]},
        ]
    )
    sites = client.list_sites(ORG, 100)
    assert [s["id"] for s in sites] == ["a", "b", "c"]
    assert client._stub.requested == [None, "CURSOR_2", "CURSOR_3"]


def test_pagination_stops_when_the_cursor_repeats():
    """A cursor that does not advance would otherwise re-request one page forever."""
    client = _client_with(
        [
            {"items": [_site(id="a")], "next": {"page": "SAME"}},
            {"items": [_site(id="b")], "next": {"page": "SAME"}},
        ]
    )
    sites = client.list_sites(ORG, 100)
    assert [s["id"] for s in sites] == ["a", "b"]
    assert len(client._stub.requested) == 2


def test_pagination_honours_max_fetch():
    client = _client_with(
        [
            {"items": [_site(id="a"), _site(id="b")], "next": {"page": "CURSOR_2"}},
            {"items": [_site(id="c")]},
        ]
    )
    assert len(client.list_sites(ORG, 1)) == 1


def test_records_without_an_id_are_dropped():
    class _Single:
        def list_sites(self, organization_id, max_fetch):
            return [_site(), {"object": "site", "title": "No identifier"}, "not a dict"]

    events = collector.fetch_sites(_Single(), ORG, 100)
    assert len(events) == 1


def test_empty_inventory_is_not_an_error():
    client = _client_with([{"items": []}])
    assert client.list_sites(ORG, 100) == []


def test_malformed_response_does_not_raise():
    client = _client_with(["not a dict"])
    assert client.list_sites(ORG, 100) == []
