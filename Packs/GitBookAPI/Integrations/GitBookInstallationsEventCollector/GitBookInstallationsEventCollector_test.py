# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the GitBook Integration Installations Event Collector."""

import GitBookInstallationsEventCollector as collector


ORG = "org_test_1234"
NOW = "2026-08-02T00:00:00Z"


def _item(installation=None, integration=None):
    base_installation = {
        "id": "inst_abc",
        "status": "active",
        "space_selection": "all",
        "site_selection": "selected",
        "spaces": 4,
        "createdAt": "2026-01-01T00:00:00.000Z",
        "updatedAt": "2026-07-01T00:00:00.000Z",
        "configuration": {"apiToken": "secret-value"},
        "externalIds": ["ext_1", "ext_2"],
        "target": {"organization": ORG},
        "network": {"proxy": True},
        "urls": {
            "location": "/integrations/example/installations/inst_abc",
            "app": "https://app.gitbook.com/o/org_test_1234/integrations/example",
            "publicEndpoint": "https://integrations.gitbook.com/example",
            "publicContentEndpoint": "https://content.gitbook.com/example",
        },
    }
    base_integration = {
        "object": "integration",
        "name": "example",
        "title": "Example",
        "description": "An example integration",
        "version": 3,
        "verified": False,
        "visibility": "public",
        "target": "organization",
        "scopes": ["space:content:read", "space:content:write"],
        "categories": ["analytics"],
        "owner": {
            "object": "organization",
            "id": "org_vendor_9",
            "title": "Example Vendor",
        },
        "urls": {"app": "https://app.gitbook.com/integrations/example"},
    }
    base_installation.update(installation or {})
    base_integration.update(integration or {})
    return {"installation": base_installation, "integration": base_integration}


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


def test_installation_and_integration_are_flattened_into_columns():
    """Both nested objects must become columns, not blobs a rule would have to parse."""
    event = collector.build_event(_item(), ORG, NOW)
    assert event["id"] == "inst_abc"
    assert event["status"] == "active"
    assert event["spaces"] == 4
    assert event["integration_name"] == "example"
    assert event["integration_title"] == "Example"
    assert event["integration_owner_id"] == "org_vendor_9"
    assert event["integration_owner_title"] == "Example Vendor"
    assert event["target_organization"] == ORG
    assert event["network_proxy"] is True
    assert event["urls_app"].startswith("https://app.gitbook.com/")
    assert event["external_ids"] == "ext_1,ext_2"
    assert all(not isinstance(v, dict | list) for v in event.values())


def test_nested_object_where_a_string_is_expected_never_reaches_a_column():
    """A field the specification types as a string can still arrive as an object."""
    event = collector.build_event(
        _item(
            installation={
                "target": {"organization": {"id": ORG}},
                "urls": {"app": ["https://app.gitbook.com/"]},
            },
            integration={"owner": {"id": {"nested": True}, "title": ["Example Vendor"]}},
        ),
        ORG,
        NOW,
    )
    assert "target_organization" not in event
    assert "urls_app" not in event
    assert "integration_owner_id" not in event
    assert "integration_owner_title" not in event
    assert all(not isinstance(v, dict | list) for v in event.values())


def test_configuration_is_never_collected():
    """The configuration is integration-supplied and can hold its credentials."""
    event = collector.build_event(_item(), ORG, NOW)
    assert "configuration" not in event
    assert "secret-value" not in str(event)

    # Skipping it by name rather than by type, so a scalar configuration is
    # dropped too instead of being written straight into a column.
    scalar = collector.build_event(_item(installation={"configuration": "token=secret-value"}), ORG, NOW)
    assert "configuration" not in scalar
    assert "secret-value" not in str(scalar)


def test_scopes_are_flattened_and_write_reach_is_resolved_once():
    """Scope reach is resolved here rather than by parsing a string in every rule."""
    writer = collector.build_event(_item(), ORG, NOW)
    assert writer["integration_scopes"] == "space:content:read,space:content:write"
    assert writer["integration_scope_count"] == 2
    assert writer["can_write_content"] is True
    assert writer["can_inject_script"] is False

    injector = collector.build_event(
        _item(integration={"scopes": ["site:metadata:read", "site:script:inject"]}),
        ORG,
        NOW,
    )
    assert injector["can_write_content"] is False
    assert injector["can_inject_script"] is True

    # The specification marks scopes optional on a record, so an absent list is
    # not an error.
    none_declared = collector.build_event(_item(integration={"scopes": None}), ORG, NOW)
    assert none_declared["integration_scopes"] == ""
    assert none_declared["integration_scope_count"] == 0
    assert none_declared["can_write_content"] is False


def test_snapshot_metadata_is_stamped_on_every_record():
    event = collector.build_event(_item(), ORG, NOW)
    assert event["_time"] == NOW
    assert event["snapshot_at"] == NOW
    assert event["source_log_type"] == "installation"
    assert event["organization_id"] == ORG


def test_pagination_follows_the_opaque_cursor():
    """The page parameter is an identifier from the previous response, never constructed."""
    client = _client_with(
        [
            {"items": [_item(installation={"id": "a"})], "next": {"page": "CURSOR_2"}},
            {"items": [_item(installation={"id": "b"})], "next": {"page": "CURSOR_3"}},
            {"items": [_item(installation={"id": "c"})]},
        ]
    )
    items = client.list_installations(ORG, 100)
    assert [collector.installation_id(i) for i in items] == ["a", "b", "c"]
    assert client._stub.requested == [None, "CURSOR_2", "CURSOR_3"]


def test_pagination_stops_when_the_cursor_repeats():
    """A cursor that does not advance would otherwise re-request one page forever."""
    client = _client_with(
        [
            {"items": [_item(installation={"id": "a"})], "next": {"page": "SAME"}},
            {"items": [_item(installation={"id": "b"})], "next": {"page": "SAME"}},
        ]
    )
    items = client.list_installations(ORG, 100)
    assert [collector.installation_id(i) for i in items] == ["a", "b"]
    assert len(client._stub.requested) == 2


def test_pagination_honours_max_fetch():
    client = _client_with(
        [
            {
                "items": [
                    _item(installation={"id": "a"}),
                    _item(installation={"id": "b"}),
                ],
                "next": {"page": "CURSOR_2"},
            },
            {"items": [_item(installation={"id": "c"})]},
        ]
    )
    assert len(client.list_installations(ORG, 1)) == 1


def test_records_without_an_installation_id_are_dropped():
    class _Single:
        def list_installations(self, organization_id, max_fetch):
            return [
                _item(),
                {"integration": {"name": "orphan"}},
                {"installation": {"status": "active"}},
                "not a dict",
            ]

    events = collector.fetch_installations(_Single(), ORG, 100)
    assert len(events) == 1
    assert events[0]["id"] == "inst_abc"


def test_empty_inventory_is_not_an_error():
    client = _client_with([{"items": []}])
    assert client.list_installations(ORG, 100) == []


def test_malformed_response_does_not_raise():
    client = _client_with(["not a dict"])
    assert client.list_installations(ORG, 100) == []


def test_missing_integration_object_does_not_raise():
    """The wrapper is specification-derived, so a half-populated item must still build."""
    event = collector.build_event({"installation": {"id": "inst_abc"}}, ORG, NOW)
    assert event["id"] == "inst_abc"
    assert event["integration_scope_count"] == 0
    assert all(not isinstance(v, dict | list) for v in event.values())
