# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for the GitBook Space Git Sync Event Collector."""

import pytest

import GitBookSpaceGitSyncEventCollector as collector


ORG = "org_test_1234"
NOW = "2026-08-02T00:00:00Z"


def _space(**overrides):
    base = {
        "object": "space",
        "id": "space_abc",
        "title": "Example Space",
        "visibility": "public",
        "createdAt": "2026-01-01T00:00:00.000Z",
        "updatedAt": "2026-08-01T00:00:00.000Z",
        "organization": ORG,
        "urls": {"location": "/o/org_test_1234/s/space_abc"},
    }
    base.update(overrides)
    return base


def _git_info(**overrides):
    # The field names are those GET /spaces/{spaceId}/git/info actually returns.
    base = {
        "repoName": "example-org/example-repo",
        "url": "https://github.com/example-org/example-repo/tree/main/docs",
        "installationProvider": "github",
        "integration": "github",
        "installationId": "installation_abc",
        "installationStatus": "active",
        "state": "success",
        "updatedAt": "2026-08-01T00:00:00.000Z",
        "operation": {"object": "git-operation", "state": "success"},
    }
    base.update(overrides)
    return base


def _error(message):
    return collector.DemistoException(f"Error in API call to GitBook {message}")


class _StubClient:
    """Returns canned responses so the loops can be exercised without a network.

    A queued Exception is raised instead of returned, which is how a status
    other than 200 is simulated.
    """

    def __init__(self, responses):
        self.responses = responses
        self.requested = []
        self.paths = []

    def _http_request(self, method, url_suffix, params=None):
        self.requested.append((params or {}).get("page"))
        self.paths.append(url_suffix)
        response = self.responses[len(self.requested) - 1]
        if isinstance(response, Exception):
            raise response
        return response


def _client_with(responses):
    client = collector.Client.__new__(collector.Client)
    stub = _StubClient(responses)
    client._http_request = stub._http_request  # type: ignore[method-assign]
    client._stub = stub
    return client


class _FakeClient:
    """Stands in for the client when the two step fetch is under test."""

    def __init__(self, spaces, git_info_by_space):
        self.spaces = spaces
        self.git_info_by_space = git_info_by_space
        self.git_info_calls = []

    def list_spaces(self, organization_id, max_fetch):
        return self.spaces

    def get_git_info(self, space_id):
        self.git_info_calls.append(space_id)
        return self.git_info_by_space.get(space_id)


def test_space_and_git_config_are_flattened_into_scalar_columns():
    """Nothing may reach a column as a dict or a list, at either nesting level."""
    event = collector.build_event(_space(), _git_info(), ORG, NOW)
    assert event["space_id"] == "space_abc"
    assert event["space_title"] == "Example Space"
    assert event["space_visibility"] == "public"
    assert event["git_sync_configured"] is True
    assert event["git_installationId"] == "installation_abc"
    assert event["git_installationProvider"] == "github"
    # The nested operation object is flattened one level, not kept as a blob.
    assert event["git_operation_state"] == "success"
    assert all(not isinstance(v, dict | list) for v in event.values())
    # The nested objects must not survive as blobs under their own names.
    assert "space_urls" not in event
    assert "git_operation" not in event


def test_no_field_reaches_a_column_as_a_dict_or_a_list():
    """The scalar guard must cover every field, including the identifying ones."""
    for space in (
        _space(id={"value": "space_abc"}),
        _space(title={"text": "Example Space"}),
        _space(title=["Example", "Space"]),
    ):
        event = collector.build_event(space, _git_info(), ORG, NOW)
        assert all(not isinstance(v, dict | list) for v in event.values())

    nested = collector.build_event(
        _space(),
        {"installation": {"id": "i1", "scopes": ["a"], "meta": {"deep": 1}}},
        ORG,
        NOW,
    )
    assert all(not isinstance(v, dict | list) for v in nested.values())


def test_git_sync_configured_cannot_be_overwritten_by_a_collected_field():
    """A git field named sync_configured would otherwise land on the same column."""
    event = collector.build_event(_space(), {"sync_configured": "no"}, ORG, NOW)
    assert event["git_sync_configured"] is True


def test_repository_identity_is_captured_under_git_prefixed_columns():
    """The repository identity is what separates egress from ordinary docs-as-code.

    A space synced to a repository inside the organisation's own namespace is a
    sanctioned workflow; one synced outside it is a content egress path. That
    distinction needs the repository NAME, so its absence would make the whole
    record undetectable rather than merely thinner.
    """
    event = collector.build_event(_space(), _git_info(), ORG, NOW)
    assert event["git_repoName"] == "example-org/example-repo"
    assert event["git_installationProvider"] == "github"
    assert event["git_repository_named"] is True


def test_sync_configured_without_a_nameable_repository_is_flagged():
    """Configured but unnameable is a different finding from not configured."""
    event = collector.build_event(_space(), {"installationStatus": "pending"}, ORG, NOW)
    assert event["git_sync_configured"] is True
    assert event["git_repository_named"] is False


def test_a_space_without_git_sync_is_still_a_record():
    """A space that stops syncing must show as a change, not as a missing row."""
    event = collector.build_event(_space(), None, ORG, NOW)
    assert event["space_id"] == "space_abc"
    assert event["git_sync_configured"] is False
    assert not any(key.startswith("git_") for key in event if key != "git_sync_configured")


def test_snapshot_metadata_is_stamped_on_every_record():
    for git_info in (_git_info(), None):
        event = collector.build_event(_space(), git_info, ORG, NOW)
        assert event["_time"] == NOW
        assert event["snapshot_at"] == NOW
        assert event["source_log_type"] == "git_sync"
        assert event["organization_id"] == ORG


def test_404_from_git_info_is_an_answer_not_an_error():
    """A space with no git sync answers 404, which must not fail the run."""
    client = _client_with([_error("[404] - Not Found")])
    assert client.get_git_info("space_abc") is None


def test_404_is_recognised_from_the_attached_response():
    class _Res:
        status_code = 404

    error = collector.DemistoException("Failed to parse json object from response")
    error.res = _Res()
    assert collector._is_not_found(error) is True


def test_any_other_status_from_git_info_still_raises():
    """Swallowing a real failure would read as a space with no git sync."""
    for status in (
        "[401] - Unauthorized",
        "[403] - Forbidden",
        "[500] - Internal Server Error",
    ):
        client = _client_with([_error(status)])
        with pytest.raises(collector.DemistoException):
            client.get_git_info("space_abc")


def test_pagination_follows_the_opaque_cursor():
    """The page parameter is an identifier from the previous response, never constructed."""
    client = _client_with(
        [
            {"items": [_space(id="a")], "next": {"page": "CURSOR_2"}},
            {"items": [_space(id="b")], "next": {"page": "CURSOR_3"}},
            {"items": [_space(id="c")]},
        ]
    )
    spaces = client.list_spaces(ORG, 100)
    assert [s["id"] for s in spaces] == ["a", "b", "c"]
    assert client._stub.requested == [None, "CURSOR_2", "CURSOR_3"]


def test_pagination_stops_when_the_cursor_repeats():
    """A cursor that does not advance would otherwise re-request one page forever."""
    client = _client_with(
        [
            {"items": [_space(id="a")], "next": {"page": "SAME"}},
            {"items": [_space(id="b")], "next": {"page": "SAME"}},
        ]
    )
    spaces = client.list_spaces(ORG, 100)
    assert [s["id"] for s in spaces] == ["a", "b"]
    assert len(client._stub.requested) == 2


def test_pagination_honours_max_fetch():
    client = _client_with(
        [
            {"items": [_space(id="a"), _space(id="b")], "next": {"page": "CURSOR_2"}},
            {"items": [_space(id="c")]},
        ]
    )
    assert len(client.list_spaces(ORG, 1)) == 1


def test_every_space_produces_exactly_one_record():
    client = _FakeClient(
        [_space(id="a"), _space(id="b")],
        {"a": _git_info()},
    )
    events = collector.fetch_git_sync(client, ORG, 100)
    assert [e["space_id"] for e in events] == ["a", "b"]
    assert [e["git_sync_configured"] for e in events] == [True, False]
    assert client.git_info_calls == ["a", "b"]


def test_records_without_an_id_are_dropped():
    """A space with no identifier cannot be joined to its git configuration."""
    client = _FakeClient([_space(), {"object": "space", "title": "No Id"}, "not a dict"], {})
    events = collector.fetch_git_sync(client, ORG, 100)
    assert len(events) == 1
    assert client.git_info_calls == ["space_abc"]


def test_empty_space_list_is_not_an_error():
    client = _client_with([{"items": []}])
    assert client.list_spaces(ORG, 100) == []
    assert collector.fetch_git_sync(_FakeClient([], {}), ORG, 100) == []


def test_malformed_response_does_not_raise():
    assert _client_with(["not a dict"]).list_spaces(ORG, 100) == []
    assert _client_with([{"items": "not a list"}]).list_spaces(ORG, 100) == []
    assert _client_with(["not a dict"]).get_git_info("space_abc") is None
