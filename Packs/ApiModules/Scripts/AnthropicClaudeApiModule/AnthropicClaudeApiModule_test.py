"""Unit tests for the shared AnthropicClaudeApiModule.

The shared module owns every integration concern: the ``AnthropicClient`` (LLM Messages
API), the ``ComplianceClient`` (with the ``_apply_ucp_api_key`` override), the event
collector, all fourteen read-only and delete compliance commands, all four LLM commands,
and the ``run_anthropic_claude_integration()`` dispatcher. Both consuming integrations
(``AnthropicClaude`` parent + ``AnthropicClaudeStandardConnector`` satellite) are
byte-identical shims that just call the dispatcher — the YAML is the enforcement boundary.
"""

import json
import os
from types import SimpleNamespace

import pytest
import requests
from CommonServerPython import CommandResults, DemistoException, UcpException

from AnthropicClaudeApiModule import (
    AnthropicClient,
    ApiPaths,
    ComplianceClient,
    Config,
    _delete_command,
    add_time_to_events,
    chat_file_delete_command,
    conversation_to_chat_context,
    deduplicate_events,
    ensure_api_key,
    ensure_compliance_key,
    extract_assistant_message,
    fetch_events_command,
    fetch_events_with_pagination,
    get_events_command,
    get_project_document_command,
    list_chat_messages_command,
    list_chats_command,
    list_group_members_command,
    list_groups_command,
    list_organization_users_command,
    list_organizations_command,
    list_project_attachments_command,
    list_projects_command,
    list_role_permissions_command,
    list_roles_command,
    module_test_compliance,
    project_document_delete_command,
    resolve_org_uuid,
    module_test_llm,
    send_message_command,
)


BASE_URL = "https://api.anthropic.com/"


def build_compliance_client() -> ComplianceClient:
    return ComplianceClient(url=BASE_URL, api_key="sk-ant-api01-test", proxy=False, verify=False)


def build_llm_client() -> AnthropicClient:
    return AnthropicClient(url=BASE_URL, api_key="llm-key", model="claude-3-haiku-20240307", proxy=False, verify=False)


def load_test_data(filename: str) -> dict:
    """Loads a JSON fixture from the test_data directory colocated with this test file."""
    path = os.path.join(os.path.dirname(__file__), "test_data", filename)
    with open(path) as fh:
        return json.load(fh)


def make_response(status_code: int, body: dict | None = None) -> requests.Response:
    """Build a real requests.Response so ``.status_code`` and ``.json()`` behave normally."""
    response = requests.Response()
    response.status_code = status_code
    if body is not None:
        response._content = json.dumps(body).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
    return response


def make_activities(start: int, count: int, base_minute: int = 0) -> list[dict]:
    """Builds a list of activity events with increasing ids/timestamps."""
    return [
        {
            "id": f"activity_{i:04d}",
            "activity_type": "chat.created",
            "created_at": f"2026-06-11T07:{base_minute:02d}:{i % 60:02d}Z",
        }
        for i in range(start, start + count)
    ]


# ── Config / ApiPaths ─────────────────────────────────────────────────────────


def test_config_carries_full_surface():
    """Sanity: the shared Config carries every constant the collector + all commands need."""
    assert Config.VENDOR == "anthropic"
    assert Config.PRODUCT == "claude"
    assert Config.ACTIVITIES_PAGE_SIZE == 5000
    assert Config.MAX_FETCH_CALLS == 10
    assert Config.DEFAULT_MAX_EVENTS_PER_FETCH == 50000
    assert Config.DEFAULT_FETCH_LOOKBACK == "1 minute"
    assert Config.MAX_RETRIES == 3
    assert Config.BACKOFF_FACTOR == 2
    assert Config.RETRY_STATUS_CODES == (429, 500, 502, 503, 504)
    assert Config.DEFAULT_LIST_LIMIT == 50
    assert Config.COMPLIANCE_KEY_DOCS.startswith("https://")
    assert Config.API_KEY_DOCS.startswith("https://")


def test_apipaths_carries_full_surface():
    assert ApiPaths.ACTIVITIES == "v1/compliance/activities"
    assert ApiPaths.ORGANIZATIONS == "v1/compliance/organizations"
    assert ApiPaths.GROUPS == "v1/compliance/groups"
    assert ApiPaths.CHATS == "v1/compliance/apps/chats"
    assert ApiPaths.PROJECTS == "v1/compliance/apps/projects"
    assert ApiPaths.CHAT_FILES == "v1/compliance/apps/chats/files"
    assert ApiPaths.PROJECT_DOCUMENTS == "v1/compliance/apps/projects/documents"
    # Classmethod interpolation.
    assert ApiPaths.organization_users("org-1") == "v1/compliance/organizations/org-1/users"
    assert ApiPaths.role_permissions("org-1", "role-1") == "v1/compliance/organizations/org-1/roles/role-1/permissions"
    assert ApiPaths.group_members("grp-1") == "v1/compliance/groups/grp-1/members"
    assert ApiPaths.chat_messages("chat-1") == "v1/compliance/apps/chats/chat-1/messages"
    assert ApiPaths.project_attachments("proj-1") == "v1/compliance/apps/projects/proj-1/attachments"
    assert ApiPaths.project_document("proj-1", "doc-1") == "v1/compliance/apps/projects/proj-1/documents/doc-1"


# ── ensure_api_key / ensure_compliance_key / resolve_org_uuid ─────────────────


def test_ensure_api_key_raises_when_missing():
    with pytest.raises(DemistoException, match="API Key"):
        ensure_api_key(None)
    with pytest.raises(DemistoException, match="API Key"):
        ensure_api_key("")


def test_ensure_api_key_passes_when_present():
    ensure_api_key("some-key")


def test_ensure_compliance_key_raises_when_missing():
    with pytest.raises(DemistoException, match="Compliance Access Key"):
        ensure_compliance_key(None)
    with pytest.raises(DemistoException, match="Compliance Access Key"):
        ensure_compliance_key("")


def test_ensure_compliance_key_passes_when_present():
    ensure_compliance_key("sk-ant-api01-test")


def test_resolve_org_uuid_falls_back_to_param():
    assert resolve_org_uuid({"org_uuid": "arg-org"}, {"organization_uuid": "param-org"}) == "arg-org"
    assert resolve_org_uuid({}, {"organization_uuid": "param-org"}) == "param-org"


def test_resolve_org_uuid_missing_raises():
    with pytest.raises(DemistoException, match="Organization UUID is required"):
        resolve_org_uuid({}, {})


# ── ComplianceClient constructor (legacy XSOAR path) ──────────────────────────


def test_client_constructor_sets_x_api_key_header_for_legacy_path():
    """On the legacy XSOAR path the header is pre-populated in the constructor."""
    client = build_compliance_client()
    assert client.headers["x-api-key"] == "sk-ant-api01-test"
    assert client.headers["accept"] == "application/json"


# ── ComplianceClient._apply_ucp_api_key (UCP path) ────────────────────────────


def _make_ctx() -> SimpleNamespace:
    """Minimal UcpRequestContext-compatible stub — the override only touches ``headers``."""
    return SimpleNamespace(headers={}, params={}, auth=None, data=None, json_data=None)


def test_apply_ucp_api_key_writes_x_api_key_from_flat_form():
    """Flat form: {'type': 'api_key', 'key': '...'} — the CSP alias for manifest auth.parameter='api_key'."""
    client = build_compliance_client()
    ctx = _make_ctx()
    creds = {"type": "api_key", "key": "sk-ant-flat-key"}

    client._apply_ucp_api_key(creds, ctx)

    assert ctx.headers["x-api-key"] == "sk-ant-flat-key"
    assert ctx.headers["accept"] == "application/json"
    # Guard-rail: MUST NOT set the default Authorization header the base implementation writes.
    assert "Authorization" not in ctx.headers


def test_apply_ucp_api_key_writes_x_api_key_from_nested_form():
    """Nested form: {'type': 'api_key', 'api_key': {'key': '...'}} — also valid per BaseClient contract."""
    client = build_compliance_client()
    ctx = _make_ctx()
    creds = {"type": "api_key", "api_key": {"key": "sk-ant-nested-key"}}

    client._apply_ucp_api_key(creds, ctx)

    assert ctx.headers["x-api-key"] == "sk-ant-nested-key"
    assert "Authorization" not in ctx.headers


def test_apply_ucp_api_key_raises_ucp_exception_on_empty_key(mocker):
    """Empty key must raise UcpException so the dispatcher surfaces the generic UCP error."""
    mocker.patch("AnthropicClaudeApiModule.demisto.error")
    client = build_compliance_client()
    ctx = _make_ctx()
    creds = {"type": "api_key", "api_key": {"key": ""}}

    with pytest.raises(UcpException):
        client._apply_ucp_api_key(creds, ctx)


def test_apply_ucp_api_key_raises_when_no_key_provided(mocker):
    mocker.patch("AnthropicClaudeApiModule.demisto.error")
    client = build_compliance_client()
    ctx = _make_ctx()

    with pytest.raises(UcpException):
        client._apply_ucp_api_key({"type": "api_key"}, ctx)


def test_apply_ucp_api_key_preserves_existing_accept_header():
    """setdefault must not overwrite an accept header the caller already set."""
    client = build_compliance_client()
    ctx = _make_ctx()
    ctx.headers["accept"] = "application/vnd.api+json"

    client._apply_ucp_api_key({"type": "api_key", "key": "k"}, ctx)

    assert ctx.headers["accept"] == "application/vnd.api+json"


# ── http_get / http_delete ────────────────────────────────────────────────────


def test_http_get_retries_on_rate_limit(mocker):
    """ComplianceClient.http_get enables back-off retries on 429 and transient 5xx codes."""
    client = build_compliance_client()
    request_mock = mocker.patch.object(client, "_http_request", return_value={"data": []})

    client.http_get("v1/compliance/activities", params={"limit": 1})

    kwargs = request_mock.call_args.kwargs
    assert kwargs["retries"] == Config.MAX_RETRIES
    assert kwargs["backoff_factor"] == Config.BACKOFF_FACTOR
    assert 429 in kwargs["status_list_to_retry"]


def test_http_delete_treats_404_as_ok(mocker):
    """404 is included in ok_codes so 'already deleted' does not raise."""
    client = build_compliance_client()
    request_mock = mocker.patch.object(client, "_http_request", return_value=make_response(404))

    response = client.http_delete("v1/compliance/apps/chats/files/gone")

    assert response.status_code == 404
    call_kwargs = request_mock.call_args.kwargs
    assert call_kwargs["method"] == "DELETE"
    assert 404 in call_kwargs["ok_codes"]
    assert call_kwargs["status_list_to_retry"] == list(Config.RETRY_STATUS_CODES)
    assert call_kwargs["retries"] == Config.MAX_RETRIES
    assert call_kwargs["backoff_factor"] == Config.BACKOFF_FACTOR
    assert call_kwargs["resp_type"] == "response"


# ── Event collector: helpers ──────────────────────────────────────────────────


def test_add_time_to_events():
    events = [{"created_at": "2026-06-11T07:08:59Z"}, {"id": "no_time"}]
    add_time_to_events(events)
    assert events[0]["_time"] == "2026-06-11T07:08:59Z"
    assert "_time" not in events[1]


def test_deduplicate_events():
    events = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    assert deduplicate_events(events, ["b"]) == [{"id": "a"}, {"id": "c"}]
    assert deduplicate_events(events, []) == events
    assert deduplicate_events([], ["b"]) == []


# ── Event collector: fetch_events_with_pagination ─────────────────────────────


def test_fetch_events_first_run(mocker):
    """First run: uses the one-minute lookback lower bound, single page, no has_more."""
    client = build_compliance_client()
    response = {"data": make_activities(0, 3), "has_more": False, "last_id": "activity_0002"}
    get_mock = mocker.patch.object(client, "get_activities", return_value=response)

    events, next_run = fetch_events_with_pagination(client, last_run={}, max_events=50000, activity_types=None)

    assert len(events) == 3
    # First call should use created_at.gte (first-fetch lower bound), not after_id.
    _, kwargs = get_mock.call_args
    assert kwargs["created_at_gte"] is not None
    assert kwargs["after_id"] is None
    assert next_run["newest_created_at"] == "2026-06-11T07:00:02Z"


def test_fetch_events_subsequent_run(mocker):
    """Subsequent run: uses created_at.gt against the previously stored newest timestamp."""
    client = build_compliance_client()
    response = {"data": make_activities(5, 2), "has_more": False, "last_id": "activity_0006"}
    get_mock = mocker.patch.object(client, "get_activities", return_value=response)

    last_run = {"newest_created_at": "2026-06-11T07:00:04Z", "last_fetched_ids": ["activity_0004"]}
    events, next_run = fetch_events_with_pagination(client, last_run, max_events=50000, activity_types=None)

    assert len(events) == 2
    _, kwargs = get_mock.call_args
    assert kwargs["created_at_gt"] == "2026-06-11T07:00:04Z"
    assert kwargs["created_at_gte"] is None


def test_fetch_events_pagination(mocker):
    """Cursor pagination: walks multiple pages until has_more is False."""
    client = build_compliance_client()
    page1 = {"data": make_activities(0, 2), "has_more": True, "last_id": "activity_0001"}
    page2 = {"data": make_activities(2, 2), "has_more": False, "last_id": "activity_0003"}
    get_mock = mocker.patch.object(client, "get_activities", side_effect=[page1, page2])

    events, _ = fetch_events_with_pagination(client, last_run={}, max_events=50000, activity_types=None)

    assert len(events) == 4
    assert get_mock.call_count == 2
    # The second call must carry the cursor from page1's last_id.
    second_kwargs = get_mock.call_args_list[1].kwargs
    assert second_kwargs["after_id"] == "activity_0001"


def test_fetch_events_dedup(mocker):
    """Boundary events already seen in the previous run are not returned again."""
    client = build_compliance_client()
    response = {
        "data": [
            {"id": "activity_dup", "created_at": "2026-06-11T07:00:04Z", "activity_type": "x"},
            {"id": "activity_new", "created_at": "2026-06-11T07:00:05Z", "activity_type": "y"},
        ],
        "has_more": False,
        "last_id": "activity_new",
    }
    mocker.patch.object(client, "get_activities", return_value=response)

    last_run = {"newest_created_at": "2026-06-11T07:00:04Z", "last_fetched_ids": ["activity_dup"]}
    events, _ = fetch_events_with_pagination(client, last_run, max_events=50000, activity_types=None)

    ids = [e["id"] for e in events]
    assert "activity_dup" not in ids
    assert "activity_new" in ids


def test_fetch_events_respects_max_events(mocker):
    """The collector stops once max_events is reached even if more pages exist."""
    client = build_compliance_client()
    page = {"data": make_activities(0, 3), "has_more": True, "last_id": "activity_0002"}
    mocker.patch.object(client, "get_activities", return_value=page)

    events, _ = fetch_events_with_pagination(client, last_run={}, max_events=3, activity_types=None)

    assert len(events) == 3


def test_fetch_events_no_drop_across_cap_boundary_two_runs(mocker):
    """When total events exceed max_events_per_fetch, the cap must not drop events across runs.

    Run 1 collects exactly `max_events`; the persisted cursor must reflect only the delivered
    events so run 2 resumes from the correct boundary and the remaining events are returned with
    no gaps and no overlap.
    """
    client = build_compliance_client()
    # Six unique events across two ascending pages; cap each run at 3.
    all_events = make_activities(0, 6)
    page_first_half = {"data": all_events[:3], "has_more": True, "last_id": "activity_0002"}
    mocker.patch.object(client, "get_activities", return_value=page_first_half)

    run1_events, run1_next = fetch_events_with_pagination(client, last_run={}, max_events=3, activity_types=None)
    run1_ids = [e["id"] for e in run1_events]

    assert run1_ids == ["activity_0000", "activity_0001", "activity_0002"]
    # Cursor reflects the newest DELIVERED event only.
    assert run1_next["newest_created_at"] == all_events[2]["created_at"]

    # Run 2 resumes after the boundary; the API returns the remaining events.
    page_second_half = {"data": all_events[3:], "has_more": False, "last_id": "activity_0005"}
    mocker.patch.object(client, "get_activities", return_value=page_second_half)

    run2_events, _ = fetch_events_with_pagination(client, last_run=run1_next, max_events=3, activity_types=None)
    run2_ids = [e["id"] for e in run2_events]

    # No event is dropped and none is duplicated across the cap boundary.
    assert run2_ids == ["activity_0003", "activity_0004", "activity_0005"]
    assert set(run1_ids).isdisjoint(run2_ids)
    assert sorted(run1_ids + run2_ids) == [e["id"] for e in all_events]


def test_fetch_events_descending_feed_shape(mocker):
    """The real Activity Feed returns events newest-first; the cursor must capture the newest one."""
    client = build_compliance_client()
    page = load_test_data("activities_page1.json")
    # Close out pagination so the single fixture page is the whole cycle.
    page = {**page, "has_more": False}
    mocker.patch.object(client, "get_activities", return_value=page)

    events, next_run = fetch_events_with_pagination(client, last_run={}, max_events=50000, activity_types=None)

    assert len(events) == 2
    # activity_002 (07:08:59) is newer than activity_001 (07:08:58) despite appearing first.
    assert next_run["newest_created_at"] == "2026-06-11T07:08:59Z"
    assert next_run["last_fetched_ids"] == ["activity_002"]


# ── Event collector: fetch_events_command / get_events_command ────────────────


def test_fetch_events_pushes_to_xsiam(mocker):
    """fetch_events sets _time, pushes events with the correct vendor/product, and persists last_run."""
    client = build_compliance_client()
    response = {"data": make_activities(0, 2), "has_more": False, "last_id": "activity_0001"}
    mocker.patch.object(client, "get_activities", return_value=response)
    mocker.patch("AnthropicClaudeApiModule.demisto.getLastRun", return_value={})
    set_last_run = mocker.patch("AnthropicClaudeApiModule.demisto.setLastRun")
    send_mock = mocker.patch("AnthropicClaudeApiModule.send_events_to_xsiam")

    fetch_events_command(client, params={"max_events_per_fetch": "1000"})

    send_mock.assert_called_once()
    sent_events = send_mock.call_args.args[0]
    assert send_mock.call_args.kwargs["vendor"] == Config.VENDOR
    assert send_mock.call_args.kwargs["product"] == Config.PRODUCT
    assert all("_time" in e for e in sent_events)
    set_last_run.assert_called_once()


def test_get_events_command_no_push(mocker):
    client = build_compliance_client()
    response = {"data": make_activities(0, 2), "has_more": False, "last_id": "activity_0001"}
    mocker.patch.object(client, "get_activities", return_value=response)

    events, results = get_events_command(client, args={"limit": "50"})

    assert len(events) == 2
    assert isinstance(results, CommandResults)
    assert all("_time" in e for e in events)


def test_get_events_command_with_time_range(mocker):
    """start_time/end_time map to created_at.gte / created_at.lt bounds on the Activity Feed query."""
    client = build_compliance_client()
    response = {"data": make_activities(0, 1), "has_more": False, "last_id": "activity_0000"}
    get_mock = mocker.patch.object(client, "get_activities", return_value=response)

    get_events_command(
        client,
        args={"limit": "10", "start_time": "2025-06-07T08:09:10Z", "end_time": "2025-06-07T09:09:10Z"},
    )

    kwargs = get_mock.call_args.kwargs
    assert kwargs["created_at_gte"] == "2025-06-07T08:09:10Z"
    assert kwargs["created_at_lt"] == "2025-06-07T09:09:10Z"


# ── Read-only compliance commands ─────────────────────────────────────────────


def test_list_organizations_command(mocker):
    client = build_compliance_client()
    response = {"data": [{"uuid": "org-1", "name": "Acme", "created_at": "2026-01-01T00:00:00Z"}]}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_organizations_command(client, args={"limit": "50"})

    assert results.outputs_prefix == "AnthropicClaude.Organization"
    assert results.outputs[0]["uuid"] == "org-1"


def test_list_organization_users_command(mocker):
    client = build_compliance_client()
    response = {"data": [{"id": "u1", "email": "user@example.com", "organization_role": "admin"}]}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_organization_users_command(client, args={"org_uuid": "org-1", "limit": "10"}, params={})

    assert results.outputs_prefix == "AnthropicClaude.Organization.User"
    get_mock.assert_called_once()
    assert "organizations/org-1/users" in get_mock.call_args.args[0]


def test_list_roles_single_role(mocker):
    """When role_id is provided, the single-role endpoint is used (no data[] wrapper)."""
    client = build_compliance_client()
    response = {"id": "role-1", "name": "Owner", "description": "desc"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_roles_command(client, args={"org_uuid": "org-1", "role_id": "role-1"}, params={})

    assert results.outputs["id"] == "role-1"
    assert "roles/role-1" in get_mock.call_args.args[0]


def test_list_roles_list_mode(mocker):
    client = build_compliance_client()
    response = {"data": [{"id": "role-1", "name": "Owner"}], "next_page": "tok123"}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_roles_command(client, args={"org_uuid": "org-1"}, params={})

    assert results.outputs[0]["id"] == "role-1"
    assert "tok123" in results.readable_output


def test_list_role_permissions_command(mocker):
    client = build_compliance_client()
    response = {"data": [{"resource_type": "chats", "action": "read"}], "next_page": "tok-perm"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_role_permissions_command(client, args={"org_uuid": "org-1", "role_id": "role-1"}, params={})

    assert results.outputs_prefix == "AnthropicClaude.Organization.Role.Permission"
    assert results.outputs[0]["resource_type"] == "chats"
    assert "roles/role-1/permissions" in get_mock.call_args.args[0]


def test_list_role_permissions_missing_role_id_raises(mocker):
    """role_id is required for the permissions endpoint; omitting it must raise."""
    client = build_compliance_client()
    mocker.patch.object(client, "http_get")
    with pytest.raises(KeyError):
        list_role_permissions_command(client, args={"org_uuid": "org-1"}, params={})


def test_list_groups_single_group(mocker):
    client = build_compliance_client()
    response = {"id": "grp-1", "name": "Engineers", "source_type": "scim"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_groups_command(client, args={"group_id": "grp-1"})

    assert results.outputs["id"] == "grp-1"
    assert "groups/grp-1" in get_mock.call_args.args[0]


def test_list_group_members_dt_prefix(mocker):
    """Group members merge into the parent Group entry via DT."""
    client = build_compliance_client()
    response = {"data": [{"user_id": "u1", "email": "user@example.com"}]}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_group_members_command(client, args={"group_id": "grp-1"})

    assert results.outputs_prefix == "AnthropicClaude.Group(val.id == 'grp-1').Member"
    assert results.outputs[0]["user_id"] == "u1"


def test_list_chats_command(mocker):
    client = build_compliance_client()
    response = {"data": [{"id": "chat-1", "name": "Chat", "model": "claude-3"}]}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_chats_command(client, args={"user_ids": "u1,u2", "limit": "100"})

    assert results.outputs_prefix == "AnthropicClaude.Chat"
    params = get_mock.call_args.kwargs["params"]
    assert params["user_ids[]"] == ["u1", "u2"]


def test_list_chats_date_range_param_mapping(mocker):
    """created_at_gte argument maps to the created_at.gte query parameter."""
    client = build_compliance_client()
    response = {"data": [{"id": "chat-1", "name": "Chat"}]}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    list_chats_command(client, args={"user_ids": "u1", "created_at_gte": "2025-06-07T08:09:10Z"})

    params = get_mock.call_args.kwargs["params"]
    assert params["created_at.gte"] == "2025-06-07T08:09:10Z"


def test_list_chat_messages_command(mocker):
    client = build_compliance_client()
    response = {"chat_messages": [{"id": "m1", "role": "user", "created_at": "2026-01-01T00:00:00Z"}]}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_chat_messages_command(client, args={"chat_id": "chat-1"})

    # Messages merge into the parent Chat entry via DT.
    assert results.outputs_prefix == "AnthropicClaude.Chat(val.id == 'chat-1').Message"
    assert results.outputs[0]["id"] == "m1"


def test_list_projects_single_project(mocker):
    client = build_compliance_client()
    response = {"id": "proj-1", "name": "Project", "is_private": True}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_projects_command(client, args={"project_id": "proj-1"})

    assert results.outputs["id"] == "proj-1"
    assert "projects/proj-1" in get_mock.call_args.args[0]


def test_list_project_attachments_command(mocker):
    client = build_compliance_client()
    response = {
        "data": [{"id": "att-1", "filename": "diagram.png", "mime_type": "image/png"}],
        "next_page": "tok-att",
    }
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_project_attachments_command(client, args={"project_id": "proj-1"})

    # Attachments merge into the parent Project entry via DT.
    assert results.outputs_prefix == "AnthropicClaude.Project(val.id == 'proj-1').Attachment"
    assert results.outputs[0]["id"] == "att-1"
    assert "projects/proj-1/attachments" in get_mock.call_args.args[0]
    assert "tok-att" in results.readable_output


def test_get_project_document_command(mocker):
    client = build_compliance_client()
    response = {"id": "claude_proj_doc_1", "filename": "spec.md", "content": "hello"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = get_project_document_command(client, args={"project_id": "proj-1", "document_id": "claude_proj_doc_1"})

    assert results.outputs_prefix == "AnthropicClaude.ProjectDocument"
    assert results.outputs["content"] == "hello"
    assert "projects/proj-1/documents/claude_proj_doc_1" in get_mock.call_args.args[0]


# ── Delete commands ──────────────────────────────────────────────────────────


def test_chat_file_delete_command_happy_path(mocker):
    """Happy path: hits the flat chat-files delete path and reports the deleted id."""
    client = build_compliance_client()
    delete_mock = mocker.patch.object(
        client, "http_delete", return_value=make_response(200, {"id": "claude_file_1", "type": "claude_file_deleted"})
    )

    results = chat_file_delete_command(client, args={"file_id": "claude_file_1"})

    delete_mock.assert_called_once_with(f"{ApiPaths.CHAT_FILES}/claude_file_1")
    assert isinstance(results, CommandResults)
    assert results.outputs["id"] == "claude_file_1"
    assert results.outputs["type"] == "claude_file_deleted"
    assert results.outputs["Deleted"] is True
    assert results.outputs_prefix == "AnthropicClaude.DeletedFile"


def test_chat_file_delete_command_idempotent_on_404(mocker):
    """A 404 (already deleted / unknown id) is treated as an idempotent success and annotated."""
    client = build_compliance_client()
    mocker.patch.object(client, "http_delete", return_value=make_response(404))

    results = chat_file_delete_command(client, args={"file_id": "claude_file_gone"})

    assert results.outputs["Deleted"] is True
    assert "was already deleted" in results.readable_output


def test_chat_file_delete_command_missing_arg_raises():
    client = build_compliance_client()
    with pytest.raises(KeyError):
        chat_file_delete_command(client, args={})


def test_project_document_delete_command_happy_path(mocker):
    """Happy path: hits the flat project-documents delete path and reports the deleted id."""
    client = build_compliance_client()
    delete_mock = mocker.patch.object(
        client,
        "http_delete",
        return_value=make_response(200, {"id": "claude_proj_doc_1", "type": "claude_project_document_deleted"}),
    )

    results = project_document_delete_command(client, args={"document_id": "claude_proj_doc_1"})

    delete_mock.assert_called_once_with(f"{ApiPaths.PROJECT_DOCUMENTS}/claude_proj_doc_1")
    assert results.outputs["id"] == "claude_proj_doc_1"
    assert results.outputs["type"] == "claude_project_document_deleted"
    assert results.outputs["Deleted"] is True
    assert results.outputs_prefix == "AnthropicClaude.DeletedProjectDocument"


def test_project_document_delete_command_idempotent_on_404(mocker):
    client = build_compliance_client()
    mocker.patch.object(client, "http_delete", return_value=make_response(404))

    results = project_document_delete_command(client, args={"document_id": "claude_proj_doc_gone"})

    assert results.outputs["Deleted"] is True
    assert "was already deleted" in results.readable_output


def test_project_document_delete_command_missing_arg_raises():
    client = build_compliance_client()
    with pytest.raises(KeyError):
        project_document_delete_command(client, args={})


def test_delete_command_falls_back_when_response_body_not_json(mocker):
    """When the DELETE response body cannot be parsed as JSON the helper still returns a valid result."""
    client = build_compliance_client()
    response = requests.Response()
    response.status_code = 200
    response._content = b"not-json"
    mocker.patch.object(client, "http_delete", return_value=response)

    results = _delete_command(
        client,
        resource_id="rid",
        url_suffix="v1/some/path/rid",
        deleted_type="some_type",
        outputs_prefix="Any.Prefix",
        resource_label="Thing",
    )

    assert results.outputs["id"] == "rid"
    assert results.outputs["type"] == "some_type"
    assert results.raw_response == {"id": "rid", "type": "some_type"}


# ── module_test_compliance ────────────────────────────────────────────────────


def test_module_test_compliance_success(mocker):
    client = build_compliance_client()
    mocker.patch.object(client, "get_activities", return_value={"data": []})
    assert module_test_compliance(client) == "ok"


def test_module_test_compliance_auth_failure(mocker):
    client = build_compliance_client()
    mocker.patch.object(client, "get_activities", side_effect=DemistoException("Error 401 Unauthorized"))
    result = module_test_compliance(client)
    assert "Authorization Error" in result


def test_module_test_compliance_other_error_raises(mocker):
    client = build_compliance_client()
    mocker.patch.object(client, "get_activities", side_effect=DemistoException("500 Server Error"))
    with pytest.raises(DemistoException):
        module_test_compliance(client)


# ── LLM: AnthropicClient / helpers / commands ────────────────────────────────


def test_anthropic_client_constructor_sets_llm_headers():
    client = build_llm_client()
    assert client.api_key == "llm-key"
    assert client.model == "claude-3-haiku-20240307"
    assert client.headers["x-api-key"] == "llm-key"
    assert client.headers["Content-Type"] == "application/json"
    assert client.headers["anthropic-version"]  # populated to the module constant


def test_conversation_to_chat_context_alternates_user_and_assistant():
    conversation = [
        {"user": "hi", "assistant": "hello"},
        {"user": "bye", "assistant": "goodbye"},
    ]
    context = conversation_to_chat_context(conversation)
    assert context == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
        {"role": "user", "content": "bye"},
        {"role": "assistant", "content": "goodbye"},
    ]


def test_extract_assistant_message_concatenates_text_parts():
    response = {"content": [{"type": "text", "text": "Hello, "}, {"type": "text", "text": "world!"}]}
    assert extract_assistant_message(response) == "Hello, world!"


def test_extract_assistant_message_skips_non_text_parts():
    response = {
        "content": [
            {"type": "tool_use", "name": "some_tool"},
            {"type": "text", "text": "only this"},
        ]
    }
    assert extract_assistant_message(response) == "only this"


def test_send_message_command_happy_path(mocker):
    client = build_llm_client()
    mocker.patch("AnthropicClaudeApiModule.demisto.context", return_value={})
    mocker.patch.object(
        client,
        "get_messages",
        return_value={
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "hi there"}],
            "usage": {"input_tokens": 5, "output_tokens": 2},
        },
    )

    results, response = send_message_command(client, args={"message": "hello", "reset_conversation_history": "yes"})

    assert isinstance(results, CommandResults)
    assert response["content"][0]["text"] == "hi there"
    # The conversation step is written back to the AnthropicClaude.Conversation context path.
    assert results.outputs_prefix == "AnthropicClaude.Conversation"
    assert results.outputs == [{"user": "hello", "assistant": "hi there"}]
    assert results.replace_existing is True


def test_send_message_command_requires_message():
    client = build_llm_client()
    with pytest.raises(ValueError, match="Message not provided"):
        send_message_command(client, args={})


def test_module_test_llm_success(mocker):
    client = build_llm_client()
    mocker.patch.object(client, "get_messages", return_value={"content": [{"type": "text", "text": "pong"}]})
    assert module_test_llm(client, params={"max_tokens": "1024"}) == "ok"


def test_module_test_llm_auth_error_returns_labeled_message(mocker):
    client = build_llm_client()
    mocker.patch.object(client, "get_messages", side_effect=DemistoException("403 Forbidden"))
    assert "Authorization Error" in module_test_llm(client, params={"max_tokens": "1024"})


def test_module_test_llm_other_error_raises(mocker):
    client = build_llm_client()
    mocker.patch.object(client, "get_messages", side_effect=DemistoException("500 Server Error"))
    with pytest.raises(DemistoException):
        module_test_llm(client, params={"max_tokens": "1024"})
