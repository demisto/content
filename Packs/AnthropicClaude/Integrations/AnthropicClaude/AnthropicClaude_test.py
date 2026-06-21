"""Unit tests for the Anthropic Claude Compliance API event collection and read-only commands."""

import pytest
from CommonServerPython import CommandResults, DemistoException
from AnthropicClaude import (
    Config,
    ComplianceClient,
    add_time_to_events,
    deduplicate_events,
    fetch_events_with_pagination,
    fetch_events_command,
    get_events_command,
    list_organizations_command,
    list_organization_users_command,
    list_roles_command,
    list_groups_command,
    list_group_members_command,
    list_chats_command,
    list_chat_messages_command,
    list_projects_command,
    get_project_document_command,
    module_test_compliance,
    resolve_org_uuid,
    require_compliance_key,
    require_api_key,
)

BASE_URL = "https://api.anthropic.com/"


def build_client() -> ComplianceClient:
    return ComplianceClient(url=BASE_URL, api_key="sk-ant-api01-test", proxy=False, verify=False)


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


""" EVENT COLLECTOR TESTS """


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


def test_fetch_events_first_run(mocker):
    """First run: uses the one-minute lookback lower bound, single page, no has_more."""
    client = build_client()
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
    client = build_client()
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
    client = build_client()
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
    client = build_client()
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
    client = build_client()
    page = {"data": make_activities(0, 3), "has_more": True, "last_id": "activity_0002"}
    mocker.patch.object(client, "get_activities", return_value=page)

    events, _ = fetch_events_with_pagination(client, last_run={}, max_events=3, activity_types=None)

    assert len(events) == 3


def test_fetch_events_pushes_to_xsiam(mocker):
    """fetch_events sets _time, pushes events with the correct vendor/product, and persists last_run."""
    client = build_client()
    response = {"data": make_activities(0, 2), "has_more": False, "last_id": "activity_0001"}
    mocker.patch.object(client, "get_activities", return_value=response)
    mocker.patch("AnthropicClaude.demisto.getLastRun", return_value={})
    set_last_run = mocker.patch("AnthropicClaude.demisto.setLastRun")
    send_mock = mocker.patch("AnthropicClaude.send_events_to_xsiam")

    fetch_events_command(client, params={"max_events_per_fetch": "1000"})

    send_mock.assert_called_once()
    sent_events = send_mock.call_args.args[0]
    assert send_mock.call_args.kwargs["vendor"] == Config.VENDOR
    assert send_mock.call_args.kwargs["product"] == Config.PRODUCT
    assert all("_time" in e for e in sent_events)
    set_last_run.assert_called_once()


def test_get_events_command_no_push(mocker):
    client = build_client()
    response = {"data": make_activities(0, 2), "has_more": False, "last_id": "activity_0001"}
    mocker.patch.object(client, "get_activities", return_value=response)

    events, results = get_events_command(client, args={"limit": "50"})

    assert len(events) == 2
    assert isinstance(results, CommandResults)
    assert all("_time" in e for e in events)


""" COMPLIANCE COMMAND TESTS """


def test_list_organizations_command(mocker):
    client = build_client()
    response = {"data": [{"uuid": "org-1", "name": "Acme", "created_at": "2026-01-01T00:00:00Z"}]}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_organizations_command(client, args={"limit": "50"})

    assert results.outputs_prefix == "AnthropicClaude.Organization"
    assert results.outputs[0]["uuid"] == "org-1"


def test_list_organization_users_command(mocker):
    client = build_client()
    response = {"data": [{"id": "u1", "email": "user@example.com", "organization_role": "admin"}]}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_organization_users_command(client, args={"org_uuid": "org-1", "limit": "10"}, params={})

    assert results.outputs_prefix == "AnthropicClaude.Organization.User"
    get_mock.assert_called_once()
    assert "organizations/org-1/users" in get_mock.call_args.args[0]


def test_list_roles_single_role(mocker):
    """When role_id is provided, the single-role endpoint is used (no data[] wrapper)."""
    client = build_client()
    response = {"id": "role-1", "name": "Owner", "description": "desc"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_roles_command(client, args={"org_uuid": "org-1", "role_id": "role-1"}, params={})

    assert results.outputs["id"] == "role-1"
    assert "roles/role-1" in get_mock.call_args.args[0]


def test_list_roles_list_mode(mocker):
    client = build_client()
    response = {"data": [{"id": "role-1", "name": "Owner"}], "next_page": "tok123"}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_roles_command(client, args={"org_uuid": "org-1"}, params={})

    assert results.outputs[0]["id"] == "role-1"
    assert "tok123" in results.readable_output


def test_list_groups_single_group(mocker):
    client = build_client()
    response = {"id": "grp-1", "name": "Engineers", "source_type": "scim"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_groups_command(client, args={"group_id": "grp-1"})

    assert results.outputs["id"] == "grp-1"
    assert "groups/grp-1" in get_mock.call_args.args[0]


def test_list_chats_command(mocker):
    client = build_client()
    response = {"data": [{"id": "chat-1", "name": "Chat", "model": "claude-3"}]}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_chats_command(client, args={"user_ids": "u1,u2", "limit": "100"})

    assert results.outputs_prefix == "AnthropicClaude.Chat"
    params = get_mock.call_args.kwargs["params"]
    assert params["user_ids[]"] == ["u1", "u2"]


def test_list_chat_messages_command(mocker):
    client = build_client()
    response = {"chat_messages": [{"id": "m1", "role": "user", "created_at": "2026-01-01T00:00:00Z"}]}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_chat_messages_command(client, args={"chat_id": "chat-1"})

    # Messages merge into the parent Chat entry via DT.
    assert results.outputs_prefix == "AnthropicClaude.Chat(val.id == 'chat-1').Message"
    assert results.outputs[0]["id"] == "m1"


def test_list_projects_single_project(mocker):
    client = build_client()
    response = {"id": "proj-1", "name": "Project", "is_private": True}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = list_projects_command(client, args={"project_id": "proj-1"})

    assert results.outputs["id"] == "proj-1"
    assert "projects/proj-1" in get_mock.call_args.args[0]


def test_get_project_document_command(mocker):
    client = build_client()
    response = {"id": "claude_proj_doc_1", "filename": "spec.md", "content": "hello"}
    get_mock = mocker.patch.object(client, "http_get", return_value=response)

    results = get_project_document_command(client, args={"project_id": "proj-1", "document_id": "claude_proj_doc_1"})

    assert results.outputs_prefix == "AnthropicClaude.ProjectDocument"
    assert results.outputs["content"] == "hello"
    assert "projects/proj-1/documents/claude_proj_doc_1" in get_mock.call_args.args[0]


def test_list_group_members_dt_prefix(mocker):
    """Group members merge into the parent Group entry via DT."""
    client = build_client()
    response = {"data": [{"user_id": "u1", "email": "user@example.com"}]}
    mocker.patch.object(client, "http_get", return_value=response)

    results = list_group_members_command(client, args={"group_id": "grp-1"})

    assert results.outputs_prefix == "AnthropicClaude.Group(val.id == 'grp-1').Member"
    assert results.outputs[0]["user_id"] == "u1"


def test_resolve_org_uuid_falls_back_to_param():
    assert resolve_org_uuid({"org_uuid": "arg-org"}, {"organization_uuid": "param-org"}) == "arg-org"
    assert resolve_org_uuid({}, {"organization_uuid": "param-org"}) == "param-org"


def test_resolve_org_uuid_missing_raises():
    with pytest.raises(DemistoException, match="Organization UUID is required"):
        resolve_org_uuid({}, {})


def test_require_compliance_key_missing_raises():
    with pytest.raises(DemistoException, match="Compliance Access Key"):
        require_compliance_key(None)
    # Present key does not raise.
    require_compliance_key("sk-ant-api01-test")


def test_require_api_key_missing_raises():
    with pytest.raises(DemistoException, match="API Key"):
        require_api_key(None)
    require_api_key("some-key")


""" TEST-MODULE TESTS """


def test_test_module_compliance_success(mocker):
    client = build_client()
    mocker.patch.object(client, "get_activities", return_value={"data": []})
    assert module_test_compliance(client) == "ok"


def test_test_module_compliance_auth_failure(mocker):
    from CommonServerPython import DemistoException

    client = build_client()
    mocker.patch.object(client, "get_activities", side_effect=DemistoException("Error 401 Unauthorized"))
    result = module_test_compliance(client)
    assert "Authorization Error" in result


def test_test_module_compliance_other_error_raises(mocker):
    from CommonServerPython import DemistoException

    client = build_client()
    mocker.patch.object(client, "get_activities", side_effect=DemistoException("500 Server Error"))
    with pytest.raises(DemistoException):
        module_test_compliance(client)
