import demistomock as demisto
import pytest
from TaegisXDRv3 import (
    Client,
    _format_single_comment_for_note,
    _friendly_owner_label,
    _is_valid_assignee_id,
    _taegis_is_rate_limit_error,
    _taegis_rate_limit_params_from_dict,
    _taegis_rate_limit_sleep_seconds,
    _taegis_severity_to_label,
    _taegis_status_code_from_exc,
    _taegis_threat_score_from_severity,
    add_evidence_to_investigation_command,
    archive_investigation_command,
    close_investigation_command,
    create_comment_command,
    create_investigation_command,
    create_sharelink_command,
    execute_playbook_command,
    fetch_alerts_command,
    fetch_assets_command,
    fetch_comment_command,
    fetch_endpoint_command,
    fetch_investigation_alerts_command,
    fetch_playbook_execution_command,
    fetch_users_command,
    format_comments_for_mirroring,
    generate_id_url,
    get_mapping_fields_command,
    get_mirroring,
    isolate_asset_command,
    map_priority_from_taegis,
    map_priority_to_taegis,
    taegis_push_assignee_status_command,
    test_module as run_test_module,
    transform_entities_to_grid,
    unarchive_investigation_command,
    update_alert_status_command,
    update_comment_command,
    update_investigation_command,
)


def client():
    return Client(client_id="id", client_secret="secret", base_url="https://api.example.com", verify=False)


# --- rate-limit helpers ---


def test_rate_limit_params_defaults():
    assert _taegis_rate_limit_params_from_dict({}) == (True, 3, 5)


def test_rate_limit_params_from_config():
    params = {"api_rate_limit_retry_enabled": "false", "api_rate_limit_max_retries": "7", "api_rate_limit_base_delay_seconds": "20"}
    assert _taegis_rate_limit_params_from_dict(params) == (False, 7, 20)


def test_rate_limit_params_clamps_out_of_range():
    params = {"api_rate_limit_max_retries": "99", "api_rate_limit_base_delay_seconds": "999"}
    enabled, max_retries, base_delay = _taegis_rate_limit_params_from_dict(params)
    assert max_retries == 10
    assert base_delay == 60


def test_rate_limit_params_invalid_values_fall_back_to_defaults():
    params = {"api_rate_limit_max_retries": "not-a-number"}
    assert _taegis_rate_limit_params_from_dict(params) == (True, 3, 5)


class _FakeResponse:
    def __init__(self, status_code=None, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _FakeApiException(Exception):
    def __init__(self, message, res=None):
        super().__init__(message)
        self.res = res


def test_status_code_from_exc():
    exc = _FakeApiException("boom", res=_FakeResponse(status_code=429))
    assert _taegis_status_code_from_exc(exc) == 429


def test_status_code_from_exc_no_response():
    assert _taegis_status_code_from_exc(ValueError("boom")) is None


def test_is_rate_limit_error_by_status_code():
    exc = _FakeApiException("boom", res=_FakeResponse(status_code=429))
    assert _taegis_is_rate_limit_error(exc) is True


def test_is_rate_limit_error_by_message():
    assert _taegis_is_rate_limit_error(Exception("Error: too many requests")) is True
    assert _taegis_is_rate_limit_error(Exception("Unauthorized")) is False


def test_rate_limit_sleep_seconds_uses_retry_after_header():
    exc = _FakeApiException("boom", res=_FakeResponse(headers={"Retry-After": "12"}))
    assert _taegis_rate_limit_sleep_seconds(exc, base_delay=5, attempt_index=0) == 12


def test_rate_limit_sleep_seconds_exponential_backoff_without_header():
    exc = Exception("boom")
    assert _taegis_rate_limit_sleep_seconds(exc, base_delay=5, attempt_index=2) == 20


# --- severity / priority mapping ---


@pytest.mark.parametrize(
    "severity,label",
    [(None, "-"), (0.1, "Info"), (0.3, "Low"), (0.5, "Medium"), (0.7, "High"), (0.9, "Critical")],
)
def test_severity_to_label(severity, label):
    assert _taegis_severity_to_label(severity) == label


def test_threat_score_from_severity():
    assert _taegis_threat_score_from_severity(0.74) == "7.4"
    assert _taegis_threat_score_from_severity(None) == ""


@pytest.mark.parametrize(
    "xsoar_severity,expected",
    [(None, 3), (1, 1), (4, 4), (0, 3), ("High", 3), ("critical", 4), ("unknown", 3)],
)
def test_map_priority_to_taegis(xsoar_severity, expected):
    assert map_priority_to_taegis(xsoar_severity) == expected


@pytest.mark.parametrize("taegis_priority,expected", [(1, "Low"), (4, "Critical"), (99, "Medium")])
def test_map_priority_from_taegis(taegis_priority, expected):
    assert map_priority_from_taegis(taegis_priority) == expected


# --- assignee / user helpers ---


def test_is_valid_assignee_id_symbolic():
    assert _is_valid_assignee_id("@secureworks") is True
    assert _is_valid_assignee_id("@customer") is True


def test_is_valid_assignee_id_auth0():
    assert _is_valid_assignee_id("auth0|abc123") is True


def test_is_valid_assignee_id_uuid():
    assert _is_valid_assignee_id("12345678-1234-1234-1234-123456789012") is True


def test_is_valid_assignee_id_rejects_garbage():
    assert _is_valid_assignee_id("not-an-id") is False
    assert _is_valid_assignee_id("") is False
    assert _is_valid_assignee_id(None) is False


def test_friendly_owner_label_full_name_and_email():
    user = {"given_name": "Alice", "family_name": "Smith", "email": "alice@example.com"}
    assert _friendly_owner_label(user) == "Alice Smith (alice@example.com)"


def test_friendly_owner_label_falls_back_to_id():
    assert _friendly_owner_label({"id": "uuid-1"}) == "uuid-1"


# --- generic utilities ---


def test_generate_id_url_escapes_slashes():
    assert generate_id_url("https://xdr.example.com", "investigations", "abc/def") == "https://xdr.example.com/investigations/abc%2Fdef"


def test_transform_entities_to_grid_empty():
    assert transform_entities_to_grid([]) == []


def test_transform_entities_to_grid_entity_context_format():
    entities = [{"type": "ip_address", "displayName": "1.2.3.4", "id": "e1"}]
    rows = transform_entities_to_grid(entities)
    assert rows == [
        {
            "type": "ip_address",
            "value": "1.2.3.4",
            "Type": "ip_address",
            "Value": "1.2.3.4",
            "columnheader1": "ip_address",
            "columnheader2": "1.2.3.4",
        }
    ]


def test_transform_entities_to_grid_legacy_string_format():
    entities = [{"entities": ["ip_address:5.6.7.8"]}]
    rows = transform_entities_to_grid(entities)
    assert rows[0]["type"] == "ip_address"
    assert rows[0]["value"] == "5.6.7.8"


def test_format_single_comment_for_note_with_author():
    comment = {"author": {"given_name": "Bob", "family_name": "Jones"}, "comment": "hi", "createdAt": "2026-01-01"}
    assert _format_single_comment_for_note(comment) == "**Bob Jones** - 2026-01-01\n\nhi"


def test_format_single_comment_for_note_missing_author_falls_back_to_email():
    comment = {"author": {"email_normalized": "bob@example.com"}, "comment": "hi"}
    assert _format_single_comment_for_note(comment).startswith("**bob@example.com**")


def test_format_comments_for_mirroring_empty():
    assert format_comments_for_mirroring([]) == ""


def test_format_comments_for_mirroring_multiple_comments():
    comments = [{"author": {}, "comment": "first"}, {"author": {}, "comment": "second"}]
    rendered = format_comments_for_mirroring(comments)
    assert "first" in rendered
    assert "second" in rendered
    assert rendered.startswith("### Taegis XDR Case Comments")


def test_get_mirroring_reads_params(mocker):
    mocker.patch.object(demisto, "params", return_value={"mirror_direction": "Incoming And Outgoing"})
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")

    result = get_mirroring()

    assert result["mirror_direction"] == "Both"
    assert result["mirror_tags"] == ["comments", "CommentFromTaegis"]
    assert result["mirror_instance"] == "instance-1"


def test_get_mapping_fields_command_returns_scheme():
    response = get_mapping_fields_command()
    extracted = response.extract_mapping()
    assert "Taegis XDR - Case" in extracted
    assert "id" in extracted["Taegis XDR - Case"]


# --- Client ---


def test_client_auth_sets_bearer_header(mocker):
    c = client()
    mocker.patch.object(c, "_http_request", return_value={"access_token": "tok-123"})

    c.auth()

    assert c._auth_header["Authorization"] == "Bearer tok-123"


def test_client_graphql_run_passes_query_and_variables(mocker):
    c = client()
    http_mock = mocker.patch.object(c, "_http_request", return_value={"data": {}})

    c.graphql_run(query="{ ping }", variables={"a": 1})

    _, kwargs = http_mock.call_args
    assert kwargs["json_data"] == {"query": "{ ping }", "variables": {"a": 1}}


def test_client_http_request_retries_on_rate_limit(mocker):
    c = client()
    mocker.patch.object(demisto, "debug")
    mocker.patch("time.sleep")
    responses = [_FakeApiException("rate limited", res=_FakeResponse(status_code=429)), {"ok": True}]
    mocker.patch.object(c, "_http_request", side_effect=responses)

    result = c._http_request_with_rate_limit_retry("GET", "/x")

    assert result == {"ok": True}


def test_test_module_success(mocker):
    c = client()
    mocker.patch.object(c, "test", return_value={"version": "1.0"})
    assert run_test_module(c) == "ok"


# --- commands ---


def test_create_comment_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"addCommentToInvestigation": {"id": "c1"}}})

    result = create_comment_command(c, "https://xdr.example.com", {"comment": "hi", "id": "inv-1"})

    assert result.outputs == {"id": "c1"}
    assert result.outputs_prefix == "TaegisXDR.CommentCreate"


def test_create_comment_command_missing_comment_raises():
    c = client()
    with pytest.raises(ValueError, match="comment cannot be empty"):
        create_comment_command(c, "https://xdr.example.com", {"id": "inv-1"})


def test_create_comment_command_api_error_raises(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"errors": [{"message": "not found"}]})

    with pytest.raises(ValueError, match="not found"):
        create_comment_command(c, "https://xdr.example.com", {"comment": "hi", "id": "inv-1"})


def test_add_evidence_to_investigation_command_success(mocker):
    c = client()
    mocker.patch.object(
        c, "graphql_run", return_value={"data": {"addEvidenceToInvestigation": {"investigationId": "inv-1"}}}
    )

    result = add_evidence_to_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "alerts": "a1"})

    assert result.outputs["url"] == "https://xdr.example.com/investigations/inv-1"


def test_add_evidence_to_investigation_command_requires_evidence():
    c = client()
    with pytest.raises(ValueError, match="alerts, events, or alert_query"):
        add_evidence_to_investigation_command(c, "https://xdr.example.com", {"id": "inv-1"})


def test_isolate_asset_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"isolateAsset": {"id": "asset-1"}}})

    result = isolate_asset_command(c, "https://xdr.example.com", {"id": "asset-1", "reason": "compromised"})

    assert result.outputs == {"id": "asset-1"}


def test_isolate_asset_command_missing_reason_raises():
    c = client()
    with pytest.raises(ValueError, match="missing reason"):
        isolate_asset_command(c, "https://xdr.example.com", {"id": "asset-1"})


def test_update_alert_status_command_rejects_invalid_status():
    c = client()
    with pytest.raises(ValueError, match="not valid for updating an alert"):
        update_alert_status_command(c, "https://xdr.example.com", {"ids": "a1", "status": "NOT_A_REAL_STATUS"})


def test_update_alert_status_command_success(mocker):
    c = client()
    mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"alertsServiceUpdateResolutionInfo": {"resolution_status": "OPEN"}}},
    )

    result = update_alert_status_command(c, "https://xdr.example.com", {"ids": "a1", "status": "OPEN"})

    assert result.outputs == {"resolution_status": "OPEN"}


def test_close_investigation_command_rejects_invalid_status():
    c = client()
    with pytest.raises(ValueError, match="status must be one of"):
        close_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "status": "NOT_REAL"})


def test_close_investigation_command_success_defaults_reason_and_alerts_resolution(mocker):
    c = client()
    graphql_mock = mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"closeInvestigation": {"id": "inv-1", "status": "CLOSED_INCONCLUSIVE"}}},
    )

    result = close_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "status": "CLOSED_INCONCLUSIVE"})

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["input"]["reason"] == "Closed from Cortex XSOAR"
    assert kwargs["variables"]["input"]["alertsResolutionStatus"] == "OTHER"
    assert result.outputs["url"] == "https://xdr.example.com/investigations/inv-1"


def test_close_investigation_command_honors_explicit_alerts_resolution_status(mocker):
    c = client()
    graphql_mock = mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"closeInvestigation": {"id": "inv-1", "status": "CLOSED_INCONCLUSIVE"}}},
    )

    close_investigation_command(
        c,
        "https://xdr.example.com",
        {"id": "inv-1", "status": "CLOSED_INCONCLUSIVE", "alerts_resolution_status": "TRUE_POSITIVE_BENIGN"},
    )

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["input"]["alertsResolutionStatus"] == "TRUE_POSITIVE_BENIGN"


def test_update_investigation_command_requires_at_least_one_field():
    c = client()
    with pytest.raises(ValueError, match="No valid investigation fields"):
        update_investigation_command(c, "https://xdr.example.com", {"id": "inv-1"})


def test_update_investigation_command_rejects_invalid_priority():
    c = client()
    with pytest.raises(ValueError, match="Priority must be between 1-4"):
        update_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "priority": 9})


def test_update_investigation_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"updateInvestigationV2": {"id": "inv-1"}}})

    result = update_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "title": "New title"})

    assert result.outputs["url"] == "https://xdr.example.com/investigations/inv-1"


def test_update_investigation_command_honors_snake_case_key_findings(mocker):
    c = client()
    graphql_mock = mocker.patch.object(
        c, "graphql_run", return_value={"data": {"updateInvestigationV2": {"id": "inv-1"}}}
    )

    update_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "key_findings": "root cause found"})

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["input"]["keyFindings"] == "root cause found"


def test_update_investigation_command_allows_clearing_key_findings_with_empty_string(mocker):
    c = client()
    graphql_mock = mocker.patch.object(
        c, "graphql_run", return_value={"data": {"updateInvestigationV2": {"id": "inv-1"}}}
    )

    update_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "key_findings": ""})

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["input"]["keyFindings"] == ""


def test_update_investigation_command_still_accepts_internal_camelcase_keyfindings(mocker):
    """taegis_push_assignee_status_command / update_remote_system_command build update_args
    with the literal 'keyFindings' key (matching the Taegis GraphQL field name) and call this
    function directly, bypassing the yml arg name entirely - that path must keep working."""
    c = client()
    graphql_mock = mocker.patch.object(
        c, "graphql_run", return_value={"data": {"updateInvestigationV2": {"id": "inv-1"}}}
    )

    update_investigation_command(c, "https://xdr.example.com", {"id": "inv-1", "keyFindings": "from internal caller"})

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["input"]["keyFindings"] == "from internal caller"


def test_taegis_push_assignee_status_command_requires_incident_context(mocker):
    c = client()
    mocker.patch.object(demisto, "incident", return_value=None)
    mocker.patch.object(demisto, "args", return_value={})

    with pytest.raises(ValueError, match="No current incident context"):
        taegis_push_assignee_status_command(c, "https://xdr.example.com")


def test_taegis_push_assignee_status_command_requires_mirror_id(mocker):
    c = client()
    mocker.patch.object(demisto, "incident", return_value={"id": "1"})
    mocker.patch.object(demisto, "args", return_value={"assignee_id": "@secureworks"})

    with pytest.raises(ValueError, match="Investigation ID is required"):
        taegis_push_assignee_status_command(c, "https://xdr.example.com")


def test_taegis_push_assignee_status_command_pushes_explicit_args(mocker):
    c = client()
    mocker.patch.object(demisto, "incident", return_value={"dbotMirrorId": "inv-1"})
    mocker.patch.object(
        demisto, "args", return_value={"id": "inv-1", "assignee_id": "@secureworks", "status": "AWAITING_ACTION"}
    )
    mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"updateInvestigationV2": {"id": "inv-1"}}},
    )

    result = taegis_push_assignee_status_command(c, "https://xdr.example.com")

    assert result.outputs["assigneeId"] == "@secureworks"
    assert result.outputs["status"] == "AWAITING_ACTION"


# --- previously yml-undeclared commands (now wired into TaegisXDRv3.yml) ---


def test_update_comment_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"updateInvestigationComment": {"id": "c1"}}})

    result = update_comment_command(c, "https://xdr.example.com", {"id": "c1", "comment": "edited"})

    assert result.outputs == {"id": "c1"}


def test_update_comment_command_missing_comment_raises():
    c = client()
    with pytest.raises(ValueError, match="comment cannot be empty"):
        update_comment_command(c, "https://xdr.example.com", {"id": "c1"})


def test_create_investigation_command_success(mocker):
    c = client()
    mocker.patch.object(
        c, "graphql_run", return_value={"data": {"createInvestigationV2": {"id": "inv-1"}}}
    )

    result = create_investigation_command(c, "https://xdr.example.com", {"title": "New case"})

    assert result.outputs["url"] == "https://xdr.example.com/investigations/inv-1"


def test_create_investigation_command_requires_title():
    c = client()
    with pytest.raises(ValueError, match="Title must be defined"):
        create_investigation_command(c, "https://xdr.example.com", {})


def test_create_sharelink_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"createShareLink": {"id": "link-1"}}})

    result = create_sharelink_command(c, "https://xdr.example.com", {"id": "inv-1", "type": "investigationId"})

    assert result.outputs["url"] == "https://xdr.example.com/share/link-1"


def test_create_sharelink_command_rejects_invalid_type():
    c = client()
    with pytest.raises(ValueError, match="not valid for creating a ShareLink"):
        create_sharelink_command(c, "https://xdr.example.com", {"id": "inv-1", "type": "not_a_real_type"})


def test_execute_playbook_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"executePlaybookInstance": {"id": "exec-1"}}})

    result = execute_playbook_command(c, "https://xdr.example.com", {"id": "pb-1"})

    assert result.outputs["url"] == "https://xdr.example.com/automations/playbook-executions/exec-1"


def test_execute_playbook_command_requires_id():
    c = client()
    with pytest.raises(ValueError, match="missing playbook_id"):
        execute_playbook_command(c, "https://xdr.example.com", {})


def test_execute_playbook_command_passes_inputs(mocker):
    c = client()
    graphql_mock = mocker.patch.object(
        c, "graphql_run", return_value={"data": {"executePlaybookInstance": {"id": "exec-1"}}}
    )

    execute_playbook_command(c, "https://xdr.example.com", {"id": "pb-1", "inputs": {"key": "value"}})

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["parameters"] == {"key": "value"}


def test_fetch_alerts_command_by_query(mocker):
    c = client()
    mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"alertsServiceSearch": {"alerts": {"list": [{"id": "a1"}]}}}},
    )

    result = fetch_alerts_command(c, "https://xdr.example.com", {})

    assert result.outputs[0]["url"] == "https://xdr.example.com/alerts/a1"


def test_fetch_alerts_command_by_ids(mocker):
    c = client()
    graphql_mock = mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"alertsServiceRetrieveAlertsById": {"alerts": {"list": [{"id": "a1"}]}}}},
    )

    fetch_alerts_command(c, "https://xdr.example.com", {"ids": "alert://a1"})

    _, kwargs = graphql_mock.call_args
    assert kwargs["variables"]["ids"] == ["alert://a1"]


def test_fetch_assets_command_success(mocker):
    c = client()
    mocker.patch.object(
        c, "graphql_run", return_value={"data": {"searchAssetsV2": {"assets": [{"id": "asset-1"}]}}}
    )

    result = fetch_assets_command(c, "https://xdr.example.com", {"hostname": "host1"})

    assert result.outputs == [{"id": "asset-1"}]


def test_fetch_comment_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"comment": {"id": "c1"}}})

    result = fetch_comment_command(c, "https://xdr.example.com", {"id": "c1"})

    assert result.outputs == {"id": "c1"}


def test_fetch_comment_command_requires_id():
    c = client()
    with pytest.raises(ValueError, match="missing comment_id"):
        fetch_comment_command(c, "https://xdr.example.com", {})


def test_fetch_endpoint_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"assetEndpointInfo": {"hostId": "h1"}}})

    result = fetch_endpoint_command(c, "https://xdr.example.com", {"id": "h1"})

    assert result.outputs == {"hostId": "h1"}


def test_fetch_investigation_alerts_command_success(mocker):
    c = client()
    mocker.patch.object(
        c,
        "graphql_run",
        return_value={"data": {"investigationAlerts": {"alerts": [{"id": "a1"}]}}},
    )

    result = fetch_investigation_alerts_command(c, "https://xdr.example.com", {"id": "inv-1"})

    assert result.outputs[0]["url"] == "https://xdr.example.com/alerts/a1"


def test_fetch_investigation_alerts_command_requires_id():
    c = client()
    with pytest.raises(ValueError, match="missing investigation_id"):
        fetch_investigation_alerts_command(c, "https://xdr.example.com", {})


def test_fetch_playbook_execution_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"playbookExecution": {"id": "exec-1"}}})

    result = fetch_playbook_execution_command(c, "https://xdr.example.com", {"id": "exec-1"})

    assert result.outputs["url"] == "https://xdr.example.com/automations/playbook-executions/exec-1"


def test_fetch_users_command_search(mocker):
    c = client()
    mocker.patch.object(
        c, "graphql_run", return_value={"data": {"tdrUsersSearch": {"results": [{"user_id": "u1"}]}}}
    )

    result = fetch_users_command(c, "https://xdr.example.com", {})

    assert result.outputs == [{"user_id": "u1"}]


def test_fetch_users_command_by_id_requires_auth0_prefix():
    c = client()
    with pytest.raises(ValueError, match="auth0"):
        fetch_users_command(c, "https://xdr.example.com", {"id": "not-auth0-format"})


def test_archive_investigation_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"archiveInvestigation": {"id": "inv-1"}}})

    result = archive_investigation_command(c, "https://xdr.example.com", {"id": "inv-1"})

    assert result.outputs["status"] == "Successfully Archived Investigation"


def test_archive_investigation_command_requires_id():
    c = client()
    with pytest.raises(ValueError, match="missing investigation id"):
        archive_investigation_command(c, "https://xdr.example.com", {})


def test_unarchive_investigation_command_success(mocker):
    c = client()
    mocker.patch.object(c, "graphql_run", return_value={"data": {"unArchiveInvestigation": {"id": "inv-1"}}})

    result = unarchive_investigation_command(c, "https://xdr.example.com", {"id": "inv-1"})

    assert result.outputs["status"] == "Successfully Unarchived Investigation"


def test_unarchive_investigation_command_not_currently_archived(mocker):
    c = client()
    mocker.patch.object(
        c, "graphql_run", return_value={"errors": [{"message": "investigation is not archived"}]}
    )

    result = unarchive_investigation_command(c, "https://xdr.example.com", {"id": "inv-1"})

    assert result.outputs["status"] == "Investigation is not currently archived"
