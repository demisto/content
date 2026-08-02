"""Unit tests for the Kibana integration."""

import base64
import importlib
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType
from unittest.mock import MagicMock

import demistomock as demisto
import pytest

UTC = timezone.utc  # noqa: UP017

DEFAULT_PARAMS = {
    "url": "https://example.com",
    "elastic_port": "9200",
    "kibana_port": "443",
    "auth_type": "Basic auth",
    "credentials": {"identifier": "user", "password": "pass"},
    "api_key_auth_credentials": {"identifier": "key_id", "password": "key_secret"},
    "client_type": "Elasticsearch",
    "insecure": False,
    "timeout": "60",
    "proxy": False,
}


def _stub_elasticsearch_modules():
    """Stub the optional elasticsearch/opensearch clients so the module imports without them installed."""
    for name in ("elasticsearch", "elasticsearch7", "opensearchpy", "elastic_transport"):
        module = ModuleType(name)
        # Provide the symbols imported by Kibana.py at module load time.
        module.Elasticsearch = MagicMock()  # type: ignore[attr-defined]
        module.OpenSearch = MagicMock()  # type: ignore[attr-defined]
        module.RequestsHttpConnection = MagicMock()  # type: ignore[attr-defined]
        module.RequestsHttpNode = object  # type: ignore[attr-defined]
        sys.modules.setdefault(name, module)


@pytest.fixture()
def kibana(mocker):
    """Import the Kibana module with mocked params and stubbed clients."""
    _stub_elasticsearch_modules()
    mocker.patch.object(demisto, "params", return_value=dict(DEFAULT_PARAMS))
    if "Kibana" in sys.modules:
        module = importlib.reload(sys.modules["Kibana"])
    else:
        module = importlib.import_module("Kibana")
    return module


def test_port_fallback_defaults(mocker):
    """
    Given: params without explicit ports.
    When: the module is imported.
    Then: ELASTIC_SERVER/KIBANA_SERVER fall back to 9200/443 (no TypeError).
    """
    _stub_elasticsearch_modules()
    params = dict(DEFAULT_PARAMS)
    params["elastic_port"] = ""
    params["kibana_port"] = ""
    mocker.patch.object(demisto, "params", return_value=params)
    module = importlib.reload(sys.modules["Kibana"]) if "Kibana" in sys.modules else importlib.import_module("Kibana")

    assert module.ELASTIC_SERVER.endswith(":9200")
    assert module.KIBANA_SERVER.endswith(":443")


def test_get_api_key_header_val_with_tuple(kibana):
    """
    Given: an API key as a (id, secret) tuple.
    When: building the ApiKey header value.
    Then: it returns a base64-encoded "ApiKey ..." string.
    """
    result = kibana.get_api_key_header_val(("my_id", "my_secret"))
    expected = "ApiKey " + base64.b64encode(b"my_id:my_secret").decode()
    assert result == expected


def test_get_api_key_header_val_with_string(kibana):
    """
    Given: an API key already encoded as a string.
    When: building the ApiKey header value.
    Then: it is returned as-is with the ApiKey prefix.
    """
    assert kibana.get_api_key_header_val("encoded_key") == "ApiKey encoded_key"


def test_is_access_token_expired_valid(kibana):
    """
    Given: an expiration time well in the future.
    When: checking whether the token is expired.
    Then: it returns False.
    """
    future = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert kibana.is_access_token_expired(future) is False


def test_is_access_token_expired_past(kibana):
    """
    Given: an expiration time in the past.
    When: checking whether the token is expired.
    Then: it returns True.
    """
    past = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert kibana.is_access_token_expired(past) is True


def test_is_access_token_expired_invalid(kibana):
    """
    Given: a malformed expiration string.
    When: checking whether the token is expired.
    Then: it is treated as expired (returns True).
    """
    assert kibana.is_access_token_expired("not-a-date") is True


def test_verify_es_server_version_v8_with_v7_client_raises(kibana):
    """
    Given: an ES v8 server while the configured client is the legacy v7 'Elasticsearch'.
    When: verifying the server version.
    Then: a configuration ValueError is raised.
    """
    with pytest.raises(ValueError, match="Configuration Error"):
        kibana.verify_es_server_version({"version": {"number": "8.4.1"}})


def test_verify_es_server_version_v7_ok(kibana):
    """
    Given: an ES v7 server with the default 'Elasticsearch' client.
    When: verifying the server version.
    Then: no exception is raised.
    """
    kibana.verify_es_server_version({"version": {"number": "7.3.0"}})


def test_kibana_find_cases_uses_arg_to_datetime_and_raw_response(kibana, mocker):
    """
    Given: a from_time argument and a successful API response.
    When: kibana_find_cases is called.
    Then: from_time is normalized to ISO format, and the CommandResults includes outputs and raw_response.
    """
    api_response = {"cases": [{"id": "1", "status": "open"}]}
    http_mock = mocker.patch.object(kibana, "http_request", return_value=api_response)

    result = kibana.kibana_find_cases({"status": "open", "from_time": "2025-10-02T00:00:00Z"}, proxies=None)

    assert result.outputs == api_response["cases"]
    assert result.raw_response == api_response
    assert result.outputs_prefix == "Kibana.Cases"
    # arg_to_datetime should have converted from_time into the API "from" param.
    _, kwargs = http_mock.call_args
    assert kwargs["params"]["from"] is not None


def test_kibana_update_alert_status_returns_command_results(kibana, mocker):
    """
    Given: a successful update call.
    When: kibana_update_alert_status is called.
    Then: it returns a CommandResults (not a plain string) with the expected readable output.
    """
    mocker.patch.object(kibana, "http_request", return_value={})

    result = kibana.kibana_update_alert_status({"alert_id": "a1", "status": "closed"}, proxies=None)

    assert isinstance(result, kibana.CommandResults)
    assert result.readable_output == "Updated alert ID a1 to status of closed"


def test_kibana_delete_case_serializes_ids_as_json(kibana, mocker):
    """
    Given: a case_id to delete.
    When: kibana_delete_case is called.
    Then: the ids query param is a proper JSON-encoded list, and a CommandResults is returned.
    """
    http_mock = mocker.patch.object(kibana, "http_request", return_value={})

    result = kibana.kibana_delete_case({"case_id": "case-123"}, proxies=None)

    _, kwargs = http_mock.call_args
    assert kwargs["params"]["ids"] == '["case-123"]'
    assert isinstance(result, kibana.CommandResults)


def test_kibana_get_user_list_handles_v8_body(kibana, mocker):
    """
    Given: an ES v8 client response exposing a .body attribute.
    When: kibana_get_user_list is called.
    Then: the users are read from .body and returned in CommandResults.
    """
    es_response = MagicMock()
    es_response.body = {"users": [{"username": "alice"}]}
    es = MagicMock()
    es.security.query_user.return_value = es_response
    mocker.patch.object(kibana, "elasticsearch_builder", return_value=es)

    result = kibana.kibana_get_user_list({}, proxies=None)

    assert result.outputs == [{"username": "alice"}]


def test_kibana_get_user_list_handles_v7_dict(kibana, mocker):
    """
    Given: an ES v7/OpenSearch client returning a plain dict (no .body).
    When: kibana_get_user_list is called.
    Then: the users are read directly from the dict (no AttributeError).
    """
    es = MagicMock()
    es.security.query_user.return_value = {"users": [{"username": "bob"}]}
    mocker.patch.object(kibana, "elasticsearch_builder", return_value=es)

    result = kibana.kibana_get_user_list({}, proxies=None)

    assert result.outputs == [{"username": "bob"}]


def test_test_func_success(kibana, mocker):
    """
    Given: a successful connectivity/auth check.
    When: test_func is called.
    Then: it returns "ok".
    """
    mocker.patch.object(kibana, "test_connectivity_auth", return_value=(True, "Connectivity test successful"))
    assert kibana.test_func(proxies=None) == "ok"


def test_http_request_returns_json_on_success(kibana, mocker):
    """
    Given: a server responding 200 with a JSON body.
    When: http_request is called with parse_json=True (default).
    Then: the parsed JSON is returned.
    """
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"ok": True}
    mocker.patch.object(kibana.requests, "request", return_value=response)

    result = kibana.http_request(method="GET", url_suffix="/api/status", headers={})

    assert result == {"ok": True}


def test_http_request_returns_none_on_204(kibana, mocker):
    """
    Given: a server responding 204 No Content.
    When: http_request is called.
    Then: None is returned (no JSON parsing attempted).
    """
    response = MagicMock()
    response.status_code = 204
    mocker.patch.object(kibana.requests, "request", return_value=response)

    assert kibana.http_request(method="DELETE", url_suffix="/api/lists", headers={}) is None


def test_http_request_calls_return_error_on_failure(kibana, mocker):
    """
    Given: a server responding 500 with a JSON error body.
    When: http_request is called.
    Then: return_error is invoked with the status code and reason.
    """
    response = MagicMock()
    response.status_code = 500
    response.json.return_value = {"message": "boom"}
    mocker.patch.object(kibana.requests, "request", return_value=response)
    return_error_mock = mocker.patch.object(kibana, "return_error")

    kibana.http_request(method="GET", url_suffix="/api/status", headers={})

    return_error_mock.assert_called_once()
    assert "500" in return_error_mock.call_args[0][0]


def test_test_connectivity_auth_basic_success(kibana, mocker):
    """
    Given: Basic auth configured and a healthy v7 server.
    When: test_connectivity_auth is called.
    Then: it returns (True, "Connectivity test successful").
    """
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"version": {"number": "7.10.0"}}
    mocker.patch.object(kibana, "AUTH_TYPE", kibana.BASIC_AUTH)
    mocker.patch.object(kibana.requests, "get", return_value=response)

    success, message = kibana.test_connectivity_auth(proxies=None)

    assert success is True
    assert message == "Connectivity test successful"


def test_test_connectivity_auth_failure_status(kibana, mocker):
    """
    Given: Basic auth configured and a server returning 403.
    When: test_connectivity_auth is called.
    Then: it returns (False, message) describing the failure.
    """
    response = MagicMock()
    response.status_code = 403
    response.reason = "Forbidden"
    mocker.patch.object(kibana, "AUTH_TYPE", kibana.BASIC_AUTH)
    mocker.patch.object(kibana.requests, "get", return_value=response)

    success, message = kibana.test_connectivity_auth(proxies=None)

    assert success is False
    assert "Failed to connect" in message


def test_test_func_failure(kibana, mocker):
    """
    Given: a failed connectivity/auth check.
    When: test_func is called.
    Then: it returns the failure message.
    """
    mocker.patch.object(kibana, "test_connectivity_auth", return_value=(False, "Failed to connect."))
    assert kibana.test_func(proxies=None) == "Failed to connect."


# Command functions that wrap http_request and return a CommandResults with a fixed readable_output.
# Each entry: (function_name, args, http_response, expected_readable_output)
SIMPLE_WRITE_COMMANDS = [
    ("kibana_assign_alert_user", {"alert_id": "a1", "user_id": "u1"}, {}, "Assigned user ID u1 to alert a1"),
    ("kibana_add_alert_note", {"alert_id": "e1", "note": "hello"}, {}, "Added note hello to alert e1"),
    ("kibana_delete_rule", {"rule_id": "r1"}, {}, "Successfully deleted rule with ID of r1"),
    ("kibana_disable_alert_rule", {"rule_id": "r1"}, {}, "Successfully disabled rule with ID of r1"),
    ("kibana_enable_alert_rule", {"rule_id": "r1"}, {}, "Successfully enabled rule with ID of r1"),
    (
        "kibana_create_value_list",
        {"description": "d", "list_id": "l1", "name": "n1", "data_type": "keyword"},
        {},
        "Successfully created value list with name of n1",
    ),
    (
        "kibana_create_value_list_item",
        {"list_id": "l1", "new_value_list_item": "v1"},
        {},
        "Successfully added v1 to value list with ID of l1",
    ),
    (
        "kibana_import_value_list_items",
        {"list_id": "l1", "file_content": "c1"},
        {},
        "Successfully imported c1 to value list with ID of l1",
    ),
    (
        "kibana_delete_value_list_item",
        {"item_id": "i1", "list_id": "l1"},
        {},
        "Successfully deleted i1 from value list with ID of l1",
    ),
    ("kibana_delete_value_list", {"list_id": "l1"}, {}, "Successfully deleted value list with ID of l1"),
    (
        "kibana_delete_case_comment",
        {"case_id": "c1", "comment_id": "cm1"},
        {},
        "Deleted comment with ID cm1 from case c1",
    ),
    (
        "kibana_add_case_comment",
        {"case_id": "c1", "case_owner": "o", "comment": "txt"},
        {"updated_at": "2025-01-01"},
        "Case comment updated at 2025-01-01",
    ),
]


@pytest.mark.parametrize("func_name, args, response, expected", SIMPLE_WRITE_COMMANDS)
def test_simple_write_commands(kibana, mocker, func_name, args, response, expected):
    """
    Given: a write-style command and a successful API response.
    When: the command function is called.
    Then: it returns a CommandResults with the expected human-readable output.
    """
    mocker.patch.object(kibana, "http_request", return_value=response)

    result = getattr(kibana, func_name)(args, proxies=None)

    assert isinstance(result, kibana.CommandResults)
    assert result.readable_output == expected


# Command functions that wrap http_request and surface (a slice of) the response as outputs.
# Each entry: (function_name, args, http_response, expected_outputs, outputs_prefix)
READ_COMMANDS = [
    (
        "kibana_find_alerts_for_case",
        {"case_id": "c1"},
        {"alerts": [{"id": "x"}]},
        {"alerts": [{"id": "x"}]},
        "Kibana.Alerts.For.Case",
    ),
    (
        "kibana_update_case_status",
        {"case_id": "c1", "status": "closed", "version_id": "v1"},
        [{"id": "c1", "status": "closed"}],
        [{"id": "c1", "status": "closed"}],
        "Kibana.Updated.Case.Status",
    ),
    (
        "kibana_find_user_spaces",
        {},
        [{"id": "default"}],
        [{"id": "default"}],
        "Kibana.User.Spaces",
    ),
    (
        "kibana_find_case_comments",
        {"case_id": "c1"},
        {"comments": [{"id": "cm1"}]},
        [{"id": "cm1"}],
        "Kibana.Case.Comments",
    ),
    (
        "kibana_search_rule_details",
        {"kql_query": "name:*"},
        {"data": [{"id": "r1"}]},
        [{"id": "r1"}],
        "Kibana.Rule.Details",
    ),
    (
        "kibana_get_alerting_health",
        {},
        {"status": "ok"},
        {"status": "ok"},
        "Alerting.Framework.Health",
    ),
    (
        "kibana_get_exception_lists",
        {},
        {"data": [{"id": "el1"}]},
        [{"id": "el1"}],
        "Kibana.Exception.Lists",
    ),
    (
        "kibana_get_value_lists",
        {},
        {"data": [{"id": "vl1"}]},
        [{"id": "vl1"}],
        "Alerting.Value.Lists",
    ),
    (
        "kibana_get_value_list_items",
        {"list_id": "l1", "result_size": "10"},
        {"data": [{"value": "v1"}]},
        [{"value": "v1"}],
        "Value.List.Items",
    ),
    (
        "kibana_get_status",
        {},
        {"status": {"overall": {"level": "available"}}},
        {"overall": {"level": "available"}},
        "Kibana.Operational.Status",
    ),
    (
        "kibana_get_task_manager_health",
        {},
        {"stats": {"runtime": {}}},
        {"runtime": {}},
        "Kibana.Task.Manager.Health",
    ),
    (
        "kibana_get_upgrade_readiness_status",
        {},
        {"readyForUpgrade": True},
        {"readyForUpgrade": True},
        "Kibana.Upgrade.Readiness.Status",
    ),
    (
        "kibana_get_case_information",
        {"case_id": "c1"},
        {"id": "c1", "title": "t"},
        {"id": "c1", "title": "t"},
        "Kibana.Case.Info",
    ),
]


@pytest.mark.parametrize("func_name, args, response, expected_outputs, prefix", READ_COMMANDS)
def test_read_commands(kibana, mocker, func_name, args, response, expected_outputs, prefix):
    """
    Given: a read-style command and a successful API response.
    When: the command function is called.
    Then: it returns a CommandResults with the expected outputs and outputs_prefix.
    """
    mocker.patch.object(kibana, "http_request", return_value=response)

    result = getattr(kibana, func_name)(args, proxies=None)

    assert isinstance(result, kibana.CommandResults)
    assert result.outputs == expected_outputs
    assert result.outputs_prefix == prefix


def test_kibana_list_detection_alerts_flattens_sources(kibana, mocker):
    """
    Given: a detection alerts search response with nested hits.
    When: kibana_list_detection_alerts is called.
    Then: each hit's _source is flattened into the outputs list.
    """
    response = {"hits": {"hits": [{"_source": {"id": "1"}}, {"_source": {"id": "2"}}]}}
    mocker.patch.object(kibana, "http_request", return_value=response)

    result = kibana.kibana_list_detection_alerts({"alert_status": "open"}, proxies=None)

    assert result.outputs == [{"id": "1"}, {"id": "2"}]
    assert result.outputs_prefix == "Kibana.Detection.Alerts"


def test_kibana_get_user_by_email_returns_users(kibana, mocker):
    """
    Given: an email wildcard and an ES client returning matching users.
    When: kibana_get_user_by_email is called.
    Then: the users list is returned in CommandResults.
    """
    es = MagicMock()
    es.security.query_user.return_value = {"users": [{"username": "carol"}]}
    mocker.patch.object(kibana, "elasticsearch_builder", return_value=es)

    result = kibana.kibana_get_user_by_email({"email_wildcard": "carol@*"}, proxies=None)

    assert result.outputs == [{"username": "carol"}]
    assert result.outputs_prefix == "Kibana.User.Data"


def test_kibana_add_file_to_case_uploads_and_reports(kibana, mocker, tmp_path):
    """
    Given: a file registered in the war room and a successful upload.
    When: kibana_add_file_to_case is called.
    Then: it uploads the file and returns a success message including the file name.
    """
    file_path = tmp_path / "evidence.txt"
    file_path.write_text("data")
    mocker.patch.object(kibana.demisto, "getFilePath", return_value={"path": str(file_path), "name": "evidence.txt"})
    http_mock = mocker.patch.object(kibana, "http_request", return_value={})

    result = kibana.kibana_add_file_to_case({"case_id": "c1", "file_id": "f1"}, proxies=None)

    assert result == "Successfully added file evidence.txt to case c1"
    _, kwargs = http_mock.call_args
    assert kwargs["url_suffix"] == "/api/cases/c1/files"
