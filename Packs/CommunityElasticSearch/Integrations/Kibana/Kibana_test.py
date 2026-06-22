"""Unit tests for the Kibana integration."""

import base64
import importlib
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType
from unittest.mock import MagicMock

import demistomock as demisto
import pytest

UTC = timezone.utc

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


def test_test_func_failure(kibana, mocker):
    """
    Given: a failed connectivity/auth check.
    When: test_func is called.
    Then: it returns the failure message.
    """
    mocker.patch.object(kibana, "test_connectivity_auth", return_value=(False, "Failed to connect."))
    assert kibana.test_func(proxies=None) == "Failed to connect."
