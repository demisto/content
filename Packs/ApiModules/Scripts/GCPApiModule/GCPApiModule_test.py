import json
from unittest.mock import MagicMock

import pytest
from COOCApiModule import CloudIntegration, CloudTypes, ErrorType
from CommonServerPython import DemistoException
from GCPApiModule import GCPIntegration, GCPServices
from googleapiclient.errors import HttpError

SERVICE_ACCOUNT_JSON = json.dumps({"type": "service_account", "project_id": "sa-project"})


def build_integration(
    mocker,
    command: str = "gcp-compute-instances-list",
    args: dict | None = None,
    params: dict | None = None,
    connector_id: str | None = None,
) -> GCPIntegration:
    """Build a ``GCPIntegration`` with ``get_connector_id`` patched to return ``connector_id``."""
    mocker.patch("COOCApiModule.get_connector_id", return_value=connector_id)
    return GCPIntegration(command, args if args is not None else {}, params if params is not None else {})


def build_http_error(status: int, content: bytes | str = b"", content_type: str = "application/json") -> HttpError:
    """Build an ``HttpError`` with ``status``, ``content`` and the content-type header."""
    resp = MagicMock()
    resp.status = status
    resp.get.side_effect = lambda key, default=None: content_type if key == "content-type" else default
    resp.reason = "error"
    return HttpError(resp, content if isinstance(content, bytes) else content.encode())


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_init_resolves_project_id_as_account_id(mocker):
    """
    Given: A project_id argument.
    When: GCPIntegration is created.
    Then: account_id is the project_id, and the cloud type is GCP.
    """
    integration = build_integration(mocker, args={"project_id": "p1"})

    assert integration.account_id == "p1"
    assert integration.cloud_type == CloudTypes.GCP.value


def test_init_prioritizes_identifier_over_project_id(mocker):
    """
    Given: Both identifier and project_id arguments (e.g. gcp-resource-manager-project-create).
    When: GCPIntegration is created.
    Then: account_id is the identifier, which is used to create the CTS token.
    """
    integration = build_integration(mocker, args={"identifier": "folders/1", "project_id": "p1"})

    assert integration.account_id == "folders/1"


def test_cloud_type_class_attribute():
    """
    Given: The GCPIntegration class.
    When: Reading its class attributes.
    Then: cloud_type is GCP and account_id_arg is project_id.
    """
    assert GCPIntegration.cloud_type == CloudTypes.GCP.value
    assert GCPIntegration.account_id_arg == "project_id"


# ---------------------------------------------------------------------------
# _resolve_service
# ---------------------------------------------------------------------------


def test_resolve_service_by_member_name():
    """
    Given: A command whose second word is a GCPServices member name.
    When: _resolve_service is called.
    Then: The matching service is returned.
    """
    assert GCPIntegration._resolve_service("gcp-compute-instances-list") == GCPServices.COMPUTE


def test_resolve_service_by_prefix_map():
    """
    Given: A command whose second word is mapped in SERVICE_PREFIX_MAP.
    When: _resolve_service is called.
    Then: The mapped service is returned.
    """
    assert GCPIntegration._resolve_service("gcp-gke-cluster-get") == GCPServices.CONTAINER


def test_resolve_service_cloudfunctions_uses_v1():
    """
    Given: A gcp-cloudfunctions-* command.
    When: _resolve_service is called.
    Then: The v1 Cloud Functions service is returned.
    """
    assert GCPIntegration._resolve_service("gcp-cloudfunctions-function-execute") == GCPServices.CLOUD_FUNCTIONS_V1


def test_resolve_service_unknown_command_raises():
    """
    Given: A command with an unknown service word.
    When: _resolve_service is called.
    Then: A DemistoException naming the command is raised.
    """
    with pytest.raises(DemistoException, match="gcp-unknown-thing"):
        GCPIntegration._resolve_service("gcp-unknown-thing")


def test_resolve_service_command_without_dash_raises():
    """
    Given: A command without a dash.
    When: _resolve_service is called.
    Then: A DemistoException is raised.
    """
    with pytest.raises(DemistoException, match="Could not resolve"):
        GCPIntegration._resolve_service("gcp")


# ---------------------------------------------------------------------------
# execute_mapped_command / get_client
# ---------------------------------------------------------------------------


def test_execute_mapped_command_regular_command_passes_creds_first(mocker):
    """
    Given: A regular command.
    When: execute_mapped_command is called.
    Then: The handler is called with (creds, args).
    """
    integration = build_integration(mocker, args={"project_id": "p1"})
    creds = MagicMock()
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=creds)
    handler = MagicMock(return_value="result")

    assert integration.execute_mapped_command(handler) == "result"
    handler.assert_called_once_with(creds, {"project_id": "p1"})


def test_execute_mapped_command_polling_command_passes_args_first(mocker):
    """
    Given: A polling command.
    When: execute_mapped_command is called.
    Then: The handler is called with (args, creds).
    """
    integration = build_integration(mocker, command="gcp-compute-zone-operation-wait", args={"project_id": "p1"})
    creds = MagicMock()
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=creds)
    handler = MagicMock(return_value="result")

    assert integration.execute_mapped_command(handler) == "result"
    handler.assert_called_once_with({"project_id": "p1"}, creds)


def test_get_client_builds_client_for_command_service(mocker):
    """
    Given: A storage command.
    When: get_client is called.
    Then: The service client is built for the storage service with the Google credentials.
    """
    integration = build_integration(mocker, command="gcp-storage-bucket-list")
    creds = MagicMock()
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=creds)
    get_service_client = mocker.patch.object(GCPIntegration, "get_service_client", return_value="client")

    assert integration.get_client() == "client"
    get_service_client.assert_called_once_with(creds, GCPServices.STORAGE)


# ---------------------------------------------------------------------------
# build_service_client
# ---------------------------------------------------------------------------


def test_build_service_client_platform_path_uses_credentials(mocker):
    """
    Given: The Cortex Platform path.
    When: build_service_client is called.
    Then: The Google client is built with the credentials and no custom HTTP transport.
    """
    build = mocker.patch("GCPApiModule.build", return_value="client")
    build_http = mocker.patch.object(GCPIntegration, "_build_http_client")
    creds = MagicMock()

    assert GCPIntegration.build_service_client(GCPServices.COMPUTE, creds, is_platform_path=True, params={}) == "client"
    build.assert_called_once_with("compute", "v1", credentials=creds)
    build_http.assert_not_called()


def test_build_service_client_marketplace_path_uses_authorized_http(mocker):
    """
    Given: The marketplace path with the proxy and insecure parameters.
    When: build_service_client is called.
    Then: The HTTP transport honors the parameters, and the client is built over AuthorizedHttp.
    """
    build = mocker.patch("GCPApiModule.build", return_value="client")
    build_http = mocker.patch.object(GCPIntegration, "_build_http_client", return_value="http")
    authorized_http = mocker.patch("GCPApiModule.AuthorizedHttp", return_value="authorized")
    creds = MagicMock()

    result = GCPIntegration.build_service_client(
        GCPServices.STORAGE, creds, is_platform_path=False, params={"proxy": True, "insecure": True}
    )

    assert result == "client"
    build_http.assert_called_once_with(use_proxy=True, verify_ssl=False)
    authorized_http.assert_called_once_with(creds, http="http")
    build.assert_called_once_with("storage", "v1", http="authorized")


def test_get_service_client_uses_connector_to_select_path(mocker):
    """
    Given: An integration with a connector ID.
    When: get_service_client is called.
    Then: build_service_client is called with is_platform_path=True.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    build_service_client = mocker.patch.object(GCPIntegration, "build_service_client", return_value="client")
    creds = MagicMock()

    assert integration.get_service_client(creds, GCPServices.KMS) == "client"
    build_service_client.assert_called_once_with(GCPServices.KMS, creds, is_platform_path=True, params={})


# ---------------------------------------------------------------------------
# _get_google_credentials
# ---------------------------------------------------------------------------


def test_get_google_credentials_invalid_json_raises(mocker):
    """
    Given: A credentials parameter that is not valid JSON.
    When: _get_google_credentials is called.
    Then: A DemistoException about the JSON format is raised.
    """
    integration = build_integration(mocker, params={"credentials": {"password": "not json"}})

    with pytest.raises(DemistoException, match="Invalid Service Account JSON format"):
        integration._get_google_credentials()


def test_get_google_credentials_service_account_build_failure_raises(mocker):
    """
    Given: A service account JSON that Google cannot build credentials from.
    When: _get_google_credentials is called.
    Then: A DemistoException with the failure is raised.
    """
    integration = build_integration(mocker, params={"credentials": {"password": SERVICE_ACCOUNT_JSON}})
    mocker.patch("GCPApiModule.google_service_account.Credentials.from_service_account_info", side_effect=ValueError("bad key"))

    with pytest.raises(DemistoException, match="bad key"):
        integration._get_google_credentials()


def test_get_google_credentials_service_account_keeps_project_id_argument(mocker):
    """
    Given: A service account JSON, a project_id parameter and a project_id argument.
    When: _get_google_credentials is called.
    Then: The project_id argument is kept and used as the account_id.
    """
    integration = build_integration(
        mocker,
        args={"project_id": "arg-project"},
        params={"credentials": {"password": SERVICE_ACCOUNT_JSON}, "project_id": "param-project"},
    )
    creds = MagicMock()
    mocker.patch("GCPApiModule.google_service_account.Credentials.from_service_account_info", return_value=creds)

    assert integration._get_google_credentials() == creds
    assert integration.args["project_id"] == "arg-project"
    assert integration.account_id == "arg-project"


def test_get_google_credentials_service_account_uses_project_id_parameter(mocker):
    """
    Given: A service account JSON and a project_id parameter, without a project_id argument.
    When: _get_google_credentials is called.
    Then: The project_id parameter is propagated to the args and used as the account_id.
    """
    integration = build_integration(
        mocker, params={"credentials": {"password": SERVICE_ACCOUNT_JSON}, "project_id": "param-project"}
    )
    mocker.patch("GCPApiModule.google_service_account.Credentials.from_service_account_info", return_value=MagicMock())

    integration._get_google_credentials()

    assert integration.args["project_id"] == "param-project"
    assert integration.account_id == "param-project"


def test_get_google_credentials_service_account_falls_back_to_json_project_id(mocker):
    """
    Given: A service account JSON with a project_id, without a project_id argument or parameter.
    When: _get_google_credentials is called.
    Then: The project_id of the service account JSON is used.
    """
    integration = build_integration(mocker, params={"credentials": {"password": SERVICE_ACCOUNT_JSON}})
    mocker.patch("GCPApiModule.google_service_account.Credentials.from_service_account_info", return_value=MagicMock())

    integration._get_google_credentials()

    assert integration.args["project_id"] == "sa-project"
    assert integration.account_id == "sa-project"


def test_get_google_credentials_service_account_keeps_identifier_as_account_id(mocker):
    """
    Given: A service account JSON, a project_id parameter and an identifier argument (global command).
    When: _get_google_credentials is called.
    Then: project_id is propagated to the args, but the identifier stays the account_id.
    """
    integration = build_integration(
        mocker,
        args={"identifier": "organizations/1"},
        params={"credentials": {"password": SERVICE_ACCOUNT_JSON}, "project_id": "param-project"},
    )
    mocker.patch("GCPApiModule.google_service_account.Credentials.from_service_account_info", return_value=MagicMock())

    integration._get_google_credentials()

    assert integration.args["project_id"] == "param-project"
    assert integration.account_id == "organizations/1"


def test_get_google_credentials_service_account_without_any_project_id_raises(mocker):
    """
    Given: A service account JSON without a project_id, and no project_id argument or parameter.
    When: _get_google_credentials is called.
    Then: A DemistoException about the missing project_id is raised.
    """
    integration = build_integration(mocker, params={"credentials": {"password": json.dumps({"type": "service_account"})}})
    mocker.patch("GCPApiModule.google_service_account.Credentials.from_service_account_info", return_value=MagicMock())

    with pytest.raises(DemistoException, match="Missing required parameter 'project_id'"):
        integration._get_google_credentials()


def test_get_google_credentials_cts_without_account_raises(mocker):
    """
    Given: The Cortex Platform path without a project_id or identifier.
    When: _get_google_credentials is called.
    Then: A DemistoException about the missing parameter is raised before CTS is called.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    get_credentials = mocker.patch.object(GCPIntegration, "get_credentials")

    with pytest.raises(DemistoException, match="Provide 'project_id'"):
        integration._get_google_credentials()
    get_credentials.assert_not_called()


def test_get_google_credentials_cts_failure_raises(mocker):
    """
    Given: The Cortex Platform path where the CTS call fails.
    When: _get_google_credentials is called.
    Then: A DemistoException wrapping the failure is raised.
    """
    integration = build_integration(mocker, args={"project_id": "p1"}, connector_id="connector-1")
    mocker.patch.object(GCPIntegration, "get_credentials", side_effect=Exception("cts down"))

    with pytest.raises(DemistoException, match="Failed to authenticate with GCP via CTS: cts down"):
        integration._get_google_credentials()


def test_get_google_credentials_cts_without_token_raises(mocker):
    """
    Given: The Cortex Platform path where the CTS credentials have no access token.
    When: _get_google_credentials is called.
    Then: A DemistoException about the missing token is raised.
    """
    integration = build_integration(mocker, args={"project_id": "p1"}, connector_id="connector-1")
    mocker.patch.object(GCPIntegration, "get_credentials", return_value={})

    with pytest.raises(DemistoException, match="token is missing from CTS credentials"):
        integration._get_google_credentials()


def test_get_google_credentials_cts_returns_token_credentials(mocker):
    """
    Given: The Cortex Platform path with a CTS access token.
    When: _get_google_credentials is called.
    Then: Google credentials with the token are returned.
    """
    integration = build_integration(mocker, args={"project_id": "p1"}, connector_id="connector-1")
    mocker.patch.object(GCPIntegration, "get_credentials", return_value={"access_token": "token"})

    creds = integration._get_google_credentials()

    assert creds.token == "token"


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


def test_health_check_without_token_returns_connectivity_error(mocker):
    """
    Given: Credentials without an access token.
    When: health_check is called.
    Then: A connectivity HealthCheckError is returned.
    """
    integration = build_integration(mocker, connector_id="connector-1")

    error = integration.health_check({}, "p1", "connector-1")

    assert not isinstance(error, list)
    assert error is not None
    assert error.error_type == ErrorType.CONNECTIVITY_ERROR


def test_health_check_all_services_succeed_returns_none(mocker):
    """
    Given: A token and every service probe succeeding.
    When: health_check is called.
    Then: None is returned and every GCP service is probed.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    probe = mocker.patch.object(GCPIntegration, "_test_service_connectivity")

    assert integration.health_check({"access_token": "token"}, "p1", "connector-1") is None
    assert probe.call_count == len(GCPServices)


def test_health_check_ignores_permission_errors(mocker):
    """
    Given: A probe that fails with a permission error.
    When: health_check is called.
    Then: The permission error is not reported and None is returned.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "_test_service_connectivity", side_effect=Exception("Permission denied"))

    assert integration.health_check({"access_token": "token"}, "p1", "connector-1") is None


def test_health_check_returns_one_error_per_failed_service(mocker):
    """
    Given: Two services whose probes fail with non-permission errors.
    When: health_check is called.
    Then: A list with one connectivity HealthCheckError per failed service is returned.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())

    def probe(api, service, account_id):
        if service in (GCPServices.KMS, GCPServices.LOGGING):
            raise Exception(f"{service.api_name} unreachable")

    mocker.patch.object(GCPIntegration, "_test_service_connectivity", side_effect=probe)

    errors = integration.health_check({"access_token": "token"}, "p1", "connector-1")

    assert isinstance(errors, list)
    assert len(errors) == 2
    assert all(error.error_type == ErrorType.CONNECTIVITY_ERROR for error in errors)
    assert "cloudkms unreachable" in errors[0].message


# ---------------------------------------------------------------------------
# test_module
# ---------------------------------------------------------------------------


def test_test_module_returns_ok_on_first_reachable_service(mocker):
    """
    Given: A Resource Manager probe that succeeds.
    When: test_module is called.
    Then: "ok" is returned after probing only Resource Manager.
    """
    integration = build_integration(mocker, params={"project_id": "p1"})
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    probe = mocker.patch.object(GCPIntegration, "_test_service_connectivity")

    assert integration.test_module() == "ok"
    probe.assert_called_once()
    assert probe.call_args.args[1] == GCPServices.RESOURCE_MANAGER


def test_test_module_skips_disabled_service(mocker):
    """
    Given: A Resource Manager probe that fails with SERVICE_DISABLED, and a Compute probe that succeeds.
    When: test_module is called.
    Then: The disabled service is skipped and "ok" is returned.
    """
    integration = build_integration(mocker, params={"project_id": "p1"})
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    disabled = build_http_error(403, b'{"error": {"status": "SERVICE_DISABLED"}}')
    probe = mocker.patch.object(GCPIntegration, "_test_service_connectivity", side_effect=[disabled, None])

    assert integration.test_module() == "ok"
    assert probe.call_args.args[1] == GCPServices.COMPUTE


def test_test_module_raises_on_real_failure(mocker):
    """
    Given: A Resource Manager probe that fails with an error other than SERVICE_DISABLED.
    When: test_module is called.
    Then: A DemistoException with the project and the failure is raised.
    """
    integration = build_integration(mocker, params={"project_id": "p1"})
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "_test_service_connectivity", side_effect=Exception("invalid grant"))

    with pytest.raises(DemistoException, match="Failed to connect to GCP project 'p1': invalid grant"):
        integration.test_module()


def test_test_module_raises_when_all_services_disabled(mocker):
    """
    Given: Every service probe failing with SERVICE_DISABLED.
    When: test_module is called.
    Then: A DemistoException saying that all probed APIs are disabled is raised.
    """
    integration = build_integration(mocker, params={"project_id": "p1"})
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    disabled = build_http_error(403, b"API has not been used in project p1")
    mocker.patch.object(GCPIntegration, "_test_service_connectivity", side_effect=disabled)

    with pytest.raises(DemistoException, match="all probed GCP service APIs are disabled"):
        integration.test_module()


# ---------------------------------------------------------------------------
# handle_error / handle_permission_error
# ---------------------------------------------------------------------------


def test_handle_error_http_error_uses_permission_flow(mocker):
    """
    Given: An HttpError.
    When: handle_error is called.
    Then: handle_permission_error is called with the account_id and the command.
    """
    integration = build_integration(mocker, command="gcp-compute-instances-list", args={"project_id": "p1"})
    permission_error = mocker.patch.object(GCPIntegration, "handle_permission_error")
    base_handle_error = mocker.patch.object(CloudIntegration, "handle_error")
    error = build_http_error(403)

    integration.handle_error(error)

    permission_error.assert_called_once_with(error, "p1", "gcp-compute-instances-list")
    base_handle_error.assert_not_called()


def test_handle_error_http_error_without_account_uses_na(mocker):
    """
    Given: An HttpError and no account_id.
    When: handle_error is called.
    Then: handle_permission_error is called with "N/A" as the account.
    """
    integration = build_integration(mocker, command="gcp-compute-instances-list")
    permission_error = mocker.patch.object(GCPIntegration, "handle_permission_error")
    error = build_http_error(403)

    integration.handle_error(error)

    permission_error.assert_called_once_with(error, "N/A", "gcp-compute-instances-list")


def test_handle_error_other_error_uses_base_class(mocker):
    """
    Given: An error that is not an HttpError.
    When: handle_error is called.
    Then: The base class handles the error.
    """
    integration = build_integration(mocker)
    permission_error = mocker.patch.object(GCPIntegration, "handle_permission_error")
    base_handle_error = mocker.patch.object(CloudIntegration, "handle_error")
    error = ValueError("boom")

    integration.handle_error(error)

    base_handle_error.assert_called_once_with(error)
    permission_error.assert_not_called()


def test_handle_permission_error_reports_matching_permission(mocker):
    """
    Given: A 403 JSON error that names a permission of the command.
    When: handle_permission_error is called.
    Then: The matching permission is reported through return_multiple_permissions_error.
    """
    report = mocker.patch("GCPApiModule.return_multiple_permissions_error")
    content = json.dumps({"error": {"message": "Required 'compute.instances.list' permission"}}).encode()

    GCPIntegration.handle_permission_error(build_http_error(403, content), "p1", "gcp-compute-instances-list")

    entries = report.call_args.args[0]
    assert entries == [
        {"account_id": "p1", "message": "Required 'compute.instances.list' permission", "name": "compute.instances.list"}
    ]


def test_handle_permission_error_without_matching_permission_reports_na(mocker):
    """
    Given: A 401 JSON error that names no permission of the command.
    When: handle_permission_error is called.
    Then: A permission error entry named "N/A" is reported.
    """
    report = mocker.patch("GCPApiModule.return_multiple_permissions_error")
    content = json.dumps({"error": {"message": "Request had invalid credentials"}}).encode()

    GCPIntegration.handle_permission_error(build_http_error(401, content), "p1", "gcp-compute-instances-list")

    assert report.call_args.args[0][0]["name"] == "N/A"


def test_handle_permission_error_unknown_command_reports_na(mocker):
    """
    Given: A 403 JSON error for a command that is not in COMMAND_REQUIREMENTS.
    When: handle_permission_error is called.
    Then: No KeyError is raised and one permission error entry named "N/A" is reported.
    """
    report = mocker.patch("GCPApiModule.return_multiple_permissions_error")
    content = json.dumps({"error": {"message": "Required 'compute.instances.list' permission"}}).encode()

    GCPIntegration.handle_permission_error(build_http_error(403, content), "p1", "gcp-not-a-real-command")

    assert report.call_args.args[0] == [
        {"account_id": "p1", "message": "Required 'compute.instances.list' permission", "name": "N/A"}
    ]


def test_handle_permission_error_non_permission_status_uses_command_name(mocker):
    """
    Given: A 500 error and a command name.
    When: handle_permission_error is called.
    Then: The returned error names the command that was passed in.
    """
    mocker.patch("GCPApiModule.return_multiple_permissions_error")
    return_error = mocker.patch("GCPApiModule.return_error")

    GCPIntegration.handle_permission_error(build_http_error(500, b"server error"), "p1", "gcp-storage-bucket-list")

    assert return_error.call_args.args[0].startswith("Failed to execute command gcp-storage-bucket-list. Error:")


def test_handle_permission_error_non_permission_status_returns_error(mocker):
    """
    Given: A 500 error.
    When: handle_permission_error is called.
    Then: return_error is called with the original error, and no permission error is reported.
    """
    report = mocker.patch("GCPApiModule.return_multiple_permissions_error")
    return_error = mocker.patch("GCPApiModule.return_error")

    GCPIntegration.handle_permission_error(build_http_error(500, b"server error"), "p1", "gcp-compute-instances-list")

    return_error.assert_called_once()
    report.assert_not_called()


def test_handle_permission_error_non_json_403_returns_error(mocker):
    """
    Given: A 403 error without a JSON body.
    When: handle_permission_error is called.
    Then: return_error is called, and no permission error is reported.
    """
    report = mocker.patch("GCPApiModule.return_multiple_permissions_error")
    return_error = mocker.patch("GCPApiModule.return_error")

    GCPIntegration.handle_permission_error(
        build_http_error(403, b"<html>forbidden</html>", content_type="text/html"), "p1", "gcp-compute-instances-list"
    )

    return_error.assert_called_once()
    report.assert_not_called()


# ---------------------------------------------------------------------------
# _is_service_disabled_error / _get_configured_project_id
# ---------------------------------------------------------------------------


def test_is_service_disabled_error_service_disabled_status():
    """
    Given: A 403 error whose body contains SERVICE_DISABLED.
    When: _is_service_disabled_error is called.
    Then: It returns True.
    """
    assert GCPIntegration._is_service_disabled_error(build_http_error(403, b'{"status": "SERVICE_DISABLED"}')) is True


def test_is_service_disabled_error_not_used_in_project_message():
    """
    Given: A 403 error whose body says the API has not been used in the project.
    When: _is_service_disabled_error is called.
    Then: It returns True.
    """
    assert GCPIntegration._is_service_disabled_error(build_http_error(403, b"API has not been used in project 123")) is True


def test_is_service_disabled_error_other_403():
    """
    Given: A 403 error for a missing permission.
    When: _is_service_disabled_error is called.
    Then: It returns False.
    """
    assert GCPIntegration._is_service_disabled_error(build_http_error(403, b"permission denied")) is False


def test_is_service_disabled_error_non_403():
    """
    Given: A 404 error whose body contains SERVICE_DISABLED.
    When: _is_service_disabled_error is called.
    Then: It returns False, because only 403 errors are service-disabled errors.
    """
    assert GCPIntegration._is_service_disabled_error(build_http_error(404, b"SERVICE_DISABLED")) is False


def test_get_configured_project_id_uses_parameter(mocker):
    """
    Given: A project_id parameter (with surrounding spaces) and a service account JSON.
    When: _get_configured_project_id is called.
    Then: The stripped project_id parameter is returned.
    """
    integration = build_integration(mocker, params={"project_id": " p1 ", "credentials": {"password": SERVICE_ACCOUNT_JSON}})

    assert integration._get_configured_project_id() == "p1"


def test_get_configured_project_id_falls_back_to_service_account_json(mocker):
    """
    Given: No project_id parameter and a service account JSON with a project_id.
    When: _get_configured_project_id is called.
    Then: The project_id of the service account JSON is returned.
    """
    integration = build_integration(mocker, params={"credentials": {"password": SERVICE_ACCOUNT_JSON}})

    assert integration._get_configured_project_id() == "sa-project"


def test_get_configured_project_id_uses_given_service_account_info(mocker):
    """
    Given: No project_id parameter and an already parsed service account JSON.
    When: _get_configured_project_id is called with it.
    Then: The project_id of the given service account JSON is returned.
    """
    integration = build_integration(mocker)

    assert integration._get_configured_project_id({"project_id": "given-project"}) == "given-project"


def test_get_configured_project_id_invalid_json_raises(mocker):
    """
    Given: No project_id parameter and invalid service account JSON.
    When: _get_configured_project_id is called.
    Then: A DemistoException about the missing project_id is raised.
    """
    integration = build_integration(mocker, params={"credentials": {"password": "not json"}})

    with pytest.raises(DemistoException, match="Missing required parameter 'project_id'"):
        integration._get_configured_project_id()


def test_get_configured_project_id_without_any_source_raises(mocker):
    """
    Given: No project_id parameter and no credentials.
    When: _get_configured_project_id is called.
    Then: A DemistoException about the missing project_id is raised.
    """
    integration = build_integration(mocker)

    with pytest.raises(DemistoException, match="Missing required parameter 'project_id'"):
        integration._get_configured_project_id()


def test_test_module_uses_service_account_project_id(mocker):
    """
    Given: No project_id parameter and a service account JSON with a project_id.
    When: test_module is called.
    Then: The connectivity probe runs against the project of the service account JSON.
    """
    integration = build_integration(mocker, params={"credentials": {"password": SERVICE_ACCOUNT_JSON}})
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=MagicMock())
    mocker.patch.object(GCPIntegration, "get_service_client", return_value=MagicMock())
    probe = mocker.patch.object(GCPIntegration, "_test_service_connectivity")

    assert integration.test_module() == "ok"
    assert probe.call_args.args[2] == "sa-project"


# ---------------------------------------------------------------------------
# _test_service_connectivity / _build_http_client
# ---------------------------------------------------------------------------


def test_test_service_connectivity_resource_manager_uses_test_iam_permissions():
    """
    Given: The Resource Manager service.
    When: _test_service_connectivity is called.
    Then: testIamPermissions is called on the project.
    """
    api = MagicMock()

    GCPIntegration._test_service_connectivity(api, GCPServices.RESOURCE_MANAGER, "p1")

    api.projects().testIamPermissions.assert_called_once_with(
        resource="projects/p1", body={"permissions": ["resourcemanager.projects.get"]}
    )


def test_test_service_connectivity_compute_lists_firewalls():
    """
    Given: The Compute service.
    When: _test_service_connectivity is called.
    Then: A minimal firewalls list request is sent.
    """
    api = MagicMock()

    GCPIntegration._test_service_connectivity(api, GCPServices.COMPUTE, "p1")

    api.firewalls().list.assert_called_once_with(project="p1", maxResults=1)


def test_test_service_connectivity_logging_lists_entries():
    """
    Given: The Logging service.
    When: _test_service_connectivity is called.
    Then: A minimal log entries list request is sent.
    """
    api = MagicMock()

    GCPIntegration._test_service_connectivity(api, GCPServices.LOGGING, "p1")

    api.entries().list.assert_called_once_with(body={"resourceNames": ["projects/p1"], "pageSize": 1})


def test_test_service_connectivity_propagates_api_error():
    """
    Given: A probe request that fails.
    When: _test_service_connectivity is called.
    Then: The error is raised to the caller.
    """
    api = MagicMock()
    api.buckets().list().execute.side_effect = build_http_error(403, b"SERVICE_DISABLED")

    with pytest.raises(HttpError):
        GCPIntegration._test_service_connectivity(api, GCPServices.STORAGE, "p1")


def test_build_http_client_proxy_without_https_value_raises(mocker):
    """
    Given: use_proxy=True and no https proxy configured.
    When: _build_http_client is called.
    Then: A DemistoException about the empty https proxy is raised.
    """
    mocker.patch("GCPApiModule.handle_proxy", return_value={})

    with pytest.raises(DemistoException, match="https proxy value is empty"):
        GCPIntegration._build_http_client(use_proxy=True, verify_ssl=True)


def test_build_http_client_proxy_adds_scheme_and_default_port(mocker):
    """
    Given: use_proxy=True and an https proxy without a scheme or port.
    When: _build_http_client is called.
    Then: The proxy is configured with the host and the https default port 443.
    """
    mocker.patch("GCPApiModule.handle_proxy", return_value={"https": "proxy.local"})

    http = GCPIntegration._build_http_client(use_proxy=True, verify_ssl=True)

    assert http.proxy_info.proxy_host == "proxy.local"
    assert http.proxy_info.proxy_port == 443


def test_build_http_client_insecure_disables_certificate_validation(mocker):
    """
    Given: use_proxy=False and verify_ssl=False.
    When: _build_http_client is called.
    Then: No proxy is configured and SSL certificate validation is disabled.
    """
    mocker.patch("GCPApiModule.handle_proxy", return_value={})

    http = GCPIntegration._build_http_client(use_proxy=False, verify_ssl=False)

    assert http.proxy_info is None
    assert http.disable_ssl_certificate_validation is True


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------


def build_registration_integration(mocker, command: str = "gcp-storage-test-registered", args: dict | None = None):
    """Build a ``GCPIntegration`` subclass instance with its own registry.

    A fresh subclass per test keeps registrations from leaking into ``GCPIntegration`` or other tests.
    """

    class RegistrationTestGCPIntegration(GCPIntegration):
        pass

    mocker.patch("COOCApiModule.get_connector_id", return_value=None)
    return RegistrationTestGCPIntegration(command, args if args is not None else {"project_id": "p1"}, {})


def test_registered_command_receives_service_client(mocker):
    """
    Given: A handler registered for a storage command.
    When: execute_command is called with an empty commands mapping.
    Then: The handler gets the storage service client built from the Google credentials, and the args.
    """
    integration = build_registration_integration(mocker)
    creds = MagicMock()
    mocker.patch.object(GCPIntegration, "_get_google_credentials", return_value=creds)
    get_service_client = mocker.patch.object(GCPIntegration, "get_service_client", return_value="storage-client")
    handler = mocker.Mock(return_value="registered-result")
    type(integration).register("gcp-storage-test-registered")(handler)

    assert integration.execute_command({}) == "registered-result"
    get_service_client.assert_called_once_with(creds, GCPServices.STORAGE)
    handler.assert_called_once_with("storage-client", {"project_id": "p1"})


def test_registered_polling_command_receives_args_first(mocker):
    """
    Given: A handler registered with polling=True.
    When: execute_command is called.
    Then: The handler gets (args, client).
    """
    integration = build_registration_integration(mocker)
    mocker.patch.object(GCPIntegration, "get_client", return_value="client")
    handler = mocker.Mock(return_value="polling-result")
    type(integration).register("gcp-storage-test-registered", polling=True)(handler)

    assert integration.execute_command({}) == "polling-result"
    handler.assert_called_once_with({"project_id": "p1"}, "client")


def test_registered_command_takes_precedence_over_mapping(mocker):
    """
    Given: A command that is both registered and in the commands mapping.
    When: execute_command is called.
    Then: Only the registered handler runs, and the mapped handler does not get credentials.
    """
    integration = build_registration_integration(mocker)
    mocker.patch.object(GCPIntegration, "get_client", return_value="client")
    registered = mocker.Mock(return_value="registered")
    mapped = mocker.Mock(return_value="mapped")
    type(integration).register("gcp-storage-test-registered")(registered)

    assert integration.execute_command({"gcp-storage-test-registered": mapped}) == "registered"
    mapped.assert_not_called()


def test_run_registered_command_success(mocker):
    """
    Given: A registered handler.
    When: run is called.
    Then: The handler result is passed to return_results.
    """
    integration = build_registration_integration(mocker)
    mocker.patch.object(GCPIntegration, "get_client", return_value="client")
    type(integration).register("gcp-storage-test-registered")(lambda client, args: "run-result")
    return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    return_results.assert_called_once_with("run-result")


def test_run_registered_command_http_error_uses_permission_flow(mocker):
    """
    Given: A registered handler that raises an HttpError.
    When: run is called.
    Then: The traceback is logged and handle_permission_error is called with the account and the command.
    """
    import demistomock as demisto

    integration = build_registration_integration(mocker)
    mocker.patch.object(GCPIntegration, "get_client", return_value="client")
    error = build_http_error(403)
    type(integration).register("gcp-storage-test-registered")(mocker.Mock(side_effect=error))
    log_error = mocker.patch.object(demisto, "error")
    permission_error = mocker.patch.object(GCPIntegration, "handle_permission_error")
    return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    log_error.assert_called_once()
    permission_error.assert_called_once_with(error, "p1", "gcp-storage-test-registered")
    return_results.assert_not_called()
