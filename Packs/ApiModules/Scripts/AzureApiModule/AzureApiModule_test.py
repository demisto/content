from typing import Any
from unittest.mock import MagicMock

import AzureApiModule
import pytest
from AzureApiModule import (
    AzureIntegration,
    AzureServices,
    DEFAULT_AZURE_AD_ENDPOINT,
    DEFAULT_RESOURCE,
    DEFAULT_SCOPE,
    PERMISSIONS_VERSION,
    PREFIX_URL_AZURE,
    STORAGE_RESOURCE,
    STORAGE_SCOPE,
    TokenScope,
)
from COOCApiModule import CloudIntegration, CloudTypes, ErrorType
from CommonServerPython import CommandResults, DemistoException

MARKETPLACE_PARAMS = {
    "app_id": "app",
    "subscription_id": "sub-param",
    "tenant_id": "tenant",
    "auth_type": "Client Credentials",
    "credentials": {"password": "secret"},
}


def build_integration(
    mocker,
    command: str = "azure-nsg-security-rule-update",
    args: dict | None = None,
    params: dict | None = None,
    connector_id: str | None = None,
    client_class: Any = None,
) -> AzureIntegration:
    """Build an ``AzureIntegration`` with ``get_connector_id`` patched to return ``connector_id``.

    When ``client_class`` is given, an ``AzureIntegration`` subclass with that ``client_class`` is built, the
    same way integrations set their client.
    """
    mocker.patch("COOCApiModule.get_connector_id", return_value=connector_id)
    integration_class = AzureIntegration
    if client_class is not None:
        integration_class = type("ClientAzureIntegration", (AzureIntegration,), {"client_class": client_class})
    return integration_class(command, args or {}, params if params is not None else dict(MARKETPLACE_PARAMS))


def mock_accounts(mocker, accounts: list):
    """Patch ``AzureIntegration.iter_accounts`` to yield ``accounts`` (a fresh iterator per call)."""
    return mocker.patch.object(AzureIntegration, "iter_accounts", side_effect=lambda: iter(accounts))


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_init_resolves_subscription_id_from_args_before_params(mocker):
    """
    Given: A subscription_id in both the args and the params.
    When: AzureIntegration is created.
    Then: account_id is the subscription_id argument, and the cloud type is Azure.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-arg"})

    assert integration.account_id == "sub-arg"
    assert integration.cloud_type == CloudTypes.AZURE.value


def test_cloud_type_class_attribute():
    """
    Given: The AzureIntegration class.
    When: Reading its class attributes.
    Then: cloud_type is Azure and account_id_arg is subscription_id.
    """
    assert AzureIntegration.cloud_type == CloudTypes.AZURE.value
    assert AzureIntegration.account_id_arg == "subscription_id"


def test_init_defaults_azure_ad_endpoint(mocker):
    """
    Given: Params without azure_ad_endpoint.
    When: AzureIntegration is created.
    Then: The commercial Azure AD endpoint is used.
    """
    integration = build_integration(mocker)

    assert integration.azure_ad_endpoint == DEFAULT_AZURE_AD_ENDPOINT


# ---------------------------------------------------------------------------
# is_gov_account
# ---------------------------------------------------------------------------


def test_is_gov_account_without_connector_returns_false(mocker):
    """
    Given: The marketplace path (no connector ID).
    When: is_gov_account is called.
    Then: It returns False without calling the onboarding API.
    """
    integration = build_integration(mocker)
    get_accounts = mock_accounts(mocker, [])

    assert integration.is_gov_account() is False
    get_accounts.assert_not_called()


def test_is_gov_account_gov_partition_returns_true(mocker):
    """
    Given: A connector whose account for the subscription_id has the GOV cloud partition.
    When: is_gov_account is called.
    Then: It returns True.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(mocker, [{"account_id": "sub-1", "cloud_partition": "GOV"}])

    assert integration.is_gov_account() is True


def test_is_gov_account_lowercase_gov_partition_returns_true(mocker):
    """
    Given: An account whose cloud partition is "gov" in lowercase.
    When: is_gov_account is called.
    Then: The comparison is case insensitive and it returns True.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(mocker, [{"account_id": "sub-1", "cloud_partition": "gov"}])

    assert integration.is_gov_account() is True


def test_is_gov_account_commercial_partition_returns_false(mocker):
    """
    Given: An account with the COMMERCIAL cloud partition.
    When: is_gov_account is called.
    Then: It returns False.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(mocker, [{"account_id": "sub-1", "cloud_partition": "COMMERCIAL"}])

    assert integration.is_gov_account() is False


def test_is_gov_account_missing_partition_returns_false(mocker):
    """
    Given: An account without cloud partition information.
    When: is_gov_account is called.
    Then: It returns False.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(mocker, [{"account_id": "sub-1"}])

    assert integration.is_gov_account() is False


def test_is_gov_account_checks_only_the_matching_account(mocker):
    """
    Given: A GOV account that is not the requested subscription.
    When: is_gov_account is called for another subscription.
    Then: It returns False, because only the matching account is checked.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(mocker, [{"account_id": "sub-other", "cloud_partition": "GOV"}])

    assert integration.is_gov_account() is False


def test_is_gov_account_explicit_account_id_overrides_subscription_id(mocker):
    """
    Given: A subscription_id of a commercial account, and an explicit account_id of a GOV account.
    When: is_gov_account is called with the explicit account_id.
    Then: The explicit account is checked and it returns True.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(
        mocker,
        [{"account_id": "sub-1", "cloud_partition": "COMMERCIAL"}, {"account_id": "sub-2", "cloud_partition": "GOV"}],
    )

    assert integration.is_gov_account("sub-2") is True


def test_is_gov_account_empty_account_id_checks_first_account(mocker):
    """
    Given: An empty account_id and a connector whose first account is GOV.
    When: is_gov_account is called with account_id="".
    Then: The first account of the connector is checked and it returns True.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mock_accounts(
        mocker,
        [{"account_id": "sub-9", "cloud_partition": "GOV"}, {"account_id": "sub-1", "cloud_partition": "COMMERCIAL"}],
    )

    assert integration.is_gov_account("") is True


def test_is_gov_account_empty_account_id_and_no_accounts_returns_false(mocker):
    """
    Given: An empty account_id and a connector without accounts.
    When: is_gov_account is called.
    Then: It returns False.
    """
    integration = build_integration(mocker, params={}, connector_id="connector-1")
    mock_accounts(mocker, [])

    assert integration.is_gov_account() is False


def test_is_gov_account_stops_fetching_after_matching_account(mocker):
    """
    Given: A connector whose matching account is the first of several accounts.
    When: is_gov_account is called.
    Then: It returns the partition of the matching account without consuming the remaining accounts.
    """
    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    consumed: list[str] = []

    def accounts():
        for account in [{"account_id": "sub-1", "cloud_partition": "GOV"}, {"account_id": "sub-2"}, {"account_id": "sub-3"}]:
            consumed.append(account["account_id"])
            yield account

    mocker.patch.object(AzureIntegration, "iter_accounts", side_effect=accounts)

    assert integration.is_gov_account() is True
    assert consumed == ["sub-1"]


def test_is_gov_account_empty_account_id_reads_only_first_account(mocker):
    """
    Given: An empty account_id and a connector with several accounts.
    When: is_gov_account is called with account_id="".
    Then: Only the first account is consumed.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    consumed: list[str] = []

    def accounts():
        for account in [{"account_id": "sub-1", "cloud_partition": "COMMERCIAL"}, {"account_id": "sub-2"}]:
            consumed.append(account["account_id"])
            yield account

    mocker.patch.object(AzureIntegration, "iter_accounts", side_effect=accounts)

    assert integration.is_gov_account("") is False
    assert consumed == ["sub-1"]


def test_is_gov_account_api_failure_returns_false_and_logs(mocker):
    """
    Given: The onboarding API fails while fetching the accounts.
    When: is_gov_account is called.
    Then: The failure is logged and False is returned (the commercial endpoints are used).
    """
    import demistomock as demisto

    integration = build_integration(mocker, args={"subscription_id": "sub-1"}, connector_id="connector-1")
    mocker.patch.object(AzureIntegration, "iter_accounts", side_effect=DemistoException("Failed to fetch accounts"))
    log_error = mocker.patch.object(demisto, "error")

    assert integration.is_gov_account() is False
    log_error.assert_called_once()
    assert "Failed to fetch accounts" in log_error.call_args.args[0]


def test_is_gov_account_api_failure_on_later_page_returns_false(mocker):
    """
    Given: The onboarding API fails on a later page, before the matching account is found.
    When: is_gov_account is called.
    Then: False is returned.
    """
    import demistomock as demisto

    integration = build_integration(mocker, args={"subscription_id": "sub-9"}, connector_id="connector-1")

    def accounts():
        yield {"account_id": "sub-1", "cloud_partition": "GOV"}
        raise DemistoException("page 2 failed")

    mocker.patch.object(AzureIntegration, "iter_accounts", side_effect=accounts)
    mocker.patch.object(demisto, "error")

    assert integration.is_gov_account() is False


# ---------------------------------------------------------------------------
# switch_to_gov_account_if_needed / run_health_check
# ---------------------------------------------------------------------------


def test_switch_to_gov_account_if_needed_platform_gov_account_switches(mocker):
    """
    Given: The Cortex Platform path and a GOV account.
    When: switch_to_gov_account_if_needed is called.
    Then: The Gov endpoints are selected.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(AzureIntegration, "is_gov_account", return_value=True)
    switch = mocker.patch("AzureApiModule.switch_to_gov_account")

    integration.switch_to_gov_account_if_needed()

    switch.assert_called_once()


def test_switch_to_gov_account_if_needed_platform_commercial_account_does_not_switch(mocker):
    """
    Given: The Cortex Platform path and a commercial account.
    When: switch_to_gov_account_if_needed is called.
    Then: The commercial endpoints are kept.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(AzureIntegration, "is_gov_account", return_value=False)
    switch = mocker.patch("AzureApiModule.switch_to_gov_account")

    integration.switch_to_gov_account_if_needed()

    switch.assert_not_called()


def test_switch_to_gov_account_if_needed_passes_account_id_to_is_gov_account(mocker):
    """
    Given: The Cortex Platform path.
    When: switch_to_gov_account_if_needed is called with an explicit account_id.
    Then: The account_id is passed to is_gov_account.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    is_gov = mocker.patch.object(AzureIntegration, "is_gov_account", return_value=False)
    mocker.patch("AzureApiModule.switch_to_gov_account")

    integration.switch_to_gov_account_if_needed(account_id="")

    is_gov.assert_called_once_with("")


def test_switch_to_gov_account_if_needed_marketplace_gov_endpoint_switches(mocker):
    """
    Given: The marketplace path with the US Gov Azure AD endpoint (with a trailing slash).
    When: switch_to_gov_account_if_needed is called.
    Then: The Gov endpoints are selected without calling the onboarding API.
    """
    params = dict(MARKETPLACE_PARAMS, azure_ad_endpoint="https://login.microsoftonline.us/")
    integration = build_integration(mocker, params=params)
    is_gov = mocker.patch.object(AzureIntegration, "is_gov_account")
    switch = mocker.patch("AzureApiModule.switch_to_gov_account")

    integration.switch_to_gov_account_if_needed()

    switch.assert_called_once()
    is_gov.assert_not_called()


def test_switch_to_gov_account_if_needed_marketplace_commercial_endpoint_does_not_switch(mocker):
    """
    Given: The marketplace path with the commercial Azure AD endpoint (with a trailing slash).
    When: switch_to_gov_account_if_needed is called.
    Then: The commercial endpoints are kept.
    """
    params = dict(MARKETPLACE_PARAMS, azure_ad_endpoint=f"{DEFAULT_AZURE_AD_ENDPOINT}/")
    integration = build_integration(mocker, params=params)
    switch = mocker.patch("AzureApiModule.switch_to_gov_account")

    integration.switch_to_gov_account_if_needed()

    switch.assert_not_called()


def test_run_health_check_checks_gov_for_first_account(mocker):
    """
    Given: The Cortex Platform path with a subscription_id parameter.
    When: run_health_check is called.
    Then: The Gov decision is made for the first account of the connector (account_id=""),
          and the base health check runs.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    switch = mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    base_health_check = mocker.patch.object(CloudIntegration, "run_health_check", return_value="ok")

    assert integration.run_health_check() == "ok"
    switch.assert_called_once_with(account_id="")
    base_health_check.assert_called_once()


# ---------------------------------------------------------------------------
# get_client
# ---------------------------------------------------------------------------


def test_get_client_platform_without_subscription_raises(mocker):
    """
    Given: The Cortex Platform path without a subscription_id in the args or params.
    When: get_client is called.
    Then: A DemistoException is raised before any credentials are requested.
    """
    integration = build_integration(mocker, params={}, connector_id="connector-1")
    get_credentials = mocker.patch.object(AzureIntegration, "get_credentials")

    with pytest.raises(DemistoException, match="No subscription_id was provided"):
        integration.get_client()
    get_credentials.assert_not_called()


def test_get_client_platform_without_token_raises(mocker):
    """
    Given: The Cortex Platform path where the CTS credentials have no access token.
    When: get_client is called.
    Then: A DemistoException about the missing token is raised.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(AzureIntegration, "get_credentials", return_value={})

    with pytest.raises(DemistoException, match="token is missing from credentials"):
        integration.get_client()


def test_get_client_platform_builds_client_with_bearer_headers(mocker):
    """
    Given: The Cortex Platform path with a CTS access token, and a storage command.
    When: get_client is called.
    Then: The token is requested with the storage token scope, auth params are not validated,
          and client_class is built with the bearer headers.
    """
    client_class = MagicMock()
    integration = build_integration(
        mocker, command="azure-storage-container-create", connector_id="connector-1", client_class=client_class
    )
    get_credentials = mocker.patch.object(AzureIntegration, "get_credentials", return_value={"access_token": "token"})
    validate = mocker.patch.object(AzureIntegration, "validate_auth_params")

    result = integration.get_client()

    assert result == client_class.return_value
    get_credentials.assert_called_once_with(scopes=["STORAGE"])
    validate.assert_not_called()
    assert client_class.call_args.kwargs["headers"] == AzureIntegration._bearer_headers("token")
    assert client_class.call_args.kwargs["resource"] == STORAGE_RESOURCE
    assert client_class.call_args.kwargs["scope"] == STORAGE_SCOPE


def test_get_client_marketplace_validates_auth_params(mocker):
    """
    Given: The marketplace path.
    When: get_client is called.
    Then: The auth params are validated for the configured auth type, no CTS credentials are
          requested, and client_class is built without headers and with the client secret.
    """
    client_class = MagicMock()
    integration = build_integration(mocker, command="azure-nsg-security-rule-update", client_class=client_class)
    validate = mocker.patch.object(AzureIntegration, "validate_auth_params")
    get_credentials = mocker.patch.object(AzureIntegration, "get_credentials")

    integration.get_client()

    validate.assert_called_once_with(integration.params, "Client Credentials", "azure-nsg-security-rule-update")
    get_credentials.assert_not_called()
    kwargs = client_class.call_args.kwargs
    assert kwargs["headers"] == {}
    assert kwargs["enc_key"] == "secret"
    assert kwargs["connection_type"] == "Client Credentials"
    assert kwargs["resource"] == DEFAULT_RESOURCE
    assert kwargs["scope"] == DEFAULT_SCOPE


# ---------------------------------------------------------------------------
# is_storage_command / get_command_and_token_scopes / get_command_resource / validate_auth_params
# ---------------------------------------------------------------------------


def test_is_storage_command_storage_container_command():
    """
    Given: A storage-container command.
    When: is_storage_command is called.
    Then: It returns True.
    """
    assert AzureIntegration.is_storage_command("azure-storage-container-create") is True


def test_is_storage_command_storage_special_command():
    """
    Given: A storage blob command listed in STORAGE_SPECIAL_COMMANDS.
    When: is_storage_command is called.
    Then: It returns True.
    """
    assert AzureIntegration.is_storage_command("azure-storage-blob-tag-get") is True


def test_is_storage_command_management_storage_command():
    """
    Given: A storage blob command that uses the management API.
    When: is_storage_command is called.
    Then: It returns False.
    """
    assert AzureIntegration.is_storage_command("azure-storage-blob-service-properties-get") is False


def test_get_command_and_token_scopes_storage_and_default():
    """
    Given: A storage command and a management command.
    When: get_command_and_token_scopes is called.
    Then: The storage scopes are returned for the storage command and the default scopes otherwise.
    """
    assert AzureIntegration.get_command_and_token_scopes("azure-storage-container-create") == (
        STORAGE_SCOPE,
        [TokenScope.STORAGE],
    )
    assert AzureIntegration.get_command_and_token_scopes("azure-nsg-security-rule-update") == (
        DEFAULT_SCOPE,
        [TokenScope.DEFAULT],
    )


def test_get_command_resource_storage_and_default():
    """
    Given: A storage command and a management command.
    When: get_command_resource is called.
    Then: The storage resource is returned for the storage command and the default resource otherwise.
    """
    assert AzureIntegration.get_command_resource("azure-storage-blob-get") == STORAGE_RESOURCE
    assert AzureIntegration.get_command_resource("azure-nsg-security-rule-update") == DEFAULT_RESOURCE


def test_resolve_service_storage_command():
    """
    Given: A storage data-plane command.
    When: _resolve_service is called.
    Then: AzureServices.STORAGE is returned.
    """
    assert AzureIntegration._resolve_service("azure-storage-container-create") is AzureServices.STORAGE


def test_resolve_service_from_command_prefix():
    """
    Given: A command whose second word is an alias of a service (nsg).
    When: _resolve_service is called.
    Then: The service of the alias (NETWORK) is returned.
    """
    assert AzureIntegration._resolve_service("azure-nsg-security-rule-update") is AzureServices.NETWORK


def test_resolve_service_from_command_service_map():
    """
    Given: A command whose service can't be derived from its name.
    When: _resolve_service is called.
    Then: The service from COMMAND_SERVICE_MAP is returned.
    """
    assert AzureIntegration._resolve_service("azure-set-storage-account-https-only-quick-action") is AzureServices.STORAGE


def test_resolve_service_test_module():
    """
    Given: The test-module command.
    When: _resolve_service is called.
    Then: AzureServices.RESOURCE_MANAGER is returned.
    """
    assert AzureIntegration._resolve_service("test-module") is AzureServices.RESOURCE_MANAGER


def test_resolve_service_unknown_command_raises():
    """
    Given: A command with an unknown service prefix.
    When: _resolve_service is called.
    Then: A DemistoException is raised.
    """
    with pytest.raises(DemistoException, match="Could not resolve an Azure service"):
        AzureIntegration._resolve_service("azure-unknown-command")


def test_get_client_storage_management_command_uses_management_scope(mocker):
    """
    Given: A storage-service command that uses the management API (azure-storage-account-update).
    When: get_client is called.
    Then: The client is built with the default management scope and resource, not the storage ones.
    """
    client_class = MagicMock()
    integration = build_integration(mocker, command="azure-storage-account-update", client_class=client_class)
    mocker.patch.object(AzureIntegration, "validate_auth_params")

    integration.get_client()

    assert client_class.call_args.kwargs["scope"] == DEFAULT_SCOPE
    assert client_class.call_args.kwargs["resource"] == DEFAULT_RESOURCE


def test_get_client_uses_service_client_class(mocker):
    """
    Given: An AzureIntegration subclass with a client class for AzureServices.STORAGE, and a storage command.
    When: get_client is called.
    Then: The storage client class is built instead of the default client_class.
    """
    default_client_class = MagicMock()
    storage_client_class = MagicMock()
    mocker.patch("COOCApiModule.get_connector_id", return_value=None)
    integration_class = type(
        "ServiceAzureIntegration",
        (AzureIntegration,),
        {"client_class": default_client_class, "service_client_classes": {AzureServices.STORAGE: storage_client_class}},
    )
    integration = integration_class("azure-storage-container-create", {}, dict(MARKETPLACE_PARAMS))
    mocker.patch.object(AzureIntegration, "validate_auth_params")

    assert integration.get_client() == storage_client_class.return_value
    default_client_class.assert_not_called()
    assert storage_client_class.call_args.kwargs["scope"] == STORAGE_SCOPE


def test_get_client_falls_back_to_client_class(mocker):
    """
    Given: An AzureIntegration subclass with a client class only for AzureServices.STORAGE, and a network command.
    When: get_client is called.
    Then: The default client_class is built.
    """
    default_client_class = MagicMock()
    storage_client_class = MagicMock()
    mocker.patch("COOCApiModule.get_connector_id", return_value=None)
    integration_class = type(
        "ServiceAzureIntegration",
        (AzureIntegration,),
        {"client_class": default_client_class, "service_client_classes": {AzureServices.STORAGE: storage_client_class}},
    )
    integration = integration_class("azure-nsg-security-rule-update", {}, dict(MARKETPLACE_PARAMS))
    mocker.patch.object(AzureIntegration, "validate_auth_params")

    assert integration.get_client() == default_client_class.return_value
    storage_client_class.assert_not_called()


def test_is_polling_command_for_polling_commands(mocker):
    """
    Given: A command listed in POLLING_COMMANDS and a regular command.
    When: is_polling_command is called.
    Then: It returns True only for the polling command.
    """
    assert build_integration(mocker, command="azure-vn-ip-group-create").is_polling_command() is True
    assert build_integration(mocker, command="azure-nsg-security-rule-update").is_polling_command() is False


def test_validate_auth_params_missing_client_secret_raises():
    """
    Given: Client Credentials params without a client secret.
    When: validate_auth_params is called.
    Then: A DemistoException names the missing Client Secret.
    """
    params = {"app_id": "app", "tenant_id": "tenant", "subscription_id": "sub"}

    with pytest.raises(DemistoException, match="Client Secret"):
        AzureIntegration.validate_auth_params(params, "Client Credentials")


def test_validate_auth_params_auth_helper_command_does_not_require_auth_code():
    """
    Given: Authorization Code params without an authorization code, for an auth helper command.
    When: validate_auth_params is called.
    Then: No exception is raised, because the code is obtained by the auth helper command.
    """
    params = {"app_id": "app", "redirect_uri": "https://localhost", "subscription_id": "sub"}

    AzureIntegration.validate_auth_params(params, "Authorization Code", "azure-generate-login-url")


def test_validate_auth_params_data_command_requires_auth_code():
    """
    Given: Authorization Code params without an authorization code, for a data command.
    When: validate_auth_params is called.
    Then: A DemistoException names the missing Authorization code.
    """
    params = {"app_id": "app", "redirect_uri": "https://localhost", "subscription_id": "sub"}

    with pytest.raises(DemistoException, match="Authorization code"):
        AzureIntegration.validate_auth_params(params, "Authorization Code", "azure-nsg-security-rule-update")


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------


def test_health_check_without_account_id_returns_internal_error(mocker):
    """
    Given: An empty account_id.
    When: health_check is called.
    Then: An internal HealthCheckError is returned.
    """
    integration = build_integration(mocker, connector_id="connector-1")

    error = integration.health_check({"access_token": "token"}, "", "connector-1")

    assert error is not None
    assert error.error_type == ErrorType.INTERNAL_ERROR
    assert "Missing Subscription ID" in error.message


def test_health_check_without_token_returns_connectivity_error(mocker):
    """
    Given: Credentials without an access token.
    When: health_check is called.
    Then: A connectivity HealthCheckError is returned.
    """
    integration = build_integration(mocker, connector_id="connector-1")

    error = integration.health_check({}, "sub-1", "connector-1")

    assert error is not None
    assert error.error_type == ErrorType.CONNECTIVITY_ERROR
    assert "Failed to authenticate" in error.message


def test_health_check_connectivity_failure_returns_connectivity_error(mocker):
    """
    Given: Valid credentials, but the connectivity test fails.
    When: health_check is called.
    Then: A connectivity HealthCheckError with the failure is returned.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    mocker.patch.object(AzureIntegration, "_test_connectivity", side_effect=Exception("boom"))

    error = integration.health_check({"access_token": "token"}, "sub-1", "connector-1")

    assert error is not None
    assert error.error_type == ErrorType.CONNECTIVITY_ERROR
    assert "boom" in error.message


def test_health_check_success_returns_none(mocker):
    """
    Given: Valid credentials and a successful connectivity test.
    When: health_check is called.
    Then: None is returned, and the connectivity test uses a client for the account with bearer headers.
    """
    integration = build_integration(mocker, connector_id="connector-1")
    test_connectivity = mocker.patch.object(AzureIntegration, "_test_connectivity", return_value="ok")

    assert integration.health_check({"access_token": "token"}, "sub-1", "connector-1") is None
    client = test_connectivity.call_args.args[0]
    assert client.subscription_id == "sub-1"
    assert client.headers["Authorization"] == "Bearer token"


# ---------------------------------------------------------------------------
# test_module / execute_command / execute_mapped_command
# ---------------------------------------------------------------------------


def test_test_module_switches_gov_then_tests_connectivity(mocker):
    """
    Given: The marketplace path.
    When: test_module is called.
    Then: The Gov endpoints are selected if needed and connectivity is tested with the client.
    """
    integration = build_integration(mocker)
    switch = mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)
    test_connectivity = mocker.patch.object(AzureIntegration, "_test_connectivity", return_value="ok")

    assert integration.test_module() == "ok"
    switch.assert_called_once()
    test_connectivity.assert_called_once_with(client)


def test_execute_command_routes_auth_helper_command(mocker):
    """
    Given: An auth helper command.
    When: execute_command is called.
    Then: The command runs through execute_auth_command and not through the commands mapping.
    """
    integration = build_integration(mocker, command="azure-auth-reset")
    mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    auth = mocker.patch.object(AzureIntegration, "execute_auth_command", return_value="done")
    handler = MagicMock()

    assert integration.execute_command({"azure-auth-reset": handler}) == "done"
    auth.assert_called_once()
    handler.assert_not_called()


def test_execute_command_runs_mapped_command(mocker):
    """
    Given: A regular command in the commands mapping.
    When: execute_command is called.
    Then: The Gov endpoints are selected if needed and the handler is called with client, params and args.
    """
    integration = build_integration(mocker, args={"rule_name": "r1"})
    switch = mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)
    handler = MagicMock(return_value="result")

    assert integration.execute_command({"azure-nsg-security-rule-update": handler}) == "result"
    switch.assert_called_once()
    handler.assert_called_once_with(client=client, params=integration.params, args={"rule_name": "r1"})


def test_execute_mapped_command_polling_command_passes_args_positionally(mocker):
    """
    Given: A polling command.
    When: execute_mapped_command is called.
    Then: The handler receives the args as its first positional argument.
    """
    integration = build_integration(mocker, command="azure-vn-ip-group-create", args={"ip_group_name": "g1"})
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)
    handler = MagicMock(return_value="result")

    assert integration.execute_mapped_command(handler) == "result"
    handler.assert_called_once_with({"ip_group_name": "g1"}, client=client, params=integration.params)


# ---------------------------------------------------------------------------
# execute_auth_command
# ---------------------------------------------------------------------------


def test_execute_auth_command_reset_does_not_build_client(mocker):
    """
    Given: The azure-auth-reset command.
    When: execute_auth_command is called.
    Then: reset_auth runs and no client is built.
    """
    integration = build_integration(mocker, command="azure-auth-reset")
    reset = mocker.patch("AzureApiModule.reset_auth", return_value="reset done")
    get_client = mocker.patch.object(AzureIntegration, "get_client")

    assert integration.execute_auth_command() == "reset done"
    reset.assert_called_once()
    get_client.assert_not_called()


def test_execute_auth_command_generate_login_url(mocker):
    """
    Given: The azure-generate-login-url command.
    When: execute_auth_command is called.
    Then: generate_login_url is called with the MicrosoftClient and the Azure AD endpoint.
    """
    integration = build_integration(mocker, command="azure-generate-login-url")
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)
    generate = mocker.patch("AzureApiModule.generate_login_url", return_value="login url")

    assert integration.execute_auth_command() == "login url"
    generate.assert_called_once_with(client.ms_client, DEFAULT_AZURE_AD_ENDPOINT)


def test_execute_auth_command_start(mocker):
    """
    Given: The azure-auth-start command.
    When: execute_auth_command is called.
    Then: CommandResults wrapping the MicrosoftClient start_auth output is returned.
    """
    integration = build_integration(mocker, command="azure-auth-start")
    client = MagicMock()
    client.ms_client.start_auth.return_value = "follow these steps"
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)

    result = integration.execute_auth_command()

    assert isinstance(result, CommandResults)
    assert result.readable_output == "follow these steps"
    client.ms_client.start_auth.assert_called_once_with("!azure-auth-complete")


def test_execute_auth_command_complete(mocker):
    """
    Given: The azure-auth-complete command.
    When: execute_auth_command is called.
    Then: The access token is fetched and a completion message is returned.
    """
    integration = build_integration(mocker, command="azure-auth-complete")
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)

    assert integration.execute_auth_command() == "Authorization completed successfully."
    client.ms_client.get_access_token.assert_called_once()


def test_execute_auth_command_test(mocker):
    """
    Given: The azure-auth-test command.
    When: execute_auth_command is called.
    Then: The access token is fetched and "Success!" is returned.
    """
    integration = build_integration(mocker, command="azure-auth-test")
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)

    assert integration.execute_auth_command() == "Success!"
    client.ms_client.get_access_token.assert_called_once()


def test_execute_auth_command_without_ms_client_raises(mocker):
    """
    Given: A client without a MicrosoftClient (Cortex Platform path).
    When: execute_auth_command is called for azure-auth-test.
    Then: A DemistoException explains that the auth commands are not supported on the Cortex Platform.
    """
    integration = build_integration(mocker, command="azure-auth-test")
    client = MagicMock()
    client.ms_client = None
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)

    with pytest.raises(DemistoException, match="supported only on Cortex XSOAR and Cortex XSIAM"):
        integration.execute_auth_command()


# ---------------------------------------------------------------------------
# _test_connectivity
# ---------------------------------------------------------------------------


def build_connectivity_client(connection_type: str) -> MagicMock:
    """Return a mock client with ``connection_type`` and the subscription ``sub-1``."""
    client = MagicMock()
    client.connection_type = connection_type
    client.subscription_id = "sub-1"
    return client


def test_test_connectivity_device_code_raises_without_request():
    """
    Given: A client with the Device Code auth type.
    When: _test_connectivity is called.
    Then: A DemistoException points to azure-auth-test, and no request is sent.
    """
    client = build_connectivity_client("Device Code")

    with pytest.raises(DemistoException, match="azure-auth-test"):
        AzureIntegration._test_connectivity(client)
    client.http_request.assert_not_called()


def test_test_connectivity_managed_identities_lists_resource_groups():
    """
    Given: A client with the Azure Managed Identities auth type.
    When: _test_connectivity is called.
    Then: The resource groups list request is sent and "ok" is returned.
    """
    client = build_connectivity_client("Azure Managed Identities")

    assert AzureIntegration._test_connectivity(client) == "ok"
    client.http_request.assert_called_once_with(
        method="GET", full_url=f"{PREFIX_URL_AZURE}sub-1/resourcegroups", params={"$top": "1"}
    )


def test_test_connectivity_client_credentials_lists_role_assignments():
    """
    Given: A client with the Client Credentials auth type.
    When: _test_connectivity is called.
    Then: The role assignments list request is sent and "ok" is returned.
    """
    client = build_connectivity_client("Client Credentials")

    assert AzureIntegration._test_connectivity(client) == "ok"
    client.http_request.assert_called_once_with(
        method="GET",
        full_url=f"{PREFIX_URL_AZURE}sub-1/providers/Microsoft.Authorization/roleAssignments",
        params={"api-version": PERMISSIONS_VERSION},
    )


def test_test_connectivity_connection_error_raises_connectivity_error():
    """
    Given: A client whose request fails with a connection error.
    When: _test_connectivity is called.
    Then: An exception with a connectivity error message is raised.
    """
    client = build_connectivity_client("Client Credentials")
    client.http_request.side_effect = AzureApiModule.ConnectionError("unreachable")

    with pytest.raises(Exception, match="Connectivity Error: Cannot reach Azure endpoint"):
        AzureIntegration._test_connectivity(client)


def test_bearer_headers():
    """
    Given: An access token.
    When: _bearer_headers is called.
    Then: The bearer authorization and JSON content headers are returned.
    """
    assert AzureIntegration._bearer_headers("token") == {
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------


def build_registration_integration(mocker, args: dict | None = None):
    """Build an ``AzureIntegration`` subclass instance with its own registry.

    A fresh subclass per test keeps registrations from leaking into ``AzureIntegration`` or other tests.
    """

    class RegistrationTestAzureIntegration(AzureIntegration):
        pass

    mocker.patch("COOCApiModule.get_connector_id", return_value=None)
    return RegistrationTestAzureIntegration("azure-test-registered", args or {}, dict(MARKETPLACE_PARAMS))


def test_registered_command_runs_after_gov_switch(mocker):
    """
    Given: A handler registered on the Azure integration.
    When: execute_command is called with an empty commands mapping.
    Then: The Gov endpoints are selected before the client is built and the handler runs with (client, args).
    """
    integration = build_registration_integration(mocker, args={"subscription_id": "sub-1"})
    calls: list[str] = []
    mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed", side_effect=lambda: calls.append("gov"))
    client = MagicMock()

    def fake_get_client(self):
        calls.append("client")
        return client

    mocker.patch.object(AzureIntegration, "get_client", fake_get_client)

    def handler(handler_client, args):
        calls.append("handler")
        assert handler_client is client
        assert args == {"subscription_id": "sub-1"}
        return "registered-result"

    type(integration).register("azure-test-registered")(handler)

    assert integration.execute_command({}) == "registered-result"
    assert calls == ["gov", "client", "handler"]


def test_registered_polling_command_receives_args_first(mocker):
    """
    Given: A handler registered with polling=True.
    When: execute_command is called.
    Then: The handler gets (args, client), unlike the (args, client=, params=) signature of existing polling commands.
    """
    integration = build_registration_integration(mocker, args={"ip_group_name": "g1"})
    mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    client = MagicMock()
    mocker.patch.object(AzureIntegration, "get_client", return_value=client)
    handler = MagicMock(return_value="polling-result")
    type(integration).register("azure-test-registered", polling=True)(handler)

    assert integration.execute_command({}) == "polling-result"
    handler.assert_called_once_with({"ip_group_name": "g1"}, client)


def test_registered_command_takes_precedence_over_mapping(mocker):
    """
    Given: A command that is both registered and in the commands mapping.
    When: execute_command is called.
    Then: Only the registered handler runs.
    """
    integration = build_registration_integration(mocker)
    mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    mocker.patch.object(AzureIntegration, "get_client", return_value=MagicMock())
    registered = MagicMock(return_value="registered")
    mapped = MagicMock(return_value="mapped")
    type(integration).register("azure-test-registered")(registered)

    assert integration.execute_command({"azure-test-registered": mapped}) == "registered"
    mapped.assert_not_called()


def test_run_registered_command_success(mocker):
    """
    Given: A registered handler.
    When: run is called.
    Then: The handler result is passed to return_results.
    """
    integration = build_registration_integration(mocker)
    mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    mocker.patch.object(AzureIntegration, "get_client", return_value=MagicMock())
    type(integration).register("azure-test-registered")(lambda client, args: "run-result")
    mocker.patch("COOCApiModule.handle_proxy")
    return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    return_results.assert_called_once_with("run-result")


def test_run_registered_command_error(mocker):
    """
    Given: A registered handler that raises.
    When: run is called.
    Then: The traceback is logged once and return_error is called with the command and the error.
    """
    import demistomock as demisto

    integration = build_registration_integration(mocker)
    mocker.patch.object(AzureIntegration, "switch_to_gov_account_if_needed")
    mocker.patch.object(AzureIntegration, "get_client", return_value=MagicMock())
    type(integration).register("azure-test-registered")(MagicMock(side_effect=ValueError("boom")))
    mocker.patch("COOCApiModule.handle_proxy")
    log_error = mocker.patch.object(demisto, "error")
    return_error = mocker.patch("COOCApiModule.return_error")
    return_results = mocker.patch("COOCApiModule.return_results")

    integration.run({})

    log_error.assert_called_once()
    return_error.assert_called_once_with("Failed to execute azure-test-registered command.\nError:\nboom")
    return_results.assert_not_called()
