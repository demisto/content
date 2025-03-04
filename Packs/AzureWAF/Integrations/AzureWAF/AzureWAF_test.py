import pytest
import AzureWAF as waf
import demistomock as demisto

API_VERSION = "2020-05-01"

GET_COMMAND_DATA = [
    (
        {"policy_name": "pol1", "verbose": "false", "limit": "10"},  # args, case: default resource_group
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies/pol1",
            "params": {"api-version": API_VERSION},
        },  # expected
    ),
    (
        {"verbose": "false", "limit": "10"},  # args, case: list of policies in default resource_group
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies",
            "params": {"api-version": API_VERSION},
        },  # expected
    ),
    (
        {"verbose": "true", "limit": "10"},  # args, case: list of policies in default resource_group with full data
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies",
            "params": {"api-version": API_VERSION},
        },  # expected
    ),
    (
        {"resource_group_name": ["res1"], "verbose": "false", "limit": "10"},
        # args, case: list of policies in custom resource_group
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/res1/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies",
            "params": {"api-version": API_VERSION},
        },  # expected
    ),
]


@pytest.mark.parametrize("demisto_args,expected_results", GET_COMMAND_DATA)
def test_get_policy_by_resource_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - retrieving policy's data

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    m = mocker.patch.object(client, "http_request", return_value={"properties": "test"})
    waf.policies_get_command(client, **demisto_args)
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("method") == expected_results.get("method")


def test_get_array_policy_with_exception(mocker):
    """
    Given:
        - search task's argument

    When:
        - retrieving policy's data

    Then:
        - validating the body sent to request is matching the search

    """
    demisto_args = {
        "policy_name": "pol1",
        "resource_group_name": ["res1", "res2"],
        "verbose": "false",
        "limit": "10",
        "subscription_id": "sub1",
    }
    expected_results = {
        "method": "GET",
        "full_url": "https://management.azure.com/subscriptions/sub1/resourceGroups/res2/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies/pol1",
        "params": {"api-version": API_VERSION},
    }
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    side_effect = [Exception("Test"), {"properties": "test2"}]
    expected_outputs = [{"properties": "res1 threw Exception: Test"}, {"properties": "test2"}]
    m = mocker.patch.object(client, "http_request", side_effect=side_effect)
    commandResult = waf.policies_get_command(client, **demisto_args)
    assert commandResult.outputs == expected_outputs
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("params") == expected_results.get("params")


UPSERT_COMMAND_DATA = [
    (
        {
            "policy_name": "pol1",
            "resource_group_name": ["res1"],
            "verbose": "false",
            "limit": "10",
            "managed_rules": '{"test": "test"}',
            "location": "east",
        },  # args, case: custom resource_group update rule
        {
            "method": "PUT",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/res1/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies/pol1",
            "params": {"api-version": API_VERSION},
            "body": {"location": "east", "properties": {"managedRules": {"test": "test"}}},
        },  # expected
    ),
    (
        {
            "policy_name": "pol1",
            "resource_group_name": ["res1"],
            "verbose": "false",
            "limit": "10",
            "managed_rules": '{"test": "test"}',
            "custom_rules": '{"test": "test"}',
            "location": "east",
        },  # args, case: custom resource_group update rule with key hierarchy
        {
            "method": "PUT",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/res1/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies/pol1",
            "params": {"api-version": API_VERSION},
            "body": {"location": "east", "properties": {"customRules": {"test": "test"}, "managedRules": {"test": "test"}}},
        },  # expected
    ),
]


@pytest.mark.parametrize("demisto_args,expected_results", UPSERT_COMMAND_DATA)
def test_policy_upsert_request_body_happy(mocker, demisto_args, expected_results):
    """
    Given:
        - a policy to update or a new policy

    When:
        - updating or creating policy's data

    Then:
        - validating the body sent to request is matching the api requires

    """

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    m = mocker.patch.object(client, "http_request", return_value={"name": "pol1", "id": "id", "properties": {}})
    waf.policy_upsert_command(client, **demisto_args)
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("data") == expected_results.get("body")
    assert m.call_args[1].get("params") == expected_results.get("params")


def test_policy_array_group_names_upsert_request(mocker):
    """
    Given:
        - a policy to update or a new policy

    When:
        - updating or creating policy's data

    Then:
        - validating the body sent to request is matching the api requires

    """
    demisto_args = {
        "policy_name": "pol1",
        "resource_group_name": ["res1", "res2"],
        "verbose": "false",
        "limit": "10",
        "managed_rules": '{"test": "test"}',
        "custom_rules": '{"test": "test"}',
        "location": "east",
    }
    expected_results = {
        "method": "PUT",
        "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/res2/providers/Microsoft.Network/\
ApplicationGatewayWebApplicationFirewallPolicies/pol1",
        "params": {"api-version": API_VERSION},
        "body": {
            "location": "east",
            "properties": {
                "customRules": {"test": "test"},
                "managedRules": {"test": "test"},
            },
        },
    }
    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    expected_commandResult_output = [{"properties": "res1 threw Exception: Test"}, {"name": "pol1", "id": "id", "properties": {}}]
    m = mocker.patch.object(
        client, "http_request", side_effect=[Exception("Test"), {"name": "pol1", "id": "id", "properties": {}}]
    )
    commandResult = waf.policy_upsert_command(client, **demisto_args)
    assert commandResult.outputs == expected_commandResult_output
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("data") == expected_results.get("body")
    assert m.call_args[1].get("params") == expected_results.get("params")


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {
            "resource_group_name": "res1",
            "managed_rules": '{"test": "test"}',
            "location": "east",
            "verbose": "false",
            "limit": "10",
        },  # args, case: missing policy name
        "In order to add/ update policy, please provide policy_name, location and managed_rules. ",  # expected
    ),
    (
        {"policy_name": "pol1", "resource_group_name": "res1", "location": "east"},  # args, case: missing managed_rules
        "In order to add/ update policy, please provide policy_name, location and managed_rules. ",  # expected
    ),
    (
        {
            "policy_name": "pol1",
            "resource_group_name": "res1",
            "managed_rules": '{"test": "test"}',
        },  # args, case: missing location
        "In order to add/ update policy, please provide policy_name, location and managed_rules. ",  # expected
    ),
]


@pytest.mark.parametrize("demisto_args,expected_error_msg", UPSERT_COMMAND_DATA_BAD_CASES)
def test_policy_upsert_request_body_fails(mocker, demisto_args, expected_error_msg):
    """
    Given:
        - a policy to update or a new policy

    When:
        - updating or creating policy's data without policy_name, location or managed_rules.

    Then:
        - failing when missing required data

    """

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    mocker.patch.object(client, "http_request", return_value={})
    with pytest.raises(Exception) as e:
        waf.policy_upsert_command(client, **demisto_args)
    assert str(e.value) == expected_error_msg


@pytest.mark.parametrize(
    "params, expected_results",
    [
        ({"auth_type": "Device Code"}, "When using device code flow configuration"),
        ({"auth_type": "Authorization Code"}, "When using user auth flow configuration"),
    ],
)
def test_test_module_command(mocker, params, expected_results):
    """
    Given:
        - Case 1: Integration params with 'Device' as auth_type.
        - Case 2: Integration params with 'User Auth' as auth_type.
    When:
        - Calling test-module command.
    Then
        - Assert the right exception was thrown.
        - Case 1: Should throw an exception related to Device-code-flow config and return True.
        - Case 2: Should throw an exception related to User-Auth-flow config and return True.
    """
    mocker.patch.object(waf, "test_connection", side_effect=Exception("mocked error"))
    mocker.patch.object(demisto, "params", return_value=params)
    with pytest.raises(Exception) as e:
        waf.test_module(None, {})
    assert expected_results in str(e.value)


@pytest.mark.parametrize(argnames="client_id", argvalues=["test_client_id", None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Given:
        - Managed Identities client id for authentication.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """

    from AzureWAF import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import AzureWAF

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {"managed_identities_client_id": {"password": client_id}, "auth_type": "Azure Managed Identities"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(AzureWAF, "return_results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in AzureWAF.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.management_azure]
    assert client_id and qs["client_id"] == [client_id] or "client_id" not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-waf-generate-login-url
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureWAF import main, Scopes
    import AzureWAF

    redirect_uri = "redirect_uri"
    tenant_id = "tenant_id"
    client_id = "client_id"
    mocked_params = {
        "redirect_uri": redirect_uri,
        "auth_type": "Authorization Code",
        "self_deployed": "True",
        "tenant_id": tenant_id,
        "app_id": client_id,
        "credentials": {"password": "client_secret"},
    }
    mocker.patch.object(demisto, "params", return_value=mocked_params)
    mocker.patch.object(demisto, "command", return_value="azure-waf-generate-login-url")
    mocker.patch.object(AzureWAF, "return_results")

    # call
    main()

    # assert
    expected_url = (
        f"[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        f"response_type=code&scope=offline_access%20{Scopes.management_azure}"
        f"&client_id={client_id}&redirect_uri={redirect_uri})"
    )
    res = AzureWAF.return_results.call_args[0][0].readable_output
    assert expected_url in res


def test_subscriptions_list_command(mocker):
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    expected_results = {
        "method": "GET",
        "full_url": "https://management.azure.com/subscriptions",
        "params": {"api-version": API_VERSION},
    }
    m = mocker.patch.object(
        client,
        "http_request",
        return_value={
            "value": [
                {
                    "id": "/subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb",
                    "authorizationSource": "Legacy, RoleBased",
                    "managedByTenants": [],
                    "subscriptionId": "0f907ea4-bc8b-4c11-9d7e-805c2fd144fb",
                    "tenantId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
                    "displayName": "Pay-As-You-Go",
                    "state": "Enabled",
                    "subscriptionPolicies": {
                        "locationPlacementId": "Public_2014-09-01",
                        "quotaId": "PayAsYouGo_2014-09-01",
                        "spendingLimit": "Off",
                    },
                },
                {
                    "id": "/subscriptions/057b1785-fd7b-4ca3-ad1b-709e4b1668be",
                    "authorizationSource": "RoleBased",
                    "managedByTenants": [],
                    "subscriptionId": "057b1785-fd7b-4ca3-ad1b-709e4b1668be",
                    "tenantId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
                    "displayName": "Access to Azure Active Directory",
                    "state": "Enabled",
                    "subscriptionPolicies": {
                        "locationPlacementId": "Public_2014-09-01",
                        "quotaId": "AAD_2015-09-01",
                        "spendingLimit": "On",
                    },
                },
            ]
        },
    )
    commandResult = waf.subscriptions_list_command(client)

    assert commandResult.readable_output == (
        "### Subscriptions: \n"
        "|displayName|state|subscriptionId|tenantId|\n"
        "|---|---|---|---|\n"
        "| Pay-As-You-Go | Enabled | 0f907ea4-bc8b-4c11-9d7e-805c2fd144fb | ebac1a16-81bf-449b-8d43-5732c3c1d999 |\n"
        "| Access to Azure Active Directory | Enabled | 057b1785-fd7b-4ca3-ad1b-709e4b1668be |"
        " ebac1a16-81bf-449b-8d43-5732c3c1d999 |\n"
    )
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("params") == expected_results.get("params")


def test_resource_group_list_command(mocker):
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    expected_results = {
        "method": "GET",
        "full_url": "https://management.azure.com/subscriptions/pol1/resourcegroups",
        "params": {"api-version": API_VERSION, "$top": 10},
    }
    demisto_args = {"subscription_id": "pol1", "verbose": "false", "limit": "10", "location": "east"}
    m = mocker.patch.object(
        client,
        "http_request",
        return_value={
            "value": [
                {
                    "id": "/subscriptions/pol1/resourceGroups/cloud-shell-storage-eastus",
                    "name": "cloud-shell-storage-eastus",
                    "type": "Microsoft.Resources/resourceGroups",
                    "location": "eastus",
                    "properties": {"provisioningState": "Succeeded"},
                },
                {
                    "id": "/subscriptions/pol1/resourceGroups/demisto",
                    "name": "demisto",
                    "type": "Microsoft.Resources/resourceGroups",
                    "location": "centralus",
                    "properties": {"provisioningState": "Succeeded"},
                },
                {
                    "id": "/subscriptions/pol1/resourceGroups/compute-integration",
                    "name": "compute-integration",
                    "type": "Microsoft.Resources/resourceGroups",
                    "location": "eastus",
                    "properties": {"provisioningState": "Succeeded"},
                },
            ]
        },
    )

    commandResult = waf.resource_group_list_command(client, **demisto_args)

    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert commandResult.readable_output == (
        "### Resource Groups: \n"
        "|Subscription ID pol1|\n"
        "|---|\n"
        "| [{'name': 'cloud-shell-storage-eastus', 'location': 'eastus', 'tags': {}, 'provisioningState': 'Succeeded'}],"
        "<br>[{'name': 'demisto', 'location': 'centralus', 'tags': {}, 'provisioningState': 'Succeeded'}],"
        "<br>[{'name': 'compute-integration', 'location': 'eastus', 'tags': {}, 'provisioningState': 'Succeeded'}] |\n"
    )
