import AzureWAF as waf
import demistomock as demisto
import pytest

API_VERSION = "2020-05-01"
FRONT_DOOR_API_VERSION = "2022-05-01"

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
    m = mocker.patch.object(client, "http_request", return_value={"properties": {"test": "test"}})
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
    side_effect = [Exception("Test"), {"properties": {"test2": "test2"}}]
    expected_outputs = [{"properties": "res1 threw Exception: Test"}, {"properties": {"test2": "test2"}}]
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
        ({"auth_type": "Device Code"}, "When using Device Code flow configuration"),
        ({"auth_type": "Authorization Code"}, "When using Authorization Code flow configuration"),
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

    import AzureWAF
    from AzureWAF import MANAGED_IDENTITIES_TOKEN_URL, Resources, main

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
    assert (client_id and qs["client_id"] == [client_id]) or "client_id" not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-waf-generate-login-url
        - Ensure the generated url are as expected.
    """
    # prepare
    import AzureWAF
    import demistomock as demisto
    from AzureWAF import Scopes, main

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


# Front Door WAF Policy Tests

FRONT_DOOR_GET_COMMAND_DATA = [
    (
        {"policy_name": "fd_pol1", "verbose": "false", "limit": "10"},  # args, case: default resource_group
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/\
FrontDoorWebApplicationFirewallPolicies/fd_pol1",
            "params": {"api-version": FRONT_DOOR_API_VERSION},
        },  # expected
    ),
    (
        {"verbose": "false", "limit": "10"},  # args, case: list of policies in default resource_group
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/test/providers/Microsoft.Network/\
FrontDoorWebApplicationFirewallPolicies",
            "params": {"api-version": FRONT_DOOR_API_VERSION},
        },  # expected
    ),
    (
        {"resource_group_name": ["fd_res1"], "verbose": "false", "limit": "10"},
        # args, case: list of policies in custom resource_group
        {
            "method": "GET",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/fd_res1/providers/Microsoft.Network/\
FrontDoorWebApplicationFirewallPolicies",
            "params": {"api-version": FRONT_DOOR_API_VERSION},
        },  # expected
    ),
]


@pytest.mark.parametrize("demisto_args,expected_results", FRONT_DOOR_GET_COMMAND_DATA)
def test_front_door_get_policy_by_resource_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument for Front Door policy

    When:
        - retrieving Front Door policy's data

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    m = mocker.patch.object(client, "http_request", return_value={"properties": {"test": "test"}})
    waf.front_door_policies_list_command(client, **demisto_args)
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("params") == expected_results.get("params")


def test_front_door_get_array_policy_with_exception(mocker):
    """
    Given:
        - search task's argument for Front Door policy

    When:
        - retrieving Front Door policy's data with multiple resource groups

    Then:
        - validating the body sent to request is matching the search and handles exceptions

    """
    demisto_args = {
        "policy_name": "fd_pol1",
        "resource_group_name": ["fd_res1", "fd_res2"],
        "verbose": "false",
        "limit": "10",
        "subscription_id": "sub1",
    }
    expected_results = {
        "method": "GET",
        "full_url": "https://management.azure.com/subscriptions/sub1/resourceGroups/fd_res2/providers/Microsoft.Network/\
FrontDoorWebApplicationFirewallPolicies/fd_pol1",
        "params": {"api-version": FRONT_DOOR_API_VERSION},
    }
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    side_effect = [Exception("Test"), {"properties": "test2"}]
    expected_outputs = [{"properties": "fd_res1 threw Exception: Test"}, {"properties": "test2"}]
    m = mocker.patch.object(client, "http_request", side_effect=side_effect)
    commandResult = waf.front_door_policies_list_command(client, **demisto_args)
    assert commandResult.outputs == expected_outputs
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("params") == expected_results.get("params")


def test_front_door_policies_list_all_in_subscription_command(mocker):
    """
    Given:
        - subscription_id argument

    When:
        - listing all Front Door policies in subscription

    Then:
        - validating the request is correct

    """
    demisto_args = {"verbose": "false", "limit": "10", "subscription_id": "sub1"}
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    m = mocker.patch.object(client, "http_request", return_value={"value": [{"name": "policy1", "id": "id1"}]})
    commandResult = waf.front_door_policies_list_all_in_subscription_command(client, **demisto_args)
    assert "FrontDoorWebApplicationFirewallPolicies" in m.call_args[1].get("full_url")
    assert m.call_args[1].get("method") == "GET"
    assert m.call_args[1].get("params") == {"api-version": FRONT_DOOR_API_VERSION}
    assert commandResult.outputs_prefix == "AzureWAF.FrontDoorPolicy"


FRONT_DOOR_UPSERT_COMMAND_DATA = [
    (
        {
            "policy_name": "fd_pol1",
            "resource_group_name": ["fd_res1"],
            "verbose": "false",
            "managed_rules": '{"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.0"}]}',
            "location": "global",
        },  # args, case: custom resource_group update rule
        {
            "method": "PUT",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/fd_res1/providers/Microsoft.Network/\
FrontDoorWebApplicationFirewallPolicies/fd_pol1",
            "params": {"api-version": FRONT_DOOR_API_VERSION},
            "body": {
                "location": "global",
                "properties": {"managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.0"}]}},
                "sku": {"name": "Classic_AzureFrontDoor"},
            },
        },  # expected
    ),
    (
        {
            "policy_name": "fd_pol1",
            "resource_group_name": ["fd_res1"],
            "verbose": "false",
            "managed_rules": '{"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.0"}]}',
            "custom_rules": '{"customRules": [{"name": "Rule1", "priority": 1}]}',
            "location": "global",
            "sku": "Premium_AzureFrontDoor",
        },  # args, case: custom resource_group update rule with custom rules and SKU
        {
            "method": "PUT",
            "full_url": "https://management.azure.com/subscriptions/test/resourceGroups/fd_res1/providers/Microsoft.Network/\
FrontDoorWebApplicationFirewallPolicies/fd_pol1",
            "params": {"api-version": FRONT_DOOR_API_VERSION},
            "body": {
                "location": "global",
                "properties": {
                    "customRules": {"customRules": [{"name": "Rule1", "priority": 1}]},
                    "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.0"}]},
                },
                "sku": {"name": "Premium_AzureFrontDoor"},
            },
        },  # expected
    ),
]


@pytest.mark.parametrize("demisto_args,expected_results", FRONT_DOOR_UPSERT_COMMAND_DATA)
def test_front_door_policy_upsert_request_body_happy(mocker, demisto_args, expected_results):
    """
    Given:
        - a Front Door policy to update or a new policy

    When:
        - updating or creating Front Door policy's data

    Then:
        - validating the body sent to request is matching the api requires

    """

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    m = mocker.patch.object(client, "http_request", return_value={"name": "fd_pol1", "id": "id", "properties": {}})
    waf.front_door_policy_upsert_command(client, **demisto_args)
    assert m.call_args[1].get("method") == expected_results.get("method")
    assert m.call_args[1].get("full_url") == expected_results.get("full_url")
    assert m.call_args[1].get("data") == expected_results.get("body")
    assert m.call_args[1].get("params") == expected_results.get("params")


def test_front_door_policy_array_group_names_upsert_request(mocker):
    """
    Given:
        - a Front Door policy to update or create with multiple resource groups

    When:
        - updating or creating Front Door policy's data across multiple resource groups

    Then:
        - validating the body sent to request is matching the API requirements
        - validating that all resource groups are processed successfully

    """
    demisto_args = {
        "policy_name": "fd_pol1",
        "resource_group_name": ["fd_res1", "fd_res2"],
        "verbose": "false",
        "managed_rules": '{"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.0"}]}',
        "custom_rules": '{"customRules": [{"name": "Rule1"}]}',
        "location": "global",
    }

    # Expected request body for both resource groups
    expected_body = {
        "location": "global",
        "properties": {
            "customRules": {"customRules": [{"name": "Rule1"}]},
            "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.0"}]},
        },
        "sku": {"name": "Classic_AzureFrontDoor"},
    }

    # Mock successful responses for both resource groups
    mock_response_1 = {"name": "fd_pol1", "id": "id1", "properties": {}}
    mock_response_2 = {"name": "fd_pol1", "id": "id2", "properties": {}}

    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )

    # Mock http_request to return successful responses for both calls
    m = mocker.patch.object(client, "http_request", side_effect=[mock_response_1, mock_response_2])

    # Execute the command
    commandResult = waf.front_door_policy_upsert_command(client, **demisto_args)

    # Verify the command returns both results
    assert commandResult.outputs is not None
    assert isinstance(commandResult.outputs, list)
    assert len(commandResult.outputs) == 2
    assert commandResult.outputs[0] == mock_response_1
    assert commandResult.outputs[1] == mock_response_2

    # Verify http_request was called twice (once per resource group)
    assert m.call_count == 2

    # Verify the first call (fd_res1)
    first_call = m.call_args_list[0][1]
    assert first_call.get("method") == "PUT"
    assert "fd_res1" in first_call.get("full_url")
    assert "FrontDoorWebApplicationFirewallPolicies/fd_pol1" in first_call.get("full_url")
    assert first_call.get("data") == expected_body
    assert first_call.get("params") == {"api-version": FRONT_DOOR_API_VERSION}

    # Verify the second call (fd_res2)
    second_call = m.call_args_list[1][1]
    assert second_call.get("method") == "PUT"
    assert "fd_res2" in second_call.get("full_url")
    assert "FrontDoorWebApplicationFirewallPolicies/fd_pol1" in second_call.get("full_url")
    assert second_call.get("data") == expected_body
    assert second_call.get("params") == {"api-version": FRONT_DOOR_API_VERSION}


FRONT_DOOR_UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {
            "resource_group_name": "fd_res1",
            "managed_rules": '{"test": "test"}',
            "location": "global",
            "verbose": "false",
        },  # args, case: missing policy name
        "In order to add/update Front Door policy, please provide policy_name and managed_rules.",  # expected
    ),
    (
        {"policy_name": "fd_pol1", "resource_group_name": "fd_res1", "location": "global"},
        # args, case: missing managed_rules
        "In order to add/update Front Door policy, please provide policy_name and managed_rules.",  # expected
    ),
]


@pytest.mark.parametrize("demisto_args,expected_error_msg", FRONT_DOOR_UPSERT_COMMAND_DATA_BAD_CASES)
def test_front_door_policy_upsert_request_body_fails(mocker, demisto_args, expected_error_msg):
    """
    Given:
        - a Front Door policy to update or a new policy

    When:
        - updating or creating Front Door policy's data without policy_name or managed_rules

    Then:
        - failing when missing required data

    """

    mocker.patch.object(demisto, "args", return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )
    mocker.patch.object(client, "http_request", return_value={})
    with pytest.raises(Exception) as e:
        waf.front_door_policy_upsert_command(client, **demisto_args)
    assert str(e.value) == expected_error_msg


def test_front_door_policy_delete_command(mocker):
    """
    Given:
        - policy_name and resource_group_name

    When:
        - deleting a Front Door policy

    Then:
        - validating the request is correct and returns proper message

    """
    demisto_args = {"policy_name": "fd_pol1", "resource_group_name": ["fd_res1"], "subscription_id": "test"}

    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )

    class MockResponse:
        status_code = 200

    m = mocker.patch.object(client, "http_request", return_value=MockResponse())
    mocker.patch.object(demisto, "dt", return_value=None)

    commandResult = waf.front_door_policy_delete_command(client, **demisto_args)

    assert "Front Door Policy fd_pol1 was deleted successfully" in commandResult.readable_output
    assert m.call_args[1].get("method") == "DELETE"
    assert "FrontDoorWebApplicationFirewallPolicies/fd_pol1" in m.call_args[1].get("full_url")
    assert m.call_args[1].get("params") == {"api-version": FRONT_DOOR_API_VERSION}


def test_front_door_policy_delete_command_not_found(mocker):
    """
    Given:
        - policy_name for a non-existent Front Door policy

    When:
        - deleting a Front Door policy

    Then:
        - validating the proper not found message is returned

    """
    demisto_args = {"policy_name": "fd_pol1", "resource_group_name": ["fd_res1"], "subscription_id": "test"}

    client = waf.AzureWAFClient(
        app_id="", subscription_id="test", resource_group_name="test", verify=True, proxy=False, auth_type="Device"
    )

    class MockResponse:
        status_code = 204

    mocker.patch.object(client, "http_request", return_value=MockResponse())
    mocker.patch.object(demisto, "dt", return_value=None)

    commandResult = waf.front_door_policy_delete_command(client, **demisto_args)

    assert "Front Door policy fd_pol1 was deleted or not found." in commandResult.readable_output
