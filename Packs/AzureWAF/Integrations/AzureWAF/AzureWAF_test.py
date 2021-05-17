import pytest
import AzureWAF as waf
import demistomock as demisto

GET_COMMAND_DATA = [
    (
        {'policy_name': 'pol1', 'resource_group_name': 'res1', 'verbose': 'false', 'limit': '10'},
        # args, case: custom resource_group
        {"method": "GET",
         "url_suffix":
             "/resourceGroups/res1/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/pol1"
         }  # expected
    ),
    (
        {'policy_name': 'pol1', 'verbose': 'false', 'limit': '10'},  # args, case: default resource_group
        {"method": "GET",
         "url_suffix":
             "/resourceGroups/test/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/pol1"
         }  # expected
    ),
    (
        {'verbose': 'false', 'limit': '10'},  # args, case: list of policies in default resourse_group
        {"method": "GET",
         "url_suffix":
             "/resourceGroups/test/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
         }  # expected
    ),
    (
        {'verbose': 'true', 'limit': '10'},  # args, case: list of policies in default resourse_group with full data
        {"method": "GET",
         "url_suffix":
             "/resourceGroups/test/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
         }  # expected
    ),
    (
        {'resource_group_name': 'res1', 'verbose': 'false', 'limit': '10'},
        # args, case: list of policies in custom resourse_group
        {"method": "GET",
         "url_suffix":
             "/resourceGroups/res1/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
         }  # expected
    ),

]


@pytest.mark.parametrize('demisto_args,expected_results', GET_COMMAND_DATA)
def test_get_policy_by_resource_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - retrieving policy's data

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id='',
        subscription_id='test',
        resource_group_name='test',
        verify=True,
        proxy=False
    )
    m = mocker.patch.object(client, 'http_request', return_value={'properties': 'test'})
    waf.policies_get_command(client, **demisto_args)
    assert m.call_args[1].get('url_suffix') == expected_results.get("url_suffix")
    assert m.call_args[1].get('method') == expected_results.get("method")


UPSERT_COMMAND_DATA = [
    (
        {'policy_name': 'pol1', 'resource_group_name': 'res1', 'verbose': 'false', 'limit': '10',
         'managed_rules': '{"test": "test"}', 'location': 'east'
         },  # args, case: custom resource_group update rule
        {"method": "PUT",
         "url_suffix":
             "/resourceGroups/res1/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/pol1",
         "body": {'location': 'east', 'properties': {'managedRules': {'test': 'test'}}}
         }  # expected
    ),
    (
        {'policy_name': 'pol1', 'resource_group_name': 'res1', 'verbose': 'false', 'limit': '10',
         'managed_rules': '{"test": "test"}', 'custom_rules': '{"test": "test"}', 'location': 'east'
         },  # args, case: custom resource_group update rule with key hierarchy
        {"method": "PUT",
         "url_suffix":
             "/resourceGroups/res1/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/pol1",
         "body": {'location': 'east', 'properties': {'customRules': {'test': 'test'},
                                                     'managedRules': {'test': 'test'}}}
         }  # expected
    ),

]


@pytest.mark.parametrize('demisto_args,expected_results', UPSERT_COMMAND_DATA)
def test_policy_upsert_request_body_happy(mocker, demisto_args, expected_results):
    """
    Given:
        - a policy to update or a new policy

    When:
        - updating or creating policy's data

    Then:
        - validating the body sent to request is matching the api requires

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id='',
        subscription_id='test',
        resource_group_name='test',
        verify=True,
        proxy=False
    )
    m = mocker.patch.object(client, 'http_request', return_value={'name': 'pol1', 'id': 'id', 'properties': {}})
    waf.policy_upsert_command(client, **demisto_args)
    assert m.call_args[1].get('method') == expected_results.get("method")
    assert m.call_args[1].get('url_suffix') == expected_results.get("url_suffix")
    assert m.call_args[1].get('data') == expected_results.get("body")


UPSERT_COMMAND_DATA_BAD_CASES = [
    (
        {'resource_group_name': 'res1',
         'managed_rules': '{"test": "test"}', 'location': 'east', 'verbose': 'false', 'limit': '10'
         },  # args, case: missing policy name
        "In order to add/ update policy, please provide policy_name, location and managed_rules. "  # expected
    ),
    (
        {'policy_name': 'pol1',
         'resource_group_name': 'res1',
         'location': 'east'
         },  # args, case: missing managed_rules
        "In order to add/ update policy, please provide policy_name, location and managed_rules. "  # expected
    ),
    (
        {'policy_name': 'pol1',
         'resource_group_name': 'res1',
         'managed_rules': '{"test": "test"}'
         },  # args, case: missing location
        "In order to add/ update policy, please provide policy_name, location and managed_rules. "  # expected
    ),

]


@pytest.mark.parametrize('demisto_args,expected_error_msg', UPSERT_COMMAND_DATA_BAD_CASES)
def test_policy_upsert_request_body_fails(mocker, demisto_args, expected_error_msg):
    """
    Given:
        - a policy to update or a new policy

    When:
        - updating or creating policy's data without policy_name, location or managed_rules.

    Then:
        - failing when missing required data

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = waf.AzureWAFClient(
        app_id='',
        subscription_id='test',
        resource_group_name='test',
        verify=True,
        proxy=False
    )
    mocker.patch.object(client, 'http_request', return_value={})
    with pytest.raises(Exception) as e:
        waf.policy_upsert_command(client, **demisto_args)
    assert str(e.value) == expected_error_msg
