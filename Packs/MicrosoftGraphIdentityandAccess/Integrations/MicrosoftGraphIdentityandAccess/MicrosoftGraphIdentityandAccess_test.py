import MicrosoftGraphIdentityandAccess
import pytest
from CommonServerPython import DemistoException, CommandResults
from MicrosoftApiModule import NotFoundError

ipv4 = {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "12.34.221.11/22"}  # noqa
ipv6 = {"@odata.type": "#microsoft.graph.iPv6CidrRange", "cidrAddress": "2001:0:9d38:90d6:0:0:0:0/63"}  # noqa


@pytest.mark.parametrize(
    "ips,expected",
    [
        ("12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63", [ipv4, ipv6]),
        ("12.34.221.11/22,12.34.221.11/22", [ipv4, ipv4]),
        ("2001:0:9d38:90d6:0:0:0:0/63,2001:0:9d38:90d6:0:0:0:0/63", [ipv6, ipv6]),
    ],
)
def test_ms_ip_string_to_list(ips, expected):
    """
    Given:
    -   Ips in a string

    When:
    -   Convetting them to an ip list.

    Then:
    - Ensure that the list we get is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.ms_ip_string_to_list(ips) == expected


@pytest.mark.parametrize("last,expected", [({"latest_detection_found": "2022-06-06"}, "2022-06-06")])
def test_get_last_fetch_time(last, expected):
    """
    Given:
    -   A dict with the last run details.

    When:
    -  Getting the last run time value.

    Then:
    - Ensure that the time is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.get_last_fetch_time(last, {}) == expected


@pytest.mark.parametrize("date,expected", [("2022-06-06", "2022-06-06.000")])
def test_date_str_to_azure_format(date, expected):
    """
    Given:
    -   A date to convert to Azure format.

    When:
    -  Converting the date value.

    Then:
    - Ensure that the date is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.date_str_to_azure_format(date) == expected


@pytest.mark.parametrize(
    "incident,expected",
    [
        ({}, {"name": "Azure AD:   ", "occurred": "2022-06-06Z", "rawJSON": "{}"}),
        (
            {"riskEventType": "3", "riskDetail": "2", "id": "1"},
            {
                "name": "Azure AD: 1 3 2",
                "occurred": "2022-06-06Z",
                "rawJSON": '{"riskEventType": "3", "riskDetail": "2", "id": "1"}',
            },
        ),
    ],
)
def test_detection_to_incident(incident, expected):
    """
    Given:
    -  A dict with the incident details.

    When:
    -  Getting the incident.

    Then:
    - Ensure that the dict is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.detection_to_incident(incident, "2022-06-06") == expected


@pytest.mark.parametrize(
    "incident,expected",
    [
        ({}, {"name": "Azure User at Risk:  -  - ", "occurred": "2025-05-06Z", "rawJSON": "{}"}),
        (
            {"userPrincipalName": "test", "riskLevel": "high", "riskState": "atRisk"},
            {
                "name": "Azure User at Risk: test - atRisk - high",
                "occurred": "2025-05-06Z",
                "rawJSON": '{"userPrincipalName": "test", "riskLevel": "high", "riskState": "atRisk"}',
            },
        ),
    ],
)
def test_risky_user_to_incident(incident, expected):
    """
    Given:
    -  A dict with the incident details.

    When:
    -  Getting the incident.

    Then:
    - Ensure that the dict is what we expected.
    """
    assert MicrosoftGraphIdentityandAccess.risky_user_to_incident(incident, "2025-05-06") == expected


@pytest.mark.parametrize(
    "incidents,expected",
    [
        ([], ([], "2025-05-14T01:00:00.0000000Z")),
        (
            [  # incidents input
                {
                    "userPrincipalName": "test",
                    "riskLevel": "medium",
                    "riskState": "atRisk",
                    "riskLastUpdatedDateTime": "2025-05-14T02:00:00.0000000Z",
                }
            ],  # expected output
            (
                [
                    {
                        "name": "Azure User at Risk: test - atRisk - medium",
                        "occurred": "2025-05-14T02:00:00.000000Z",
                        "rawJSON": '{"userPrincipalName": "test", "riskLevel": "medium", "riskState": "atRisk", "riskLastUpdatedDateTime": "2025-05-14T02:00:00.0000000Z"}',  # noqa: E501
                    }
                ],
                "2025-05-14T02:00:00.0000000Z",
            ),
        ),
    ],
)
def test_risky_users_to_incidents(incidents, expected):
    """
    Given:
    -  A dict with the incident details.

    When:
    -  Getting the incident.

    Then:
    - Ensure that the dict is what we expected.
    """
    assert MicrosoftGraphIdentityandAccess.risky_users_to_incidents(incidents, "2025-05-14T01:00:00.0000000Z") == expected


@pytest.mark.parametrize(
    "last_fetch,parameters,expected",
    [
        ("2025-05-06", {"alerts_to_fetch": "Risk Detections"}, "detectedDateTime gt 2025-05-06"),
        ("2025-05-06", {"alerts_to_fetch": "Risky Users"}, "riskLastUpdatedDateTime gt 2025-05-06"),
    ],
)
def test_build_filter(last_fetch, parameters, expected):
    """
    Given:
    -   A date to set a filter by.

    When:
    -  Doing an odata query.

    Then:
    - Ensure that the filter is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.build_filter(last_fetch, parameters) == expected


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
    import demistomock as demisto
    import MicrosoftGraphIdentityandAccess
    from MicrosoftGraphIdentityandAccess import MANAGED_IDENTITIES_TOKEN_URL, Resources, main

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        "managed_identities_client_id": {"password": client_id},
        "use_managed_identities": "True",
        "credentials": {"password": "pass"},
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(MicrosoftGraphIdentityandAccess, "return_results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in MicrosoftGraphIdentityandAccess.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert (client_id and qs["client_id"] == [client_id]) or "client_id" not in qs


@pytest.mark.parametrize(
    "expected_error",
    [
        (
            "Either enc_key or (Certificate Thumbprint and Private Key) must be provided. For "
            "further information see https://xsoar.pan.dev/docs/reference/articles/"
            "microsoft-integrations---authentication"
        )
    ],
)
def test_missing_creds_error_thrown(expected_error):
    """
    Given:
    - expected_error
    When:
    - Attempting to create a client without key or Certificate Thumbprint and Private Key
    Then:
    - Ensure that the right option was returned.
    - Case 1: Should return param.
    """
    from MicrosoftGraphIdentityandAccess import Client

    with pytest.raises(DemistoException) as e:
        Client("", False, False, client_credentials=True)
    assert str(e.value.message) == expected_error


def test_list_role_members_command(mocker):
    """
    Given:
    - A client
    - A role ID which does not exist or invalid

    When:
    - Executing the command 'msgraph-identity-directory-role-members-list'

    Then:
    - Ensure the Exception is caught and a CommandResults with an informative readable_output is returned
    """
    from MicrosoftGraphIdentityandAccess import Client, list_role_members_command

    client = Client("", False, False)
    message = "Resource '0000c00f' does not exist or one of its queried reference-property objects are not present."
    mocker.patch.object(Client, "get_role_members", side_effect=NotFoundError(message=message))
    result = list_role_members_command(ms_client=client, args={"role_id": "0000c00f", "limit": 1})
    assert result.readable_output == "Role ID: 0000c00f, was not found or invalid"
        
@pytest.mark.parametrize(
    "args, policies_response, expected_outputs, expected_readable_output, expected_prefix, expected_key_field",
    [
        # Case 1: Multiple policies with limit
        (
            {"limit": "2"},
            [
                {"id": "policy1", "displayName": "Policy One", "state": "enabled",
                 "conditions": {"users": {"includeUsers": ["user1"], "excludeUsers": ["user2"]}}},
                {"id": "policy2", "displayName": "Policy Two", "state": "disabled",
                 "conditions": {"users": {"includeUsers": ["user3"], "excludeUsers": []}}},
                {"id": "policy3", "displayName": "Policy Three", "state": "enabled"}
            ],
            [
                {"id": "policy1", "displayName": "Policy One", "state": "enabled",
                 "conditions": {"users": {"includeUsers": ["user1"], "excludeUsers": ["user2"]}}},
                {"id": "policy2", "displayName": "Policy Two", "state": "disabled",
                 "conditions": {"users": {"includeUsers": ["user3"], "excludeUsers": []}}}
            ],
            "Policy One",  # Just checking a substring from one of the expected policies
            "MSGraphIdentity.ConditionalAccessPolicy",
            "ID"
        ),
        
        # Case 2: Filter query
        (
            {"filter": "state eq 'enabled'"},
            [
                {"id": "policy1", "displayName": "Policy One", "state": "enabled"}
            ],
            [
                {"id": "policy1", "displayName": "Policy One", "state": "enabled"}
            ],
            "Policy One",
            "MSGraphIdentity.ConditionalAccessPolicy",
            "ID"
        ),
        
        # Case 3: all_results=False (default limit = 50)
        (
            {"all_results": "false"},
            [{"id": f"policy{i}", "displayName": f"Policy {i}", "state": "enabled"} for i in range(1, 55)],
            [{"id": f"policy{i}", "displayName": f"Policy {i}", "state": "enabled"} for i in range(1, 51)],
            "Policy 1",
            "MSGraphIdentity.ConditionalAccessPolicy",
            "ID"
        ),
        
        # Case 4: Empty policies list
        (
            {},
            [],
            None,
            "No Conditional Access policies found",
            None,
            None
        )
    ]
)
def test_list_conditional_access_policies_command_scenarios(
    mocker, args, policies_response, expected_outputs, expected_readable_output, expected_prefix, expected_key_field
):
    """
    Given:
        - Different cases for listing conditional access policies:
          - Multiple policies with limit
          - Filter query
          - Multiple policies with default limiting
          - Empty policies list
    When:
        - Calling list_conditional_access_policies_command
    Then:
        - Verify correct outputs and readable output are generated
        - Verify the correct number of policies are returned based on limits
        - Verify empty response is handled correctly
    """
    from MicrosoftGraphIdentityandAccess import Client, list_conditional_access_policies_command
    
    mock_client = mocker.Mock(spec=Client)
    mock_client.list_conditional_access_policies.return_value = policies_response
    
    result = list_conditional_access_policies_command(mock_client, args)
    
    # Check that we got a CommandResults object
    assert isinstance(result, CommandResults)
    
    # Check for empty policies case
    if not policies_response:
        assert expected_readable_output in result.readable_output
        assert result.outputs is None
        return
    
    # Check outputs match expected
    assert result.outputs == expected_outputs
    
    # Check prefix and key field
    assert result.outputs_prefix == expected_prefix
    assert result.outputs_key_field == expected_key_field
    
    # Check readable output contains expected policy names
    assert expected_readable_output in result.readable_output

@pytest.mark.parametrize(
    "args, expected_exception_message",
    [
        # Case: both policy_id and filter provided
        (
            {"policy_id": "abc123", "filter": "state eq 'enabled'"},
            "Cannot provide both policy_id and filter_query at the same time"
        ),
    ]
)
def test_list_conditional_access_policies_command_invalid_args(mocker, args, expected_exception_message):
    """
    Given:
        - Invalid combinations of arguments (both policy_id and filter)
    When:
        - Calling list_conditional_access_policies_command
    Then:
        - Verify appropriate exceptions are raised
    """
    from MicrosoftGraphIdentityandAccess import Client, list_conditional_access_policies_command, DemistoException
    
    mock_client = mocker.Mock(spec=Client)
    
    with pytest.raises(DemistoException) as e:
        list_conditional_access_policies_command(mock_client, args)
    
    assert expected_exception_message in str(e.value)
    
@pytest.mark.parametrize(
    "args, expected_policy, mock_response, expected_output",
    [
        # Case: Only JSON policy provided
        (
            {"policy": '{"displayName": "Test Policy", "state": "enabled"}'},
            {"displayName": "Test Policy", "state": "enabled"},
            CommandResults(readable_output="Conditional Access policy policy123 was successfully created.",
                           outputs={"id": "policy123"}),
            "Conditional Access policy policy123 was successfully created.",
        ),
        # Case: JSON policy with empty elements that should be removed
        (
        {
            "policy": (
                '{'
                '"displayName": "Clean Policy", '
                '"state": "enabled", '
                '"conditions": {'
                    '"users": {'
                        '"includeUsers": [], '
                        '"excludeUsers": null'
                    '}'
                '}'
                '}'
            )
        },
            {"displayName": "Clean Policy", "state": "enabled", "conditions": {"users": {"includeUsers": []}}},
            CommandResults(readable_output="Conditional Access policy policy123 was successfully created.",
                           outputs={"id": "policy123"}),
            "Conditional Access policy policy123 was successfully created.",
        ),
        # Case: Build policy from structured args
        (
            {
                "policy_name": "Structured Policy",
                "state": "enabled",
                "client_app_types": "browser,mobileAppsAndDesktopClients",
                "include_users": "user1,user2",
                "include_groups": "group1",
                "exclude_users": "admin1",
                "sign_in_risk_levels": "high",
                "user_risk_levels": "medium",
                "platform_include": "android,iOS",
                "grant_controls_operator": "AND",
                "grant_controls": "block",
                "session_controls": "cloudAppSecurity"
            },
            {
                "displayName": "Structured Policy",
                "state": "enabled",
                "conditions": {
                    "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
                    "users": {
                        "includeUsers": ["user1", "user2"],
                        "includeGroups": ["group1"],
                        "excludeUsers": ["admin1"]
                    },
                    "signInRiskLevels": ["high"],
                    "userRiskLevels": ["medium"],
                    "platforms": {
                        "includePlatforms": ["android", "iOS"]
                    }
                },
                "grantControls": {
                    "operator": "AND",
                    "builtInControls": ["block"]
                },
                "sessionControls": {
                    "cloudAppSecurity": {}
                }
            },
            CommandResults(readable_output="Conditional Access policy policy123 was successfully created.",
                           outputs={"id": "policy123"}),
            "Conditional Access policy policy123 was successfully created.",
        ),
        # Case: Invalid JSON string in policy argument
        (
            {"policy": "{displayName: Test Policy, state: enabled}"},  # Missing quotes
            None,
            None,
            "The provided policy string is not a valid JSON",
        ),
        # Case: Empty policy argument but missing required fields for building policy
        (
            {
                "policy_name": "Missing Fields Policy",
                "state": "enabled",
                "sign_in_risk_levels": "low",
                "user_risk_levels": "low"
            },
            None,
            None,
            "Missing required field(s): client_app_types",
        ),
    ]
)
def test_create_conditional_access_policy_command(mocker, args, expected_policy, mock_response,
                                                  expected_output):
    """
    Tests the create_conditional_access_policy_command function with various inputs.
    
    Tests:
    - Providing a JSON policy directly
    - Providing a JSON policy with empty elements that should be cleaned
    - Building policy from structured arguments
    - Invalid JSON string handling
    - Missing required fields for policy building
    """
    from MicrosoftGraphIdentityandAccess import create_conditional_access_policy_command, Client, DemistoException
    
    mock_client = mocker.Mock(spec=Client)
    
    if expected_policy:
        # For successful cases, mock the client method
        mock_client.create_conditional_access_policy.return_value = mock_response
        
        # If this is a case where build_policy should be called
        if "policy" not in args or not args["policy"]:
            mocker.patch("MicrosoftGraphIdentityandAccess.build_policy", return_value=expected_policy)
            
        mocker.patch("MicrosoftGraphIdentityandAccess.remove_empty_elements", return_value=expected_policy)
        
        result = create_conditional_access_policy_command(mock_client, args)
        assert isinstance(result, CommandResults)
        assert expected_output in result.readable_output
        
        # Verify client was called with the right policy
        if "policy" in args and args["policy"] and isinstance(args["policy"], str):
            # If policy is a JSON string, it should be parsed then passed
            mock_client.create_conditional_access_policy.assert_called_once()
            # We can't easily verify the exact arg value since it depends on the json parsing
        else:
            # For structured args, verify build_policy was called
            mock_client.create_conditional_access_policy.assert_called_once_with(expected_policy)
    else:
        # For error cases
        if "policy" in args and args["policy"] and isinstance(args["policy"], str) and "Invalid JSON" in expected_output:
            # Invalid JSON string case
            with pytest.raises(DemistoException) as e:
                create_conditional_access_policy_command(mock_client, args)
            assert expected_output in str(e.value)
        else:
            # Missing required fields case
            mocker.patch("MicrosoftGraphIdentityandAccess.build_policy", side_effect=DemistoException(expected_output))
            with pytest.raises(DemistoException) as e:
                create_conditional_access_policy_command(mock_client, args)
            assert expected_output in str(e.value)

@pytest.mark.parametrize(
    "field, existing_list, new_list, expected, expected_messages",
    [
        # Test for signInRiskLevels specific handling
        ("signInRiskLevels", ["low"], ["medium", "high"], sorted(["low", "medium", "high"]), []),
        
        # Test for signInRiskLevels with 'none' value
        ("signInRiskLevels", ["none"], ["low"], sorted(["none", "low"]), []),
        
        # Test with None value (lowercase)
        ("includeUsers", ["none"], ["user1"], ["user1"], []),
        
        # Test with multiple None values
        ("includeGroups", ["None"], ["group1"], ["group1"], []),
        
        # Test with special value 'all' (lowercase)
        (
            "includeUsers",
            ["all"],
            ["user2"],
            ["all"],
            ["Field 'includeUsers' kept as 'all' (special value cannot be merged).\n"
             "To update this field, use update_action='override'."]
        ),
        
        # Test with mixed case in existing list (normal values)
        ("includeUsers", ["User1", "USER2"], ["user3"], sorted(["User1", "USER2", "user3"]), []),
        
        # Test when new list contains multiple special values
        ("includeLocations", ["loc1"], ["All"], ["All"], []),
        
        # Test with duplicated values between existing and new lists
        ("includeUsers", ["user1", "user2"], ["user2", "user3"], sorted(["user1", "user2", "user3"]), []),
        
        # Test with both lists containing the same values
        ("includeGroups", ["group1", "group2"], ["group1", "group2"], sorted(["group1", "group2"]), []),
    ]
)
def test_resolve_merge_value_advanced_cases(field, existing_list, new_list, expected, expected_messages):
    """
    Given:
        - Different field types (signInRiskLevels, includeUsers, etc.)
        - Various combinations of existing and new lists
        - Special values, case variations, and duplicates
    When:
        - Calling resolve_merge_value to merge these lists
    Then:
        - Verify the correct merging logic is applied based on field type and list content
        - Verify appropriate messages are generated for special cases
    """
    from MicrosoftGraphIdentityandAccess import resolve_merge_value
    
    messages = []
    result = resolve_merge_value(field, existing_list, new_list, messages)
    assert sorted(result) == sorted(expected)
    assert messages == expected_messages
    
@pytest.mark.parametrize(
    "base_existing, new_dict, expected_messages, expected_new",
    [
        # Test Case 1: Merging nested list fields
        (
            {"state": "disabled"},
            {"state": "enabled"},
            ["Field `state` is not a list - overriding the value."],
            {"state": "enabled"}
        ),
        # Test Case 2: Field doesn't exist in base
        (
            {"conditions": {"locations": None}},
            {"conditions": {"locations": ["AllTrusted"]}},
            ["Field `conditions/locations` was empty - new list left untouched."],
            {"conditions": {"locations": ["AllTrusted"]}}
        ),
        # Test Case 3: Empty dictionaries in path
        (
            {"conditions": {}},
            {"conditions": {"users": {"includeUsers": ["user1"]}}},
            ["Field `conditions/users/includeUsers` was empty - new list left untouched."],
            {"conditions": {"users": {"includeUsers": ["user1"]}}}
        ),
    ]
)
def test_merge_policy_section(mocker, base_existing, new_dict, expected_messages, expected_new):
    """
    Tests the merge_policy_section function with various test cases.
    
    Tests:
    - Merging list fields at different nesting levels
    - Handling fields that don't exist in the base
    - Empty dictionaries in the path
    """
    from MicrosoftGraphIdentityandAccess import merge_policy_section
    
    # Mock the resolve_merge_value function to return the new value
    # This isolates the test to focus on merge_policy_section's behavior
    mocker.patch(
        "MicrosoftGraphIdentityandAccess.resolve_merge_value",
        side_effect=lambda field, existing, new, msgs: new
    )
    
    # Copy the dictionaries to avoid modifying the test parameters
    import copy
    base_copy = copy.deepcopy(base_existing)
    new_copy = copy.deepcopy(new_dict)
    
    # Run the function
    messages = []
    merge_policy_section(base_copy, new_copy, messages)
    
    # Verify the messages match expected
    assert sorted(messages) == sorted(expected_messages)
    
    # Verify the new dictionary was modified as expected
    assert new_copy == expected_new

def test_merge_policy_section_with_actual_resolve_logic(mocker):
    """
    Tests the merge_policy_section function with the actual resolve_merge_value logic.
    This test verifies that:
    1. Lists in nested structures are properly merged (includeUsers, excludeUsers)
    2. The merge operation correctly combines values from both dictionaries
    3. No error messages are generated during a standard merge operation
    4. The integrated behavior of merge_policy_section and resolve_merge_value functions works as expected
    """

    from MicrosoftGraphIdentityandAccess import merge_policy_section
    
    # Define test data with list fields that should be merged
    base_existing = {
        "conditions": {
            "users": {
                "includeUsers": ["user1", "user2"],
                "excludeUsers": ["admin1"]
            }
        }
    }
    
    new_dict = {
        "conditions": {
            "users": {
                "includeUsers": ["user3"],
                "excludeUsers": ["admin2"]
            }
        }
    }
    
    # Expected result after merging
    expected_new = {
        "conditions": {
            "users": {
                "includeUsers": ["user1", "user2", "user3"],
                "excludeUsers": ["admin1", "admin2"]
            }
        }
    }
    
    # Run the merge
    messages = []
    merge_policy_section(base_existing, new_dict, messages)
    
    # Sort the lists to ensure consistent comparison
    new_dict["conditions"]["users"]["includeUsers"].sort()
    new_dict["conditions"]["users"]["excludeUsers"].sort()
    expected_new["conditions"]["users"]["includeUsers"].sort()
    expected_new["conditions"]["users"]["excludeUsers"].sort()
    
    # Verify the result matches expected
    assert new_dict == expected_new
    
    # Verify no error messages were generated
    assert len(messages) == 0

def test_merge_policy_section_with_special_values(mocker):
    """
    Tests the merge_policy_section function when special values like 'All' are present in lists.
    This verifies that special values are preserved during merging and appropriate messages are generated.
    The test checks that:
    1. When 'All' is in includeUsers, it remains and is not merged with other values
    2. Regular lists (like excludeUsers) are properly merged
    3. A warning message is generated when a special value is encountered
    """
    from MicrosoftGraphIdentityandAccess import merge_policy_section
    
    # Define test data with special values
    base_existing = {
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": ["admin1"]
            }
        }
    }
    
    new_dict = {
        "conditions": {
            "users": {
                "includeUsers": ["user1"],
                "excludeUsers": ["admin2"]
            }
        }
    }
    
    # Expected result should keep 'All' value
    expected_new = {
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": ["admin1", "admin2"]
            }
        }
    }
    
    # Run the merge
    messages = []
    merge_policy_section(base_existing, new_dict, messages)
    
    # Sort the excludeUsers list for consistent comparison
    new_dict["conditions"]["users"]["excludeUsers"].sort()
    expected_new["conditions"]["users"]["excludeUsers"].sort()
    
    # Verify the result matches expected
    assert new_dict["conditions"]["users"]["includeUsers"] == ["All"]
    assert sorted(new_dict["conditions"]["users"]["excludeUsers"]) == sorted(expected_new["conditions"]["users"]["excludeUsers"])
    
    # Verify the message about special value was generated
    assert any("special value" in msg for msg in messages)
    
@pytest.mark.parametrize(
    "args, expected_policy",
    [
        (
            {
                "policy_name": "Test Policy",
                "state": "enabled",
                "sign_in_risk_levels": "high",
                "user_risk_levels": "medium",
                "client_app_types": "browser,mobileAppsAndDesktopClients",
                "include_users": "user1,user2",
                "exclude_users": "admin1",
                "grant_control_enforcement": "mfa",
                "grant_control_operator": "AND",
                
            },
            {
                "displayName": "Test Policy",
                "state": "enabled",
                "conditions": {
                    "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
                    "applications": {
                        "includeApplications": [],
                        "excludeApplications": [],
                        "includeUserActions": [],
                    },
                    "users": {
                        "includeUsers": ["user1", "user2"],
                        "excludeUsers": ["admin1"],
                        "includeRoles": [],
                        "excludeRoles": [],
                        "includeGroups": [],
                        "excludeGroups": [],
                    },
                    "platforms": {
                        "includePlatforms": [],
                        "excludePlatforms": [],
                    },
                    "locations": {
                        "includeLocations": [],
                        "excludeLocations": [],
                    },
                    "signInRiskLevels": ["high"],
                    "userRiskLevels": ["medium"],
                },
                "grantControls": {
                    "operator": "AND",
                    "builtInControls": ["mfa"]
                }
            },
        ),
        (
            {
                "policy_name": "Complete Policy",
                "state": "disabled",
                "sign_in_risk_levels": "high,medium",
                "user_risk_levels": "low",
                "client_app_types": "browser",
                "include_applications": "Office365",
                "exclude_applications": "Salesforce",
                "include_user_actions": "urn:user:registerSecurityInfo",
                "include_users": "All",
                "exclude_users": "admin1,admin2",
                "include_roles": "GlobalAdmin",
                "exclude_roles": "Reader",
                "include_groups": "group1,group2",
                "exclude_groups": "group3",
                "include_platforms": "android,iOS",
                "exclude_platforms": "windows",
                "include_locations": "AllTrusted",
                "exclude_locations": "loc1",
                "grant_control_operator": "OR",
                "grant_control_enforcement": "block,mfa"
            },
            {
                "displayName": "Complete Policy",
                "state": "disabled",
                "conditions": {
                    "clientAppTypes": ["browser"],
                    "applications": {
                        "includeApplications": ["Office365"],
                        "excludeApplications": ["Salesforce"],
                        "includeUserActions": ["urn:user:registerSecurityInfo"],
                    },
                    "users": {
                        "includeUsers": ["All"],
                        "excludeUsers": ["admin1", "admin2"],
                        "includeRoles": ["GlobalAdmin"],
                        "excludeRoles": ["Reader"],
                        "includeGroups": ["group1", "group2"],
                        "excludeGroups": ["group3"],
                    },
                    "platforms": {
                        "includePlatforms": ["android", "iOS"],
                        "excludePlatforms": ["windows"],
                    },
                    "locations": {
                        "includeLocations": ["AllTrusted"],
                        "excludeLocations": ["loc1"],
                    },
                    "signInRiskLevels": ["high", "medium"],
                    "userRiskLevels": ["low"],
                },
                "grantControls": {
                    "operator": "OR",
                    "builtInControls": ["block", "mfa"]
                }
            },
        ),
    ]
)
def test_build_policy(args, expected_policy):
    """
    Tests the build_policy function with various input sets.
    
    This test covers:
    - Only some of the fields populated
    - Full policy with all options populated
    """
    from MicrosoftGraphIdentityandAccess import build_policy
    

    policy = build_policy(args)
    assert policy == expected_policy
        
@pytest.mark.parametrize(
    "policy_id, response_mock, expected_output, expected_exception",
    [
        # Case 1: Successful deletion
        (
            "policy123",
            {"status_code": 204, "text": ""},
            "Conditional Access policy policy123 was successfully deleted.",
            None
        ),
        # Case 2: Policy not found
        (
            "nonexistent",
            DemistoException("Error deleting Conditional Access policy nonexistent."),
            None,
            DemistoException("Error deleting Conditional Access policy nonexistent."),
        ),
    ]
)
def test_delete_conditional_access_policy_command(mocker, policy_id, response_mock, expected_output, expected_exception):
    """
    Tests the delete_conditional_access_policy_command function with various input sets.
    
    This test covers:
    - Successful policy deletion
    - Policy not found scenarios
    """
    from MicrosoftGraphIdentityandAccess import delete_conditional_access_policy_command, Client
    
    mock_client = mocker.Mock(spec=Client)
    
    if isinstance(response_mock, DemistoException):
        mock_client.delete_conditional_access_policy.side_effect = response_mock
    else:
        mock_response = mocker.Mock()
        if response_mock:
            mock_response.status_code = response_mock["status_code"]
            mock_response.text = response_mock["text"]
        mock_client.delete_conditional_access_policy.return_value = CommandResults(readable_output=expected_output)
    
    if expected_exception:
        with pytest.raises(type(expected_exception)) as e:
            delete_conditional_access_policy_command(mock_client, {"policy_id": policy_id})
        assert str(e.value) == str(expected_exception)
    else:
        result = delete_conditional_access_policy_command(mock_client, {"policy_id": policy_id})
        assert isinstance(result, CommandResults)
        assert result.readable_output == expected_output
        
        # If no exception, verify client was called correctly
        if policy_id and not isinstance(response_mock, DemistoException):
            mock_client.delete_conditional_access_policy.assert_called_once_with(policy_id)
            
@pytest.mark.parametrize(
    "args, existing_policy, new_policy_built, mock_result, expected_messages, expected_output",
    [
        # Case 1: Basic append mode with no special values
        (
            {
                "policy_id": "policy123",
                "update_action": "append",
                "include_users": "user3",
                "state": "enabled"
            },
            [{
                "id": "policy123",
                "state": "disabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["user1", "user2"]
                    }
                }
            }],
            {
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["user3"]
                    }
                }
            },
            CommandResults(readable_output="Conditional Access policy policy123 was successfully updated."),
            [],
            "Conditional Access policy policy123 was successfully updated."
        ),
        # Case 2: Append mode with special value in existing policy
        (
            {
                "policy_id": "policy123",
                "update_action": "append",
                "include_users": "user3",
                "state": "enabled"
            },
            [{
                "id": "policy123",
                "state": "disabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"]
                    }
                }
            }],
            {
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["user3"]
                    }
                }
            },
            CommandResults(readable_output="Conditional Access policy policy123 was successfully updated."),
            ["Field 'includeUsers' kept as 'All' (special value cannot be merged).\n"
             "To update this field, use update_action='override'."],
            "Conditional Access policy policy123 was successfully updated.\n\nNote:\n"
            "Field 'includeUsers' kept as 'All' (special value cannot be merged).\n"
            "To update this field, use update_action='override'."
        ),
        # Case 3: Override mode
        (
            {
                "policy_id": "policy123",
                "update_action": "override",
                "include_users": "user3",
                "state": "enabled"
            },
            [],  # Not used in override mode
            {
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["user3"]
                    }
                }
            },
            CommandResults(readable_output="Conditional Access policy policy123 was successfully updated."),
            [],
            "Conditional Access policy policy123 was successfully updated."
        ),
        # Case 4: Direct policy provided as JSON string
        (
            {
                "policy_id": "policy123",
                "policy": '{"state": "enabled", "conditions": {"users": {"includeUsers": ["user3"]}}}'
            },
            [],  # Not used when direct policy is provided
            {},  # Not used when direct policy is provided
            CommandResults(readable_output="Conditional Access policy policy123 was successfully updated."),
            [],
            "Conditional Access policy policy123 was successfully updated."
        ),
    ]
)
def test_update_conditional_access_policy_command(mocker, args, existing_policy, new_policy_built,
                                                 mock_result, expected_messages, expected_output):
    """
        Parametrized test for update_conditional_access_policy_command function.
        
        Tests different scenarios for updating conditional access policies:
        - Case 1: Append mode with modifying excludes
        - Case 2: Append mode with special value handling
        - Case 3: Override mode
        - Case 4: Direct policy provided as JSON string
        
        Args:
            mocker: pytest fixture for mocking
            args: command arguments for the function under test
            existing_policy: policy to be returned by list_conditional_access_policies
            new_policy_built: policy returned by build_policy
            mock_result: mock result to be returned by update_conditional_access_policy
            expected_messages: messages expected to be added during policy merging
            expected_output: expected human-readable output in CommandResults
    """
    from MicrosoftGraphIdentityandAccess import update_conditional_access_policy_command, Client
    
    mock_client = mocker.Mock(spec=Client)
    mock_client.list_conditional_access_policies.return_value = existing_policy
    mock_client.update_conditional_access_policy.return_value = mock_result
    
    # Mock build_policy to return our predefined policy
    mocker.patch("MicrosoftGraphIdentityandAccess.build_policy", return_value=new_policy_built)
    
    # Mock remove_empty_elements to return the same policy (no empty elements)
    mocker.patch("MicrosoftGraphIdentityandAccess.remove_empty_elements", return_value=new_policy_built)
    
    # Mock merge_policy_section to add our expected messages
    def mock_merge(existing, new, messages):
        messages.extend(expected_messages)
    
    mocker.patch("MicrosoftGraphIdentityandAccess.merge_policy_section", side_effect=mock_merge)
    
    # Mock return_results to avoid affecting test output
    mocker.patch("MicrosoftGraphIdentityandAccess.return_results")
    
    result = update_conditional_access_policy_command(mock_client, args)
    
    assert isinstance(result, CommandResults)
    assert result.readable_output == expected_output
    
    # Check client method calls based on the scenario
    if "policy" in args:
        # For direct policy JSON case
        mock_client.update_conditional_access_policy.assert_called_once()
        assert mock_client.list_conditional_access_policies.call_count == 0
    elif args.get("update_action") == "append":
        # For append mode
        mock_client.list_conditional_access_policies.assert_called_once_with(args["policy_id"])
        mock_client.update_conditional_access_policy.assert_called_once_with(args["policy_id"], new_policy_built)
    else:
        # For override mode
        assert mock_client.list_conditional_access_policies.call_count == 0
        mock_client.update_conditional_access_policy.assert_called_once_with(args["policy_id"], new_policy_built)

@pytest.mark.parametrize(
    "root, path, expected",
    [
        # Basic nested dictionary access
        ({"a": {"b": {"c": "value"}}}, ["a", "b", "c"], "value"),
        
        # Non-existent key in path
        ({"a": {"b": {"c": "value"}}}, ["a", "b", "d"], None),
        
        # Empty path
        ({"a": {"b": {"c": "value"}}}, [], {"a": {"b": {"c": "value"}}}),
        
        # Path with non-existent root key
        ({"a": {"b": {"c": "value"}}}, ["x", "y", "z"], None),
        
        # Path with mixed types
        ({"a": {"b": [1, 2, {"c": "value"}]}}, ["a", "b"], [1, 2, {"c": "value"}]),
        
        # Root is empty dictionary
        ({}, ["a", "b", "c"], None),
        
        # Path that's partially valid (exists until a point)
        ({"a": {"b": {"c": "value"}}}, ["a", "b", "c", "d"], None),
        
        # Dictionary with numerical keys
        ({1: {2: {3: "value"}}}, [1, 2, 3], "value"),
        
        # Access to nested None value
        ({"a": {"b": None}}, ["a", "b"], None),
        
        # Dictionary with special characters in keys
        ({"a": {"@special": {"$key": "value"}}}, ["a", "@special", "$key"], "value"),
    ],
)
def test_deep_get(root, path, expected):
    """
    Test the deep_get function with various inputs.
    
    Tests:
    - Basic dictionary traversal
    - Handling of non-existent keys
    - Empty path
    - Non-existent root keys
    - Accessing different data types
    - Empty dictionaries
    - Paths longer than the nesting
    - Numerical keys
    - Handling None values
    - Special characters in keys
    """
    from MicrosoftGraphIdentityandAccess import deep_get
    
    result = deep_get(root, path)
    assert result == expected
    
@pytest.mark.parametrize(
    "root, path, value, expected",
    [
        # Basic test - create a new nested structure
        ({}, ["a", "b", "c"], 42, {"a": {"b": {"c": 42}}}),
        
        # Test with existing root dictionary
        ({"x": 1}, ["a", "b", "c"], 42, {"x": 1, "a": {"b": {"c": 42}}}),
        
        # Test with partial existing path
        ({"a": {"b": {}}}, ["a", "b", "c"], 42, {"a": {"b": {"c": 42}}}),
        
        # Test with fully existing path (overwrite value)
        ({"a": {"b": {"c": 10}}}, ["a", "b", "c"], 42, {"a": {"b": {"c": 42}}}),
        
        # Test with single level path
        ({}, ["key"], "value", {"key": "value"}),
        
        # Test with different value types
        ({}, ["a", "b"], [1, 2, 3], {"a": {"b": [1, 2, 3]}}),
        ({}, ["a", "b"], {"nested": "dict"}, {"a": {"b": {"nested": "dict"}}}),
        ({}, ["a", "b"], None, {"a": {"b": None}}),
        
        # Test with mixed key types (though not recommended, it's technically possible)
        ({"a": {}}, ["a", 1], "value", {"a": {1: "value"}}),
        
        # Test with empty path - not practical but edge case handling
        ({}, [], ValueError, {}),
    ],
)
def test_deep_set(root, path, value, expected):
    """
    Tests the deep_set function with various cases.
    
    Given:
    - A root dictionary
    - A path to set
    - A value to set at that path
    
    When:
    - deep_set is called with these parameters
    
    Then:
    - The dictionary is updated correctly for valid inputs
    - For invalid inputs (like empty path), an error is raised
    """
    # Make a copy of the root to avoid modifying the test data
    root_copy = root.copy()
    
    if value is ValueError:
        with pytest.raises(IndexError):
            MicrosoftGraphIdentityandAccess.deep_set(root_copy, path, "any_value")
    else:
        MicrosoftGraphIdentityandAccess.deep_set(root_copy, path, value)
        assert root_copy == expected

