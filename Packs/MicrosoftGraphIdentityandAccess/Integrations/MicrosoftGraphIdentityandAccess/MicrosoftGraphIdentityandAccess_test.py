import MicrosoftGraphIdentityandAccess
import pytest
from CommonServerPython import DemistoException
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
    "field, existing_list, new_list, expected, expected_messages",
    [
        # Test replacing 'None' with new values
        ("includeUsers", ["None"], ["user1"], ["user1"], []),

        # Test existing 'All' - should not update
        (
            "includeUsers",
            ["All"],
            ["user1"],
            ["All"],
            ["Note: The field 'includeUsers' was not updated because it currently holds the special value 'All'."
             " This value cannot be merged with others. All other updates were applied."
             " To update this field, use update_action='override'."]
        ),

        # Test existing 'AllTrusted' - should not update
        (
            "includeLocations",
            ["AllTrusted"],
            ["loc1"],
            ["AllTrusted"],
            ["Note: The field 'includeLocations' was not updated because it currently holds the special value 'AllTrusted'."
             " This value cannot be merged with others. All other updates were applied."
             " To update this field, use update_action='override'."]
        ),

        # Test new list is special value - should override
        ("includeUsers", ["user1"], ["All"], ["All"], []),

        # Test regular merge
        ("includeUsers", ["user1"], ["user2"], sorted(["user1", "user2"]), []),

        # Test empty existing list
        ("includeUsers", [], ["user1"], ["user1"], []),

        # Test both lists empty
        ("includeUsers", [], [], [], []),
    ]
)
def test_resolve_merge_value(field, existing_list, new_list, expected, expected_messages):
    """
    Given:
        - An existing list and a new list of values for a specific field in a policy.
    When:
        - Calling resolve_merge_value to decide how to merge these lists.
    Then:
        - Verify the correct merging logic or override behavior.
        - Verify if appropriate messages are generated when special values are involved (e.g., 'All').
    """
    from MicrosoftGraphIdentityandAccess import resolve_merge_value
    
    messages = []
    result = resolve_merge_value(field, existing_list, new_list, messages)
    assert sorted(result) == sorted(expected)
    assert messages == expected_messages

@pytest.mark.parametrize(
    "src, expected",
    [
        # All values are valid – no changes expected
        ({"a": 1, "b": [1], "c": {"d": 2}}, {"a": 1, "b": [1], "c": {"d": 2}}),

        # Top-level empty values should be removed
        ({"a": None, "b": "", "c": [], "d": {}}, {}),

        # Recursive cleaning – also in nested structures
        (
            {
                "a": 1,
                "b": "",
                "c": {
                    "d": [],
                    "e": {"f": {}, "g": 3},
                    "h": "",
                },
            },
            {"a": 1, "c": {"e": {"g": 3}}},
        ),

        # List as a value – should not be altered unless it's completely empty
        ({"a": [None, 1, ""]}, {"a": [None, 1, ""]}),
    ],
)
def test_clean_dict(src, expected):
    """
    Given:
        - A dictionary with nested structures containing empty or null-like values.
    When:
        - Cleaning the dictionary using clean_dict.
    Then:
        - Verify that all empty values and empty nested structures are removed.
    """
    from MicrosoftGraphIdentityandAccess import clean_dict

    assert clean_dict(src) == expected

@pytest.mark.parametrize(
    "exception_input, expected_output",
    [
        # Case 1: Exception with a dictionary containing an 'error' field
        (
            Exception({"error": {"code": "BadRequest", "message": "Invalid policy"}}),
            {"code": "BadRequest", "message": "Invalid policy"}
        ),

        # Case 2: Exception as a string that contains a JSON object
        (
            Exception("Something failed: {\"error\": {\"code\": \"AuthError\", \"message\": \"Unauthorized access\"}}"),
            {"code": "AuthError", "message": "Unauthorized access"}
        ),

        # Case 3: Exception as a string that does not contain JSON
        (
            Exception("Something went wrong"),
            {"code": "UnknownError", "message": "Something went wrong"}
        ),

        # Case 4: Exception with no arguments at all
        (
            Exception(),
            {"code": "UnknownError", "message": ""}
        ),

        # Case 5: Exception with a dictionary that does not have an 'error' key
        (
            Exception({"status": 403}),
            {"code": "UnknownError", "message": "{'status': 403}"}
        ),
    ]
)
def test_parse_error_from_exception(exception_input, expected_output):
    """
    Given:
        - An exception raised in different formats (dict, string with JSON, plain string, etc.).
    When:
        - Parsing the error using parse_error_from_exception.
    Then:
        - Verify that the correct code and message are extracted or fallback values are used.
    """

    from MicrosoftGraphIdentityandAccess import parse_error_from_exception
    result = parse_error_from_exception(exception_input)
    assert result == expected_output

def test_update_policy_missing_policy_id_raises():
    """
    Given:
        - args that do NOT include 'policy_id'.
    When:
        - Running update_conditional_access_policy_command.
    Then:
        - ValueError should be raised with the correct message.
    """
    from MicrosoftGraphIdentityandAccess import Client, update_conditional_access_policy_command

    client = Client("", False, False)
    args = {}
    with pytest.raises(ValueError) as e:
        update_conditional_access_policy_command(client, args)

    assert str(e.value) == "The 'policy_id' argument is required to update a Conditional Access policy."
    

@pytest.mark.parametrize(
    "args, should_raise, delete_mock, expected_output",
    [
        # Case 1: Missing policy_id
        ({}, True, None, "The 'policy_id' argument is required to delete a Conditional Access policy."),

        # Case 2: policy_id provided but not found
        ({"policy_id": "nonexistent-id"}, False, Exception("API Error with status 404"),
         "Error deleting Conditional Access policy:"),

        # Case 3: Successful deletion
        ({"policy_id": "valid-id"}, False, None, "Conditional Access policy valid-id was successfully deleted.")
    ]
)
def test_delete_conditional_access_policy_command(mocker, args, should_raise, delete_mock, expected_output):
    """
    Given:
        - Different cases of policy deletion including:
            - Missing 'policy_id'
            - Valid 'policy_id' but API error
            - Valid 'policy_id' and successful deletion
    When:
        - Executing delete_conditional_access_policy_command.
    Then:
        - Verify correct behavior for each case: exception raised or readable_output contains success/failure.
    """
    from MicrosoftGraphIdentityandAccess import (Client, delete_conditional_access_policy_command, CommandResults,)
    client = Client("", False, False)

    if delete_mock is not None:
        mocker.patch.object(
            client.ms_client, "http_request",
            side_effect=delete_mock
        )
    else:
        mocker.patch.object(
            client.ms_client, "http_request",
            return_value=None
        )

    if should_raise:
        with pytest.raises(ValueError) as e:
            delete_conditional_access_policy_command(client, args)
        assert str(e.value) == expected_output
    else:
        result = delete_conditional_access_policy_command(client, args)
        assert isinstance(result, CommandResults)
        assert expected_output in result.readable_output
        

@pytest.mark.parametrize(
    "args, mock_response, expected_count, expected_call_args, expected_display",
    [
        (
            {},  # case: no policy_id, returns list
            {"value": [{"id": "1", "displayName": "Policy A", "state": "enabled"}]},
            1,
            (None, None),
            "Policy A"
        ),
        (
            {"policy_id": "abc123"},  # case: specific policy by id
            {"id": "abc123", "displayName": "Policy B", "state": "disabled"},
            1,
            ("abc123", None),
            "Policy B"
        ),
        (
            {"filter": "state eq 'enabled'"},  # case: filtered list
            {"value": [{"id": "2", "displayName": "Policy C", "state": "enabled"}]},
            1,
            (None, "state eq 'enabled'"),
            "Policy C"
        ),
        (
            {},  # case: empty list
            {"value": []},
            0,
            (None, None),
            None
        ),
        (
            {"policy_id": "not-found"},  # case: not found single policy
            None,
            0,
            ("not-found", None),
            None
        ),
    ]
)
def test_list_conditional_access_policies_command_cases(
    mocker, args, mock_response, expected_count, expected_call_args, expected_display
):
    """
    Given:
        - A variety of inputs such as a specific policy ID, a filter, no input, or an empty result.
    When:
        - Calling list_conditional_access_policies_command.
    Then:
        - Verify that the correct policy list is returned and the client was called with the right arguments.
        - Verify the readable_output reflects the expected policies.
    """
    from MicrosoftGraphIdentityandAccess import Client, list_conditional_access_policies_command

    mock_client = mocker.Mock(spec=Client)
    mock_client.list_conditional_access_policies.return_value = mock_response

    result = list_conditional_access_policies_command(mock_client, args)

    # assert the call was correct
    mock_client.list_conditional_access_policies.assert_called_once_with(*expected_call_args)

    # assert the output length
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected_count
    else:
        assert result.outputs is None
    # assert something from the output (only if something returned)
    if expected_display:
        assert expected_display in result.readable_output


@pytest.mark.parametrize(
    "input_value, expected",
    [
        ("a,b,c", ["a", "b", "c"]),
        (" a , b ,c ", ["a", "b", "c"]),
        (["a", "b"], ["a", "b"]),
        ([], []),
        (None, []),
        ("", []),
    ]
)
def test_convert_to_list(input_value, expected):
    """
    Given:
        - A string or list to convert to a list.
    When:
        - Calling convert_to_list with different types and formats.
    Then:
        - Ensure the resulting list is correctly formatted.
    """
    from MicrosoftGraphIdentityandAccess import convert_to_list

    assert convert_to_list(input_value) == expected


@pytest.mark.parametrize(
    "existing_policy, new_policy, expected_result, expected_messages",
    [
        # Normal merge case
        (
            {"conditions": {"users": {"includeUsers": ["user1"]}}},
            {"conditions": {"users": {"includeUsers": ["user2"]}}},
            {"conditions": {"users": {"includeUsers": ["user1", "user2"]}}},
            [],
        ),

        # Special value 'All' blocks update
        (
            {"conditions": {"users": {"includeUsers": ["All"]}}},
            {"conditions": {"users": {"includeUsers": ["user2"]}}},
            {"conditions": {"users": {"includeUsers": ["All"]}}},
            ["Note: The field 'includeUsers' was not updated because it currently holds the special value 'All'."
             " This value cannot be merged with others. All other updates were applied."
             " To update this field, use update_action='override'."],
        ),

        # New policy does not contain the field - nothing happens
        (
            {"conditions": {"users": {"includeUsers": ["user1"]}}},
            {"conditions": {"users": {}}},
            {"conditions": {"users": {}}},
            [],
        ),

        # No sub_section usage
        (
            {"grantControls": {"builtInControls": ["mfa"]}},
            {"grantControls": {"builtInControls": ["compliantDevice"]}},
            {"grantControls": {"builtInControls": ["compliantDevice", "mfa"]}},
            [],
        ),
    ]
)
def test_merge_field(mocker, existing_policy, new_policy, expected_result, expected_messages):
    """
    Given:
        - An existing policy and a new policy dict
    When:
        - Merging a specific field (includeUsers or builtInControls)
    Then:
        - Ensure the result reflects expected merging or blocked updates
    """
    from MicrosoftGraphIdentityandAccess import merge_field

    messages: list[str] = []

    if "grantControls" in new_policy:
        merge_field("grantControls", None, "builtInControls", existing_policy, new_policy, messages)
    else:
        merge_field("conditions", "users", "includeUsers", existing_policy, new_policy, messages)

    assert new_policy == expected_result
    assert messages == expected_messages