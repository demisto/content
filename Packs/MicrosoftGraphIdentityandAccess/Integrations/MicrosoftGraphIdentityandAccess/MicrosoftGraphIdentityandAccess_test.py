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
            ["The field 'includeUsers' was not updated because it currently holds the special value 'All'."
             " This value cannot be merged with others. All other updates were applied."
             " To update this field, use update_action='override'."]
        ),

        # Test existing 'AllTrusted' - should not update
        (
            "includeLocations",
            ["AllTrusted"],
            ["loc1"],
            ["AllTrusted"],
            ["The field 'includeLocations' was not updated because it currently holds the special value 'AllTrusted'."
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
    "args, should_raise, delete_mock, expected_output",
    [
        # Case 1: policy_id provided but not found
        ({"policy_id": "nonexistent-id"}, False, Exception("API Error with status 404"),
         "Error deleting Conditional Access policy:"),

        # Case 2: Successful deletion
        ({"policy_id": "valid-id"}, False, None, "Conditional Access policy valid-id was successfully deleted.")
    ]
)
def test_delete_conditional_access_policy_command(mocker, args, should_raise, delete_mock, expected_output):
    """
    Given:
        - Different cases of policy deletion including:
            - Valid 'policy_id' but API error
            - Valid 'policy_id' and successful deletion
    When:
        - Executing delete_conditional_access_policy_command.
    Then:
        - Verify correct behavior for each case: exception raised or readable_output contains success/failure.
    """
    from unittest.mock import Mock

    from MicrosoftGraphIdentityandAccess import (Client, delete_conditional_access_policy_command, CommandResults,)
    client = Client("", False, False)

    if delete_mock is not None:
        mocker.patch.object(
            client.ms_client, "http_request",
            side_effect=delete_mock
        )
    else:
        mock_response = Mock()
        mock_response.status_code = 204
        mocker.patch.object(
            client.ms_client, "http_request",
            return_value=mock_response
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
            [{"id": "1", "displayName": "Policy A", "state": "enabled"}],
            1,
            (None, None),
            "Policy A"
        ),
        (
            {"policy_id": "abc123"},  # case: specific policy by id
            [{"id": "abc123", "displayName": "Policy B", "state": "disabled"}],
            1,
            ("abc123", None),
            "Policy B"
        ),
        (
            {"filter": "state eq 'enabled'"},  # case: filtered list
            [{"id": "2", "displayName": "Policy C", "state": "enabled"}],
            1,
            (None, "state eq 'enabled'"),
            "Policy C"
        ),
        (
            {},  # case: empty list
            [],
            0,
            (None, None),
            None
        ),
        (
            {"policy_id": "not-found"},  # case: not found single policy
            [],
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
    "policy_input, response_mock, expected_output, expect_exception",
    [
        # Case 1: Invalid JSON string -> should raise ValueError
        ("{invalid_json}", None, "The provided policy string is not a valid JSON.", ValueError),

        # Case 2: Response with non-204 status code
        (
            {"state": "disabled"},
            {"status_code": 400, "text": "Bad Request"},
            "An error occurred while updating Conditional Access policy 'abc123':\n",
            None,
        ),

        # Case 3: Successful update (status code 204)
        (
            {"state": "enabled"},
            {"status_code": 204, "text": "No Content"},
            "Conditional Access policy abc123 was successfully updated.",
            None,
        ),
    ]
)

def test_update_conditional_access_policy_cases(policy_input, response_mock, expected_output, expect_exception, mocker):
    """
    Given:
        - A Conditional Access policy update input (either a dict or JSON string).
    When:
        - Calling update_conditional_access_policy with the mocked client.
    Then:
        - For invalid JSON: raise ValueError.
        - For valid JSON string but incorrect structure: return CommandResults with error.
        - For non-204 response: readable_output shows an error.
        - For 204 response: readable_output shows success.
    """
    from MicrosoftGraphIdentityandAccess import Client
    from CommonServerPython import CommandResults
    
    mock_client = Client("", False, False)

    if expect_exception:
        with pytest.raises(expect_exception) as e:
            mock_client.update_conditional_access_policy("abc123", policy_input)
        assert expected_output in str(e.value)
    else:
        mock_response = mocker.Mock()
        mock_response.status_code = response_mock["status_code"]
        mock_response.text = response_mock["text"]
        mock_response.__str__ = mocker.Mock(return_value=response_mock["text"])
        mocker.patch.object(mock_client.ms_client, "http_request", return_value=mock_response)
        result = mock_client.update_conditional_access_policy("abc123", policy_input)
        assert isinstance(result, CommandResults)
        assert result.readable_output.startswith(expected_output)


@pytest.mark.parametrize(
    "base_existing, new_input, expected_merged, expected_messages",
    [
        (
            # Case 1: Regular merge of list field
            {"conditions": {"users": {"includeUsers": ["user1"]}}},
            {"conditions": {"users": {"includeUsers": ["user2"]}}},
            {"conditions": {"users": {"includeUsers": sorted(["user1", "user2"])}}},
            [],
        ),
        (
            # Case 2: Merge with special value 'All'
            {"conditions": {"users": {"includeUsers": ["All"]}}},
            {"conditions": {"users": {"includeUsers": ["user2"]}}},
            {"conditions": {"users": {"includeUsers": ["All"]}}},
            [
                "The field 'includeUsers' was not updated because it currently holds the special value 'All'."
                " This value cannot be merged with others. All other updates were applied."
                " To update this field, use update_action='override'."
            ],
        ),
        (
            # Case 3: Non-list field - should skip
            {"state": "enabled"},
            {"state": "disabled"},
            {"state": "disabled"},  # unchanged due to skip
            [],  # we don't capture demisto.info in test
        ),
    ]
)
def test_merge_policy_section_behavior(base_existing, new_input, expected_merged, expected_messages, mocker):
    """
    Given:
        - An existing policy dict.
        - A new policy dict with updated values.
    When:
        - Calling merge_policy_section to merge list-based fields (append logic).
    Then:
        - Fields that are lists should be merged correctly.
        - Special values (like 'All') should not be merged, and a message should be logged.
        - Non-list fields should be ignored for merging.
    """
    from MicrosoftGraphIdentityandAccess import merge_policy_section

    # Patch resolve_merge_value to use actual logic

    messages: list[str] = []
    # Deepcopy to avoid mutation
    import copy
    base_existing_copy = copy.deepcopy(base_existing)
    new_input_copy = copy.deepcopy(new_input)

    merge_policy_section(base_existing_copy, new_input_copy, messages)

    assert new_input_copy == expected_merged
    assert messages == expected_messages
    


@pytest.mark.parametrize(
    "policy_input, http_response, expected_output, expected_in_context, expect_exception",
    [
        # Case 1: Valid dict input, response has ID
        (
            {"state": "enabled"},
            {"id": "abc123", "state": "enabled"},
            "Conditional Access policy abc123 was successfully created.",
            True,
            None,
        ),

        # Case 2: Valid JSON string input, response has ID
        (
            '{"state": "enabled"}',
            {"id": "abc123", "state": "enabled"},
            "Conditional Access policy abc123 was successfully created.",
            True,
            None,
        ),

        # Case 4: Invalid JSON string
        (
            '{"state": enabled}',  # missing quotes around value
            None,
            "The provided policy string is not a valid JSON.",
            False,
            None,
        ),

        # Case 5: API exception raised during request
        (
            {"state": "enabled"},
            Exception("Network error"),
            "Error creating Conditional Access policy:\nNetwork error",
            False,
            None,
        ),
    ]
)
def test_create_conditional_access_policy(mocker, policy_input, http_response, expected_output,
                                          expected_in_context, expect_exception):
    """
    Given:
        - Various policy inputs (valid/invalid JSON, dict).
    When:
        - Calling create_conditional_access_policy.
    Then:
        - Ensure it correctly handles:
            - Successful creation
            - Missing ID in response
            - JSON decoding errors
            - Network/API errors
    """
    from MicrosoftGraphIdentityandAccess import Client, CommandResults

    mock_client = Client("", False, False)

    if isinstance(http_response, Exception):
        mocker.patch.object(mock_client.ms_client, "http_request", side_effect=http_response)
    elif isinstance(http_response, dict):
        mocker.patch.object(mock_client.ms_client, "http_request", return_value=http_response)

    if expect_exception:
        with pytest.raises(Exception) as e:
            mock_client.create_conditional_access_policy(policy_input)
        assert expected_output in str(e.value)
    else:
        result = mock_client.create_conditional_access_policy(policy_input)
        assert isinstance(result, CommandResults)
        assert expected_output in result.readable_output
        if expected_in_context:
            assert result.outputs.get("id") == "abc123"
        else:
            assert result.outputs is None or not result.outputs.get("id")

import pytest
from CommonServerPython import CommandResults
from MicrosoftGraphIdentityandAccess import create_conditional_access_policy_command, Client


@pytest.mark.parametrize(
    "args, mock_return, expected_in_output, should_mock_call",
    [
        # ✅ Case 2: Valid structured input
        (
            {
                "policy_name": "TestPolicy",
                "state": "enabled",
                "client_app_types": "browser",
                "sign_in_risk_levels": "low",
                "user_risk_levels": "medium",
            },
            CommandResults(readable_output="Policy created"),
            "Policy created",
            True,
        ),
        # Case 3: Empty strings for required lists
        (
            {
                "policy_name": "TestPolicy",
                "state": "enabled",
                "client_app_types": "",
                "sign_in_risk_levels": "",
                "user_risk_levels": "",
            },
            None,
            "Missing required field(s):",
            False,
        ),
    ],
)
def test_create_policy_command_variants(mocker, args, mock_return, expected_in_output, should_mock_call):
    mock_client = mocker.Mock(spec=Client)
    if should_mock_call:
        mock_client.create_conditional_access_policy.return_value = mock_return

    result = create_conditional_access_policy_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert expected_in_output in result.readable_output

import pytest
from CommonServerPython import CommandResults
from MicrosoftGraphIdentityandAccess import update_conditional_access_policy_command


@pytest.mark.parametrize(
    "args, existing_policy, mock_result, expected_note_text, expect_merge_message",
    [
        (
            # Case: existing includeUsers is ['All'], should trigger merge message
            {
                "policy_id": "abc123",
                "update_action": "append",
                "include_users": "user1",
                "state": "enabled"
            },
            # mocked list_conditional_access_policies result
            [{
                "id": "abc123",
                "state": "disabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"]
                    }
                }
            }],
            # mocked update_conditional_access_policy result
            CommandResults(readable_output="Policy updated"),
            "The field 'includeUsers' was not updated because it currently holds the special value 'All'",
            True
        ),
        (
            # Case: no merge message because no special value
            {
                "policy_id": "abc123",
                "update_action": "append",
                "include_users": "user1",
                "state": "enabled"
            },
            [{
                "id": "abc123",
                "state": "disabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["user5"]
                    }
                }
            }],
            CommandResults(readable_output="Policy updated"),
            "Note:",
            False
        ),
        (
            # Case: message should NOT be appended because readable_output starts with 'Error'
            {
                "policy_id": "abc123",
                "update_action": "append",
                "include_users": "user1",
                "state": "enabled"
            },
            [{
                "id": "abc123",
                "state": "disabled",
                "conditions": {
                    "users": {
                        "includeUsers": ["All"]
                    }
                }
            }],
            CommandResults(readable_output="Error: update failed"),
            "Note:",
            False
        ),
    ]
)
def test_update_policy_appends_merge_messages_correctly(
    mocker, args, existing_policy, mock_result, expected_note_text, expect_merge_message
):
    mock_client = mocker.Mock(spec=Client)

    # Mock list_conditional_access_policies
    mock_client.list_conditional_access_policies.return_value = existing_policy
    # Mock update_conditional_access_policy
    mock_client.update_conditional_access_policy.return_value = mock_result

    result = update_conditional_access_policy_command(mock_client, args)

    assert isinstance(result, CommandResults)

    if expect_merge_message:
        assert expected_note_text in result.readable_output
        assert result.readable_output.startswith("Policy updated")
        assert "\n\nNote:\n" in result.readable_output
    else:
        assert expected_note_text not in result.readable_output or result.readable_output.startswith("Error")
