import pytest

from CyberArkPAS import (
    Client,
    add_user_command,
    get_users_command,
    update_user_command,
    add_safe_command,
    update_safe_command,
    get_list_safes_command,
    get_safe_by_name_command,
    add_safe_member_command,
    update_safe_member_command,
    list_safe_members_command,
    add_account_command,
    update_account_command,
    get_list_accounts_command,
    get_list_account_activity_command,
    fetch_incidents,
    get_account_details_command,
    order_properties_to_dict,
)
from test_data.context import (
    ADD_USER_CONTEXT,
    GET_USERS_CONTEXT,
    UPDATE_USER_CONTEXT,
    UPDATE_SAFE_CONTEXT,
    GET_LIST_SAFES_CONTEXT,
    GET_SAFE_BY_NAME_CONTEXT,
    ADD_SAFE_CONTEXT,
    ADD_SAFE_MEMBER_CONTEXT,
    UPDATE_SAFE_MEMBER_CONTEXT,
    LIST_SAFE_MEMBER_CONTEXT,
    ADD_ACCOUNT_CONTEXT,
    UPDATE_ACCOUNT_CONTEXT,
    GET_LIST_ACCOUNT_CONTEXT,
    GET_LIST_ACCOUNT_ACTIVITIES_CONTEXT,
    INCIDENTS,
    INCIDENTS_AFTER_FETCH,
    INCIDENTS_LIMITED_BY_MAX_SIZE,
    INCIDENTS_FILTERED_BY_SCORE,
    GET_ACCOUNT_CONTEXT,
)
from test_data.http_resonses import (
    ADD_USER_RAW_RESPONSE,
    UPDATE_USER_RAW_RESPONSE,
    GET_USERS_RAW_RESPONSE,
    ADD_SAFE_RAW_RESPONSE,
    UPDATE_SAFE_RAW_RESPONSE,
    GET_LIST_SAFES_RAW_RESPONSE,
    GET_SAFE_BY_NAME_RAW_RESPONSE,
    ADD_SAFE_MEMBER_RAW_RESPONSE,
    UPDATE_SAFE_MEMBER_RAW_RESPONSE,
    LIST_SAFE_MEMBER_RAW_RESPONSE,
    ADD_ACCOUNT_RAW_RESPONSE,
    UPDATE_ACCOUNT_RAW_RESPONSE,
    GET_LIST_ACCOUNT_RAW_RESPONSE,
    GET_LIST_ACCOUNT_ACTIVITIES_RAW_RESPONSE,
    GET_SECURITY_EVENTS_RAW_RESPONSE,
    GET_SECURITY_EVENTS_WITH_UNNECESSARY_INCIDENT_RAW_RESPONSE,
    GET_SECURITY_EVENTS_WITH_15_INCIDENT_RAW_RESPONSE,
    GET_ACCOUNT_RAW_RESPONSE,
)

ADD_USER_ARGS = {
    "change_password_on_the_next_logon": "true",
    "description": "new user for test",
    "email": "usertest@test.com",
    "enable_user": "true",
    "first_name": "user",
    "last_name": "test",
    "password": "12345Aa",
    "password_never_expires": "false",
    "profession": "testing integrations",
    "username": "TestUser",
}

UPDATE_USER_ARGS = {
    "change_password_on_the_next_logon": "true",
    "description": "updated description",
    "email": "update@test.com",
    "enable_user": "true",
    "first_name": "test1",
    "last_name": "updated-name",
    "password_never_expires": "false",
    "profession": "test1",
    "user_id": "123",
    "username": "TestUser1",
}

GET_USER_ARGS = {"filter": "filteroption", "search": "searchoption"}

ADD_SAFE_ARGS = {"description": "safe for tests", "number_of_days_retention": "100", "safe_name": "TestSafe"}

UPDATE_SAFE_ARGS = {
    "description": "UpdatedSafe",
    "number_of_days_retention": "150",
    "safe_name": "TestSafe",
    "safe_new_name": "UpdatedName",
}

GET_SAFE_BY_NAME_ARGS = {"safe_name": "TestSafe"}

ADD_SAFE_MEMBER_ARGS = {
    "member_name": "TestUser",
    "requests_authorization_level": "0",
    "safe_name": "TestSafe",
    "permissions": ["ManageSafeMembers"],
}

UPDATE_SAFE_MEMBER_ARGS = {
    "member_name": "TestUser",
    "permissions": "UseAccounts",
    "requests_authorization_level": "0",
    "safe_name": "TestSafe",
}

LIST_SAFE_MEMBER_ARGS = {"safe_name": "TestSafe"}

ADD_ACCOUNT_ARGS = {
    "account_name": "TestAccount1",
    "address": "/",
    "automatic_management_enabled": "true",
    "password": "12345Aa",
    "platform_id": "WinServerLocal",
    "safe_name": "TestSafe",
    "secret_type": "password",
    "username": "TestUser",
}

UPDATE_ACCOUNT_ARGS = {"account_id": "77_4", "account_name": "NewName"}

GET_ACCOUNT_ARGS = {
    "account_id": "11_1",
}

GET_LIST_ACCOUNT_ARGS = {"limit": "2", "offset": "0"}

GET_LIST_ACCOUNT_ACTIVITIES_ARGS = {"account_id": "77_4"}


@pytest.mark.parametrize(
    "command, args, http_response, context",
    [
        (add_user_command, ADD_USER_ARGS, ADD_USER_RAW_RESPONSE, ADD_USER_CONTEXT),
        (update_user_command, UPDATE_USER_ARGS, UPDATE_USER_RAW_RESPONSE, UPDATE_USER_CONTEXT),
        (get_users_command, {}, GET_USERS_RAW_RESPONSE, GET_USERS_CONTEXT),
        (add_safe_command, ADD_SAFE_ARGS, ADD_SAFE_RAW_RESPONSE, ADD_SAFE_CONTEXT),
        (update_safe_command, UPDATE_SAFE_ARGS, UPDATE_SAFE_RAW_RESPONSE, UPDATE_SAFE_CONTEXT),
        (get_list_safes_command, {}, GET_LIST_SAFES_RAW_RESPONSE, GET_LIST_SAFES_CONTEXT),
        (get_safe_by_name_command, GET_SAFE_BY_NAME_ARGS, GET_SAFE_BY_NAME_RAW_RESPONSE, GET_SAFE_BY_NAME_CONTEXT),
        (add_safe_member_command, ADD_SAFE_MEMBER_ARGS, ADD_SAFE_MEMBER_RAW_RESPONSE, ADD_SAFE_MEMBER_CONTEXT),
        (update_safe_member_command, UPDATE_SAFE_MEMBER_ARGS, UPDATE_SAFE_MEMBER_RAW_RESPONSE, UPDATE_SAFE_MEMBER_CONTEXT),
        (list_safe_members_command, LIST_SAFE_MEMBER_ARGS, LIST_SAFE_MEMBER_RAW_RESPONSE, LIST_SAFE_MEMBER_CONTEXT),
        (add_account_command, ADD_ACCOUNT_ARGS, ADD_ACCOUNT_RAW_RESPONSE, ADD_ACCOUNT_CONTEXT),
        (update_account_command, UPDATE_ACCOUNT_ARGS, UPDATE_ACCOUNT_RAW_RESPONSE, UPDATE_ACCOUNT_CONTEXT),
        (get_account_details_command, GET_ACCOUNT_ARGS, GET_ACCOUNT_RAW_RESPONSE, GET_ACCOUNT_CONTEXT),
        (get_list_accounts_command, GET_LIST_ACCOUNT_ARGS, GET_LIST_ACCOUNT_RAW_RESPONSE, GET_LIST_ACCOUNT_CONTEXT),
        (
            get_list_account_activity_command,
            GET_LIST_ACCOUNT_ACTIVITIES_ARGS,
            GET_LIST_ACCOUNT_ACTIVITIES_RAW_RESPONSE,
            GET_LIST_ACCOUNT_ACTIVITIES_CONTEXT,
        ),
    ],
)
def test_cyberark_pas_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=50
    )

    mocker.patch.object(Client, "_http_request", return_value=http_response)

    outputs = command(client, **args)
    results = outputs.to_context()

    assert results.get("EntryContext") == context


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - mock the http request result as 5 results that are sorted from the newest to the oldest
    Then
    - as defined in the demisto params - show only 2, those should be the oldest 2 available
    - validate the incidents values
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=50
    )

    mocker.patch.object(Client, "_http_request", return_value=GET_SECURITY_EVENTS_RAW_RESPONSE)

    _, incidents = fetch_incidents(client, {}, "3 days", "0", "2")
    assert incidents == INCIDENTS


def test_fetch_incidents_with_an_incident_that_was_shown_before(mocker):
    """Unit test
    Given
    - demisto params
    - raw response of the http request
    When
    - mock the http request result while one of the incidents was shown in the previous run
    Then
    - validate the incidents values, make sure the event that was shown before is not in
    the incidents again
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=50
    )

    mocker.patch.object(Client, "_http_request", return_value=GET_SECURITY_EVENTS_WITH_UNNECESSARY_INCIDENT_RAW_RESPONSE)
    # the last run dict is the same we would have got if we run the prev test before
    last_run = {"time": 1594573600000, "last_event_ids": '["5f0b3064e4b0ba4baf5c1113", "5f0b4320e4b0ba4baf5c2b05"]'}
    _, incidents = fetch_incidents(client, last_run, "3 days", "0", "1")
    assert incidents == INCIDENTS_AFTER_FETCH


def test_fetch_incidents_with_more_incidents_than_max_size(mocker):
    """Unit test
    Given
    - demisto params
    - raw response of the http request
    When
    - mock the http request result while the result is 15 incidents and we only wish to see 5
    Then
    - validate the incidents values, make sure make sure that there are only 5 incidents and that there
     are the oldest
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=5
    )

    mocker.patch.object(Client, "_http_request", return_value=GET_SECURITY_EVENTS_WITH_15_INCIDENT_RAW_RESPONSE)
    _, incidents = fetch_incidents(client, {}, "3 days", "0", max_fetch="5")
    assert len(incidents) == 5
    assert incidents == INCIDENTS_LIMITED_BY_MAX_SIZE


def test_fetch_incidents_with_specific_score(mocker):
    """Unit test
    Given
    - demisto params
    - raw response of the http request
    When
    - mock the http request result while the result is 15 incidents and we only wish to see 5
    Then
    - validate the incidents values, make sure make sure that there are only 5 incidents and that there
     are the oldest
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=10
    )

    mocker.patch.object(Client, "_http_request", return_value=GET_SECURITY_EVENTS_WITH_15_INCIDENT_RAW_RESPONSE)
    _, incidents = fetch_incidents(client, {}, "3 days", score="50", max_fetch="10")
    assert len(incidents) == 3
    assert incidents == INCIDENTS_FILTERED_BY_SCORE


@pytest.mark.parametrize("permission_exist", [True, False])
def test_add_safe_member_permissions_validate(mocker, permission_exist):
    """
    Given
    - Permissions.
    When
    - calling *add_safe_member* method.
    Then
    - Validate ManageSafeMembers was set in http body permission list.
    """
    args = ADD_SAFE_MEMBER_ARGS
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=50
    )
    mock = mocker.patch.object(Client, "_http_request")
    if not permission_exist:
        args.get("permissions").remove("ManageSafeMembers")
    add_safe_member_command(client, **args)
    permissions = mock.call_args[1].get("json_data").get("member").get("Permissions")
    for permission in permissions:
        if "ManageSafeMembers" in permission.get("Key"):
            assert permission.get("Value") == permission_exist


V11_RESPONSE_SAFES_1 = {
    "Safes": [
        {
            "safeUrlId": "Test",
            "safeName": "Test",
            "safeNumber": 2,
            "description": "",
            "location": "\\",
            "creator": {"memberId": "2", "memberName": "Administrator"},
            "olacEnabled": False,
            "managingCPM": "",
            "numberOfVersionsRetention": None,
            "numberOfDaysRetention": 30,
            "autoPurgeEnabled": False,
            "creationTime": 00000,
            "lastModificationTime": 000000,
            "isExpiredMember": False,
        },
    ],
    "Total": 1769,
    "nextLink": "example.com",
}
V12_RESPONSE_SAFES_1 = {
    "value": [
        {
            "safeUrlId": "Test",
            "safeName": "Test",
            "safeNumber": 2,
            "description": "",
            "location": "\\",
            "creator": {"memberId": "2", "memberName": "Administrator"},
            "olacEnabled": False,
            "managingCPM": "",
            "numberOfVersionsRetention": None,
            "numberOfDaysRetention": 30,
            "autoPurgeEnabled": False,
            "creationTime": 00000,
            "lastModificationTime": 000000,
            "isExpiredMember": False,
        },
    ],
    "count": 1769,
    "nextLink": "example.com",
}
COUNT_1 = "1769"
OUTPUT_1 = [
    {
        "safeUrlId": "Test",
        "safeName": "Test",
        "safeNumber": 2,
        "description": "",
        "location": "\\",
        "creator": {"memberId": "2", "memberName": "Administrator"},
        "olacEnabled": False,
        "managingCPM": "",
        "numberOfVersionsRetention": None,
        "numberOfDaysRetention": 30,
        "autoPurgeEnabled": False,
        "creationTime": 0,
        "lastModificationTime": 0,
        "isExpiredMember": False,
    }
]


@pytest.mark.parametrize(
    "response, count_or_total, expected_output",
    [(V11_RESPONSE_SAFES_1, COUNT_1, OUTPUT_1), (V12_RESPONSE_SAFES_1, COUNT_1, OUTPUT_1)],
)
def test_pas_safes_list(mocker, response: dict, count_or_total: str, expected_output: list[dict]):
    """
    Given:
        - Response to cyberark-pas-safes-list command (in either the API <=v11 version, or the >=v12 format)
        - Expected count/ total value
        - Expected output
    When:
        - cyberark-pas-safes-list is executed
    Then:
        - Ensure the readable_output contains the correct total/count and not None according to the response's structure
        - Ensure the output matches what is expected
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=50
    )
    mocker.patch.object(client, "get_list_safes", return_value=response)
    results = get_list_safes_command(client=client)
    assert count_or_total in results.readable_output
    assert results.outputs == expected_output


V11_RESPONSE_SAFES_2 = {
    "SafeMembers": [
        {
            "safeUrlId": "",
            "safeName": "Test",
            "safeNumber": 1,
            "memberId": 1,
            "memberName": "Example",
            "memberType": "Example",
            "membershipExpirationDate": None,
            "isExpiredMembershipEnable": False,
            "isPredefinedUser": True,
            "permissions": {
                "useAccounts": True,
                "retrieveAccounts": True,
                "listAccounts": True,
                "addAccounts": True,
                "updateAccountContent": True,
                "updateAccountProperties": True,
                "initiateCPMAccountManagementOperations": True,
                "specifyNextAccountContent": True,
                "renameAccounts": True,
                "deleteAccounts": True,
                "unlockAccounts": True,
                "manageSafe": True,
                "manageSafeMembers": True,
                "backupSafe": True,
                "viewAuditLog": True,
                "viewSafeMembers": True,
                "accessWithoutConfirmation": True,
                "createFolders": True,
                "deleteFolders": True,
                "moveAccountsAndFolders": True,
                "requestsAuthorizationLevel1": False,
                "requestsAuthorizationLevel2": False,
            },
        }
    ],
    "Total": 8,
}
V12_RESPONSE_SAFES_2 = {
    "value": [
        {
            "safeUrlId": "",
            "safeName": "Test",
            "safeNumber": 1,
            "memberId": 1,
            "memberName": "Example",
            "memberType": "Example",
            "membershipExpirationDate": None,
            "isExpiredMembershipEnable": False,
            "isPredefinedUser": True,
            "permissions": {
                "useAccounts": True,
                "retrieveAccounts": True,
                "listAccounts": True,
                "addAccounts": True,
                "updateAccountContent": True,
                "updateAccountProperties": True,
                "initiateCPMAccountManagementOperations": True,
                "specifyNextAccountContent": True,
                "renameAccounts": True,
                "deleteAccounts": True,
                "unlockAccounts": True,
                "manageSafe": True,
                "manageSafeMembers": True,
                "backupSafe": True,
                "viewAuditLog": True,
                "viewSafeMembers": True,
                "accessWithoutConfirmation": True,
                "createFolders": True,
                "deleteFolders": True,
                "moveAccountsAndFolders": True,
                "requestsAuthorizationLevel1": False,
                "requestsAuthorizationLevel2": False,
            },
        }
    ],
    "count": 8,
}
COUNT_2 = "8"
OUTPUT_2 = [
    {
        "safeUrlId": "",
        "safeName": "Test",
        "safeNumber": 1,
        "memberId": 1,
        "memberName": "Example",
        "memberType": "Example",
        "membershipExpirationDate": None,
        "isExpiredMembershipEnable": False,
        "isPredefinedUser": True,
        "permissions": {
            "useAccounts": True,
            "retrieveAccounts": True,
            "listAccounts": True,
            "addAccounts": True,
            "updateAccountContent": True,
            "updateAccountProperties": True,
            "initiateCPMAccountManagementOperations": True,
            "specifyNextAccountContent": True,
            "renameAccounts": True,
            "deleteAccounts": True,
            "unlockAccounts": True,
            "manageSafe": True,
            "manageSafeMembers": True,
            "backupSafe": True,
            "viewAuditLog": True,
            "viewSafeMembers": True,
            "accessWithoutConfirmation": True,
            "createFolders": True,
            "deleteFolders": True,
            "moveAccountsAndFolders": True,
            "requestsAuthorizationLevel1": False,
            "requestsAuthorizationLevel2": False,
        },
    }
]


@pytest.mark.parametrize(
    "response, count_or_total, expected_output",
    [(V11_RESPONSE_SAFES_2, COUNT_2, OUTPUT_2), (V12_RESPONSE_SAFES_2, COUNT_2, OUTPUT_2)],
)
def test_pas_safe_members_list(mocker, response: dict, count_or_total: str, expected_output: list[dict]):
    """
    Given:
        - Response to cyberark-pas-safe-members-list command (in either the <=V11 version, or the >=V12 format)
        - Expected count/ total value
        - Expected output
    When:
        - cyberark-pas-safe-members-list is executed
    Then:
        - Ensure the readable_output contains the correct total/count and not None according to the response's structure
        - Ensure the output matches what is expected
    """
    mocker.patch.object(Client, "_generate_token")
    client = Client(
        server_url="https://api.cyberark.com/", username="user1", password="12345", use_ssl=False, proxy=False, max_fetch=50
    )
    mocker.patch.object(client, "list_safe_members", return_value=response)
    results = list_safe_members_command(client=client, safe_name="Test")
    assert count_or_total in results.readable_output
    assert results.outputs == expected_output


@pytest.mark.parametrize(
    "properties,expected",
    [({}, {}), ({"a": 1}, {"a": 1}), ({"a": 1}, {"a": 1}), ("{'a': 1}", {"a": 1}), ('{"a": 1}', {"a": 1}), ("", {})],
)
def test_order_properties_to_dict(properties, expected):
    """
    Given:
        - properties as input
    When:
        - order_properties_to_dict is called on properties
    Then:
        - it returns the expected output
    """
    assert order_properties_to_dict(properties) == expected


@pytest.mark.parametrize(
    "properties,expected",
    [
        ("not json", ValueError),
    ],
)
def test_order_properties_to_dict_failure(properties, expected):
    """
    Given:
        - Invalid properties as input
    When:
        - order_properties_to_dict is called on properties
    Then:
        - An error is raised
    """
    with pytest.raises(expected):
        order_properties_to_dict(properties)
