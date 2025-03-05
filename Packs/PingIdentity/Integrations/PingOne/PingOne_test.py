from PingOne import (
    Client,
    unlock_user_command,
    deactivate_user_command,
    activate_user_command,
    set_password_command,
    add_user_to_group_command,
    remove_from_group_command,
    get_groups_for_user_command,
    get_user_command,
    create_user_command,
    update_user_command,
    delete_user_command,
)
import pytest

TEST_USER_ID = "a8890eb9-38ea-469a-bc00-b64be7903633"
TEST_GROUP_ID = "8c33d93e-a614-457a-80ed-5e922fccd906"

user_data_by_username = {
    "_embedded": {"password": {"status": "MUST_CHANGE_PASSWORD"}},
    "id": "a8890eb9-38ea-469a-bc00-b64be7903633",
    "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
    "account": {"canAuthenticate": True, "status": "OK"},
    "address": {
        "streetAddress": "9999 Marine Drive ",
        "locality": "calgary",
        "region": "BC",
        "postalCode": "12345",
        "countryCode": "CA",
    },
    "createdAt": "2021-09-03T18:04:03.916Z",
    "email": "emma.sharp@example.com",
    "enabled": True,
    "identityProvider": {"type": "PING_ONE"},
    "lifecycle": {"status": "ACCOUNT_OK"},
    "locale": "en-US",
    "mfaEnabled": False,
    "mobilePhone": "604-999-9999",
    "name": {"formatted": "Emma Sharp", "given": "Emma", "family": "Sharp"},
    "nickname": "emma.sharp",
    "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
    "preferredLanguage": "en",
    "primaryPhone": "604-123-4567",
    "updatedAt": "2021-09-08T20:18:19.419Z",
    "username": "emma.sharp",
    "verifyStatus": "NOT_INITIATED",
}

user_data_by_id = {
    "_embedded": {"password": {"status": "MUST_CHANGE_PASSWORD"}},
    "id": "a8890eb9-38ea-469a-bc00-b64be7903633",
    "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
    "account": {"canAuthenticate": True, "status": "OK"},
    "address": {
        "streetAddress": "9999 Marine Drive ",
        "locality": "calgary",
        "region": "BC",
        "postalCode": "12345",
        "countryCode": "CA",
    },
    "createdAt": "2021-09-03T18:04:03.916Z",
    "email": "emma.sharp@example.com",
    "enabled": True,
    "identityProvider": {"type": "PING_ONE"},
    "lifecycle": {"status": "ACCOUNT_OK"},
    "locale": "en-US",
    "mfaEnabled": False,
    "mobilePhone": "604-999-9999",
    "name": {"formatted": "Emma Sharp", "given": "Emma", "family": "Sharp"},
    "nickname": "emma.sharp",
    "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
    "preferredLanguage": "en",
    "primaryPhone": "604-123-4567",
    "updatedAt": "2021-09-08T20:18:19.419Z",
    "username": "emma.sharp",
    "verifyStatus": "NOT_INITIATED",
}

create_user_response = {
    "id": "9e45580c-79f3-4499-83cc-006a20dcc50e",
    "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
    "account": {"canAuthenticate": True, "status": "OK"},
    "createdAt": "2021-08-20T19:07:00.979Z",
    "enabled": True,
    "identityProvider": {"type": "PING_ONE"},
    "lifecycle": {"status": "ACCOUNT_OK"},
    "mfaEnabled": False,
    "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
    "updatedAt": "2021-08-20T19:07:00.979Z",
    "username": "marysample",
    "verifyStatus": "NOT_INITIATED",
}

single_group_data = {
    "_links": {
        "self": {
            "href": "https://api.pingone.com/v1/environments/b4f5e266-a946-4f77-9cc5-5dc91b046431/users/a8890eb9-38ea"
            "-469a-bc00-b64be7903633/memberOfGroups/8c33d93e-a614-457a-80ed-5e922fccd906"
        },
        "user": {
            "href": "https://api.pingone.com/v1/environments/b4f5e266-a946-4f77-9cc5-5dc91b046431/users/a8890eb9-38ea"
            "-469a-bc00-b64be7903633"
        },
        "environment": {"href": "https://api.pingone.com/v1/environments/b4f5e266-a946-4f77-9cc5-5dc91b046431"},
        "population": {
            "href": "https://api.pingone.com/v1/environments/b4f5e266-a946-4f77-9cc5-5dc91b046431/populations/4cd45bdb"
            "-0eb2-42fe-8475-4bcd908269f1"
        },
        "group": {
            "href": "https://api.pingone.com/v1/environments/b4f5e266-a946-4f77-9cc5-5dc91b046431/groups/8c33d93e-a614"
            "-457a-80ed-5e922fccd906"
        },
    },
    "id": "8c33d93e-a614-457a-80ed-5e922fccd906",
    "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
    "name": "Sales",
    "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
    "type": "DIRECT",
}

group_data = {
    "_embedded": {
        "groupMemberships": [
            {
                "id": "dd95b574-cff5-485e-8460-c245ad8dab0f",
                "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
                "name": "Sample Group",
                "type": "INDIRECT",
            },
            {
                "id": "8c33d93e-a614-457a-80ed-5e922fccd906",
                "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
                "name": "Sales",
                "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
                "type": "DIRECT",
            },
        ]
    },
    "count": 2,
    "size": 2,
}

update_user_data = {
    "id": "3930766f-9e36-422d-ab4d-d8a2297f98f2",
    "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
    "account": {"canAuthenticate": True, "status": "OK"},
    "createdAt": "2021-09-09T01:02:14.247Z",
    "enabled": True,
    "identityProvider": {"type": "PING_ONE"},
    "lifecycle": {"status": "ACCOUNT_OK"},
    "mfaEnabled": False,
    "nickname": "Freddie",
    "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
    "type": "",
    "updatedAt": "2021-09-09T01:05:28.536Z",
    "username": "fred.smith4",
    "verifyStatus": "NOT_INITIATED",
}


class ClientTestPing:
    """
    Test class to handle the client
    """

    def __init__(self, mocker):
        test_params = {
            "client_id": "12345",
            "client_secret": "clientsecret",
            "base_url": "https://api.pingone.com",
            "auth_url": "https://auth.pingone.com",
        }

        testing_auth_header = {"Authorization": "Bearer ACCESS_TOKEN"}
        mocker.patch.object(Client, "_request_token", return_value=testing_auth_header)

        self.client = Client(base_url="https://api.pingone.com", verify=False, proxy=False, auth_params=test_params)


@pytest.mark.parametrize("args, expected_context, expected_readable", [({"username": "emma.sharp"}, {}, "emma.sharp")])
def test_unlock_user(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "unlock_user", return_value=user_data_by_id)

    readable, outputs, _ = unlock_user_command(client, args)
    assert outputs == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize("args, expected_context, expected_readable", [({"username": "emma.sharp"}, {}, "emma.sharp")])
def test_deactivate_user(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "deactivate_user", return_value=user_data_by_id)

    readable, outputs, _ = deactivate_user_command(client, args)
    assert outputs == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize("args, expected_context, expected_readable", [({"username": "emma.sharp"}, {}, "emma.sharp")])
def test_activate_user(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "activate_user", return_value=user_data_by_id)

    readable, outputs, _ = activate_user_command(client, args)
    assert outputs == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize(
    "args, expected_context, expected_readable", [({"username": "emma.sharp", "password": "2FederateM0re"}, {}, "emma.sharp")]
)
def test_set_password(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "set_password", return_value=user_data_by_id)

    readable, outputs, _ = set_password_command(client, args)
    assert outputs == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize(
    "args, expected_context, expected_readable",
    [
        ({"username": "emma.sharp", "groupName": "Sales"}, {}, "Sales"),
        (
            {"username": "emma.sharp", "groupId": "8c33d93e-a614-457a-80ed-5e922fccd906"},
            {},
            "8c33d93e-a614-457a-80ed-5e922fccd906",
        ),
        (
            {"userId": "a8890eb9-38ea-469a-bc00-b64be7903633", "groupId": "8c33d93e-a614-457a-80ed-5e922fccd906"},
            {},
            "a8890eb9-38ea-469a-bc00-b64be7903633",
        ),
    ],
)
def test_add_user_to_group(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "get_group_id", return_value=TEST_GROUP_ID)
    mocker.patch.object(client, "add_user_to_group", return_value=single_group_data)

    readable, outputs, _ = add_user_to_group_command(client, args)

    assert outputs == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize(
    "args, expected_context, expected_readable", [({"username": "emma.sharp", "groupName": "Sales"}, {}, "")]
)
def test_remove_user_to_group(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "get_group_id", return_value=TEST_GROUP_ID)
    mocker.patch.object(client, "remove_user_from_group", return_value=single_group_data)

    readable, outputs, _ = remove_from_group_command(client, args)

    assert outputs == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize(
    "args, expected_context, expected_readable",
    [
        (
            {"username": "emma.sharp"},
            {
                "ID": "a8890eb9-38ea-469a-bc00-b64be7903633",
                "Username": "emma.sharp",
                "Email": "emma.sharp@example.com",
                "DisplayName": "Emma Sharp",
                "Enabled": True,
                "CreatedAt": "2021-09-03T18:04:03.916Z",
                "UpdatedAt": "2021-09-08T20:18:19.419Z",
            },
            "emma.sharp@example.com",
        ),
        (
            {"userId": "a8890eb9-38ea-469a-bc00-b64be7903633"},
            {
                "ID": "a8890eb9-38ea-469a-bc00-b64be7903633",
                "Username": "emma.sharp",
                "Email": "emma.sharp@example.com",
                "DisplayName": "Emma Sharp",
                "Enabled": True,
                "CreatedAt": "2021-09-03T18:04:03.916Z",
                "UpdatedAt": "2021-09-08T20:18:19.419Z",
            },
            "emma.sharp@example.com",
        ),
    ],
)
def test_get_user_cmd(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_by_id", return_value=user_data_by_id)
    mocker.patch.object(client, "get_user_by_username", return_value=user_data_by_username)
    readable, outputs, _ = get_user_command(client, args)
    assert outputs.get("PingOne.Account(val.ID && val.ID === obj.ID)")[0] == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize("args", [{"username": "emma.sharp"}])
def test_get_groups_for_user_command(mocker, args):
    client = ClientTestPing(mocker).client

    expected_context = [{"ID": "8c33d93e-a614-457a-80ed-5e922fccd906", "Name": "Sales"}]

    mocker.patch.object(client, "get_user_id", return_value=TEST_USER_ID)
    mocker.patch.object(client, "get_groups_for_user", return_value=group_data)

    _, outputs, _ = get_groups_for_user_command(client, args)

    assert outputs.get("PingOne.Account(val.ID && val.ID === obj.ID)").get("Group") == expected_context
    assert "emma.sharp" == outputs.get("PingOne.Account(val.ID && val.ID === obj.ID)").get("ID")


@pytest.mark.parametrize("args", [({"username": "marysample", "populationId": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"})])
def test_create_user_command(mocker, args):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "create_user", return_value=create_user_response)
    readable, outputs, _ = create_user_command(client, args)

    assert "9e45580c-79f3-4499-83cc-006a20dcc50e" in readable
    assert outputs.get("PingOne.Account(val.ID && val.ID === obj.ID)").get("Enabled")


@pytest.mark.parametrize(
    "args, expected_context, expected_readable",
    [
        (
            {"username": "fred.smith4", "populationId": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1", "nickname": "Freddie"},
            {
                "id": "3930766f-9e36-422d-ab4d-d8a2297f98f2",
                "environment": {"id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"},
                "account": {"canAuthenticate": True, "status": "OK"},
                "createdAt": "2021-09-09T01:02:14.247Z",
                "enabled": True,
                "identityProvider": {"type": "PING_ONE"},
                "lifecycle": {"status": "ACCOUNT_OK"},
                "mfaEnabled": False,
                "nickname": "Freddie",
                "population": {"id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"},
                "type": "",
                "updatedAt": "2021-09-09T01:05:28.536Z",
                "username": "fred.smith4",
                "verifyStatus": "NOT_INITIATED",
            },
            "fred.smith4",
        )
    ],
)
def test_update_user_command(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_id", return_value="3930766f-9e36-422d-ab4d-d8a2297f98f2")
    mocker.patch.object(client, "update_user", return_value=update_user_data)
    readable, outputs, raw_response = update_user_command(client, args)

    assert expected_readable in readable
    assert raw_response == expected_context


@pytest.mark.parametrize(
    "args, expected_context, expected_readable",
    [({"userId": "3930766f-9e36-422d-ab4d-d8a2297f98f2"}, {}, "3930766f-9e36-422d-ab4d-d8a2297f98f2")],
)
def test_delete_user(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, "get_user_by_username", return_value="3930766f-9e36-422d-ab4d-d8a2297f98f2")
    mocker.patch.object(client, "delete_user", return_value=None)

    readable, _, _ = delete_user_command(client, args)
    assert "3930766f-9e36-422d-ab4d-d8a2297f98f2" in readable
