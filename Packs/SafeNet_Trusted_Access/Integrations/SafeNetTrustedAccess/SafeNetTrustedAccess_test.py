import pytest
from requests import Response
from SafeNetTrustedAccess import Client

# Defining client object for mocker
client = Client(base_url="demisto.com")

# Defining result of command functions for mocker
user_list = [
    {
        "email": "demo.user4alert@gmail.com",
        "firstName": "Demo",
        "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
        "isSynchronized": False,
        "lastName": "User",
        "schemaVersionNumber": "1.0",
        "userName": "demouser"
    },
    {
        "email": "hello.user@gmail.com",
        "firstName": "Hello",
        "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
        "isSynchronized": False,
        "lastName": "User",
        "schemaVersionNumber": "1.0",
        "userName": "hellouser"
    }
]

user_info = {
    "email": "hello.user@gmail.com",
    "firstName": "Hello",
    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
    "isSynchronized": False,
    "lastName": "User",
    "schemaVersionNumber": "1.0",
    "userName": "hellouser"
}

create_user = {
    "email": "usertest123@gmail.com",
    "firstName": "User",
    "id": "iNlPIy6flxPgkpeUDHEAAAAc",
    "isSynchronized": False,
    "lastName": "Test",
    "schemaVersionNumber": "1.0",
    "userName": "usertest123"
}

update_user = {
    "email": "usertest123@gmail.com",
    "firstName": "Demo",
    "id": "iNlPIy6flxPgkpeUDHEAAAAc",
    "isSynchronized": False,
    "lastName": "Name",
    "schemaVersionNumber": "1.0",
    "userName": "demousername"
}

delete_user = Response()
delete_user.status_code = 204

user_groups = [
    {
        "description": "High Risk Group for Testing",
        "id": "50331650",
        "isSynchronized": False,
        "name": "TestHighRiskGroup",
        "schemaVersionNumber": "1.0"
    },
    {
        "description": "Group for testing.",
        "id": "50331652",
        "isSynchronized": False,
        "name": "TestGroup0",
        "schemaVersionNumber": "1.0"
    }
]

group_list = [
    {
        "description": "Group for testing.",
        "id": "50331649",
        "isSynchronized": False,
        "name": "TestGroup1",
        "schemaVersionNumber": "1.0"
    },
    {
        "description": "High Risk Group for Testing",
        "id": "50331650",
        "isSynchronized": False,
        "name": "TestHighRiskGroup",
        "schemaVersionNumber": "1.0"
    },
    {
        "description": "Group for testing.",
        "id": "50331652",
        "isSynchronized": False,
        "name": "TestGroup0",
        "schemaVersionNumber": "1.0"
    }
]

group_info = {
    "description": "Group for testing.",
    "id": "50331649",
    "isSynchronized": False,
    "name": "TestGroup1",
    "schemaVersionNumber": "1.0"
}

group_members = [
    {
        "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
        "links": {
            "self": "https://api.stademo.com/api/v1/tenants/HNESAUHHA6/users/CNlM6Pyq3nADXA4rWyUAAAAc?isUid=true"
        },
        "name": "demouser",
        "type": "User"
    },
    {
        "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
        "links": {
            "self": "https://api.stademo.com/api/v1/tenants/HNESAUHHA6/users/CNlM6rvB0uQDXA4rWyUAAAAc?isUid=true"
        },
        "name": "hellouser",
        "type": "User"
    }
]

create_group = {
    "description": "Group description.",
    "id": "16777219",
    "isSynchronized": False,
    "name": "TestGroup2",
    "schemaVersionNumber": "1.0"
}

remove_user = Response()
remove_user.status_code = 204

update_group = {
    "description": "Description has been updated from XSOAR end.",
    "id": "50331649",
    "isSynchronized": False,
    "name": "TestGroup1",
    "schemaVersionNumber": "1.0"
}

user_exist_group = True

add_user_group = Response()
add_user_group.status_code = 200

remove_user_group = Response()
remove_user_group.status_code = 204

access_logs = [
    {
        "actionText": "AUTH_ATTEMPT",
        "credentialType": "MobilePASS",
        "ip": "165.225.104.81",
        "message": "Login from SafeNet Authentication Service Console.",
        "resultText": "CHALLENGE",
        "serial": "1000014514",
        "timeStamp": "2021-07-22T08:19:05.5905986Z",
        "userName": "demouser"
    },
    {
        "actionText": "AUTH_ATTEMPT",
        "credentialType": "MobilePASS",
        "ip": "165.225.104.81",
        "message": "Login from SafeNet Authentication Service Console.",
        "resultText": "AUTH_SUCCESS",
        "serial": "1000014514",
        "timeStamp": "2021-07-22T08:20:45.5326006Z",
        "userName": "demouser"
    },
    {
        "actionText": "AUTH_ATTEMPT",
        "credentialType": "MobilePASS",
        "ip": "165.225.104.81",
        "message": "Login from SafeNet Authentication Service Console.",
        "resultText": "AUTH_SUCCESS",
        "serial": "1000014514",
        "timeStamp": "2021-07-22T09:20:21.1356016Z",
        "userName": "demouser"
    }
]

validate_tenant = True


''' TEST COMMAND FUNCTIONS '''


# Tests sta-get-user-list command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'limit': '5'},
         [{"email": "demo.user4alert@gmail.com", "firstName": "Demo", "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
           "isSynchronized": False, "lastName": "User", "schemaVersionNumber": "1.0", "userName": "demouser"},
          {"email": "hello.user@gmail.com", "firstName": "Hello", "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
           "isSynchronized": False, "lastName": "User", "schemaVersionNumber": "1.0", "userName": "hellouser"}],
         [{'id': 'CNlM6Pyq3nADXA4rWyUAAAAc', 'schemaVersionNumber': '1.0', 'userName': 'demouser',
           'firstName': 'Demo', 'lastName': 'User', 'email': 'demo.user4alert@gmail.com',
           'isSynchronized': False},
          {'id': 'CNlM6rvB0uQDXA4rWyUAAAAc', 'schemaVersionNumber': '1.0', 'userName': 'hellouser',
           'firstName': 'Hello', 'lastName': 'User', 'email': 'hello.user@gmail.com',
           'isSynchronized': False}])
    ])
def test_get_userlist_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_userlist_sta_command

    mocker.patch.object(client, 'get_userlist_sta', return_value=user_list)
    response = get_userlist_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs_key_field[0] in expected_output[0]
    assert 'demouser' in response.readable_output
    assert 'hellouser' in response.readable_output


# Tests sta-get-user-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'hellouser'},
         {"email": "hello.user@gmail.com", "firstName": "Hello", "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
          "isSynchronized": False, "lastName": "User", "schemaVersionNumber": "1.0", "userName": "hellouser"},
         {'id': 'CNlM6rvB0uQDXA4rWyUAAAAc', 'schemaVersionNumber': '1.0', 'userName': 'hellouser',
          'firstName': 'Hello', 'lastName': 'User', 'email': 'hello.user@gmail.com',
          'isSynchronized': False})
    ])
def test_get_user_info_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_user_info_sta_command
    mocker.patch.object(client, 'get_user_info_sta', return_value=user_info)
    response = get_user_info_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs_key_field[0] in expected_readable
    assert response.outputs['userName'] == args['userName']
    assert 'hellouser' in response.readable_output


# Tests sta-create-user command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'usertest123', 'firstName': 'User', 'lastName': 'Test', 'email': 'usertest123@gmail.com'},
         {"email": "usertest123@gmail.com", "firstName": "User", "id": "iNlPIy6flxPgkpeUDHEAAAAc",
          "isSynchronized": False, "lastName": "Test", "schemaVersionNumber": "1.0", "userName": "usertest123"},
         {"id": "iNlPIy6flxPgkpeUDHEAAAAc", "schemaVersionNumber": "1.0", "userName": "usertest123",
          "firstName": "User", "lastName": "Test", "email": "usertest123@gmail.com", "isSynchronized": False})
    ])
def test_create_user_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import create_user_sta_command
    mocker.patch.object(client, 'create_user_sta', return_value=create_user)
    response = create_user_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs_key_field[0] in expected_readable
    assert response.outputs['userName'] == args['userName']
    assert 'usertest123' in response.readable_output


# Tests sta-update-user-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'usertest123', 'firstName': 'Demo', 'lastName': 'Name', 'userName_new': 'demousername'},
         {"email": "usertest123@gmail.com", "firstName": "Demo", "id": "iNlPIy6flxPgkpeUDHEAAAAc",
          "isSynchronized": False, "lastName": "Name", "schemaVersionNumber": "1.0", "userName": "demousername"},
         {"id": "iNlPIy6flxPgkpeUDHEAAAAc", "schemaVersionNumber": "1.0", "userName": "demousername",
          "firstName": "Demo", "lastName": "Name", "email": "usertest123@gmail.com", "isSynchronized": False})
    ])
def test_update_user_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import update_user_sta_command
    mocker.patch.object(client, 'update_user_sta', return_value=update_user)
    response = update_user_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs_key_field[0] in expected_readable
    assert response.outputs['userName'] == args['userName_new']


# Tests sta-delete-user command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'userName': 'demousername'},
         {204})
    ])
def test_delete_user_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import delete_user_sta_command
    mocker.patch.object(client, 'delete_user_sta', return_value=delete_user)
    response = delete_user_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER.DELETE'
    assert response.outputs == 204
    assert 'demousername' in response.readable_output


# Tests sta-get-user-groups command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'hellouser', 'limit': '5'},
         [{"description": "High Risk Group for Testing", "id": "50331650", "isSynchronized": False,
           "name": "TestHighRiskGroup", "schemaVersionNumber": "1.0"},
          {"description": "Group for testing.", "id": "50331652", "isSynchronized": False, "name": "TestGroup0",
           "schemaVersionNumber": "1.0"}],
         [{"id": "50331650", "schemaVersionNumber": "1.0", "name": "TestHighRiskGroup",
           "description": "High Risk Group for Testing", "isSynchronized": False},
          {"id": "50331652", "schemaVersionNumber": "1.0", "name": "TestGroup0", "description": "Group for testing.",
           "isSynchronized": False}]
         )
    ])
def test_get_user_groups_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_user_groups_sta_command

    mocker.patch.object(client, 'get_user_groups_sta', return_value=user_groups)
    response = get_user_groups_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs_key_field[0] in expected_output[0]
    assert response.outputs == expected_output
    assert 'TestHighRiskGroup' in response.outputs[0]['name']
    assert 'TestGroup0' in response.outputs[1]['name']


# Tests sta-get-group-list command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'limit': '5'},
         [{"description": "Group for testing.", "id": "50331649", "isSynchronized": False,
           "name": "TestGroup1", "schemaVersionNumber": "1.0"},
          {"description": "High Risk Group for Testing", "id": "50331650", "isSynchronized": False,
           "name": "TestHighRiskGroup", "schemaVersionNumber": "1.0"},
          {"description": "Group for testing.", "id": "50331652", "isSynchronized": False, "name": "TestGroup0",
           "schemaVersionNumber": "1.0"}],
         [{"id": "50331649", "schemaVersionNumber": "1.0", "name": "TestGroup1",
           "description": "Group for testing.", "isSynchronized": False},
          {"id": "50331650", "schemaVersionNumber": "1.0", "name": "TestHighRiskGroup",
           "description": "High Risk Group for Testing", "isSynchronized": False},
          {"id": "50331652", "schemaVersionNumber": "1.0", "name": "TestGroup0", "description": "Group for testing.",
           "isSynchronized": False}]
         )
    ])
def test_get_group_list_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_group_list_sta_command

    mocker.patch.object(client, 'get_group_list_sta', return_value=group_list)
    response = get_group_list_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs_key_field[0] in expected_output[0]
    assert len(response.outputs) <= int(args['limit'])
    assert 'TestGroup1' in response.outputs[0]['name']
    assert 'TestHighRiskGroup' in response.outputs[1]['name']
    assert 'TestGroup0' in response.outputs[2]['name']


# Tests sta-get-group-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'groupName': 'TestGroup1'},
         {"description": "Group for testing.", "id": "50331649", "isSynchronized": False,
          "name": "TestGroup1", "schemaVersionNumber": "1.0"},
         {"id": "50331649", "schemaVersionNumber": "1.0", "name": "TestGroup1",
          "description": "Group for testing.", "isSynchronized": False})
    ])
def test_get_group_info_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_group_info_sta_command
    mocker.patch.object(client, 'get_group_info_sta', return_value=group_info)
    response = get_group_info_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs_key_field[0] in expected_readable
    assert response.outputs['name'] == args['groupName']
    assert 'TestGroup1' in response.readable_output


# Tests sta-get-group-members command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'groupName': 'TestGroup0'},
         [{"id": "CNlM6Pyq3nADXA4rWyUAAAAc",
           "links": {
               "self": "https://api.stademo.com/api/v1/tenants/HNESAUHHA6/users/CNlM6Pyq3nADXA4rWyUAAAAc?isUid=true"},
           "name": "demouser", "type": "User"},
          {"id": "CNlM6rvB0uQDXA4rWyUAAAAc",
           "links": {
               "self": "https://api.stademo.com/api/v1/tenants/HNESAUHHA6/users/CNlM6rvB0uQDXA4rWyUAAAAc?isUid=true"},
           "name": "hellouser", "type": "User"}],
         [{"id": "CNlM6Pyq3nADXA4rWyUAAAAc", "name": "demouser", "type": "User"},
          {"id": "CNlM6rvB0uQDXA4rWyUAAAAc", "name": "hellouser", "type": "User"}])
    ])
def test_get_group_members_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_group_members_sta_command

    mocker.patch.object(client, 'get_group_members_sta', return_value=group_members)
    response = get_group_members_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs_key_field[0] in expected_output[0]
    assert 'demouser' in response.readable_output
    assert 'hellouser' in response.readable_output


# Tests sta-create-group command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'groupName': 'TestGroup2', 'description': 'Group description.', 'isSynchronized': False},
         {"description": "Group description.", "id": "16777219", "isSynchronized": False,
          "name": "TestGroup2", "schemaVersionNumber": "1.0"},
         {"id": "16777219", "schemaVersionNumber": "1.0", "name": "TestGroup2", "description": "Group description.",
          "isSynchronized": False})
    ])
def test_create_group_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import create_group_sta_command

    mocker.patch.object(client, 'create_group_sta', return_value=create_group)
    response = create_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs_key_field[0] in expected_output
    assert response.outputs['name'] == args['groupName']
    assert 'TestGroup2' in response.readable_output


# Tests sta-delete-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup2'},
         {204})
    ])
def test_delete_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import delete_group_sta_command

    mocker.patch.object(client, 'delete_group_sta', return_value=remove_user)
    response = delete_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.DELETE.GROUP'
    assert response.outputs == 204
    assert 'TestGroup2' in response.readable_output


# Tests sta-update-group-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'groupName': 'TestGroup1', 'description': 'Description has been updated from XSOAR end.'},
         {"description": "Description has been updated from XSOAR end.", "id": "50331649", "isSynchronized": False,
          "name": "TestGroup1", "schemaVersionNumber": "1.0"},
         {"id": "50331649", "schemaVersionNumber": "1.0", "name": "TestGroup1",
          "description": "Description has been updated from XSOAR end.", "isSynchronized": False})
    ])
def test_update_group_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import update_group_sta_command

    mocker.patch.object(client, 'update_group_sta', return_value=update_group)
    response = update_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs_key_field[0] in expected_output
    assert response.outputs['description'] == args['description']


# Tests sta-add-user-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup1', 'userName': 'hellouser'},
         {200})
    ])
def test_add_user_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import add_user_group_sta_command

    mocker.patch.object(client, 'add_user_group_sta', return_value=add_user_group)
    response = add_user_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.ADD.USER.GROUP'
    assert response.outputs == 200
    assert 'TestGroup1' in response.readable_output
    assert 'hellouser' in response.readable_output


# Tests sta-user-exist-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup1', 'userName': 'hellouser'},
         True)
    ])
def test_user_exist_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import user_exist_group_sta_command

    mocker.patch.object(client, 'user_exist_group_sta', return_value=user_exist_group)
    response = user_exist_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER.EXIST.GROUP'
    assert response.outputs is True


# Tests sta-remove-user-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup1', 'userName': 'hellouser'},
         {204})
    ])
def test_remove_user_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import remove_user_group_sta_command

    mocker.patch.object(client, 'remove_user_group_sta', return_value=remove_user_group)
    response = remove_user_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.REMOVE.USER.GROUP'
    assert response.outputs == 204
    assert 'TestGroup1' in response.readable_output
    assert 'hellouser' in response.readable_output


# Tests sta-get-access-logs command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'demouser', 'since': '2021-07-21T12:22:16.718Z'},
         [{"actionText": "AUTH_ATTEMPT", "credentialType": "MobilePASS", "ip": "165.225.104.81",
           "message": "Login from SafeNet Authentication Service Console.", "resultText": "CHALLENGE",
           "serial": "1000014514", "timeStamp": "2021-07-22T08:19:05.5905986Z", "userName": "demouser"},
          {"actionText": "AUTH_ATTEMPT", "credentialType": "MobilePASS", "ip": "165.225.104.81",
           "message": "Login from SafeNet Authentication Service Console.", "resultText": "AUTH_SUCCESS",
           "serial": "1000014514", "timeStamp": "2021-07-22T08:20:45.5326006Z", "userName": "demouser"},
          {"actionText": "AUTH_ATTEMPT", "credentialType": "MobilePASS", "ip": "165.225.104.81",
           "message": "Login from SafeNet Authentication Service Console.", "resultText": "AUTH_SUCCESS",
           "serial": "1000014514", "timeStamp": "2021-07-22T09:20:21.1356016Z", "userName": "demouser"}],
         [{"timeStamp": "2021-07-22T08:19:05.5905986Z", "userName": "demouser", "actionText": "AUTH_ATTEMPT",
           "resultText": "CHALLENGE", "credentialType": "MobilePASS",
           "message": "Login from SafeNet Authentication Service Console.",
           "serial": "1000014514", "ip": "165.225.104.81"},
          {"timeStamp": "2021-07-22T08:20:45.5326006Z", "userName": "demouser", "actionText": "AUTH_ATTEMPT",
           "resultText": "AUTH_SUCCESS", "credentialType": "MobilePASS",
           "message": "Login from SafeNet Authentication Service Console.",
           "serial": "1000014514", "ip": "165.225.104.81"},
          {"timeStamp": "2021-07-22T09:20:21.1356016Z", "userName": "demouser", "actionText": "AUTH_ATTEMPT",
           "resultText": "AUTH_SUCCESS", "credentialType": "MobilePASS",
           "message": "Login from SafeNet Authentication Service Console.",
           "serial": "1000014514", "ip": "165.225.104.81"}])
    ])
def test_get_access_logs_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_access_logs_sta_command

    mocker.patch.object(client, 'get_access_logs_sta', return_value=access_logs)
    response = get_access_logs_sta_command(client, args)

    assert response.outputs_prefix == 'STA.LOGS'
    assert response.outputs_key_field in expected_output[0]
    assert response.outputs[0]['userName'] == args['userName']


# Tests sta-validate-tenant command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({}, True)
    ])
def test_validate_tenant_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import validate_tenant_sta_command

    mocker.patch.object(client, 'validate_tenant_sta', return_value=validate_tenant)
    response = validate_tenant_sta_command(client, args)

    assert response.outputs_prefix == 'STA.VALIDATE.TENANT'
    assert response.outputs is True
