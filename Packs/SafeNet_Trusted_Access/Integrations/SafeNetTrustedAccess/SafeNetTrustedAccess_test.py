import pytest
from SafeNetTrustedAccess import Client

# Defining client object for mocker
client = Client(base_url="demisto.com")

# Defining result of command functions for mocker
user_list = [
    {
        "email": "demo.user@demisto.com",
        "firstName": "Demo",
        "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
        "isSynchronized": False,
        "lastName": "User",
        "schemaVersionNumber": "1.0",
        "userName": "demouser"
    },
    {
        "email": "test.user@demisto.com",
        "firstName": "Hello",
        "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
        "isSynchronized": False,
        "lastName": "User",
        "schemaVersionNumber": "1.0",
        "userName": "hellouser"
    }
]

user_info = {
    "email": "test.user@demisto.com",
    "firstName": "Hello",
    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
    "isSynchronized": False,
    "lastName": "User",
    "schemaVersionNumber": "1.0",
    "userName": "hellouser"
}

create_user = {
    "email": "demo.user@demisto.com",
    "firstName": "User",
    "id": "iNlPIy6flxPgkpeUDHEAAAAc",
    "isSynchronized": False,
    "lastName": "Test",
    "schemaVersionNumber": "1.0",
    "userName": "usertest123"
}

update_user = {
    "email": "demo.user@demisto.com",
    "firstName": "Demo",
    "id": "iNlPIy6flxPgkpeUDHEAAAAc",
    "isSynchronized": False,
    "lastName": "Name",
    "schemaVersionNumber": "1.0",
    "userName": "testuser"
}

delete_user = {
    "Deleted": True,
    "id": "iNlsjym+x1MLesvCSusAAAAc",
    "userName": "testuser1"
}

user_groups_response = [
    {
        "description": "Unusual Activity Group for Testing",
        "id": "50331650",
        "isSynchronized": False,
        "name": "Test Group",
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

user_groups_context = {
    "email": "test.user@demisto.com",
    "firstName": "Hello",
    "groups": [
        {
            "description": "Unusual Activity Group for Testing",
            "id": "50331650",
            "isSynchronized": False,
            "name": "Test Group",
            "schemaVersionNumber": "1.0"
        },
        {
            "description": "Group for testing.",
            "id": "50331652",
            "isSynchronized": False,
            "name": "TestGroup0",
            "schemaVersionNumber": "1.0"
        }
    ],
    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
    "isSynchronized": False,
    "lastName": "User",
    "schemaVersionNumber": "1.0",
    "userName": "hellouser"
}
user_groups_data = (user_groups_response, user_groups_context)

group_list = [
    {
        "description": "Group for testing.",
        "id": "50331649",
        "isSynchronized": False,
        "name": "TestGroup1",
        "schemaVersionNumber": "1.0"
    },
    {
        "description": "Unusual Activity Group for Testing",
        "id": "50331650",
        "isSynchronized": False,
        "name": "Test Group",
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

group_members_response = [
    {
        "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
        "links": {
            "self": "https://api.safenet.com/api/v1/tenants/HNSA1UHHA6/users/CNlM6Pyq3nADXA4rWyUAAAAc?isUid=True"
        },
        "name": "demouser",
        "type": "User"
    },
    {
        "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
        "links": {
            "self": "https://api.safenet.com/api/v1/tenants/HNSA1UHHA6/users/CNlM6rvB0uQDXA4rWyUAAAAc?isUid=True"
        },
        "name": "hellouser",
        "type": "User"
    }
]

group_members_context = {
    "description": "Group for testing.",
    "id": "50331652",
    "isSynchronized": False,
    "name": "TestGroup0",
    "schemaVersionNumber": "1.0",
    "users": [
        {
            "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
            "links": {
                "self": "https://api.safenet.com/api/v1/tenants/HNSA1UHHA6/users/CNlM6Pyq3nADXA4rWyUAAAAc?isUid=True"
            },
            "name": "demouser",
            "type": "User"
        },
        {
            "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
            "links": {
                "self": "https://api.safenet.com/api/v1/tenants/HNSA1UHHA6/users/CNlM6rvB0uQDXA4rWyUAAAAc?isUid=True"
            },
            "name": "hellouser",
            "type": "User"
        }
    ]
}
group_members_data = (group_members_response, group_members_context)

create_group = {
    "description": "Group description.",
    "id": "16777219",
    "isSynchronized": False,
    "name": "TestGroup2",
    "schemaVersionNumber": "1.0"
}

delete_group = {
    "Deleted": True,
    "groupName": "TestGroup2",
    "id": "16777228"
}
group_id = "16777228"

update_group = {
    "description": "Description has been updated.",
    "id": "50331649",
    "isSynchronized": False,
    "name": "TestGroup1",
    "schemaVersionNumber": "1.0"
}

user_exist_group = True

add_user_group = {
    "groupName": "TestGroup1",
    "group_id": "50331649",
    "status": True,
    "userName": "hellouser",
    "user_id": "CNlM6rvB0uQDXA4rWyUAAAAc"
}

remove_user_group = {
    "groupName": "TestGroup1",
    "group_id": "50331649",
    "status": False,
    "userName": "hellouser",
    "user_id": "CNlM6rvB0uQDXA4rWyUAAAAc"
}

logs_result = [
    {
        "actionText": "AUTH_ATTEMPT",
        "applicationName": "",
        "credentialType": "MobilePASS",
        "ip": "8.8.8.8",
        "logType": "AUTHENTICATION",
        "message": "Login from STA Console.",
        "operationObjectName": "",
        "operationObjectType": "",
        "operationType": "",
        "policyName": "",
        "resultText": "CHALLENGE",
        "serial": "1000014514",
        "state": "",
        "timeStamp": "2021-07-22T08:19:05.5905986Z",
        "userName": "demouser"
    }
]

validate_tenant = True

application_list = [
    {
        "id": "01985260-d205-41cc-9b77-61686688b288",
        "name": "Application1",
        "status": "Active"
    },
    {
        "id": "01985260-d205-37mc-9b77-61686688a933",
        "name": "Application2",
        "status": "Active"
    }
]

application_context = {
    "id": "1ccbab74-01c2-4af2-bb9b-af8f861ccfab",
    "name": "Application1",
    "status": "Active",
    "applicationType": "Saml",
    "templateName": "HB_TEST_Application_Metadata",
    "assignment": {
        "everyone": True
    },
    "schemaVersionNumber": "1.0",
    "lastModified": "2021-08-27T12:25:47.998Z"
}

application_readable = {
    "id": "1ccbab74-01c2-4af2-bb9b-af8f861ccfab",
    "name": "Application1",
    "status": "Active",
    "applicationType": "Saml",
    "templateName": "HB_TEST_Application_Metadata",
    "assignment": "Everyone",
    "schemaVersionNumber": "1.0",
    "lastModified": "2021-08-27T12:25:47.998Z"
}

application_info = (application_readable, application_context)

user_applications_response = [
    {
        "id": "01985260-d205-41cc-9b77-61686688b288",
        "name": "Application1",
        "status": "Active"
    },
    {
        "id": "01985260-d205-37mc-9b77-61686688a933",
        "name": "Application2",
        "status": "Active"
    }
]

user_applications_context = {
    "email": "test.user@demisto.com",
    "firstName": "Hello",
    "applications": [
        {
            "id": "01985260-d205-41cc-9b77-61686688b288",
            "name": "Application1",
            "status": "Active"
        },
        {
            "id": "01985260-d205-37mc-9b77-61686688a933",
            "name": "Application2",
            "status": "Active"
        }
    ],
    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
    "isSynchronized": False,
    "lastName": "User",
    "schemaVersionNumber": "1.0",
    "userName": "hellouser"
}
user_applications_data = (user_applications_response, user_applications_context)

user_sessions_readable = {
    "sessions": [
        {
            "id": "9b4c9ae7-a8b8-4ae8-a419-52ffb6c266d6",
            "start": 1607472514000,
            "expiry": 1607472526000,
            "applications": ["Application1", "Application2"]
        }
    ]
}

user_sessions_context = {
    "email": "test.user@demisto.com",
    "firstName": "Hello",
    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
    "isSynchronized": False,
    "lastName": "User",
    "schemaVersionNumber": "1.0",
    "userName": "hellouser",
    "sessions": [
        {
            "id": "9b4c9ae7-a8b8-4ae8-a419-52ffb6c266d6",
            "start": 1607472514000,
            "expiry": 1607472526000,
            "applications": [
                {
                    "id": "entity_id1",
                    "name": "Application1"
                },
                {
                    "id": "entity_id2",
                    "name": "Application2"
                }
            ]
        }
    ]
}
user_sessions_data = (user_sessions_readable, user_applications_context)

delete_sessions = {
    "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
    "userName": "hellouser",
    "sessions": {
        "Deleted": True
    }
}

''' TEST COMMAND FUNCTIONS '''


# Tests sta-get-user-list command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'limit': '5'},
         [{"email": "demo.user@demisto.com", "first_name": "Demo", "id": "CNlM6Pyq3nADXA4rWyUAAAAc",
           "isSynchronized": False, "lastName": "User", "schemaVersionNumber": "1.0", "userName": "demouser"},
          {"email": "test.user@demisto.com", "first_name": "Hello", "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
           "isSynchronized": False, "lastName": "User", "schemaVersionNumber": "1.0", "userName": "hellouser"}],
         [{'id': 'CNlM6Pyq3nADXA4rWyUAAAAc', 'schemaVersionNumber': '1.0', 'userName': 'demouser',
           'firstName': 'Demo', 'lastName': 'User', 'email': 'demo.user@demisto.com',
           'isSynchronized': False},
          {'id': 'CNlM6rvB0uQDXA4rWyUAAAAc', 'schemaVersionNumber': '1.0', 'userName': 'hellouser',
           'firstName': 'Hello', 'lastName': 'User', 'email': 'test.user@demisto.com',
           'isSynchronized': False}])
    ])
def test_get_userlist_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_userlist_sta_command

    mocker.patch.object(client, 'get_userlist_sta', return_value=user_list)
    response = get_userlist_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert 'demouser' in response.readable_output
    assert 'hellouser' in response.readable_output


# Tests sta-get-user-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'hellouser'},
         {"email": "test.user@demisto.com", "first_name": "Hello", "id": "CNlM6rvB0uQDXA4rWyUAAAAc",
          "isSynchronized": False, "lastName": "User", "schemaVersionNumber": "1.0", "userName": "hellouser"},
         {'id': 'CNlM6rvB0uQDXA4rWyUAAAAc', 'schemaVersionNumber': '1.0', 'userName': 'hellouser',
          'firstName': 'Hello', 'lastName': 'User', 'email': 'test.user@demisto.com',
          'isSynchronized': False})
    ])
def test_get_user_info_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_user_info_sta_command
    mocker.patch.object(client, 'get_user_info_sta', return_value=user_info)
    response = get_user_info_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs['userName'] == args['userName']
    assert 'hellouser' in response.readable_output


# Tests sta-create-user command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'usertest123', 'first_name': 'User', 'last_name': 'Test', 'email': 'demo.user@demisto.com'},
         {"email": "demo.user@demisto.com", "firstName": "User", "id": "iNlPIy6flxPgkpeUDHEAAAAc",
          "isSynchronized": False, "lastName": "Test", "schemaVersionNumber": "1.0", "userName": "usertest123"},
         {"id": "iNlPIy6flxPgkpeUDHEAAAAc", "schemaVersionNumber": "1.0", "userName": "usertest123",
          "firstName": "User", "lastName": "Test", "email": "demo.user@demisto.com", "isSynchronized": False})
    ])
def test_create_user_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import create_user_sta_command
    mocker.patch.object(client, 'create_user_sta', return_value=create_user)
    response = create_user_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs['userName'] == args['userName']
    assert 'usertest123' in response.readable_output


# Tests sta-update-user-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'usertest123', 'first_name': 'Demo', 'last_name': 'Name', 'userName_new': 'testuser'},
         {"email": "demo.user@demisto.com", "firstName": "Demo", "id": "iNlPIy6flxPgkpeUDHEAAAAc",
          "isSynchronized": False, "lastName": "Name", "schemaVersionNumber": "1.0", "userName": "testuser"},
         {"id": "iNlPIy6flxPgkpeUDHEAAAAc", "schemaVersionNumber": "1.0", "userName": "testuser",
          "firstName": "Demo", "lastName": "Name", "email": "demo.user@demisto.com", "isSynchronized": False})
    ])
def test_update_user_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import update_user_sta_command
    mocker.patch.object(client, 'update_user_sta', return_value=update_user)
    response = update_user_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs['userName'] == args['userName_new']


# Tests sta-delete-user command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'userName': 'testuser1'},
         {"Deleted": True, "id": "iNlsjym+x1MLesvCSusAAAAc", "userName": "testuser1"})
    ])
def test_delete_user_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import delete_user_sta_command
    mocker.patch.object(client, 'delete_user_sta', return_value=delete_user)
    response = delete_user_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert response.outputs['Deleted'] is True
    assert 'testuser1' in response.readable_output


# Tests sta-get-user-groups command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'hellouser', 'limit': '5'}, user_groups_context, user_groups_response)
    ])
def test_get_user_groups_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_user_groups_sta_command

    mocker.patch.object(client, 'user_groups_data', return_value=user_groups_data)
    response = get_user_groups_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert 'Test Group' in response.readable_output
    assert 'TestGroup0' in response.readable_output


# Tests sta-get-group-list command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'limit': '5'},
         [{"description": "Group for testing.", "id": "50331649", "isSynchronized": False,
           "name": "TestGroup1", "schemaVersionNumber": "1.0"},
          {"description": "Unusual Activity Group for Testing", "id": "50331650", "isSynchronized": False,
           "name": "Test Group", "schemaVersionNumber": "1.0"},
          {"description": "Group for testing.", "id": "50331652", "isSynchronized": False, "name": "TestGroup0",
           "schemaVersionNumber": "1.0"}],
         [{"id": "50331649", "schemaVersionNumber": "1.0", "name": "TestGroup1",
           "description": "Group for testing.", "isSynchronized": False},
          {"id": "50331650", "schemaVersionNumber": "1.0", "name": "Test Group",
           "description": "Unusual Activity Group for Testing", "isSynchronized": False},
          {"id": "50331652", "schemaVersionNumber": "1.0", "name": "TestGroup0", "description": "Group for testing.",
           "isSynchronized": False}]
         )
    ])
def test_get_group_list_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_group_list_sta_command

    mocker.patch.object(client, 'get_group_list_sta', return_value=group_list)
    response = get_group_list_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert 'TestGroup1' in response.outputs[0]['name']


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
    assert response.outputs['name'] == args['groupName']
    assert 'TestGroup1' in response.readable_output


# Tests sta-get-group-members command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'groupName': 'TestGroup0'}, group_members_context, group_members_response)
    ])
def test_get_group_members_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_group_members_sta_command

    mocker.patch.object(client, 'group_members_data', return_value=group_members_data)
    response = get_group_members_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
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
    assert response.outputs['name'] == args['groupName']
    assert 'TestGroup2' in response.readable_output


# Tests sta-delete-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup2'},
         {"Deleted": True, "groupName": "TestGroup2", "id": "16777228"})
    ])
def test_delete_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import delete_group_sta_command

    mocker.patch.object(client, 'delete_group_sta', return_value=delete_group)
    response = delete_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs['Deleted'] is True
    assert 'TestGroup2' in response.readable_output


# Tests sta-update-group-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'groupName': 'TestGroup1', 'description': 'Description has been updated.'},
         {"description": "Description has been updated.", "id": "50331649", "isSynchronized": False,
          "name": "TestGroup1", "schemaVersionNumber": "1.0"},
         {"id": "50331649", "schemaVersionNumber": "1.0", "name": "TestGroup1",
          "description": "Description has been updated.", "isSynchronized": False})
    ])
def test_update_group_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import update_group_sta_command

    mocker.patch.object(client, 'update_group_sta', return_value=update_group)
    response = update_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.GROUP'
    assert response.outputs['description'] == args['description']


# Tests sta-add-user-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup1', 'userName': 'hellouser'},
         {"groupName": "TestGroup1", "group_id": "50331649", "status": True, "userName": "hellouser",
             "user_id": "CNlM6rvB0uQDXA4rWyUAAAAc"})
    ])
def test_add_user_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import add_user_group_sta_command

    mocker.patch.object(client, 'add_user_group_sta', return_value=add_user_group)
    response = add_user_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.UPDATE.USER.GROUP'
    assert 'TestGroup1' in response.readable_output
    assert response.outputs['status'] is True
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

    assert response.outputs_prefix == 'STA.EXIST.USER.GROUP'
    assert response.outputs is True


# Tests sta-remove-user-group command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'groupName': 'TestGroup1', 'userName': 'hellouser'},
         {"groupName": "TestGroup1", "group_id": "50331649", "status": False, "userName": "hellouser",
          "user_id": "CNlM6rvB0uQDXA4rWyUAAAAc"})
    ])
def test_remove_user_group_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import remove_user_group_sta_command

    mocker.patch.object(client, 'remove_user_group_sta', return_value=remove_user_group)
    response = remove_user_group_sta_command(client, args)

    assert response.outputs_prefix == 'STA.UPDATE.USER.GROUP'
    assert response.outputs['status'] is False
    assert 'TestGroup1' in response.readable_output
    assert 'hellouser' in response.readable_output


# Tests sta-get-access-logs command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({},
         [{"actionText": "AUTH_ATTEMPT", "applicationName": "", "credentialType": "MobilePASS",
           "ip": "8.8.8.8", "logType": "AUTHENTICATION", "message": "Login from STA Console.",
           "operationObjectName": "", "operationObjectType": "", "operationType": "", "policyName": "",
           "resultText": "CHALLENGE", "serial": "1000014514", "state": "",
           "timeStamp": "2021-07-22T08:19:05.5905986Z", "userName": "demouser"}],
         [{"actionText": "AUTH_ATTEMPT", "applicationName": "", "credentialType": "MobilePASS",
           "ip": "8.8.8.8", "logType": "AUTHENTICATION", "message": "Login from STA Console.",
           "operationObjectName": "", "operationObjectType": "", "operationType": "", "policyName": "",
           "resultText": "CHALLENGE", "serial": "1000014514", "state": "",
           "timeStamp": "2021-07-22T08:19:05.5905986Z", "userName": "demouser"}])
    ])
def test_get_logs_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_logs_sta_command

    mocker.patch.object(client, 'get_logs_sta', return_value=logs_result)
    response = get_logs_sta_command(client, args)

    assert response.outputs_prefix == 'STA.LOGS'


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


# Tests sta-get-application-list command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'limit': '5'},
         [{"id": "01985260-d205-41cc-9b77-61686688b288", "name": "Application1", "status": "Active"},
          {"id": "01985260-d205-37mc-9b77-61686688a933", "name": "Application2", "status": "Active"}],
         [{"id": "01985260-d205-41cc-9b77-61686688b288", "name": "Application1", "status": "Active"},
          {"id": "01985260-d205-37mc-9b77-61686688a933", "name": "Application2", "status": "Active"}])
    ])
def test_get_application_list_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_application_list_sta_command

    mocker.patch.object(client, 'get_application_list_sta', return_value=application_list)
    response = get_application_list_sta_command(client, args)

    assert response.outputs_prefix == 'STA.APPLICATION'
    assert 'Application1' in response.readable_output
    assert 'Application2' in response.readable_output


# Tests sta-get-application-info command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'applicationName': 'Application1'}, application_context, application_readable)
    ])
def test_get_application_info_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_application_info_sta_command
    mocker.patch.object(client, 'get_application_info_sta', return_value=application_info)
    response = get_application_info_sta_command(client, args)

    assert response.outputs_prefix == 'STA.APPLICATION'
    assert args['applicationName'] in response.readable_output
    assert 'Application1' in response.readable_output


# Tests sta-get-user-applications command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'hellouser'}, user_applications_context, user_applications_response)
    ])
def test_get_user_applications_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_user_applications_sta_command

    mocker.patch.object(client, 'user_applications_data', return_value=user_applications_data)
    response = get_user_applications_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert 'Application1' in response.readable_output
    assert 'Application2' in response.readable_output


# Tests sta-get-user-sessions command function.
@pytest.mark.parametrize(
    "args, expected_output, expected_readable",
    [
        ({'userName': 'hellouser'}, user_sessions_context, user_sessions_readable)
    ])
def test_get_user_sessions_sta_command(mocker, args, expected_output, expected_readable):

    from SafeNetTrustedAccess import get_user_sessions_sta_command

    mocker.patch.object(client, 'user_sessions_data', return_value=user_sessions_data)
    response = get_user_sessions_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert 'hellouser' in response.readable_output
    assert 'Sessions' in response.readable_output


# Tests sta-delete-user-sessions command function.
@pytest.mark.parametrize(
    "args, expected_output",
    [
        ({'userName': 'hellouser'}, delete_sessions)
    ])
def test_delete_user_sessions_sta_command(mocker, args, expected_output):

    from SafeNetTrustedAccess import delete_user_sessions_sta_command

    mocker.patch.object(client, 'delete_sessions_sta', return_value=delete_sessions)
    response = delete_user_sessions_sta_command(client, args)

    assert response.outputs_prefix == 'STA.USER'
    assert 'hellouser' in response.readable_output
    assert 'deleted' in response.readable_output
