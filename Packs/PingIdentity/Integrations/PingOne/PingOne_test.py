from PingOne import Client, get_user_command, create_user_command, get_groups_for_user_command
import pytest

user_data = {
    "id": "99da7ad7-490a-4c27-b9ae-7cb685b797db",
    "environment": {
        "id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"
    },
    "account": {
        "canAuthenticate": True,
        "status": "OK"
    },
    "address": {
        "streetAddress": "146 Wayridge Street",
        "locality": "Lexington",
        "region": "KY",
        "countryCode": "US"
    },
    "createdAt": "2021-08-18T19:33:26.304Z",
    "email": "andrieu_lief@example.com",
    "enabled": True,
    "identityProvider": {
        "type": "PING_ONE"
    },
    "lifecycle": {
        "status": "ACCOUNT_OK"
    },
    "mfaEnabled": False,
    "name": {
        "formatted": "Andrieu Lief",
        "given": "Andrieu",
        "family": "Lief"
    },
    "population": {
        "id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"
    },
    "memberOfGroupNames": [
        "Sample Group",
        "Sales"
    ],
    "updatedAt": "2021-08-18T19:33:26.304Z",
    "username": "andrieu_lief",
    "verifyStatus": "NOT_INITIATED",
    "_links": {
    }
}


create_user_response = {
    "id": "9e45580c-79f3-4499-83cc-006a20dcc50e",
    "environment": {
        "id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"
    },
    "account": {
        "canAuthenticate": True,
        "status": "OK"
    },
    "createdAt": "2021-08-20T19:07:00.979Z",
    "enabled": True,
    "identityProvider": {
        "type": "PING_ONE"
    },
    "lifecycle": {
        "status": "ACCOUNT_OK"
    },
    "mfaEnabled": False,
    "population": {
        "id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"
    },
    "updatedAt": "2021-08-20T19:07:00.979Z",
    "username": "marysample6",
    "verifyStatus": "NOT_INITIATED"
}

group_data = [{
    "_embedded": {
        "groupMemberships": [
            {
                "id": "dd95b574-cff5-485e-8460-c245ad8dab0f",
                "environment": {
                    "id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"
                },
                "name": "Sample Group",
                "type": "INDIRECT"
            },
            {

                "id": "8c33d93e-a614-457a-80ed-5e922fccd906",
                "environment": {
                    "id": "b4f5e266-a946-4f77-9cc5-5dc91b046431"
                },
                "name": "Sales",
                "population": {
                    "id": "4cd45bdb-0eb2-42fe-8475-4bcd908269f1"
                },
                "type": "DIRECT"
            }
        ]
    },
    "count": 2,
    "size": 2
}]


class ClientTestPing:
    """
    Test class to handle the client
    """

    def __init__(self, mocker):
        test_params = {
            'client_id': '12345',
            'client_secret': 'clientsecret',
            'base_url': 'https://api.pingone.com',
            'auth_url': 'https://auth.pingone.com'
        }

        testing_auth_header = {'Authorization': 'Bearer ACCESS_TOKEN'}
        mocker.patch.object(Client, '_request_token', return_value=testing_auth_header)

        self.client = Client(
            base_url='https://api.pingone.com',
            verify=False,
            proxy=False,
            auth_params=test_params
        )


@pytest.mark.parametrize(
    # Write and define the expected
    "args ,expected_context, expected_readable",
    [
        ({"userId": "99da7ad7-490a-4c27-b9ae-7cb685b797db", "username": "", "verbose": 'false'},
         {'ID': '99da7ad7-490a-4c27-b9ae-7cb685b797db',
          'Username': 'andrieu_lief',
          'DisplayName': 'Andrieu Lief',
          'Email': 'andrieu_lief@example.com',
          'Enabled': True,
          'CreatedAt': "2021-08-18T19:33:26.304Z",
          'UpdatedAt': "2021-08-18T19:33:26.304Z"}, 'andrieu_lief@example.com'),
        ({"userId": "99da7ad7-490a-4c27-b9ae-7cb685b797db", "username": "", "verbose": 'true'},
         {'ID': '99da7ad7-490a-4c27-b9ae-7cb685b797db',
          'Username': 'andrieu_lief',
          'DisplayName': 'Andrieu Lief',
          'Email': 'andrieu_lief@example.com',
          'Enabled': True,
          'CreatedAt': "2021-08-18T19:33:26.304Z",
          'UpdatedAt': "2021-08-18T19:33:26.304Z"}, 'andrieu_lief@example.com')
    ]
)
def test_get_user_command(mocker, args, expected_context, expected_readable):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, 'get_user', return_value=user_data)
    readable, outputs, _ = get_user_command(client, args)
    assert outputs.get('Account(val.ID && val.ID === obj.ID)')[0] == expected_context
    assert expected_readable in readable


@pytest.mark.parametrize("args", [{'username': 'andrieu_lief'}])
def test_get_groups_for_user_command(mocker, args):
    client = ClientTestPing(mocker).client

    expected_context = [
        {'ID': 'dd95b574-cff5-485e-8460-c245ad8dab0f', 'Name': 'Sample Group'},
        {"ID": "8c33d93e-a614-457a-80ed-5e922fccd906", 'Name': 'Sales'}]
    mocker.patch.object(client, 'get_user_id', return_value='99da7ad7-490a-4c27-b9ae-7cb685b797db')
    mocker.patch.object(client, 'get_groups_for_user', return_value=group_data)
    _, outputs, _ = get_groups_for_user_command(client, args)
    assert outputs.get('Account(val.ID && val.ID === obj.ID)').get('Group') == expected_context
    assert 'andrieu_lief' == outputs.get('Account(val.ID && val.ID === obj.ID)').get('ID')


@pytest.mark.parametrize(
    "args",
    [({'username': 'marysample6',
       'populationId': '4cd45bdb-0eb2-42fe-8475-4bcd908269f1'})])
def test_create_user_command(mocker, args):
    client = ClientTestPing(mocker).client

    mocker.patch.object(client, 'create_user', return_value=create_user_response)
    readable, outputs, _ = create_user_command(client, args)
    assert '9e45580c-79f3-4499-83cc-006a20dcc50e' in readable
    assert outputs.get('Account(val.ID && val.ID === obj.ID)')[0].get('Enabled')
