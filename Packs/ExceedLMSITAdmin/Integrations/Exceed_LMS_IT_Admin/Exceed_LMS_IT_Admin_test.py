import requests
from requests.models import Response
import demistomock as demisto
from Exceed_LMS_IT_Admin import Client, get_user_command, create_user_command,\
    update_user_command, enable_disable_user_command

res = Response()
res.status_code = 200
res._content = b'[{ "email":"TestID@paloaltonetworks.com","is_active": true,' \
               b'"id":"123456","login":"TestID@paloaltonetworks.com"}]'

err_res = Response()
err_res.status_code = 200
err_res.headers.status = "200 Ok"
err_res._content = b'[]'

err_res_u = Response()
err_res_u.status_code = 404
err_res_u.headers.status = "404 Not Found"
err_res_u._content = b'[]'


inp_args = {"scim": {"id": "123456"}}

create_inp_args = {"scim": {"name": {"familyName": "J13", "givenName": "MJ"},
                            "userName": "TestID@paloaltonetworks.com"}}
update_inp_args = {"oldScim": {"id": "123456"},
                   "newScim": {"name": {"familyName": "Mj", "givenName": "Sh"},
                               "emails": [{
                                   "type": "work", "primary": "true",
                                   "value": "TestID@paloaltonetworks.com"
                               }]}}

demisto.callingContext = {'context': {'IntegrationInstance': 'Test',
                                      'IntegrationBrand': 'Test'}}


def test_get_user_command(mocker):
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com',
                    api_key='123456',
                    verify=False,
                    headers={})

    mocker.patch.object(demisto,
                        'dt',
                        return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)

    get_user = 'GetUser(val.id == obj.id ' \
               '&& val.instanceName == obj.instanceName)'
    assert outputs.get(get_user)[0].get('email') == 'TestID@paloaltonetworks.com'


def test_create_user_command(mocker):
    mocker.patch.object(requests,
                        'request',
                        return_value=res)
    client = Client(base_url='https://test.com',
                    api_key='123456',
                    verify=False,
                    headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'


def test_update_user_command(mocker):
    mocker.patch.object(requests,
                        'request',
                        return_value=res)
    client = Client(base_url='https://test.com',
                    api_key='123456',
                    verify=False,
                    headers={})

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')
    mocker.patch.object(demisto,
                        'command',
                        return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)

    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('id') == '123456'


def test_get_user_command_fail(mocker):
    mocker.patch.object(requests, 'request', return_value=err_res)
    client = Client(base_url='https://test.com', api_key='123456', verify=False, headers={})

    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)

    get_user_error = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(get_user_error)[0].get('success')
    assert outputs.get(get_user_error)[0].get('errorMessage') == "User not found"
    assert outputs.get(get_user_error)[0].get('errorCode') == 404


def test_update_user_command_fail(mocker):
    mocker.patch.object(requests, 'request', return_value=err_res_u)
    client = Client(base_url='https://test.com', api_key='123456', verify=False, headers={})

    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)
    update_user_error = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(update_user_error).get('success')
    assert outputs.get(update_user_error).get('errorMessage') == "User not found"
    assert outputs.get(update_user_error).get('errorCode') == 404


def test_create_user_command_fail(mocker):
    res.status_code = 422
    res._content = b'{ "email":"TestID@paloaltonetworks.com", "is_active": true,"id":"123456","login":"has already been taken"}'
    res.headers.status = "404 Not Found"
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', api_key='123456', verify=False, headers={})
    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')
    _, outputs, _ = create_user_command(client, create_inp_args)
    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(create_user).get('success')
    assert outputs.get(create_user).get('errorCode') == 422


def test_enable_command_success(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 200

    mocker.patch.object(demisto, 'command', return_value='activate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', api_key='1234567', headers=headers)

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert data['success']


def test_enable_command_user_not_found(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 404
    mock_response._content = b'{"error":"Couldn\'t find User with \'id\'=410966000 [WHERE \'users\'.\'account_id\' = $1]"}'
    # x = mock_response.json()
    mocker.patch.object(demisto, 'command', return_value='activate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', api_key='1234567', headers=headers)

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 404
    assert data['errorMessage'] == "User not found"


def test_enable_command_wrong_key(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 401
    mock_response._content = b'{"error":"Invalid Request: API Key has not been setup or does not match"}'
    mock_response.headers = {'status': '401, 401 Unauthorized'}
    # x = mock_response.json()
    mocker.patch.object(demisto, 'command', return_value='activate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', api_key='1234567', headers=headers)

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 401
    assert data['errorMessage'] == "401, 401 Unauthorized"


def test_disable_command_success(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 200

    mocker.patch.object(demisto, 'command', return_value='deactivate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', api_key='1234567', headers=headers)

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert data['success']


def test_disable_command_user_not_found(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 404
    mock_response._content = b'{"error":"Couldn\'t find User with \'id\'=410966000 [WHERE \'users\'.\'account_id\' = $1]"}'
    # x = mock_response.json()
    mocker.patch.object(demisto, 'command', return_value='deactivate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', api_key='1234567', headers=headers)

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 404
    assert data['errorMessage'] == "User not found"


def test_disable_command_wrong_key(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 401
    mock_response._content = b'{"error":"Invalid Request: API Key has not been setup or does not match"}'
    mock_response.headers = {'status': '401, 401 Unauthorized'}
    # x = mock_response.json()
    mocker.patch.object(demisto, 'command', return_value='deactivate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', api_key='1234567', headers=headers)

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 401
    assert data['errorMessage'] == "401, 401 Unauthorized"
