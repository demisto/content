import requests
from requests.models import Response
import demistomock as demisto
from ServiceNow_IT_Admin import Client, get_user_command, create_user_command,\
    update_user_command, disable_user_command, enable_user_command
res = Response()
res.status_code = 200
res._content = b'{"result": [{"email":"TestID@paloaltonetworks.com","active": true,' \
               b'"sys_id":"123456","user_name":"TestID@paloaltonetworks.com"}]}'
err_res = Response()
err_res.status_code = 200
err_res.headers.status = "User not found"
err_res._content = b'{"result":[]}'

err_res_u = Response()
err_res_u.status_code = 404
err_res_u.headers.status = "404 Not Found"
err_res_u._content = b'{"error":{"messages":"Error"}'


inp_args = {"scim": {"id": "123456"}}

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
                    username='test123',
                    password='123456',
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
    create_inp_args = {"scim": {"name": {"familyName": "J13", "givenName": "MJ"},
                                "userName": "TestID@paloaltonetworks.com",
                                "active": True,
                                "emails": [{
                                    "value": "TestID@paloaltonetworks.com",
                                    "type": "work"
                                }]}}
    res_create = Response()
    res_create.status_code = 201
    res_create._content = b'{"result": {"email": "TestID@paloaltonetworks.com","active": true,' \
                          b'"sys_id": "123456","user_name": "TestID@paloaltonetworks.com"}}'

    mocker.patch.object(requests,
                        'request',
                        return_value=res_create)
    client = Client(base_url='https://test.com',
                    username='test123',
                    password='123456',
                    verify=False,
                    headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)
    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'


def test_update_user_command(mocker):
    res_update = Response()
    res_update.status_code = 200
    res_update._content = b'{"result": {"email": "TestID@paloaltonetworks.com","active": true,' \
                          b'"sys_id": "123456","user_name": "TestID@paloaltonetworks.com"}}'
    mocker.patch.object(requests,
                        'request',
                        return_value=res_update)
    client = Client(base_url='https://test.com',
                    username='test123',
                    password='123456',
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
    client = Client(base_url='https://test.com', username='test123', password='123456', verify=False, headers={})

    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)
    get_user_error = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(get_user_error)[0].get('success')
    assert outputs.get(get_user_error)[0].get('errorMessage') == "User not found"
    assert outputs.get(get_user_error)[0].get('errorCode') == 404


def test_update_user_command_fail(mocker):
    err_res_u = Response()
    err_res_u.status_code = 404
    err_res_u.headers.status = "404 Not Found"
    err_res_u._content = b'{"error": {"message": "No Record found",' \
                         b'"detail": "Record doesnt exist or ACL restricts the record retrieval"},' \
                         b'"status": "failure"}'
    mocker.patch.object(requests, 'request', return_value=err_res_u)
    client = Client(base_url='https://test.com', username='test123', password='123456', verify=False, headers={})

    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)
    update_user_error = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(update_user_error).get('success')
    assert outputs.get(update_user_error).get('errorMessage') == "No Record found"
    assert outputs.get(update_user_error).get('errorCode') == 404


def test_create_user_command_fail(mocker):
    err_res_u = Response()
    err_res_u.status_code = 404
    err_res_u.headers.status = "404 Not Found"
    err_res_u._content = b'{"error": {"message": "No Record found",' \
                         b'"detail": "Record doesnt exist or ACL restricts the record retrieval"},' \
                         b'"status": "failure"}'
    create_inp_args = {"scim": {"name": {"familyName": "J13", "givenName": "MJ"},
                                "userName": "TestID@paloaltonetworks.com",
                                "active": True,
                                "emails": [{
                                    "value": "TestID@paloaltonetworks.com",
                                    "type": "work"
                                }]}}
    mocker.patch.object(requests, 'request', return_value=err_res_u)
    client = Client(base_url='https://test.com', username='test123', password='123456', verify=False, headers={})
    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')
    _, outputs, _ = create_user_command(client, create_inp_args)
    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(create_user).get('success')
    assert outputs.get(create_user).get('errorCode') == 404


def test_enable_command_success(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    res_enable = Response()
    res_enable.status_code = 200
    res_enable._content = b'{"result": {"email": "TestID@paloaltonetworks.com","active": true,' \
                          b'"sys_id": "123456","user_name": "TestID@paloaltonetworks.com"}}'
    mocker.patch.object(demisto, 'command', return_value='activate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=res_enable)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', username='test123', password='123456', headers=headers)
    readable_output, outputs, data = enable_user_command(client, args)
    assert data['success']


def test_enable_command_user_not_found(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    err_res_e = Response()
    err_res_e.status_code = 404
    err_res_e.headers.status = "404 Not Found"
    err_res_e._content = b'{"error": {"message": "No Record found",' \
                         b'"detail": "Record doesnt exist or ACL restricts the record retrieval"},' \
                         b'"status": "failure"}'
    mocker.patch.object(demisto, 'command', return_value='activate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=err_res_e)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', username='test123', password='123456', headers=headers)

    readable_output, outputs, data = enable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 404
    assert data['errorMessage'] == "No Record found"


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
    mock_response._content = b'{"error": {"detail": "Required to provide Auth information",' \
                             b'"message": "User Not Authenticated"},' \
                             b'"status": "failure"}'
    mocker.patch.object(demisto, 'command', return_value='activate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', username='test123', password='123456', headers=headers)

    readable_output, outputs, data = enable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 401
    assert data['errorMessage'] == "User Not Authenticated"


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
    mock_response._content = b'{"result": {"email": "TestID@paloaltonetworks.com","active": false,' \
                             b'"sys_id": "123456","user_name": "TestID@paloaltonetworks.com"}}'
    mocker.patch.object(demisto, 'command', return_value='deactivate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', username='test123', password='123456', headers=headers)

    readable_output, outputs, data = disable_user_command(client, args)
    assert data['success']


def test_disable_command_user_not_found(mocker):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
    }
    args = {
        'scim': '{"id": "123456"}'
    }
    err_res_d = Response()
    err_res_d.status_code = 404
    err_res_d.headers.status = "404 Not Found"
    err_res_d._content = b'{"error": {"message": "No Record found",' \
                         b'"detail": "Record doesnt exist or ACL restricts the record retrieval"},' \
                         b'"status": "failure"}'
    mocker.patch.object(demisto, 'command', return_value='deactivate-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=err_res_d)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', username='test123', password='123456', headers=headers)
    readable_output, outputs, data = disable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 404
    assert data['errorMessage'] == "No Record found"
