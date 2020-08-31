import requests
from requests.models import Response
import demistomock as demisto
from GitHub_IT_Admin import Client, get_user_command, create_user_command,\
    update_user_command, disable_user_command

res = Response()
res.status_code = 200
res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": true,' \
               b'"id":"123456","userName":"TestID@paloaltonetworks.com"}'

err_res = Response()
err_res.status_code = 404
err_res.headers = {"status": "404 Not Found"}
err_res._content = b'{"status": 404, "scimType": null, "detail": "Resource 123456 not found."}'


err_res_u = Response()
err_res_u.status_code = 404
err_res_u.headers.status = "404 Not Found"
err_res_u._content = b'[]'

inp_args = {"scim": {"id": "123456"}}

create_inp_args = {"scim": {"name": {"familyName": "J13", "givenName": "MJ"},
                            "userName": "TestID@paloaltonetworks.com",
                            "emails": [{
                                "type": "work", "primary": "true",
                                "value": "TestID@paloaltonetworks.com"
                            }]}}

update_inp_args = {"oldScim": {"id": "123456"},
                   "newScim": {"name": {"familyName": "Mj", "givenName": "Sh"},
                               "emails": [{
                                   "type": "work",
                                   "primary": "true",
                                   "value": "TestID@paloaltonetworks.com"
                               }],
                               "userName": "test123"}}


demisto.callingContext = {'context': {'IntegrationInstance': 'Test',
                                      'IntegrationBrand': 'Test'}}

existing_user = {'test'}


def test_get_user_command(mocker):
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com',
                    token='123456',
                    org='test123',
                    verify=False,
                    proxy=False,
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
                    token='123456',
                    org='test123',
                    verify=False,
                    headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'


def test_update_user_command(mocker):

    res1 = Response()
    res1.status_code = 200
    res1._content = b'{"id": "123456",' \
                    b'"externalId": "test123499999",' \
                    b'"userName": "Ghdkrwrkj_extn9999@paloaltonetworks.com",' \
                    b'"name": {' \
                    b'"givenName": "hellotest12349999",' \
                    b'"familyName": "hellotest1239999" },' \
                    b'"emails": [{ ' \
                    b'"value": "hellotest128889999@paloaltonetworks.com",' \
                    b'"type": "work",' \
                    b'"primary": true' \
                    b'}],' \
                    b'"active": true' \
                    b'}'

    mocker.patch.object(requests,
                        'request',
                        return_value=res)
    client = Client(base_url='https://test.com',
                    token='123456',
                    org='test123',
                    verify=False,
                    headers={})

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')
    mocker.patch.object(demisto,
                        'command',
                        return_value='update-user')

    mocker.patch.object(client, 'get_user', return_value=res1)
    _, outputs, _ = update_user_command(client, update_inp_args)

    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('id') == '123456'


def test_get_user_command_fail(mocker):
    mocker.patch.object(requests, 'request', return_value=err_res)
    client = Client(base_url='https://test.com', token='123456', org='test123', verify=False, headers={})

    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)
    get_user_error = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(get_user_error)[0].get('success')
    assert outputs.get(get_user_error)[0].get('errorMessage') == "404 Not Found"
    assert outputs.get(get_user_error)[0].get('errorCode') == 404


def test_update_user_command_fail(mocker):
    mocker.patch.object(requests, 'request', return_value=err_res_u)
    client = Client(base_url='https://test.com', token='123456', org='test123', verify=False, headers={})
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(demisto, 'command', return_value='update-user')
    mocker.patch.object(client, 'get_user', return_value=err_res)
    _, outputs, _ = update_user_command(client, update_inp_args)
    update_user_error = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(update_user_error).get('success')
    assert outputs.get(update_user_error).get('errorMessage') == "404 Not Found"
    assert outputs.get(update_user_error).get('errorCode') == 404


def test_create_user_command_fail(mocker):
    res.status_code = 409
    res._content = b'{ "status":409,"scimType":"uniqueness","detail":""}'
    res.headers.status = "409 Conflict"
    mocker.patch.object(requests, 'request', return_value=res)

    client = Client(base_url='https://test.com', token='123456', org='test123', verify=False, headers={})
    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')
    _, outputs, _ = create_user_command(client, create_inp_args)
    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(create_user).get('success')
    assert outputs.get(create_user).get('errorCode') == 409


def test_disable_command_success(mocker):
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 204

    mocker.patch.object(demisto, 'command', return_value='disable-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}

    client = Client(base_url='https://test.com', token='123456', org='test123', verify=False, headers={})
    readable_output, outputs, data = disable_user_command(client, args)
    assert data['success']


def test_disable_command_user_not_found(mocker):
    args = {
        'scim': '{"id": "123456"}'
    }
    err_res = Response()
    err_res.status_code = 404
    err_res.headers = {"status": "404 Not Found"}
    err_res._content = b'{"status": 404, "scimType": null, "detail": "Resource 123456 not found."}'
    mocker.patch.object(demisto, 'command', return_value='disable-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=err_res)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = Client(base_url='https://test.com', token='123456', org='test123', verify=False, headers={})

    readable_output, outputs, data = disable_user_command(client, args)
    assert not data['success']
    assert data['errorCode'] == 404
