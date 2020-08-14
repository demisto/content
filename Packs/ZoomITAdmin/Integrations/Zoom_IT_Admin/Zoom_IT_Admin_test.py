import requests
from requests.models import Response
import demistomock as demisto
from Zoom_IT_Admin import Client, get_user_command, create_user_command, \
    update_user_command, enable_disable_user_command

res = Response()
res.status_code = 200
res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"status": "active",' \
               b'"id":"123456","userName":"TestID@paloaltonetworks.com"}'

err_res = Response()
err_res.status_code = 200
err_res.headers.status = "200 Ok"
err_res._content = b'[]'

err_res_u = Response()
err_res_u.status_code = 404
err_res_u.headers.status = "404 Not Found"
err_res_u._content = b'{"message":"message","code":404}'

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


def setup_client():
    return Client(
        base_url="base url",
        api_key="api_key",
        api_secret="api_secret")


def test_get_user_command_success(mocker):
    mocker.patch.object(requests, 'request', return_value=res)
    client = setup_client()

    mocker.patch.object(demisto,
                        'dt',
                        return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)
    assert outputs.get('GetUser(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')


def test_get_user_command_fail(mocker):
    mocker.patch.object(requests, 'request', return_value=err_res_u)
    client = setup_client()

    mocker.patch.object(demisto,
                        'dt',
                        return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)
    assert not outputs.get('GetUser(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')


def test_create_user_command_success(mocker):
    res.status_code = 201
    res._content = b'{ "email":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"status": ' \
                   b'"active",' \
                   b'"id":"123456","userName":"TestID@paloaltonetworks.com"}'
    mocker.patch.object(requests,
                        'request',
                        return_value=res)
    client = setup_client()

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('success')


def test_create_user_command_fail(mocker):
    mocker.patch.object(requests,
                        'request',
                        return_value=err_res_u)
    client = setup_client()

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(create_user).get('success')


def test_update_user_command_success(mocker):
    res1 = Response()
    res1.status_code = 204
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
                        return_value=res1)
    client = setup_client()

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')
    mocker.patch.object(demisto,
                        'command',
                        return_value='update-user')

    mocker.patch.object(client, 'get_user', return_value=res1)
    #    map_changes_to_existing_user(existing_user, update_inp_args.get('newScim'))
    _, outputs, _ = update_user_command(client, update_inp_args)

    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('success')


def test_update_user_command_fail(mocker):
    res1 = Response()
    res1.status_code = 404
    res1._content = b'{"code": 404,' \
                    b'"message": "message"}'

    mocker.patch.object(requests,
                        'request',
                        return_value=res1)
    client = setup_client()

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')
    mocker.patch.object(demisto,
                        'command',
                        return_value='update-user')

    mocker.patch.object(client, 'get_user', return_value=res1)
    #    map_changes_to_existing_user(existing_user, update_inp_args.get('newScim'))
    _, outputs, _ = update_user_command(client, update_inp_args)

    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert not outputs.get(update_user).get('success')


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
    client = setup_client()

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert data['success']


def test_disable_command_fail(mocker):
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 404
    mock_response._content = b'{"message":"message","code":404}'

    mocker.patch.object(demisto, 'command', return_value='disable-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = setup_client()

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert not data['success']


def test_enable_command_success(mocker):
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 204

    mocker.patch.object(demisto, 'command', return_value='enable-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = setup_client()

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert data['success']


def test_enable_command_fail(mocker):
    args = {
        'scim': '{"id": "123456"}'
    }
    mock_response = Response()
    mock_response.status_code = 404
    mock_response._content = b'{"message":"message","code":404}'

    mocker.patch.object(demisto, 'command', return_value='enable-user')
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=mock_response)
    demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}
    client = setup_client()

    readable_output, outputs, data = enable_disable_user_command(client, args)
    assert not data['success']
