import Atlassian_Cloud_IT_Admin as atlassianITAdmin
import requests
from requests.models import Response
import demistomock as demisto

demisto.callingContext = {'context': {'IntegrationInstance': 'Test',
                                      'IntegrationBrand': 'Test'}}


def setup_client():
    client = atlassianITAdmin.Client(base_url='https://test.com',
                                     token='123456',
                                     directory_id='test123',
                                     verify=False,
                                     proxy=False,
                                     headers={})
    return client


def test_get_user_command_success(mocker):
    res = Response()
    res.status_code = 200
    res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": ' \
                   b'true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}'
    inp_args = {"scim": {"id": "123456"}}

    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')

    _, outputs, _ = atlassianITAdmin.get_user_command(setup_client(), inp_args)
    assert outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)')[0].get('success')


def test_get_user_command_fail(mocker):
    res = Response()
    res.status_code = 404
    res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": ' \
                   b'true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}'
    inp_args = {"scim": {"id": "123456"}}

    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')

    _, outputs, _ = atlassianITAdmin.get_user_command(setup_client(), inp_args)
    assert not outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)')[0].get('success')


def test_get_user_command_success_by_username(mocker):
    res = Response()
    res.status_code = 200
    res._content = b'{"Resources":[{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],' \
                   b'"is_active": true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}]}'
    inp_args = {"scim": {"userName": "test.com"}}
    map_scim = {"id": "", "userName": "test.com"}
    mocker.patch.object(atlassianITAdmin, 'map_scim', return_value=map_scim)
    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto, 'dt', return_value='123456')

    _, outputs, _ = atlassianITAdmin.get_user_command(setup_client(), inp_args)
    assert outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)')[0].get('success')


def test_get_user_command_success_by_username_fail(mocker):
    res = Response()
    res.status_code = 404
    res._content = b'{"Resources":[{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],' \
                   b'"is_active": true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}]}'
    inp_args = {"scim": {"userName": "test.com"}}
    map_scim = {"id": "", "userName": "test.com"}
    mocker.patch.object(atlassianITAdmin, 'map_scim', return_value=map_scim)
    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto, 'dt', return_value='123456')

    _, outputs, _ = atlassianITAdmin.get_user_command(setup_client(), inp_args)
    assert not outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)')[0].get('success')


def test_create_user_command_success(mocker):
    res = Response()
    res.status_code = 201
    res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": ' \
                   b'true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}'

    inp_args = {"scim": {
        "userName": "test.com",
        "emails": [
            {
                "value": "test.com",
                "type": "work",
                "primary": True
            }
        ],
        "name": {
            "familyName": "test",
            "givenName": "test"
        },
        "displayName": "test test",
        "title": "Staff IT Systems Engineer",
        "active": True
    }}
    mocker.patch.object(demisto, 'dt', return_value='123456')
    mocker.patch.object(requests, 'request', return_value=res)

    _, outputs, _ = atlassianITAdmin.create_user_command(setup_client(), inp_args)
    assert outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')


def test_create_user_command_fail(mocker):
    res = Response()
    res.status_code = 405
    res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": ' \
                   b'true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}'

    mocker.patch.object(requests, 'request', return_value=res)
    inp_args = {"scim": {
        "userName": "test.com",
        "emails": [
            {
                "value": "test.com",
                "type": "work",
                "primary": True
            }
        ],
        "name": {
            "familyName": "test",
            "givenName": "test"
        },
        "displayName": "test test",
        "title": "Staff IT Systems Engineer",
        "active": True
    }}
    mocker.patch.object(demisto, 'dt', return_value='123456')

    _, outputs, _ = atlassianITAdmin.create_user_command(setup_client(), inp_args)
    assert not outputs.get('success')


def test_update_user_command_fail(mocker):
    res = Response()
    res.status_code = 404
    res._content = b'{"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],"status": "404","detail": "Resource ' \
                   b'[USER] 1696b47d-e30f-4847-a96b-1f551036e2c3 not found"} '
    inp_args = {"oldScim": {"id": "123456"}, "newScim": {
        "userName": "test.com",
        "emails": [
            {
                "value": "test.com",
                "type": "work",
                "primary": True
            }
        ],
        "name": {
            "familyName": "test",
            "givenName": "test"
        },
        "displayName": "test test",
        "title": "Staff IT Systems Engineer",
        "active": True
    }}

    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto, 'dt', return_value='123456')
    _, outputs, _ = atlassianITAdmin.update_user_command(setup_client(), inp_args)
    assert not outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')


def test_update_user_command_success(mocker):
    res = Response()
    res.status_code = 200
    res._content = b'{"id": "123456",' \
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
    inp_args = {"oldScim": {"id": "123456"}, "newScim": {
        "userName": "test.com",
        "emails": [
            {
                "value": "test.com",
                "type": "work",
                "primary": True
            }
        ],
        "name": {
            "familyName": "test",
            "givenName": "test"
        },
        "displayName": "test test",
        "title": "Staff IT Systems Engineer",
        "active": True
    }}

    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto, 'dt', return_value='123456')
    _, outputs, _ = atlassianITAdmin.update_user_command(setup_client(), inp_args)
    assert outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')


def test_delete_user_command_success(mocker):
    res = Response()
    res.status_code = 200
    res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": ' \
                   b'true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}'
    inp_args = {"scim": {"id": "123456"}}

    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')

    _, outputs, _ = atlassianITAdmin.disable_user_command(setup_client(), inp_args)
    assert outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')


def test_delete_user_command_fail(mocker):
    res = Response()
    res.status_code = 404
    res._content = b'{ "emails":[{"value":"TestID@paloaltonetworks.com","type":"work","primary":true}],"is_active": ' \
                   b'true,' \
                   b'"id":"123456","active":true,"userName":"TestID@paloaltonetworks.com"}'
    inp_args = {"scim": {"id": "123456"}}

    mocker.patch.object(requests, 'request', return_value=res)

    mocker.patch.object(demisto,
                        'dt',
                        return_value='123456')

    _, outputs, _ = atlassianITAdmin.disable_user_command(setup_client(), inp_args)
    assert not outputs.get('(val.id == obj.id && val.instanceName == obj.instanceName)').get('success')
