import demistomock as demisto
import Smartsheet_IT_Admin as smartsheet_it_admin
import smartsheet
from smartsheet.users import Users
import json

demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}


def setup_user():
    smartsheet_obj = smartsheet.Smartsheet(access_token="auth_key")
    smartsheet_obj.errors_as_exceptions(False)
    return Users(smartsheet_obj)


def test_get_user_by_id_command_success(mocker):
    user = setup_user()
    res = '{"account": {"id": 12345678, "name": "name"}, "admin": false, "company": "", "department": "", ' \
          '"email": "testaddress", "firstName": "name", "groupAdmin": false, "id": 12345678, "lastName": "name", ' \
          '"licensedSheetCreator": false, "locale": "en_US", "mobilePhone": "", "resourceViewer": false, "role": "", ' \
          '"status": "PENDING", "timeZone": "US/Pacific", "title": "", "workPhone": ""} '
    args = {"scim": {"id": "12345678"}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    mocker.patch.object(Users, 'get_user', return_value=res)
    mocker.patch.object(demisto, 'dt', return_value="123456")
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.get_user_command(client, args)
    assert outputs.get(key).get('id') == json.loads(res).get('id')


def test_get_user_by_id_command_fail(mocker):
    user = setup_user()
    res = '{"result":{"statusCode":404}}'
    args = {"scim": {"id": "12345678"}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    mocker.patch.object(Users, 'get_user', return_value=res)
    mocker.patch.object(demisto, 'dt', return_value="123456")
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.get_user_command(client, args)
    assert not outputs.get(key).get('success')


def test_get_user_by_email_command_success(mocker):
    user = setup_user()
    args = {"scim": {"emails": [{"primary": True, "type": "work", "value": "test@email.com"}]}}
    map_scim = {"id": "", "email": "email@test.com"}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    mocker.patch.object(Users, 'list_users', return_value='{"data":[{"id":"123456"}]}')
    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.get_user_command(client, args)
    assert outputs.get(key).get('id') == "123456"


def test_get_user_by_email_command_fail(mocker):
    user = setup_user()
    args = {"scim": {"emails": [{"primary": True, "type": "work", "value": "test@email.com"}]}}
    map_scim = {"id": "", "email": "email@test.com"}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'
    mocker.patch.object(Users, 'list_users', return_value='{"data":[]}')
    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.get_user_command(client, args)
    assert not outputs.get(key).get('success')


def test_create_user_success(mocker):
    user = setup_user()
    map_scim = {"id": "", "email": "email@test.com"}
    args = {"scim": {"emails": [{"primary": True, "type": "work", "value": "test@email.com"}],
                     "urn:scim:schemas:extension:custom:1.0:user": {"test": "qwerty"}}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'

    mocker.patch.object(demisto, 'params', return_value={'customMappingCreateUser': '{"test":"test"}'})
    mocker.patch.object(Users, 'add_user',
                        return_value='{"resultCode":0,"result":{"id":"123456","email":"email@test.com"}}')
    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.create_user_command(client, args)
    assert outputs.get(key).get('id') == "123456"


def test_create_user_fail(mocker):
    user = setup_user()
    map_scim = {"id": "", "email": "email@test.com"}
    args = {"scim": {"emails": [{"primary": True, "type": "work", "value": "test@email.com"}],
                     "urn:scim:schemas:extension:custom:1.0:user": {"test": "qwerty"}}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'

    mocker.patch.object(demisto, 'params', return_value={'customMappingCreateUser': '{"test":"test"}'})
    mocker.patch.object(Users, 'add_user', return_value='{"result":{"statusCode":403,"message":"error message"}}')
    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.create_user_command(client, args)
    assert outputs.get(key).get('errorCode') == 409
    mocker.patch.object(Users, 'add_user', return_value='{"result":{"statusCode":404,"message":"error message"}}')
    _, outputs, _ = smartsheet_it_admin.create_user_command(client, args)
    assert outputs.get(key).get('errorCode') == 404


def test_update_user_success(mocker):
    user = setup_user()
    map_scim = {"id": "123456", "admin": True}
    args = {"oldScim": {"id": "123456"},
            "newScim": {"admin": True, "urn:scim:schemas:extension:custom:1.0:user": {"test": "qwerty"}}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'

    mocker.patch.object(demisto, 'params', return_value={'customMappingUpdateUser': '{"test":"test"}'})
    mocker.patch.object(Users, 'update_user',
                        return_value='{"resultCode":0,"result":{"status":"ACTIVE","email":"email@test.com"}}')
    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.update_user_command(client, args)
    assert outputs.get(key).get('success')


def test_update_user_fail(mocker):
    user = setup_user()
    map_scim = {"id": "123456", "admin": True}
    args = {"oldScim": {"id": "123456"},
            "newScim": {"admin": True, "urn:scim:schemas:extension:custom:1.0:user": {"test": "qwerty"}}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'

    mocker.patch.object(demisto, 'params', return_value={'customMappingUpdateUser': '{"test":"test"}'})
    mocker.patch.object(Users, 'update_user', return_value='{"result":{"message":"error occured","statusCode":403}}')
    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.update_user_command(client, args)
    assert outputs.get(key).get('errorCode') == 403


def test_remove_user_success(mocker):
    user = setup_user()
    map_scim = {"id": "123456"}
    args = {"customMapping": "", "scim": {"id": "123456"}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'

    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    mocker.patch.object(Users, 'remove_user', return_value='{"resultCode":0}')
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.remove_user_command(client, args)
    assert outputs.get(key).get('success')


def test_remove_user_fail(mocker):
    user = setup_user()
    map_scim = {"id": "123456"}
    args = {"customMapping": "", "scim": {"id": "123456"}}
    key = '(val.id == obj.id && val.instanceName == obj.instanceName)'

    mocker.patch.object(smartsheet_it_admin, 'map_scim', return_value=map_scim)
    mocker.patch.object(Users, 'remove_user', return_value='{"result":{"message":"error message", "statusCode":404}}')
    client = smartsheet_it_admin.Client(user)
    _, outputs, _ = smartsheet_it_admin.remove_user_command(client, args)
    assert outputs.get(key).get('errorCode') == 404
