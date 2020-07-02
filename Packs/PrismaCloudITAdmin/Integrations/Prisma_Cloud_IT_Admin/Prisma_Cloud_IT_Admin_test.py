import requests
from requests.models import Response
import demistomock as demisto
from Prisma_Cloud_IT_Admin import Client, get_user_command, create_user_command, update_user_command, enable_disable_user_command

res = Response()
res._content = b'{ "token" : 123, "email":"TestID@paloaltonetworks.com", "enabled": true}'

inp_args = {"scim": {"id": "TestID@paloaltonetworks.com"}}
create_inp_args = {"scim": {"emails": [{"type": "work", "primary": True, "value": "testxsoar27@paloaltonetworks.com"}],
                            "urn:scim:schemas:extension:custom:1.0:user": {"roleId": "123"}},
                   "customMapping": b'{"roleId":"roleId"}'}
update_inp_args = {"oldScim": {"id": "TestID@paloaltonetworks.com"},
                   "newScim": {"emails": [{"type": "work", "primary": True, "value": "testxsoar27@paloaltonetworks.com"}],
                               "urn:scim:schemas:extension:custom:1.0:user": {"roleId": "123"}},
                   "customMapping": b'{"roleId":"roleId"}'}
demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}


def test_get_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res.headers = {'x-redlock-status': 'Mocking Response'}
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, conn_username='test',
                    conn_password='test', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)

    get_user = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(get_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - User not found
    res.status_code = 400
    res.headers = {'x-redlock-status': 'User not found'}
    _, outputs, _ = get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 404
    assert outputs.get(get_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    res.headers = {'x-redlock-status': 'Other Error messages'}
    _, outputs, _ = get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 500
    assert outputs.get(get_user).get('errorMessage') == 'Other Error messages'


def test_create_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res.headers = {'x-redlock-status': 'Mocking Response'}
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, conn_username='test',
                    conn_password='test', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - Duplicate User
    res.status_code = 409
    res.headers = {'x-redlock-status': 'Duplicate User'}
    _, outputs, _ = create_user_command(client, create_inp_args)

    assert outputs.get(create_user).get('errorCode') == 409
    assert outputs.get(create_user).get('errorMessage') == 'Duplicate User'

    # Negative scenario - Other Errors
    res.status_code = 500
    res.headers = {'x-redlock-status': 'Other Error Messages'}
    _, outputs, _ = create_user_command(client, create_inp_args)

    assert outputs.get(create_user).get('errorCode') == 500
    assert outputs.get(create_user).get('errorMessage') == 'Other Error Messages'


def test_update_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res.headers = {'x-redlock-status': 'Mocking Response'}
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, conn_username='test',
                    conn_password='test', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)

    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - User not found
    res.status_code = 400
    res.headers = {'x-redlock-status': 'user_inactive_or_not_exist'}
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 404
    assert outputs.get(update_user).get('errorMessage') == 'user_inactive_or_not_exist'

    # Negative scenario - Invalid timezone
    res.status_code = 400
    res.headers = {'x-redlock-status': 'Invalid timezone'}
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 400
    assert outputs.get(update_user).get('errorMessage') == 'Invalid timezone'

    # Negative scenario - Other Errors
    res.status_code = 500
    res.headers = {'x-redlock-status': 'Other Error Messages'}
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 500
    assert outputs.get(update_user).get('errorMessage') == 'Other Error Messages'


def test_disable_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res.headers = {'x-redlock-status': 'Mocking Response'}
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, conn_username='test',
                    conn_password='test', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='disable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)

    disable_user = 'DisableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(disable_user).get('id') == 'testid@paloaltonetworks.com'

    # Negative scenario - User not found
    res.status_code = 404
    res.headers = {'x-redlock-status': 'user_inactive_or_not_exist'}
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(disable_user).get('errorCode') == 404
    assert outputs.get(disable_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    res.headers = {'x-redlock-status': 'Other Error Messages'}
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(disable_user).get('errorCode') == 500
    assert outputs.get(disable_user).get('errorMessage') == 'Other Error Messages'


def test_enable_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res.headers = {'x-redlock-status': 'Mocking Response'}
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, conn_username='test',
                    conn_password='test', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='enable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)

    enable_user = 'EnableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(enable_user).get('id') == 'testid@paloaltonetworks.com'

    # Negative scenario - User not found
    res.status_code = 404
    res.headers = {'x-redlock-status': 'user_inactive_or_not_exist'}
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(enable_user).get('errorCode') == 404
    assert outputs.get(enable_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    res.headers = {'x-redlock-status': 'Other Error Messages'}
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(enable_user).get('errorCode') == 500
    assert outputs.get(enable_user).get('errorMessage') == 'Other Error Messages'
