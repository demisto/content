import requests
from requests.models import Response
import demistomock as demisto
import Twic_IT_Admin as twic_it_admin
from Twic_IT_Admin import Client, get_user_command, create_user_command, update_user_command, \
    enable_disable_user_command

res = Response()
demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}


def test_get_user_command(mocker):
    # Positive scenario 1
    inp_args = {"scim": {"id": "TestID@paloaltonetworks.com"}}
    res.status_code = 200
    res._content = b'{"id":"12345", "emails": [{"primary": true, "value": "testxsoar2@paloaltonetworks.com"}]}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, headers={}, auth_token='123')

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)

    get_user = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(get_user).get('id') == '12345'

    # Positive scenario 2
    map_scim = {"userName": "TestID@paloaltonetworks.com"}
    mocker.patch.object(twic_it_admin, 'map_scim', return_value=map_scim)
    res._content = b'{"id":"12345", "Resources": [{"id": "12345"}], "emails": [{"primary": true, "value": ' \
                   b'"testxsoar2@paloaltonetworks.com"}]}'

    _, outputs, _ = get_user_command(client, inp_args)
    assert outputs.get(get_user).get('id') == '12345'

    # Negative scenario - User not found
    res.status_code = 404

    res._content = b'{"detail":"User Not Found", "code":404}'
    _, outputs, _ = get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 404
    assert outputs.get(get_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    res._content = b'{"detail":"Other Error messages", "code":500}'
    _, outputs, _ = get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 500
    assert outputs.get(get_user).get('errorMessage') == 'Other Error messages'


def test_create_user_command(mocker):
    # Positive scenario
    create_inp_args = {"scim": {"emails": [{"type": "work", "primary": True,
                                            "value": "testxsoar27@paloaltonetworks.com"}],
                                "urn:scim:schemas:extension:custom:1.0:user": {"office_country": "US"}}}
    res.status_code = 200
    res._content = b'{"email": "TestID@paloaltonetworks.com", "id":"12345", "active": true,' \
                   b'"userName": "TestID@paloaltonetworks.com"}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, headers={}, auth_token='123')

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - Other Errors
    res.status_code = 500
    res._content = b'{"detail":"Other Error messages", "code":500}'
    _, outputs, _ = create_user_command(client, create_inp_args)

    assert outputs.get(create_user).get('errorCode') == 500
    assert outputs.get(create_user).get('errorMessage') == 'Other Error messages'


def test_update_user_command(mocker):
    # Positive scenario
    update_inp_args = {"oldScim": {"id": "12345"},
                       "newScim": {"name": {"familyName": "Test", "givenName": "User"},
                                   "urn:scim:schemas:extension:custom:1.0:user": {"office_country": "US"}}}
    res.status_code = 200
    res._content = b'{"email": "TestID@paloaltonetworks.com", "id":"12345", "active": true,' \
                   b'"userName": "TestID@paloaltonetworks.com"}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, headers={}, auth_token='123')

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)
    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('id') == '12345'

    # Negative scenario
    res.status_code = 500
    res._content = b'{"detail":"Other Error messages", "code":500}'
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 500
    assert outputs.get(update_user).get('errorMessage') == 'Other Error messages'

    # Negative scenario - User not found
    res.status_code = 404

    res._content = b'{"detail":"User Not Found", "code":404}'
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 404
    assert outputs.get(update_user).get('errorMessage') == 'User Not Found'


def test_disable_user_command(mocker):
    # Positive scenario
    inp_args = {"scim": {"id": "12345"}}
    res.status_code = 200
    res._content = b'{"email": "TestID@paloaltonetworks.com", "id":"12345", "active": true,' \
                   b'"userName": "TestID@paloaltonetworks.com"}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, headers={}, auth_token='123')

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='disable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)
    disable_user = 'DisableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(disable_user).get('id') == '12345'

    # Negative scenario
    res.status_code = 500
    res._content = b'{"detail":"Other Error messages", "code":500}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(disable_user).get('errorCode') == 500
    assert outputs.get(disable_user).get('errorMessage') == 'Other Error messages'

    # Negative scenario - User not found
    res.status_code = 404

    res._content = b'{"detail":"User Not Found", "errorCode":404}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(disable_user).get('errorCode') == 404
    assert outputs.get(disable_user).get('errorMessage') == 'User Not Found'


def test_enable_user_command(mocker):
    # Positive scenario
    inp_args = {"scim": {"id": "TestID@paloaltonetworks.com"}}
    res.status_code = 200
    res._content = b'{"email": "TestID@paloaltonetworks.com", "id":"12345", "active": true,' \
                   b'"userName": "TestID@paloaltonetworks.com"}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, headers={}, auth_token='123')

    mocker.patch.object(demisto, 'dt', return_value='12345')
    mocker.patch.object(demisto, 'command', return_value='enable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)
    enable_user = 'EnableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(enable_user).get('id') == '12345'

    # Negative scenario
    res.status_code = 500
    res._content = b'{"detail":"Other Error messages", "errorCode":500}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(enable_user).get('errorCode') == 500
    assert outputs.get(enable_user).get('errorMessage') == 'Other Error messages'

    # Negative scenario - User not found
    res.status_code = 404

    res._content = b'{"detail":"User Not Found", "errorCode":404}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(enable_user).get('errorCode') == 404
    assert outputs.get(enable_user).get('errorMessage') == 'User Not Found'
