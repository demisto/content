import requests
from requests.models import Response
import demistomock as demisto
import Okta_IT_Admin as okta_it_admin
from Okta_IT_Admin import Client, get_user_command, create_user_command, update_user_command,\
    enable_disable_user_command, get_assigned_user_for_app_command

from datetime import datetime

res = Response()


inp_args = {"scim": {"id": "TestID@paloaltonetworks.com"}}
create_inp_args = {"scim": {"emails": [{"type": "work", "primary": True, "value": "testxsoar27@paloaltonetworks.com"}],
                            "urn:scim:schemas:extension:custom:1.0:user": {"roleId": "123"}},
                   "customMapping": b'{"roleId":"roleId"}'}
update_inp_args = {"oldScim": {"id": "TestID@paloaltonetworks.com"},
                   "newScim": {"emails": [{"type": "work", "primary": True,
                                           "value": "testxsoar27@paloaltonetworks.com"}],
                               "urn:scim:schemas:extension:custom:1.0:user": {"roleId": "123"}},
                   "customMapping": b'{"roleId":"roleId"}'}
demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}


def test_get_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_user_command(client, inp_args)

    get_user = 'GetUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(get_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - User not found
    res.status_code = 404
    res._content = b'{"errorSummary":"User Not Found"}'
    _, outputs, _ = get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 404
    assert outputs.get(get_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    res._content = b'{"errorSummary":"Other Error messages", "errorCode":500}'
    _, outputs, _ = get_user_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 500
    assert outputs.get(get_user).get('errorMessage') == 'Other Error messages'


def test_create_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='create-user')

    _, outputs, _ = create_user_command(client, create_inp_args)

    create_user = 'CreateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(create_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - Other Errors
    res.status_code = 500
    res._content = b'{"errorSummary":"Other Error messages", "errorCode":500}'
    _, outputs, _ = create_user_command(client, create_inp_args)

    assert outputs.get(create_user).get('errorCode') == 500
    assert outputs.get(create_user).get('errorMessage') == 'Other Error messages'


def test_update_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)
    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario
    res.status_code = 500
    res._content = b'{"errorSummary":"Other Error messages", "errorCode":500}'
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 500
    assert outputs.get(update_user).get('errorMessage') == 'Other Error messages'

    # Positive scenario - With user name
    # setting response for get user id
    get_res = Response()
    get_res.status_code = 200
    get_res._content = b'[{"id":"123"}]'

    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'

    map_scim = {"userName": "TestID@paloaltonetworks.com"}

    mocker.patch.object(client, 'get_user_id', return_value=get_res)
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(okta_it_admin, 'map_scim', return_value=map_scim)
    mocker.patch.object(demisto, 'command', return_value='update-user')

    _, outputs, _ = update_user_command(client, update_inp_args)
    update_user = 'UpdateUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(update_user).get('username') == 'TestID@paloaltonetworks.com'

    # Negative scenario
    get_res.status_code = 404
    get_res._content = b'{"errorSummary":"Other Error messages", "errorCode":404}'
    _, outputs, _ = update_user_command(client, update_inp_args)

    assert outputs.get(update_user).get('errorCode') == 404
    assert outputs.get(update_user).get('errorMessage') == 'User Not Found'


def test_disable_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='disable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)
    disable_user = 'DisableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(disable_user).get('username') == 'TestID@paloaltonetworks.com'

    # Negative scenario
    res.status_code = 500
    res._content = b'{"errorSummary":"Other Error messages", "errorCode":500}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(disable_user).get('errorCode') == 500
    assert outputs.get(disable_user).get('errorMessage') == 'Other Error messages'

    # Positive scenario - With user name
    # setting response for get user id
    get_res = Response()
    get_res.status_code = 200
    get_res._content = b'[{"id":"123"}]'

    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'

    map_scim = {"userName": "TestID@paloaltonetworks.com"}

    mocker.patch.object(client, 'get_user_id', return_value=get_res)
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(okta_it_admin, 'map_scim', return_value=map_scim)
    mocker.patch.object(demisto, 'command', return_value='disable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)
    disable_user = 'DisableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(disable_user).get('username') == 'TestID@paloaltonetworks.com'

    # Negative scenario
    get_res.status_code = 404
    get_res._content = b'{"errorSummary":"Other Error messages", "errorCode":404}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(disable_user).get('errorCode') == 404
    assert outputs.get(disable_user).get('errorMessage') == 'User Not Found'


def test_enable_user_command(mocker):
    # Positive scenario
    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='enable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)
    enable_user = 'EnableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(enable_user).get('username') == 'TestID@paloaltonetworks.com'

    # Negative scenario
    res.status_code = 500
    res._content = b'{"errorSummary":"Other Error messages", "errorCode":500}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(enable_user).get('errorCode') == 500
    assert outputs.get(enable_user).get('errorMessage') == 'Other Error messages'

    # Positive scenario - With user name
    # setting response for get user id
    get_res = Response()
    get_res.status_code = 200
    get_res._content = b'[{"id":"123"}]'

    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'

    map_scim = {"userName": "TestID@paloaltonetworks.com"}

    mocker.patch.object(client, 'get_user_id', return_value=get_res)
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(okta_it_admin, 'map_scim', return_value=map_scim)
    mocker.patch.object(demisto, 'command', return_value='enable-user')

    _, outputs, _ = enable_disable_user_command(client, inp_args)
    enable_user = 'EnableUser(val.id == obj.id && val.instanceName == obj.instanceName)'
    assert outputs.get(enable_user).get('username') == 'TestID@paloaltonetworks.com'

    # Negative scenario
    get_res.status_code = 404
    get_res._content = b'{"errorSummary":"Other Error messages", "errorCode":404}'
    _, outputs, _ = enable_disable_user_command(client, inp_args)

    assert outputs.get(enable_user).get('errorCode') == 404
    assert outputs.get(enable_user).get('errorMessage') == 'User Not Found'


def test_get_assigned_user_for_app_command(mocker):
    # Positive scenario
    inp_args = {"userId": "123", "applicationId": "abc"}
    res.status_code = 200
    res._content = b'{"key1": "val1", "key2": "val2"}'
    mocker.patch.object(requests, 'request', return_value=res)
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})

    mocker.patch.object(demisto, 'dt', return_value='TestID@paloaltonetworks.com')
    mocker.patch.object(demisto, 'command', return_value='get-user')

    _, outputs, _ = get_assigned_user_for_app_command(client, inp_args)

    get_user = 'Okta.UserAppAssignment(val.ID && val.ID === obj.ID)'
    assert outputs.get(get_user).get('key1') == 'val1'
    assert outputs.get(get_user).get('key2') == 'val2'

    # Negative scenario - User not found
    res.status_code = 404
    res._content = b'{"errorSummary":"User Not Found"}'
    _, outputs, _ = get_assigned_user_for_app_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 404
    assert outputs.get(get_user).get('errorMessage') == 'User Not Found'

    # Negative scenario - Other Errors
    res.status_code = 500
    res._content = b'{"errorSummary":"Other Error messages", "errorCode":500}'
    _, outputs, _ = get_assigned_user_for_app_command(client, inp_args)

    assert outputs.get(get_user).get('errorCode') == 500
    assert outputs.get(get_user).get('errorMessage') == 'Other Error messages'


def test_fetch_incidents(mocker):
    params = {"fetch_limit": 1, "fetchLogsQuery": "test query", "url": "https://test.com"}
    res.status_code = 200
    res._content = b'[{"id": "123"}]'
    client = Client(base_url='https://test.com', verify=False, auth='123', headers={})
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'key1': 'val1', 'key2': 'val2'})
    mocker.patch.object(requests, 'request', return_value=res)

    last_run, events = okta_it_admin.fetch_incidents(client=client,
                                                     last_run='2020-01-01T01:01:01Z',
                                                     fetch_time=60)

    curr_date = datetime.now().strftime('%Y-%m-%d')

    assert curr_date in last_run['time']
    assert events == [{'rawJSON': '{"id": "123"}'}]
