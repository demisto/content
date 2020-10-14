import requests
from requests.models import Response
import demistomock as demisto
import Okta_IAM as okta_iam
from okta_iam import Client, get_user_command, create_user_command, update_user_command,\
    enable_disable_user_command

from datetime import datetime

res = Response()

demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}

IAM_CONTEXT_PATH = 'IAM.Vendor(val.instanceName && val.instanceName == self.instanceName && val.email && val.email == obj.email)'


def test_get_user_command(mocker):
    # Positive scenario

    res.status_code = 200
    res._content = b'{"profile": {"email": "TestID@paloaltonetworks.com", "login": "TestID@paloaltonetworks.com"},' \
                   b' "status":true}'
    mocker.patch.object(requests, 'request', return_value=res)

    get_user_args = {'user-profile': '{\'email\': \'TestID@paloaltonetworks.com\'}'}

    client = Client(
        base_url='https://test.com',
        verify=False,
        token='123',
        user_profile=get_user_args['user-profile']
    )

    mocker.patch.object(demisto, 'command', return_value='get-user')

    get_user_command(client, get_user_args)

    results = demisto.results.call_args[0]
    entry_context = results[0]['EntryContext'][IAM_CONTEXT_PATH]

    assert entry_context.get('email') == 'TestID@paloaltonetworks.com'

    # Negative scenario - User not found
    res.status_code = 404
    res._content = b'{"errorSummary":"User Not Found"}'
    _, outputs, _ = get_user_command(client, args)

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

    mocker.patch.object(okta_iam, 'map_scim', return_value=map_scim)
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

    mocker.patch.object(okta_iam, 'map_scim', return_value=map_scim)
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

    mocker.patch.object(okta_iam, 'map_scim', return_value=map_scim)
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
