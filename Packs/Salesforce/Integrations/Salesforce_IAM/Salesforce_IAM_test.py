import demistomock as demisto
from Salesforce_IAM import Client, IAMUserProfile, get_user_command, create_user_command, update_user_command

from CommonServerPython import IAMActions, IAMErrors


def mock_client():
    client = Client(
        base_url='base_url',
        conn_client_id="client_id",
        conn_client_secret="client_secret",
        conn_username="",
        conn_password="password",
        ok_codes=(200, 201, 204),
        verify=True,
        proxy=True,
        token="token"
    )
    return client


create_inp_schme = {
    "username": "test@palo.com",
    "Email": "test@palo.com",
    "LastName": "haim",
    "FirstName": "test",
    "Alias": "a",
    "TimeZoneSidKey": "Asia/Tokyo",
    "LocaleSidKey": "en_US",
    "EmailEncodingKey": "ISO-8859-1",
    "ProfileId": "00e4K000001GgCL",
    "LanguageLocaleKey": "en_US"
}

demisto.callingContext = {'context': {'IntegrationInstance': 'Test', 'IntegrationBrand': 'Test'}}

SALESFORCE_GET_USER_OUTPUT = {
    "Email": "TestID@networks.com",
    "Username": "TestID@networks.com",
    "FirstName": "test",
    "Id": "12345",
    "IsActive": "true"
}


SALESFORCE_CREATE_USER_OUTPUT = {
    "id": "12345",
    "success": True
}


def get_outputs_from_user_profile(user_profile):
    entry_context = user_profile.to_entry()
    outputs = entry_context.get('Contents')

    return outputs


def test_create_user_command(mocker):
    args = {"user-profile": {"email": "mock@mock.com"}}
    client = mock_client()
    mocker.patch.object(client, 'get_access_token_', return_value='')

    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=SALESFORCE_CREATE_USER_OUTPUT)
    mocker.patch.object(client, 'get_user_id_and_activity_by_mail', return_value=(None, None))

    iam_user_profile = create_user_command(client, args, 'mapper_out', True, True)
    outputs = get_outputs_from_user_profile(iam_user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == '12345'


def test_get_user_command__existing_user(mocker):
    args = {"user-profile": {"email": "mock@mock.com"}}
    client = mock_client()
    mocker.patch.object(client, 'get_access_token_', return_value='')

    mocker.patch.object(client, 'get_user', return_value=SALESFORCE_GET_USER_OUTPUT)
    mocker.patch.object(client, 'get_user_id_and_activity_by_mail', return_value=("id", None))
    mocker.patch.object(IAMUserProfile, 'update_with_app_data', return_value={})

    iam_user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(iam_user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == '12345'
    assert outputs.get('username') == 'TestID@networks.com'


def test_get_user_command__non_existing_user(mocker):
    args = {"user-profile": {"email": "mock@mock.com"}}
    client = mock_client()
    mocker.patch.object(client, 'get_access_token_', return_value='')

    mocker.patch.object(client, 'get_user_id_and_activity_by_mail', return_value=(None, None))
    mocker.patch.object(client, 'get_user', return_value={})

    iam_user_profile = get_user_command(client, args, 'mapper_in')
    outputs = get_outputs_from_user_profile(iam_user_profile)

    assert outputs.get('action') == IAMActions.GET_USER
    assert outputs.get('success') is False
    assert outputs.get('errorCode') == IAMErrors.USER_DOES_NOT_EXIST[0]
    assert outputs.get('errorMessage') == IAMErrors.USER_DOES_NOT_EXIST[1]


def test_create_user_command__user_already_exists(mocker):
    args = {"user-profile": {"email": "mock@mock.com"}}
    client = mock_client()
    mocker.patch.object(client, 'get_access_token_', return_value='')

    mocker.patch.object(client, 'get_user_id_and_activity_by_mail', return_value=("mock@mock.com", ""))
    mocker.patch.object(client, 'update_user', return_value="")

    iam_user_profile = create_user_command(client, args, 'mapper_out', True, True)
    outputs = get_outputs_from_user_profile(iam_user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True


def test_update_user_command__non_existing_user(mocker):
    args = {"user-profile": {"email": "mock@mock.com"}}
    client = mock_client()
    mocker.patch.object(client, 'get_access_token_', return_value='')

    mocker.patch.object(client, 'get_user_id_and_activity_by_mail', return_value=(None, None))
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'create_user', return_value=SALESFORCE_CREATE_USER_OUTPUT)

    iam_user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=True,
                                           is_create_user_enabled=True, create_if_not_exists=True)
    outputs = get_outputs_from_user_profile(iam_user_profile)

    assert outputs.get('action') == IAMActions.CREATE_USER
    assert outputs.get('success') is True
    assert outputs.get('active') is True
    assert outputs.get('id') == '12345'


def test_update_user_command__command_is_disabled(mocker):
    args = {"user-profile": {"email": "mock@mock.com"}}
    client = mock_client()
    mocker.patch.object(client, 'get_access_token_', return_value='')

    mocker.patch.object(client, 'get_user_id_and_activity_by_mail', return_value=(None, None))
    mocker.patch.object(IAMUserProfile, 'map_object', return_value={})
    mocker.patch.object(client, 'update_user')

    user_profile = update_user_command(client, args, 'mapper_out', is_command_enabled=False,
                                       is_create_user_enabled=False, create_if_not_exists=False)
    outputs = get_outputs_from_user_profile(user_profile)

    assert outputs.get('action') == IAMActions.UPDATE_USER
    assert outputs.get('success') is True
    assert outputs.get('skipped') is True
    assert outputs.get('reason') == 'Command is disabled.'
