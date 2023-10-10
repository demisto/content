from MicrosoftGraphApplications import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
import MicrosoftGraphApplications
import demistomock as demisto
import pytest
from CommonServerPython import *
from freezegun import freeze_time


@pytest.fixture
def mocked_client():
    from MicrosoftGraphApplications import Client
    return Client(app_id='TEST', verify=False, proxy=False, connection_type='TEST', tenant_id='TEST', enc_key='TEST')


def test_reset_auth_command(mocker, requests_mock):
    """
        Given:
            -
        When:
            - Calling reset_auth.
        Then:
            - Ensure the output are as expected.
    """
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'command', return_value='msgraph-apps-auth-reset')
    mocker.patch.object(MicrosoftGraphApplications, 'return_results')

    main()

    assert 'Authorization was reset successfully. Please regenerate the credentials, and ' \
           'then click **Test** to validate the credentials and connection.' \
           in MicrosoftGraphApplications.return_results.call_args[0][0].readable_output


def test_auth_complete_with_managed_identities(mocker, requests_mock):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling auth_complete.
        Then:
            - Ensure the output are as expected.
    """
    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': 'test_client_id'},
        'authentication_type': 'Azure Managed Identities'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='msgraph-apps-auth-complete')
    mocker.patch.object(MicrosoftGraphApplications, 'return_results', return_value=params)

    main()

    assert 'Authorization completed successfully' in MicrosoftGraphApplications.return_results.call_args[0][0]


def test_auth_test_with_managed_identities(mocker, requests_mock):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling auth_test.
        Then:
            - Ensure the output are as expected.
    """

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': 'test_client_id'},
        'authentication_type': 'Azure Managed Identities'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='msgraph-apps-auth-test')
    mocker.patch.object(MicrosoftGraphApplications, 'return_results')

    main()

    assert '✅ Success!' in MicrosoftGraphApplications.return_results.call_args[0][0]


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'authentication_type': 'Azure Managed Identities'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(MicrosoftGraphApplications, 'return_results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in MicrosoftGraphApplications.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


@pytest.mark.parametrize('limit, list_url_count, next_url_count, top_param_in_url',
                         [
                             (10, 1, 0, True),
                             (0, 1, 1, False)
                         ])
def test_service_principal_list_command(mocker, requests_mock,
                                        limit, list_url_count, next_url_count, top_param_in_url):
    """
        Given:
            -
        When:
            - principal_list_command.
        Then:
            - Ensure the expected requests was made.
    """
    import re
    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    mock_res = {'value': [], '@odata.nextLink': 'https://test_next_link.test'}

    get_mock = requests_mock.get(re.compile(f'^{Resources.graph}'), json=mock_res)
    next_link_get_mock = requests_mock.get('https://test_next_link.test', json={'value': []})
    requests_mock.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', json=mock_token)

    mocker.patch.object(demisto, 'args', return_value={'limit': limit})
    mocker.patch.object(demisto, 'command', return_value='msgraph-apps-service-principal-list')

    main()

    assert get_mock.call_count == list_url_count
    assert next_link_get_mock.call_count == next_url_count
    assert ('?$top=' in str(get_mock.last_request)) == top_param_in_url


@pytest.mark.parametrize('args, expected_args',
                         [
                             ({'id': 'TEST', 'app_id': None}, "/TEST"),
                             ({'id': None, 'app_id': 'TEST'}, "(appId='TEST')"),
                             ({'id': 'TEST', 'app_id': 'TEST'}, "/TEST")
                         ])
def test_remove_service_principals_command(mocker, requests_mock, mocked_client, args, expected_args):
    """
        Given:
            - Required arguments (id or app_id or both)
        When:
            - Executing msgraph-apps-service-principal-remove command
        Then:
            - Ensure delete_service_principals client's method was called with the right argument
    """
    from MicrosoftGraphApplications import remove_service_principals_command

    requests_mock.delete("https://graph.microsoft.com/v1.0/servicePrincipals/TEST", json={})
    mock_delete_service_principals = mocker.patch.object(mocked_client, "delete_service_principals")
    remove_service_principals_command(mocked_client, args=args)

    assert mock_delete_service_principals.call_args[0][0] == expected_args


def test_remove_service_principals_command_validation(mocked_client):
    """
        Given:
            - No arguments were given
        When:
            - Executing msgraph-apps-service-principal-remove command
        Then:
            - Ensure the validation works as expected and raise an exception to missing arguments
    """
    from MicrosoftGraphApplications import remove_service_principals_command

    with pytest.raises(DemistoException,
                       match=re.escape("Either the (object's) `id` or the `application_id` arguments must be provided.")):
        remove_service_principals_command(mocked_client, args={})


GET_SERVICE_PRINCIPAL_RESPONSE = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#servicePrincipals/$entity',
                                  'id': 'XXXX', 'deletedDateTime': None, 'accountEnabled': True, 'alternativeNames': [],
                                  'appDisplayName': 'Test', 'appDescription': None,
                                  'appId': 'XXXX', 'applicationTemplateId': None, 'appOwnerOrganizationId': 'XXXX',
                                  'appRoleAssignmentRequired': False, 'createdDateTime': '', 'description': None,
                                  'disabledByMicrosoftStatus': None, 'displayName': 'Test', 'homepage': None, 'loginUrl': None,
                                  'logoutUrl': None, 'notes': None, 'notificationEmailAddresses': [],
                                  'preferredSingleSignOnMode': None, 'preferredTokenSigningKeyThumbprint': None, 'replyUrls': [],
                                  'servicePrincipalNames': ['XXXX'], 'servicePrincipalType': 'Application',
                                  'signInAudience': 'AzureADMyOrg',
                                  'tags': ['HideApp', 'WindowsAzureActiveDirectoryIntegratedApp'], 'tokenEncryptionKeyId': None,
                                  'samlSingleSignOnSettings': None, 'addIns': [], 'appRoles': [],
                                  'info': {'logoUrl': None, 'marketingUrl': None, 'privacyStatementUrl': None, 'supportUrl': None,
                                           'termsOfServiceUrl': None}, 'keyCredentials': [], 'oauth2PermissionScopes': [],
                                  'passwordCredentials': [], 'resourceSpecificApplicationPermissions': [],
                                  'verifiedPublisher': {'displayName': None, 'verifiedPublisherId': None, 'addedDateTime': None}}


def test_get_service_principal_command(requests_mock, mocked_client):
    """
        Given:
            - Required arguments (id or app_id or both)
        When:
            - Executing msgraph-apps-service-principal-get command
        Then:
            - Ensure the CommandResults contains the expected result
    """
    from MicrosoftGraphApplications import get_service_principal_command

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', json=mock_token)
    requests_mock.get("https://graph.microsoft.com/v1.0/servicePrincipals/TEST", json=GET_SERVICE_PRINCIPAL_RESPONSE)
    results = get_service_principal_command(mocked_client, args={'id': 'TEST'})

    assert results.outputs_prefix == "MSGraphApplication"
    assert results.outputs_key_field == "id"
    assert results.readable_output == '### Service Principal (application):\n|id|appId|appDisplayName|accountEnabled|\n' \
                                      '|---|---|---|---|\n| XXXX | XXXX | Test | true |\n'
    assert results.outputs == GET_SERVICE_PRINCIPAL_RESPONSE


@pytest.mark.parametrize('args, expected_id, expected_args',
                         [
                             ({'id': 'TEST', 'app_id': None, 'account_enabled': 'true'}, "/TEST",
                              {'data': {'accountEnabled': True}}),
                             ({'id': None, 'app_id': 'TEST', 'app_role_assignment_required': 'true'}, "(appId='TEST')",
                              {'data': {'appRoleAssignmentRequired': True}}),
                             ({'id': 'TEST', 'app_id': 'TEST'}, "/TEST", {'data': {}})
                         ])
def test_update_service_principals_command(mocker, requests_mock, mocked_client, args, expected_id, expected_args):
    """
        Given:
            - Required arguments (id or app_id or both)
        When:
            - Executing msgraph-apps-service-principal-update command
        Then:
            - Ensure update_service_principals client's method was called with the right arguments
    """
    from MicrosoftGraphApplications import update_service_principal_command

    requests_mock.patch("https://graph.microsoft.com/v1.0/servicePrincipals/TEST", json={})
    mock_update_service_principals = mocker.patch.object(mocked_client, "update_single_service_principal")
    update_service_principal_command(mocked_client, args=args)

    assert mock_update_service_principals.call_args[0][0] == expected_id
    assert mock_update_service_principals.call_args[1] == expected_args


ADD_PASSWORD_RESPONSE = {
    "@odata.context": "",
    "customKeyIdentifier": None,
    "displayName": "Password friendly name",
    "endDateTime": "",
    "hint": "xxx",
    "keyId": "",
    "secretText": "xxxXXXXXXXXXXX",
    "startDateTime": ""
}


@pytest.mark.parametrize('args, expected_id, expected_args',
                         [
                             ({'id': 'TEST', 'app_id': None, 'display_name': 'Password friendly name'}, "/TEST",
                              {'data': {'displayName': 'Password friendly name', 'endDateTime': '2022-02-28 12:00:00'}}),
                             ({'id': None, 'app_id': 'TEST', 'display_name': 'NAME', 'end_date_time': 'end',
                               'start_date_time': 'start'}, "(appId='TEST')",
                              {'data': {'displayName': 'NAME', 'endDateTime': 'end', 'startDateTime': 'start'}})
                         ])
@freeze_time("2022-02-28 11:00:00")
def test_add_password_service_principal_command(mocker, requests_mock, mocked_client, args, expected_id, expected_args):
    """
        Given:
            - Required arguments (id or app_id or both and display_name)
        When:
            - Executing msgraph-apps-service-principal-password-add command
        Then:
            - Ensure add_password_service_principal client's method was called with the right arguments
    """
    from MicrosoftGraphApplications import add_password_service_principal_command

    requests_mock.patch("https://graph.microsoft.com/v1.0/servicePrincipals/TEST/addPassword", json=ADD_PASSWORD_RESPONSE)
    mock_update_service_principals = mocker.patch.object(mocked_client, "add_password_service_principal")
    add_password_service_principal_command(mocked_client, args=args)

    assert mock_update_service_principals.call_args[0][0] == expected_id
    assert mock_update_service_principals.call_args[1] == expected_args


@pytest.mark.parametrize('args, expected_id, expected_args',
                         [
                             ({'id': 'TEST', 'app_id': None, 'key_id': 'XXXXXX'}, "/TEST", {'data': {'keyId': 'XXXXXX'}}),
                             ({'id': None, 'app_id': 'TEST', 'key_id': 'XXXXXX'}, "(appId='TEST')", {'data': {'keyId': 'XXXXXX'}})
                         ])
def test_remove_password_service_principal_command(mocker, requests_mock, mocked_client, args, expected_id, expected_args):
    """
        Given:
            - Required arguments (id or app_id or both and key_id)
        When:
            - Executing msgraph-apps-service-principal-password-remove command
        Then:
            - Ensure remove_password_service_principal client's method was called with the right arguments
    """
    from MicrosoftGraphApplications import remove_password_service_principal_command

    requests_mock.patch("https://graph.microsoft.com/v1.0/servicePrincipals/TEST/removePassword", json={})
    mock_update_service_principals = mocker.patch.object(mocked_client, "remove_password_service_principal")
    remove_password_service_principal_command(mocked_client, args=args)

    assert mock_update_service_principals.call_args[0][0] == expected_id
    assert mock_update_service_principals.call_args[1] == expected_args


@pytest.mark.parametrize('args,', [({'id': 'TEST', 'app_id': None})])
def test_remove_password_service_principal_command_without_required_arg(requests_mock, args, mocked_client):
    """
        Given:
            - Missing required argument (key_id)
        When:
            - Executing msgraph-apps-service-principal-password-remove command
        Then:
            - Ensure an exception is thrown due to missing required argument
    """
    from MicrosoftGraphApplications import remove_password_service_principal_command

    requests_mock.patch("https://graph.microsoft.com/v1.0/servicePrincipals/TEST/removePassword", json={})

    with pytest.raises(KeyError):
        remove_password_service_principal_command(mocked_client, args=args)


def test_unlock_configuration_service_principal_command(mocker, requests_mock, mocked_client):
    """
        Given:
            - Service principal (object) id
        When:
            - Executing msgraph-apps-service-principal-unlock-configuration command
        Then:
            - Ensure unlock_configuration_service_principal client's method was called with the right service_id
            - Ensure unlock_configuration_service_principal client's method was called with the lock == False
             (since here we're unlocking the configuration)
    """
    from MicrosoftGraphApplications import change_configuration_service_principal_lock_status

    requests_mock.patch("https://graph.microsoft.com/beta/applications/TEST", json={})
    mock_unlock_configuration_service_principal = mocker.patch.object(mocked_client, "unlock_configuration_service_principal")
    change_configuration_service_principal_lock_status(mocked_client, args={'id': 'TEST'}, lock=False)

    assert mock_unlock_configuration_service_principal.call_args_list[0].kwargs['service_id'] == 'TEST'
    assert not mock_unlock_configuration_service_principal.call_args_list[0].kwargs['lock']


def test_lock_configuration_service_principal_command(mocker, requests_mock, mocked_client):
    """
        Given:
            - Service principal (object) id
        When:
            - Executing msgraph-apps-service-principal-lock-configuration command
        Then:
            - Ensure unlock_configuration_service_principal client's method was called with the right service_id
            - Ensure unlock_configuration_service_principal client's method was called with the lock == True
             (since here locking back the configuration)
    """
    from MicrosoftGraphApplications import change_configuration_service_principal_lock_status

    requests_mock.patch("https://graph.microsoft.com/beta/applications/TEST", json={})
    mock_unlock_configuration_service_principal = mocker.patch.object(mocked_client, "unlock_configuration_service_principal")
    change_configuration_service_principal_lock_status(mocked_client, args={'id': 'TEST'}, lock=True)

    assert mock_unlock_configuration_service_principal.call_args_list[0].kwargs['service_id'] == 'TEST'
    assert mock_unlock_configuration_service_principal.call_args_list[0].kwargs['lock']


def test_unlock_configuration_service_principal_command_exception(mocker, requests_mock, mocked_client):
    """
        Given:
            - Missing service principal (object) id
        When:
            - Executing msgraph-apps-service-principal-unlock-configuration command
        Then:
            - Ensure KeyError Exception is thrown
    """
    from MicrosoftGraphApplications import change_configuration_service_principal_lock_status

    requests_mock.patch("https://graph.microsoft.com/beta/applications/TEST", json={})
    mocker.patch.object(mocked_client, "unlock_configuration_service_principal")

    with pytest.raises(KeyError):
        change_configuration_service_principal_lock_status(mocked_client, args={}, lock=False)


def test_start_auth(mocker, mocked_client):
    """
        Given:
            - A client object
        When:
            - start_auth function is called
        Then:
            - Ensure CommandResults is returned and contains the readable_output as expected

    """
    from MicrosoftGraphApplications import start_auth

    mocked_client.ms_client.start_auth = mocker.patch("MicrosoftGraphApplications.MicrosoftClient.start_auth")
    mocked_client.ms_client.start_auth.return_value = "TEST"
    readable_output = "TEST"

    assert start_auth(client=mocked_client).readable_output == readable_output
