from MicrosoftGraphApplications import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
import MicrosoftGraphApplications
import demistomock as demisto
import pytest
from CommonServerPython import *


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
def test_remove_service_principals_command(mocker, requests_mock, args, expected_args):
    """
        Given:
            - Required arguments (id or app_id or both)
        When:
            - Executing msgraph-apps-service-principal-remove command
        Then:
            - Ensure delete_service_principals client's method was called with the right argument
    """
    from MicrosoftGraphApplications import Client, remove_service_principals_command

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', json=mock_token)
    client = Client(app_id='TEST', verify=False, proxy=False, connection_type='TEST', tenant_id='TEST', enc_key='TEST')
    requests_mock.delete("https://graph.microsoft.com/v1.0/servicePrincipals/TEST", json={})
    mock_delete_service_principals = mocker.patch.object(client, "delete_service_principals")
    remove_service_principals_command(client, args=args)

    assert mock_delete_service_principals.call_args[0][0] == expected_args


def test_remove_service_principals_command_validation(requests_mock):
    """
        Given:
            - No arguments were given
        When:
            - Executing msgraph-apps-service-principal-remove command
        Then:
            - Ensure the validation works as expected and raise an exception to missing arguments
    """
    from MicrosoftGraphApplications import Client, remove_service_principals_command
    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', json=mock_token)

    client = Client(app_id='TEST', verify=False, proxy=False, connection_type='TEST', tenant_id='TEST', enc_key='TEST')

    with pytest.raises(DemistoException, match=re.escape("User must provide one of (object) id or application id.")):
        remove_service_principals_command(client, args={})


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
def test_get_service_principal_command(requests_mock):
    """
        Given:
            - Required arguments (id or app_id or both)
        When:
            - Executing msgraph-apps-service-principal-get command
        Then:
            - Ensure the CommandResults contains the expected result
    """
    from MicrosoftGraphApplications import Client, get_service_principal_command

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.post('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', json=mock_token)
    client = Client(app_id='TEST', verify=False, proxy=False, connection_type='TEST', tenant_id='TEST', enc_key='TEST')
    requests_mock.get("https://graph.microsoft.com/v1.0/servicePrincipals/TEST", json=GET_SERVICE_PRINCIPAL_RESPONSE)
    results = get_service_principal_command(client, args={'id': 'TEST'})

    assert results.outputs_prefix == "MSGraphApplication"
    assert results.outputs_key_field == "id"
    assert results.readable_output == '### Available service (application):\n|id|appId|appDisplayName|accountEnabled|\n' \
                                      '|---|---|---|---|\n| XXXX | XXXX | Test | true |\n'
    assert results.outputs == GET_SERVICE_PRINCIPAL_RESPONSE



