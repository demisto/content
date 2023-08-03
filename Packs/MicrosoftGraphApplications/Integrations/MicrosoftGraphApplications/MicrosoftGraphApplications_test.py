from MicrosoftGraphApplications import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
import MicrosoftGraphApplications
import demistomock as demisto
import pytest


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
