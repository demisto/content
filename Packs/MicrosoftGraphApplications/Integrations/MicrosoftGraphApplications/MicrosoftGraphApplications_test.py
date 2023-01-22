from MicrosoftGraphApplications import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
import MicrosoftGraphApplications
import demistomock as demisto


def test_test_module_command_with_managed_identities(mocker, requests_mock):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    managed_id_mocked_uri = MANAGED_IDENTITIES_TOKEN_URL.format(resource=Resources.graph,
                                                                client_id='test_client_id')

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.get(managed_id_mocked_uri, json=mock_token)

    params = {
        'managed_identities_client_id': 'test_client_id',
        'authentication_type': 'Azure Managed Identities'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(MicrosoftGraphApplications, 'return_results', return_value=params)

    main()

    assert 'ok' in MicrosoftGraphApplications.return_results.call_args[0][0]
