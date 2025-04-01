import pytest
import MicrosoftGraphIdentityandAccess
from CommonServerPython import DemistoException
from MicrosoftApiModule import NotFoundError

ipv4 = {'@odata.type': '#microsoft.graph.iPv4CidrRange', 'cidrAddress': '12.34.221.11/22'}  # noqa
ipv6 = {'@odata.type': '#microsoft.graph.iPv6CidrRange', 'cidrAddress': '2001:0:9d38:90d6:0:0:0:0/63'}  # noqa


@pytest.mark.parametrize("ips,expected", [("12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63", [ipv4, ipv6]),
                                          ("12.34.221.11/22,12.34.221.11/22", [ipv4, ipv4]),
                                          ("2001:0:9d38:90d6:0:0:0:0/63,2001:0:9d38:90d6:0:0:0:0/63", [ipv6, ipv6])])
def test_ms_ip_string_to_list(ips, expected):
    """
    Given:
    -   Ips in a string

    When:
    -   Convetting them to an ip list.

    Then:
    - Ensure that the list we get is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.ms_ip_string_to_list(ips) == expected


@pytest.mark.parametrize("last,expected", [({'latest_detection_found': '2022-06-06'}, '2022-06-06')])
def test_get_last_fetch_time(last, expected):
    """
    Given:
    -   A dict with the last run details.

    When:
    -  Getting the last run time value.

    Then:
    - Ensure that the time is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.get_last_fetch_time(last, {}) == expected


@pytest.mark.parametrize("date,expected", [('2022-06-06', '2022-06-06.000')])
def test_date_str_to_azure_format(date, expected):
    """
    Given:
    -   A date to convert to Azure format.

    When:
    -  Converting the date value.

    Then:
    - Ensure that the date is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.date_str_to_azure_format(date) == expected


@pytest.mark.parametrize("incident,expected",
                         [({}, {'name': 'Azure AD:   ', 'occurred': '2022-06-06Z', 'rawJSON': '{}'}),
                          ({'riskEventType': '3', 'riskDetail': '2', 'id': '1'},
                           {'name': 'Azure AD: 1 3 2',
                            'occurred': '2022-06-06Z',
                            'rawJSON': '{"riskEventType": "3", "riskDetail": "2", "id": "1"}'})
                          ])
def test_detection_to_incident(incident, expected):
    """
    Given:
    -  A dict with the incident details.

    When:
    -  Getting the incident.

    Then:
    - Ensure that the dict is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.detection_to_incident(incident, '2022-06-06') == expected


@pytest.mark.parametrize("last_fetch,expected", [('2022-06-06', 'detectedDateTime gt 2022-06-06')])
def test_build_filter(last_fetch, expected):
    """
    Given:
    -   A date to set a filter by.

    When:
    -  Doing an odata query.

    Then:
    - Ensure that the filter is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.build_filter(last_fetch, {}) == expected


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
    from MicrosoftGraphIdentityandAccess import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import MicrosoftGraphIdentityandAccess
    import demistomock as demisto

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'credentials': {'password': 'pass'}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(MicrosoftGraphIdentityandAccess, 'return_results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in MicrosoftGraphIdentityandAccess.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


@pytest.mark.parametrize('expected_error', [("Either enc_key or (Certificate Thumbprint and Private Key) must be provided. For "
                                             "further information see https://xsoar.pan.dev/docs/reference/articles/"
                                             "microsoft-integrations---authentication")])
def test_missing_creds_error_thrown(expected_error):
    """
        Given:
        - expected_error
        When:
        - Attempting to create a client without key or Certificate Thumbprint and Private Key
        Then:
        - Ensure that the right option was returned.
        - Case 1: Should return param.
    """
    from MicrosoftGraphIdentityandAccess import Client
    with pytest.raises(DemistoException) as e:
        Client("", False, False, client_credentials=True)
    assert str(e.value.message) == expected_error


def test_list_role_members_command(mocker):
    """
    Given:
    - A client
    - A role ID which does not exist or invalid

    When:
    - Executing the command 'msgraph-identity-directory-role-members-list'

    Then:
    - Ensure the Exception is caught and a CommandResults with an informative readable_output is returned
    """
    from MicrosoftGraphIdentityandAccess import Client, list_role_members_command
    client = Client("", False, False)
    message = "Resource '0000c00f' does not exist or one of its queried reference-property objects are not present."
    mocker.patch.object(Client, 'get_role_members', side_effect=NotFoundError(message=message))
    result = list_role_members_command(ms_client=client, args={'role_id': '0000c00f', 'limit': 1})
    assert result.readable_output == 'Role ID: 0000c00f, was not found or invalid'
