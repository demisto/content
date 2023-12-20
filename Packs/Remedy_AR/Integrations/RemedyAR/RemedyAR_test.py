from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401


def test_get_server_details(mocker, requests_mock):
    """
    Given: remedy-get-server-details command

    When: Running get_server_details command to get server details

    Then: Validate that the returned values are as expected

    """
    base_url = 'https://base_url'
    mocker.patch.object(demisto, 'params', return_value={'server': base_url,
                                                         'proxy': True,
                                                         'credentials': {'identifier': 'identifier', 'password': 'password'}})

    from RemedyAR import get_server_details

    mock_response = {'entries': [{
        'values': {
            'NC_IOPs': '1.1.1.1',
            'Name': 'test_name'}
    }]}
    args = {'fields': 'Name'}

    requests_mock.get(
        f'{base_url}/api/arsys/v1/entry/AST:ComputerSystem/?q=&fields=values(Name)', json=mock_response)

    response = get_server_details(args)

    assert 'Remedy AR Server Details' in response['HumanReadable']
    assert response['EntryContext']['Endpoint'][0]['Hostname'] == 'test_name'
