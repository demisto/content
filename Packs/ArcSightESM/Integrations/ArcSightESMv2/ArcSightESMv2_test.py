import demistomock as demisto
import pytest
import requests_mock


PARAMS = {
    'server': 'https://server',
    'credentials': {},
    'proxy': True}

ARGS = {'ids': 'lastDateRange',
        'lastDateRange': '2 hours'}


def test_decode_ip(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    import ArcSightESMv2

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    res = ArcSightESMv2.decode_ip('52.213.8.10')
    assert res == '52.213.8.10'

    res = ArcSightESMv2.decode_ip(3232235845)
    assert res == '192.168.1.69'


test_data = [
    (
        True,
        'get_entries_command',
        'https://server/www/manager-service/rest/ActiveListService/getEntries?alt=json'
    ),
    (
        False,
        'get_entries_command',
        'https://server/www/manager-service/services/ActiveListService/'
    ),
    (
        True,
        'clear_entries_command',
        'https://server/www/manager-service/rest/ActiveListService/clearEntries?alt=json'
    ),
    (
        False,
        'clear_entries_command',
        'https://server/www/manager-service/services/ActiveListService/'
    )
]
@pytest.mark.parametrize('use_rest, cmd_name, expected_rest_endpoint', test_data)
def test_use_rest(mocker, use_rest, cmd_name, expected_rest_endpoint):
    '''Check that the correct endpoint is queried depending on the value of the 'use_rest' integration parameter.

    This applies for the entries-related commands `as-get-entries` and `as-clear-entries`.

    Args:
        mocker (fixture): Mocking fixture
        use_rest (bool): Whether the 'use_rest' integration parameter should be mocked as True or False
        cmd_name (str): The entries-related command to run
        expected_rest_endpoint (str): The endpoint that should be queried based on the parametrized configuration

    Scenario: Execute the entries-related ArcSightESMv2 commands

    Given
    - The 'use_rest' integration parameter value
    - The ArcSightESMv2 entries-related command to execute

    When
    - case A: 'use_rest' is True and the 'as-get-entries' command is executed
    - case B: 'use_rest' is False and the 'as-get-entries' command is executed
    - case C: 'use_rest' is True and the 'as-clear-entries' command is executed
    - case D: 'use_rest' is False and the 'as-clear-entries' command is executed

    Then
    - case A: Ensure the REST endpoint for 'as-get-entries' is used
    - case B: Ensure the SOAP endpoint for 'as-get-entries' is used
    - case C: Ensure the REST endpoint for 'as-clear-entries' is used
    - case D: Ensure the SOAP endpoint for 'as-clear-entries' is used
    '''
    params = {
        'server': 'https://server',
        'credentials': {},
        'use_rest': use_rest,
        'proxy': True
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'resourceId': 'blah'})
    with requests_mock.Mocker() as m:
        fake_response = {'log.loginResponse': {'log.return': 'fake'}}
        m.post('https://server/www/core-service/rest/LoginService/login', json=fake_response)

        import ArcSightESMv2

        m.post('https://server/www/manager-service/rest/ActiveListService/clearEntries?alt=json', json={})
        m.post('https://server/www/manager-service/rest/ActiveListService/getEntries?alt=json', json={})
        fake_xml = '<?xml version="1.0"?><Envelope><Body><getEntriesResponse><return>' \
                   '<entryList><entry>1.1.1.1</entry></entryList><columns>Blah</columns>' \
                   '</return></getEntriesResponse></Body></Envelope>'
        m.post('https://server/www/manager-service/services/ActiveListService/', text=fake_xml)
        arcsight_cmd = getattr(ArcSightESMv2, cmd_name)
        arcsight_cmd()
        last_request = m.last_request
        assert last_request.url == expected_rest_endpoint
