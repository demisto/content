import base64
import pytest
import demistomock as demisto
import requests_mock


def test_wildfire_report(mocker):
    """
    Given:
        A sha256 represents a file uploaded to WildFire.
    When:
        internal-wildfire-get-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    mocker.patch.object(demisto, 'command', return_value='internal-wildfire-get-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': '123456'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})

    with open('test_data/response.pdf', 'rb') as file:
        file_content = b''
        while byte := file.read(1):
            file_content += byte

        mocker.patch('WildFireReports.fileResult', return_value=file_content)  # prevent file creation
        demisto_mock = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(f'https://test.com/publicapi/get/report?format=pdf&hash={mock_sha256}', content=file_content)

        import WildFireReports
        WildFireReports.main()

    assert demisto_mock.call_args_list[0][0][0]['data'] == base64.b64encode(file_content).decode()


def test_report_not_found(mocker):
    """
    Given:
        A sha256 represents a file not uploaded to WildFire.
    When:
        internal-wildfire-get-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567891'
    mocker.patch.object(demisto, 'command', return_value='internal-wildfire-get-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': '123456'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})
    demisto_mock = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(f'https://test.com/publicapi/get/report?format=pdf&hash={mock_sha256}', status_code=404)

        import WildFireReports
        WildFireReports.main()

    assert demisto_mock.call_args[0][0] == {'status': 'not found'}


def test_incorrect_sha256(mocker):
    """
    Given:
        An incorrect sha256.
    When:
        internal-wildfire-get-report command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mock_sha256 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789'  # The length is 63 insteadof 64
    mocker.patch.object(demisto, 'command', return_value='internal-wildfire-get-report')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': '123456'})
    mocker.patch.object(demisto, 'args', return_value={'sha256': mock_sha256})
    demisto_mock = mocker.patch.object(demisto, 'results')
    expected_description_error = 'Failed to download report.\nError:\nInvalid hash. Only SHA256 are supported.'

    import WildFireReports
    WildFireReports.main()

    assert demisto_mock.call_args_list[0].args[0].get('error', {}).get('description') == expected_description_error


def test_incorrect_authorization(mocker):
    """
    Given:
        An incorrect API token.
    When:
        test-module command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': 'incorrect api token'})
    demisto_mock = mocker.patch.object(demisto, 'results')
    expected_description_error = 'Authorization Error: make sure API Key is correctly set'

    url = 'https://test.com/publicapi/get/report'
    params = '?apikey=incorrect+api+token&format=pdf&hash=dca86121cc7427e375fd24fe5871d727'

    with requests_mock.Mocker() as m:
        m.post(url + params, status_code=401)

        import WildFireReports
        WildFireReports.main()

    assert demisto_mock.call_args_list[0].args[0] == expected_description_error


def test_empty_api_token(mocker):
    """
    Given:
        An empty API token.
    When:
        test-module command is running.
    Then:
        Ensure that the command is running as expected.
    """
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'params', return_value={'server': 'https://test.com/', 'token': ''})
    mocker.patch.object(demisto, 'getLicenseCustomField', return_value=None)
    demisto_mock = mocker.patch('WildFireReports.return_error')

    expected_description_error = 'Authorization Error: It\'s seems that the token is empty and you have not a ' \
                                 'TIM license that is up-to-date, Please fill the token or update your TIM license ' \
                                 'and try again.'
    import WildFireReports
    WildFireReports.main()

    assert demisto_mock.call_args_list[0].args[0] == expected_description_error


def test_user_secrets():
    from WildFireReports import LOG, Client
    client = Client(token='%%This_is_API_key%%', base_url='url')
    res = LOG(client.token)
    assert "%%This_is_API_key%%" not in res


@pytest.mark.parametrize('platform_to_return,expected_agent', [
    ('xsoar', 'xsoartim'),
    ('x2', 'xdr')
])
def test_agent_config(mocker, platform_to_return, expected_agent):
    """
    Given:
        Case 1: Platform type is xsoar (on prem or cloud)
        Case 2: Platform type is x2 (xsiam)

    When:
        Setting the default 'agent' param for the calls made by the WildFireReports module

    Then:
        Case 1: Ensure the calls have the 'xsoartim' agent set
        Case 2: Ensure the calls have the 'xdr' agent set
    """
    demisto_version_res = {'platform': platform_to_return}

    # We need to make two mocks since the get_demisto_version is being called twice, once from within WildFireReports
    # module and once from within CommonServerPython
    mocker.patch('CommonServerPython.get_demisto_version', return_value=demisto_version_res)
    mocker.patch('WildFireReports.get_demisto_version', return_value=demisto_version_res)
    get_file_call = mocker.patch('CommonServerPython.BaseClient._http_request')
    import WildFireReports
    client = WildFireReports.Client(token='%%This_is_API_key%%', base_url='url')

    client.get_file_report(file_hash='hash')
    get_file_call.assert_called_with('POST',
                                     url_suffix='/get/report',
                                     params={
                                         'apikey': '%%This_is_API_key%%',
                                         'agent': expected_agent,
                                         'format': 'pdf',
                                         'hash': 'hash',
                                     },
                                     resp_type='response',
                                     ok_codes=(200, 401, 404), )
