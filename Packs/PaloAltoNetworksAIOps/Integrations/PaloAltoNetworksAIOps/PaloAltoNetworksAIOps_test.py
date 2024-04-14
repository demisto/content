from unittest.mock import mock_open, patch
import pytest
from PaloAltoNetworksAIOps import Client
from pytest_mock import MockerFixture


@pytest.fixture
def AIOps_client(base_url='base_url', api_key='api_key', tsg_id='tsg_id', client_id='client_id', client_secret='client_secret',
                 verify=True, proxy=False, headers=None):
    return Client(base_url=base_url, api_key=api_key, tsg_id=tsg_id, client_id=client_id, client_secret=client_secret,
                  verify=verify, proxy=proxy, headers=headers)


''' COMMAND FUNCTIONS TESTS '''


def test_generate_access_token_request_called_with(mocker, AIOps_client):
    with patch('CommonServerPython.get_integration_context', return_value={}):
        http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
        response_mock = mocker.MagicMock()
        response_mock.return_value = {}
        http_request_mock.return_value = response_mock
        AIOps_client.generate_access_token_request()
        http_request_mock.assert_called_once_with(method='POST',
                                                  full_url='https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token',
                                                  auth=('client_id', 'client_secret'),
                                                  resp_type='response',
                                                  headers={'Content-Type': 'application/x-www-form-urlencoded',
                                                           'Accept': 'application/json'},
                                                  data={'grant_type': 'client_credentials', 'scope': 'tsg_id:tsg_id'})


def test_generate_access_token_request_check_return(mocker, AIOps_client):
    with patch('PaloAltoNetworksAIOps.get_integration_context') as mock_get_integration_context:
        mock_get_integration_context.return_value = {}
        http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
        response_mock = mocker.Mock()
        response_mock.json.return_value = {'access_token': '123', 'expires_in': 899}
        http_request_mock.return_value = response_mock
        AIOps_client.generate_access_token_request()
        assert AIOps_client._access_token == '123'


def test_generate_report_command(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import generate_report_command
    args = {'entry_id': '1234', 'requester_email': 'test@gmail.com', 'requester_name': 'test', 'export_as_file': 'false',
            'show_in_context': 'false'}
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    get_info_about_device_request_mock = mocker.patch.object(AIOps_client, 'get_info_about_device_request')
    get_info_about_device_request_mock.return_value = ('<system ><family>test1</family><model>test2</model><serial>test3</serial>'
                                                       '<hostname>test</hostname><sw-version>'
                                                       'test4</sw-version><ip-address>1.1.1.1</ip-address></system>')
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.return_value = {'upload-url': 'url_test', 'id': '1234'}
    config_file_to_report_request_mock = mocker.patch.object(AIOps_client, 'config_file_to_report_request')
    config_file_to_report_request_mock.return_value = {}
    with patch('PaloAltoNetworksAIOps.convert_config_to_bytes', return_value=(b'<?xml version="1.0"?><config>test</config>')), \
            patch('PaloAltoNetworksAIOps.polling_until_upload_report_command', return_value=None):
        generate_report_command(AIOps_client, args)
        http_request_mock.assert_called_once_with(method='POST',
                                                  full_url='https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/requests',
                                                  headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                                                           'Authorization': 'Bearer None'},
                                                  json_data={'requester-email': 'test@gmail.com', 'requester-name': 'test',
                                                             'serial': 'test3', 'version': 'test4', 'model': 'test2',
                                                             'family': 'test1'})


def test_polling_until_upload_report_command_upload_initiated_status_first_round(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import polling_until_upload_report_command
    check_upload_status_request_mock = mocker.patch.object(AIOps_client, 'check_upload_status_request')
    check_upload_status_request_mock.return_value = 'UPLOAD_INITIATED'
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    args = {'report_id': '123456789', 'first_round': 'true'}
    result = polling_until_upload_report_command(args, AIOps_client)
    assert result.scheduled_command
    assert result.readable_output == 'The report with id 123456789 was sent successfully. Download in progress...'


def test_polling_until_upload_report_command_upload_initiated_status_not_first_round(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import polling_until_upload_report_command
    check_upload_status_request_mock = mocker.patch.object(AIOps_client, 'check_upload_status_request')
    check_upload_status_request_mock.return_value = 'UPLOAD_INITIATED'
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    args = {'report_id': '123456789', 'first_round': 'false'}
    result = polling_until_upload_report_command(args, AIOps_client)
    assert result.scheduled_command
    assert result.readable_output == ''


def test_polling_until_upload_report_command_completed_with_error(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import polling_until_upload_report_command
    check_upload_status_request_mock = mocker.patch.object(AIOps_client, 'check_upload_status_request')
    check_upload_status_request_mock.return_value = 'COMPLETED_WITH_ERROR'
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    args = {'report_id': '123456789'}
    result = polling_until_upload_report_command(args, AIOps_client)
    assert not result.scheduled_command
    assert result.readable_output == 'The report with id 123456789 could not be generated- finished with an error.'


def test_polling_until_upload_report_command_config_parsed(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import polling_until_upload_report_command
    check_upload_status_request_mock = mocker.patch.object(AIOps_client, 'check_upload_status_request')
    check_upload_status_request_mock.return_value = 'CONFIG_PARSED'
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    args = {'report_id': '123456789'}
    result = polling_until_upload_report_command(args, AIOps_client)
    assert result.scheduled_command


def test_polling_until_upload_report_command_completed_with_success(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import polling_until_upload_report_command
    bpa_json = {
        'best_practices': {
            'device': {
                'feature1': [
                    {
                        'warnings': [{'check_id': 1, 'check_message': 'Warning message 1'}],
                        'notes': [{'check_id': 2, 'check_message': 'Note message 1'}]
                    }
                ],
                'feature2': [
                    {
                        'warnings': [{'check_id': 3, 'check_message': 'Warning message 2'}],
                        'notes': [{'check_id': 4, 'check_message': 'Note message 2'}]
                    }
                ]
            }
        }
    }
    check_upload_status_request_mock = mocker.patch.object(AIOps_client, 'check_upload_status_request')
    check_upload_status_request_mock.return_value = 'COMPLETED_WITH_SUCCESS'
    download_bpa_request_mock = mocker.patch.object(AIOps_client, 'download_bpa_request')
    download_bpa_request_mock.return_value = "cloud.com"
    download_bpa_request_mock = mocker.patch.object(AIOps_client, 'data_of_download_bpa_request')
    download_bpa_request_mock.return_value = bpa_json
    args = {'report_id': '123456789', 'show_in_context': 'true', 'export_as_file': 'true'}
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    mocker.patch('PaloAltoNetworksAIOps.fileResult', return_value={'File': 'report-id-123456789.md'})
    result = polling_until_upload_report_command(args, AIOps_client)
    assert not result[0].scheduled_command
    assert result[0].readable_output == ('### BPA results:\n|Check Id|Check Category|Check Feature|Check Message|Check Type|\n'
                                         '|---|---|---|---|---|\n| 1 | device | feature1 | Warning message 1 | warning |\n'
                                         '| 2 | device | feature1 | Note message 1 | note |\n| 3 | device | feature2 | '
                                         'Warning message 2 | warning |\n| 4 | device | feature2 | Note message 2 | note |\n')
    assert result[0].outputs == [{'report_id': '123456789',
                                  'report_status': 'COMPLETED_WITH_SUCCESS',
                                  'data': [{'check_id': 1, 'check_message': 'Warning message 1', 'check_type': 'warning',
                                            'check_feature': 'feature1', 'check_category': 'device'},
                                           {'check_id': 2, 'check_message': 'Note message 1', 'check_type': 'note',
                                            'check_feature': 'feature1', 'check_category': 'device'},
                                           {'check_id': 3, 'check_message': 'Warning message 2', 'check_type': 'warning',
                                            'check_feature': 'feature2', 'check_category': 'device'},
                                           {'check_id': 4, 'check_message': 'Note message 2', 'check_type': 'note',
                                            'check_feature': 'feature2', 'check_category': 'device'}]}]
    assert result[1].get('File') == "report-id-123456789.md"


def test_polling_until_upload_report_command_completed_with_success_no_context(mocker, AIOps_client):
    from PaloAltoNetworksAIOps import polling_until_upload_report_command
    bpa_json = {
        'best_practices': {
            'device': {
                'feature1': [
                    {
                        'warnings': [{'check_id': 1, 'check_message': 'Warning message 1'}],
                        'notes': [{'check_id': 2, 'check_message': 'Note message 1'}]
                    }
                ],
                'feature2': [
                    {
                        'warnings': [{'check_id': 3, 'check_message': 'Warning message 2'}],
                        'notes': [{'check_id': 4, 'check_message': 'Note message 2'}]
                    }
                ]
            }
        }
    }
    check_upload_status_request_mock = mocker.patch.object(AIOps_client, 'check_upload_status_request')
    check_upload_status_request_mock.return_value = 'COMPLETED_WITH_SUCCESS'
    download_bpa_request_mock = mocker.patch.object(AIOps_client, 'download_bpa_request')
    download_bpa_request_mock.return_value = "cloud.com"
    download_bpa_request_mock = mocker.patch.object(AIOps_client, 'data_of_download_bpa_request')
    download_bpa_request_mock.return_value = bpa_json
    args = {'report_id': '123456789', 'show_in_context': 'false', 'export_as_file': 'false'}
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    result = polling_until_upload_report_command(args, AIOps_client)
    assert not result[0].scheduled_command
    assert result[0].readable_output == ('### BPA results:\n|Check Id|Check Category|Check Feature|Check Message|Check Type|\n'
                                         '|---|---|---|---|---|\n| 1 | device | feature1 | Warning message 1 | warning |\n'
                                         '| 2 | device | feature1 | Note message 1 | note |\n| 3 | device | feature2 | '
                                         'Warning message 2 | warning |\n| 4 | device | feature2 | Note message 2 | note |\n')
    assert not result[0].outputs
    assert len(result) == 1


def test_get_info_about_device_request_called_with(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_info_about_device_request

    Then:
        - Checks the get_info_about_device_request request (the request that is calles)
    """
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response_text = ('<response status="success"><result><system><hostname>test</hostname><ip-address>1.1.1.1'
                     '</ip-address></system></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    AIOps_client.get_info_about_device_request()
    http_request_mock.assert_called_once_with('GET', '/api', params={'type': 'op', 'cmd':
                                                                     '<show><system><info></info></system></show>',
                                                                     'key': 'api_key'}, headers={'Content-Type': 'application/xml'
                                                                                                 },
                                              resp_type='xml')


def test_get_info_about_device_request_return(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_info_about_device_request

    Then:
        - Checks the get_info_about_device_request output (using adjust_xml_format)
    """
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')

    response_text = ('<response status="success"><result><system><hostname>test</hostname><ip-address>1.1.1.1'
                     '</ip-address></system></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    result = AIOps_client.get_info_about_device_request()
    assert result == '<system ><hostname>test</hostname><ip-address>1.1.1.1</ip-address></system>'


def test_get_info_about_device_request_fails(mocker: MockerFixture, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_info_about_device_request

    Then:
        - Raise an error since response not in format
    """
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    from CommonServerPython import DemistoException
    response_text = ('<response status="success"><result><systems><hostname>test</hostname><ip-address>1.1.1.1'
                     '</ip-address></systems></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    with pytest.raises(DemistoException) as e:
        AIOps_client.get_info_about_device_request()
    assert e.value.message == ("Request Succeeded, A parse error occurred- could not find system tag to adjust to AIOps API.")


def test_get_config_file_request_called_with(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_config_file_request

    Then:
        - Checks the get_config_file_request request (the request that is calles)
    """
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response_text = ('<response status="success"><result><config version="10.2.0" urldb="paloaltonetworks" '
                     'detail-version="10.2.1"><config-mgt>khbk,g</config-mgt>\n</config></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    AIOps_client.get_config_file_request()
    http_request_mock.assert_called_once_with('GET', '/api', params={'type': 'config', 'action': 'show', 'key': 'api_key'},
                                              headers={'Content-Type': 'application/xml'}, resp_type='xml')


def test_get_config_file_request_return(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_config_file_request

    Then:
        - Checks the get_info_about_device_request output (using adjust_xml_format)
    """
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')

    response_text = ('<response status="success"><result><config version="10.2.0" urldb="paloaltonetworks" '
                     'detail-version="10.2.1"><config-mgt>khbk,g</config-mgt>\n</config></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    result = AIOps_client.get_config_file_request()
    assert result == ('<config version="10.2.0" urldb="paloaltonetworks" detail-version="10.2.1"><config-mgt>khbk,g</config-mgt>'
                      '\n</config>')


def test_get_config_file_request_fails(mocker: MockerFixture, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_config_file_request

    Then:
        - Raise an error since response not in format
    """
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    from CommonServerPython import DemistoException
    response_text = ('<response status="success"><result><configs version="10.2.0" urldb="paloaltonetworks" '
                     'detail-version="10.2.1"><config-mgt>khbk,g</config-mgt>\n</configs></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    with pytest.raises(DemistoException) as e:
        AIOps_client.get_config_file_request()
    assert e.value.message == ("Request Succeeded, A parse error occurred- could not find config tag to adjust to AIOps API.")


def test_generate_bpa_report_request_called_with(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling generate_bpa_report_request

    Then:
        - Checks the generate_bpa_report_request request (the request that is calles)
    """
    requester_email = "test@gmail.com"
    requester_name = "test"
    dict_for_request = {"family": "test1", "model": "test2", "serial": "test3", "sw-version": "test4"}
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response = {"upload-url": "qejdhliqhjqo;jo'kqp", "id": "1"}
    http_request_mock.return_value = response
    AIOps_client.generate_bpa_report_request(requester_email, requester_name, dict_for_request)
    http_request_mock.assert_called_once_with(method='POST',
                                              full_url='https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/requests',
                                              headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                                                       'Authorization': 'Bearer None'}, json_data={'requester-email':
                                                                                                   'test@gmail.com',
                                                                                                   'requester-name': 'test',
                                                                                                   'serial': 'test3',
                                                                                                   'version': 'test4',
                                                                                                   'model': 'test2',
                                                                                                   'family': 'test1'})


def test_generate_bpa_report_request_return(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_config_file_request

    Then:
        - Checks the generate_bpa_report_request output (using adjust_xml_format)
    """
    requester_email = "test@gmail.com"
    requester_name = "test"
    dict_for_request = {"family": "test1", "model": "test2", "serial": "test3", "sw-version": "test4"}
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response = {"upload-url": "qejdhliqhjqo;jo'kqp", "id": "1"}
    http_request_mock.return_value = response
    result = AIOps_client.generate_bpa_report_request(requester_email, requester_name, dict_for_request)
    assert result == ("qejdhliqhjqo;jo'kqp", "1")


def test_generate_bpa_report_request_fails(mocker: MockerFixture, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling generate_bpa_report_request

    Then:
        - Raise an error since response not in format
    """
    from CommonServerPython import DemistoException
    requester_email = "test@gmail.com"
    requester_name = "test"
    dict_for_request = {"family": "test1", "model": "test2", "serial": "test3", "sw-version": "test4"}
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response = {"upload-url1": "qejdhliqhjqo;jo'kqp", "id": "1"}
    http_request_mock.return_value = response
    with pytest.raises(DemistoException) as e:
        AIOps_client.generate_bpa_report_request(requester_email, requester_name, dict_for_request)
    res = {'upload-url1': "qejdhliqhjqo;jo'kqp", 'id': '1'}
    assert e.value.message == f"Response not in format, can not find uploaded-url or report id. With response {res}."


def test_config_file_to_report_request_called_with(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    uploaded_url = "cloud.test"
    config_binary = b'<?xml version="1.0"?>\n <config>test</config>'
    AIOps_client.config_file_to_report_request(uploaded_url, config_binary)
    http_request_mock.assert_called_once_with(method='PUT', full_url='cloud.test', headers={'Content-Type':
                                                                                            'application/octet-stream',
                                                                                            'Accept': '*/*',
                                                                                            'Authorization': 'Bearer None'},
                                              data=b'<?xml version="1.0"?>\n <config>test</config>', empty_valid_codes=[200],
                                              return_empty_response=True)


def test_config_file_to_report_request_check_return(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.return_value = {'reason': 'OK', 'ok': True}
    uploaded_url = "cloud.test"
    config_binary = b'<?xml version="1.0"?>\n <config>test</config>'
    result = AIOps_client.config_file_to_report_request(uploaded_url, config_binary)
    assert result['ok']
    assert result['reason'] == 'OK'


def test_config_file_to_report_request_fails(mocker, AIOps_client):
    from CommonServerPython import DemistoException
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.side_effect = DemistoException(message='API ERROR - [404]')
    uploaded_url = "cloud.test"
    config_binary = b'<?xml version="1.0"?>\n <config>test</config>'
    with pytest.raises(DemistoException) as e:
        AIOps_client.config_file_to_report_request(uploaded_url, config_binary)
    assert e.value.message == 'API ERROR - [404]'


def test_check_upload_status_request_called_with(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    report_id = "123456789"
    AIOps_client.check_upload_status_request(report_id)
    http_request_mock.assert_called_once_with(method='GET',
                                              full_url='https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/jobs/123456789',
                                              headers={'Accept': '*/*', 'Authorization': 'Bearer None'})


def test_check_upload_status_request_check_return(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.return_value = {'status': 'COMPLETED_WITH_SUCCESS'}
    report_id = "123456789"
    result = AIOps_client.check_upload_status_request(report_id)
    assert result in ['COMPLETED_WITH_SUCCESS', 'UPLOAD_INITIATED', 'COMPLETED_WITH_ERROR', 'CONFIG_PARSED']


def test_check_upload_status_request_invalid_response(mocker, AIOps_client):
    from CommonServerPython import DemistoException
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.return_value = {'statuss': 'COMPLETED_WITH_SUCCESS'}
    report_id = "123456789"
    with pytest.raises(DemistoException) as e:
        AIOps_client.check_upload_status_request(report_id)
    assert e.value.message == 'Missing upload status, Error: parse Error.'


def test_download_bpa_request_called_with(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    report_id = "123456789"
    AIOps_client.download_bpa_request(report_id)
    http_request_mock.assert_called_once_with(method='GET',
                                              full_url=(
                                                  'https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/reports/123456789'
                                              ),
                                              headers={'Accept': 'application/json', 'Authorization': 'Bearer None'})


def test_download_bpa_request_check_return(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.return_value = {'download-url': 'cloud.com'}
    report_id = "123456789"
    result = AIOps_client.download_bpa_request(report_id)
    assert result == 'cloud.com'


def test_download_bpa_request_invalid_response(mocker, AIOps_client):
    from CommonServerPython import DemistoException
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    http_request_mock.return_value = {}
    report_id = "123456789"
    with pytest.raises(DemistoException) as e:
        AIOps_client.download_bpa_request(report_id)
    assert e.value.message == 'Missing download-url, Error: parse Error.'


def test_data_of_download_bpa_request_called_with(mocker, AIOps_client):
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    downloaded_BPA_url = "cloud.com"
    AIOps_client.data_of_download_bpa_request(downloaded_BPA_url)
    http_request_mock.assert_called_once_with(method='GET', full_url='cloud.com', headers={'Authorization': 'Bearer None'})


''' HELPER FUNCTIONS'''


def test_adjust_xml_format():
    """
    Given:
        - xml string
        - new tag root

    When:
        - Calling adjust_xml_format

    Then:
        - Get the wanted result
    """
    from PaloAltoNetworksAIOps import adjust_xml_format
    xml_data = ('<response status="success"><result><system><hostname>test</hostname><ip-address>1.2.3.4</ip-address></system>'
                '</result></response>')
    new_root_tag = 'system'
    result = adjust_xml_format(xml_data, new_root_tag)
    assert result == '<system ><hostname>test</hostname><ip-address>1.2.3.4</ip-address></system>'


def test_adjust_xml_format_invalid():
    """
    Given:
        - xml string
        - new root tag

    When:
        - Calling adjust_xml_format

    Then:
        - raise an error since a mismatch with new root tag in xml_string
    """
    from PaloAltoNetworksAIOps import adjust_xml_format
    from CommonServerPython import DemistoException
    xml_data = ('<response status="success"><result><system><hostname>test</hostname><ip-address>1.2.3.4</ip-address></system>'
                '</result></response>')
    new_root_tag = 'systems'
    with pytest.raises(DemistoException) as e:
        adjust_xml_format(xml_data, new_root_tag)
    assert e.value.message == 'Request Succeeded, A parse error occurred- could not find systems tag to adjust to AIOps API.'


def test_get_values_from_xml():
    """
    Given:
        - xml string
        - array of tags

    When:
        - Calling get_values_from_xml

    Then:
        - Get the wanted result
    """
    from PaloAltoNetworksAIOps import get_values_from_xml
    tags = ['family', 'model', 'serial', 'sw-version']
    xml_string = ('<system ><family>test1</family><model>test2</model><serial>test3</serial><hostname>test</hostname><sw-version>'
                  'test4</sw-version><ip-address>1.1.1.1</ip-address></system>')
    result = get_values_from_xml(xml_string, tags)
    assert result == ['test1', 'test2', 'test3', 'test4']


def test_get_values_from_xml_invalid():
    """
    Given:
        - xml string
        - array of tags

    When:
        - Calling get_values_from_xml

    Then:
        - raise an error since a mismatch tags in xml_string
    """
    from PaloAltoNetworksAIOps import get_values_from_xml
    from CommonServerPython import DemistoException
    tags = ['family', 'model', 'serial', 'sw-version']
    xml_string = (
        '<system ><familys>test1</familys><model>test2</model><serial>test3</serial><hostname>test</hostname><sw-version>'
        'test4</sw-version><ip-address>1.1.1.1</ip-address></system>'
    )
    with pytest.raises(DemistoException) as e:
        get_values_from_xml(xml_string, tags)
    assert e.value.message == ("Could not find the required tags in the System file. Error: 'NoneType' object has no attribute "
                               "'text'")


def test_convert_config_to_bytes_with_user_flag(mocker, AIOps_client):
    """
    Given:
        - flag is User
        - path to file from user

    When:
        - Calling convert_config_to_bytes with user flag

    Then:
        - succeed to convert into bytes
    """
    from PaloAltoNetworksAIOps import convert_config_to_bytes
    config_file_path = '/path/to/config_file.txt'
    expected_bytes = b'<?xml version="1.0"?><config>test</config>'
    with patch('builtins.open', mock_open(read_data=expected_bytes)) as mock_open_func, \
            patch('demistomock.getFilePath', return_value={'path': config_file_path}):
        result_bytes = convert_config_to_bytes('config_file.txt', 'User')
        assert result_bytes == expected_bytes
        mock_open_func.assert_called_once_with(config_file_path, 'rb')


def test_convert_config_to_bytes_get_path_exception():
    """
    Given:
        - flag is User
        - path to file from user
    When:
        - Calling convert_config_to_bytes with user flag

    Then:
        - Raise a file convertion error
    """
    from PaloAltoNetworksAIOps import convert_config_to_bytes
    from CommonServerPython import DemistoException
    with patch('demistomock.getFilePath', side_effect=Exception("invalid to parse")), pytest.raises(DemistoException) as e:
        convert_config_to_bytes('config_file.txt', 'User')
    assert e.value.message == ('The config file upload was unsuccessful or the file could not be converted. '
                               'With error: invalid to parse.')


def test_convert_config_to_bytes_invalid_getFilePath_response():
    """
    Given:
        - flag is User
        - path to file from user
    When:
        - Calling convert_config_to_bytes with user flag

    Then:
        - Raise a file convertion error
    """
    from PaloAltoNetworksAIOps import convert_config_to_bytes
    from CommonServerPython import DemistoException
    with patch('demistomock.getFilePath', return_value={}), pytest.raises(DemistoException) as e:
        convert_config_to_bytes('config_file.txt', 'User')
    assert e.value.message == "The config file upload was unsuccessful or the file could not be converted. With error: 'path'."


def test_convert_config_to_bytes_with_download_flag(mocker, AIOps_client):
    """
    Given:
        - flag is Download

    When:
        - Calling convert_config_to_bytes with Download flag

    Then:
        - succeed to convert into bytes
    """
    from PaloAltoNetworksAIOps import convert_config_to_bytes
    config_file = '<config>test</config>'
    expected_bytes = b'<?xml version="1.0"?>\n <config>test</config>'
    result = convert_config_to_bytes(config_file, 'Download')
    assert result == expected_bytes


def test_convert_config_to_bytes_converted_with_exception():
    """
    Given:
        - flag is User
        - path to file from user
    When:
        - Calling convert_config_to_bytes with user flag

    Then:
        - Raise a file convertion error
    """
    from PaloAltoNetworksAIOps import convert_config_to_bytes
    from CommonServerPython import DemistoException
    config_file = '<config>test</config>'
    with patch('io.StringIO', side_effect=Exception), pytest.raises(DemistoException) as e:
        convert_config_to_bytes(config_file, 'Download')
    assert e.value.message == 'The downloaded config file from Panorama/Pan-os could not be converted.'


def test_create_readable_output_checks_result():
    """
    Given:
        - response dict
    When:
        - Calling convert_response_for_hr

    Then:
        - convert response to the right format
    """
    from PaloAltoNetworksAIOps import convert_response_for_hr
    bpa_dict = {
        'best_practices': {
            'device': {
                'feature1': [
                    {
                        'warnings': [{'check_id': 1, 'check_message': 'Warning message 1'}],
                        'notes': [{'check_id': 2, 'check_message': 'Note message 1'}],
                        'random_field': [],
                    }
                ],
                'feature2': [
                    {
                        'warnings': [{'check_id': 3, 'check_message': 'Warning message 2'}],
                        'notes': [{'check_id': 4, 'check_message': 'Note message 2'}]
                    }
                ]
            }
        },
        'random_key': {}
    }
    result = convert_response_for_hr(bpa_dict)
    assert result == [
        {'check_id': 1, 'check_message': 'Warning message 1', 'check_type': 'warning', 'check_feature': 'feature1',
         'check_category': 'device'},
        {'check_id': 2, 'check_message': 'Note message 1', 'check_type': 'note', 'check_feature': 'feature1',
         'check_category': 'device'},
        {'check_id': 3, 'check_message': 'Warning message 2', 'check_type': 'warning', 'check_feature': 'feature2',
         'check_category': 'device'},
        {'check_id': 4, 'check_message': 'Note message 2', 'check_type': 'note', 'check_feature': 'feature2',
         'check_category': 'device'}
    ]


def test_create_markdown():
    """
    Given:
        - response array
    When:
        - Calling create_markdown

    Then:
        - Create an HR from the response
    """
    from PaloAltoNetworksAIOps import create_markdown
    response_array = [{'check_id': 1, 'check_message': 'Warning message 1', 'check_type': 'warning', 'check_feature': 'feature1',
                       'check_category': 'device'},
                      {'check_id': 2, 'check_message': 'Note message 1', 'check_type': 'note',
                          'check_feature': 'feature1', 'check_category': 'device'},
                      {'check_id': 3, 'check_message': 'Warning message 2', 'check_type': 'warning',
                          'check_feature': 'feature2', 'check_category': 'device'},
                      {'check_id': 4, 'check_message': 'Note message 2', 'check_type': 'note',
                          'check_feature': 'feature2', 'check_category': 'device'}
                      ]
    assert create_markdown(response_array) == ('### BPA results:\n|Check Id|Check Category|Check Feature|Check Message|Check Type'
                                               '|\n|---|---|---|---|---|\n| 1 | device | feature1 | Warning message 1 | warning |'
                                               '\n| 2 | device | feature1 | Note message 1 '
                                               '| note |\n| 3 | device | feature2 | Warning message 2 | warning |\n| 4 | device '
                                               '| feature2 | Note message 2 | note |\n')


def test_create_markdown_empty_array():
    """
    Given:
        - response empty array
    When:
        - Calling create_markdown

    Then:
        - Create an HR from the response- no entries
    """
    from PaloAltoNetworksAIOps import create_markdown
    response_array = []
    assert create_markdown(response_array) == '### BPA results:\n**No entries.**\n'


def test_generate_report_command_email_invalid(mocker, AIOps_client):
    """
    Given:
        - args with email invalid
    When:
        - Calling generate_report_command

    Then:
        - raise an error
    """
    from PaloAltoNetworksAIOps import generate_report_command
    from CommonServerPython import DemistoException
    args = {'entry_id': '1234', 'requester_email': 'testgmail.com', 'requester_name': 'test', 'export_as_file': 'false',
            'show_in_context': 'false'}
    generate_access_token_request_mock = mocker.patch.object(AIOps_client, 'generate_access_token_request')
    generate_access_token_request_mock.return_value = {}
    with pytest.raises(DemistoException) as e:
        generate_report_command(AIOps_client, args)
    assert e.value.message == "Invalid email testgmail.com, please make sure it is a valid email."
