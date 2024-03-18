import pytest
from PaloAltoNetworks_AIOps import Client
from pytest_mock import MockerFixture
import pytest

@pytest.fixture
def AIOps_client(base_url='base_url', api_key='api_key', tsg_id='tsg_id', client_id='client_id', client_secret='client_secret',
                 verify=True, proxy=False, headers=None):
    return Client(base_url=base_url, api_key=api_key, tsg_id=tsg_id, client_id=client_id, client_secret=client_secret,
                  verify=verify, proxy=proxy, headers=headers)


''' COMMAND FUNCTIONS TESTS '''

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
        '<show><system><info></info></system></show>', 'key': 'api_key'}, headers={'Content-Type': 'application/xml'},
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
                     '</ip-address></system></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    with pytest.raises(DemistoException) as e:
        AIOps_client.get_info_about_device_request()
    assert e.value.message == "Request Succeeded, A parse error occurred."
    
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
                     'detail-version="10.2.1"><config-mgt>khbk,g</config-mgt>\n</config></result></response>')
    response_mock = mocker.Mock()
    response_mock.text = response_text
    http_request_mock.return_value = response_mock
    with pytest.raises(DemistoException) as e:
        AIOps_client.get_config_file_request()
    assert e.value.message == "Request Succeeded, A parse error occurred."
###

def test_generate_bpa_report_request_called_with(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling generate_bpa_report_request

    Then:
        - Checks the generate_bpa_report_request request (the request that is calles)
    """
    requester_email = "test@gamil.com"
    requester_name = "test"
    dict_for_request = {"family": "test1", "model": "test2", "serial": "test3", "sw-version": "test4"}
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response = {"upload-url":"qejdhliqhjqo;jo'kqp", "id":"1"}
    http_request_mock.return_value = response
    AIOps_client.generate_bpa_report_request(requester_email, requester_name, dict_for_request)
    http_request_mock.assert_called_once_with(method='POST',
                                              full_url='https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/requests',
                                              headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                                                       'Authorization': 'Bearer {}'}, json_data={'requester-email':
                                                        'test@gamil.com', 'requester-name': 'test', 'serial': 'test3',
                                                        'version': 'test4', 'model': 'test2', 'family': 'test1'})

def test_generate_bpa_report_request_return(mocker, AIOps_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - Calling get_config_file_request

    Then:
        - Checks the generate_bpa_report_request output (using adjust_xml_format)
    """
    requester_email = "test@gamil.com"
    requester_name = "test"
    dict_for_request = {"family": "test1", "model": "test2", "serial": "test3", "sw-version": "test4"}
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response = {"upload-url":"qejdhliqhjqo;jo'kqp", "id":"1"}
    http_request_mock.return_value = response
    result = AIOps_client.generate_bpa_report_request(requester_email, requester_name, dict_for_request)
    assert result== ("qejdhliqhjqo;jo'kqp", "1")
    
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
    requester_email = "test@gamil.com"
    requester_name = "test"
    dict_for_request = {"family": "test1", "model": "test2", "serial": "test3", "sw-version": "test4"}
    http_request_mock = mocker.patch.object(AIOps_client, '_http_request')
    response = {"upload-url1":"qejdhliqhjqo;jo'kqp", "id":"1"}
    http_request_mock.return_value = response
    with pytest.raises(DemistoException) as e:
        AIOps_client.generate_bpa_report_request(requester_email, requester_name, dict_for_request)
    assert e.value.message== "Response not in format, can not find uploaded-url or report id."
    
''' HELPER FUNCTIONS'''
def test_adjust_xml_format():
    from PaloAltoNetworks_AIOps import adjust_xml_format
    xml_data = ('<response status="success"><result><system><hostname>test</hostname><ip-address>1.2.3.4</ip-address></system>'
                '</result></response>')
    new_root_tag = 'system'
    result = adjust_xml_format(xml_data, new_root_tag)
    assert result == '<system ><hostname>test</hostname><ip-address>1.2.3.4</ip-address></system>'
    
def test_get_values_from_xml():
    from PaloAltoNetworks_AIOps import get_values_from_xml
    tags = ['family', 'model', 'serial', 'sw-version']
    xml_string = ('<system ><family>test1</family><model>test2</model><serial>test3</serial><hostname>test</hostname><sw-version>'
    'test4</sw-version><ip-address>1.1.1.1</ip-address></system>')
    result = get_values_from_xml(xml_string, tags)
    assert result == ['test1', 'test2', 'test3', 'test4']

