"""Unit test cases."""
import json

import pytest

from CofenseIntelligenceV2 import *
import base64

mock_params = {'url_threshold': 'Major', 'file_threshold': 'Major', 'email_threshold': 'Major', 'ip_threshold': 'Major',
               'domain_threshold': 'Major',
               'days_back': 90}

mock_base_url = 'mock_base_url'
mock_username = 'mock_username'
mock_password = 'mock_password'

headers: dict = {
    "Authorization": f"Basic {base64.b64encode(':'.join([mock_username, mock_password]).encode()).decode().strip()}"
}
DOMAIN_RELATIONSHIP = [
    {'brand': 'Cofense Intelligence', 'entityA': 'domain', 'entityAFamily': 'Indicator', 'entityAType': 'Domain',
     'entityB': 'domain', 'entityBFamily': 'Indicator', 'entityBType': None, 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'domain', 'entityAFamily': 'Indicator', 'entityAType': 'Domain',
     'entityB': 'domain2', 'entityBFamily': 'Indicator', 'entityBType': None, 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'domain', 'entityAFamily': 'Indicator', 'entityAType': 'Domain',
     'entityB': '8e1a7d8b88096693a52173618b7b709e', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {},
     'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator'}
]

FILE_RELATIONSHIP_MD5 = [
    {'brand': 'Cofense Intelligence', 'entityA': 'md5', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': 'com', 'entityBFamily': 'Indicator', 'entityBType': 'Domain', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'md5', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': '127.0.0.1', 'entityBFamily': 'Indicator', 'entityBType': 'IP', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'md5', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': 'md5', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'md5', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': 'md5', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'}
]

FILE_RELATIONSHIP_SHA256 = [
    {'brand': 'Cofense Intelligence', 'entityA': 'sha256', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': 'com', 'entityBFamily': 'Indicator', 'entityBType': 'Domain', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'sha256', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': '127.0.0.1', 'entityBFamily': 'Indicator', 'entityBType': 'IP', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'sha256', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': 'md5', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'sha256', 'entityAFamily': 'Indicator', 'entityAType': 'File',
     'entityB': 'md5', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'}
]

EMAIL_RELATIONSHIP = [
    {'brand': 'Cofense Intelligence', 'entityA': 'email@email.com', 'entityAFamily': 'Indicator',
     'entityAType': 'Email', 'entityB': 'email@email.com', 'entityBFamily': 'Indicator',
     'entityBType': 'Email', 'fields': {}, 'name': 'related-to', 'reverseName': 'related-to',
     'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'email@email.com', 'entityAFamily': 'Indicator',
     'entityAType': 'Email', 'entityB': 'md5', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {},
     'name': 'related-to', 'reverseName': 'related-to', 'type': 'IndicatorToIndicator'}]

URL_RELATIONSHIP = [
    {'brand': 'Cofense Intelligence', 'entityA': 'url', 'entityAFamily': 'Indicator', 'entityAType': 'URL',
     'entityB': 'url', 'entityBFamily': 'Indicator', 'entityBType': None, 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'url', 'entityAFamily': 'Indicator', 'entityAType': 'URL',
     'entityB': 'url2', 'entityBFamily': 'Indicator', 'entityBType': None, 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': 'url', 'entityAFamily': 'Indicator',
     'entityAType': 'URL', 'entityB': 'f23e89543e8627182579f68c5916fd05', 'entityBFamily': 'Indicator',
     'entityBType': 'File', 'fields': {}, 'name': 'related-to', 'reverseName': 'related-to',
     'type': 'IndicatorToIndicator'}
]

IP_RELATIONSHIP = [
    {'brand': 'Cofense Intelligence', 'entityA': '127.0.0.1', 'entityAFamily': 'Indicator', 'entityAType': 'IP',
     'entityB': '127.0.0.1', 'entityBFamily': 'Indicator', 'entityBType': 'IP', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence', 'entityA': '127.0.0.1', 'entityAFamily': 'Indicator', 'entityAType': 'IP',
     'entityB': 'md5', 'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'},
    {'brand': 'Cofense Intelligence',
     'entityA': '127.0.0.1', 'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'md5',
     'entityBFamily': 'Indicator', 'entityBType': 'File', 'fields': {}, 'name': 'related-to',
     'reverseName': 'related-to', 'type': 'IndicatorToIndicator'}]
client = Client(
    base_url=mock_base_url,
    verify=True,
    headers=headers,
    proxy=False,
    score_mapping="None:0, Minor:1, Moderate:2, Major:3")


def util_load_json(path):
    """Return json data from given file path."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize("threshold, expected_value", [('None', 0), ('Minor', 1), ('Major', 3), ('Moderate', 2)])
def test_reputation_commands_threshold_working_success(threshold, expected_value):
    """Test case scenario when valid threshold value is provided."""
    assert client.severity_score.get(threshold) == expected_value


@pytest.mark.parametrize("threshold, expected_err_msg", [
    ('', "Cofense error: Invalid threshold value: . Valid values are: None, Minor, Moderate or Major"),
    ('dummy', "Cofense error: Invalid threshold value: dummy. Valid values are: None, Minor, Moderate or Major"),
    (None, "Cofense error: Invalid threshold value: None. Valid values are: None, Minor, Moderate or Major"),
])
def test_reputation_commands_threshold_when_invalid_values_provided(threshold, expected_err_msg):
    """Test case scenario when invalid threshold value is provided."""
    from CofenseIntelligenceV2 import threats_analysis

    with pytest.raises(Exception) as err:
        threats_analysis(client.severity_score, [], "dummy", threshold, "domain")
    assert str(err.value) == expected_err_msg


def test_threats_analysis():
    """
    Test case scenario for threat_analysis.

    Given:
        - an indicator to search and a threats array  from cofense search
    When:
        - Running threat_analysis
    Then:
        - Verify md table data
        - Verify dbot score
    """
    indicator = 'email1'
    threshold = 'Major'
    mock_threats = util_load_json('test_data/test_threats.json').get('threats')
    mock_md_data = util_load_json('test_data/test_threats.json').get('mock_md_data')
    mock_dbot_score = util_load_json('test_data/test_threats.json').get('mock_dbot_score')
    md_data, dbot_score = threats_analysis(client.severity_score, mock_threats, indicator, threshold, "email")
    assert mock_dbot_score == dbot_score
    assert mock_md_data == md_data


def test_create_threat_md_row():
    """
    Test case scenario for create_threat_md_row.

    Given:
        - a threats from cofense search raw response
    When:
        - run create_threat_md_row
    Then:
        - Verify md row data
    """
    threat = util_load_json('test_data/test_threats.json').get('threats')[0]
    severity_level = util_load_json('test_data/test_threats.json').get('mock_dbot_score')
    threat_md_row = create_threat_md_row(threat, severity_level)
    mock_threat_md_row = util_load_json('test_data/test_threats.json').get('mock_md_data')[0]
    assert mock_threat_md_row == threat_md_row


def test_extracted_string(mocker):
    """
    Test case scenario for string_search_response.

    Given:
        - extracted string command args
    When:
        - run extracted_string_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'str': 'str', 'limit': '10'}
    test_data = util_load_json('test_data/test_extracted_string.json')

    return_value = test_data.get('string_search_response')
    mocker.patch.object(client, 'search_cofense', return_value=return_value)
    response = extracted_string(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_outputs')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response.outputs)
    assert mock_readable_outputs == response.readable_output


def test_search_url_command(mocker):
    """
    Test case scenario for url command.

    Given:
        - url command args
    When:
        - run check_url_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'url': 'url'}
    test_data = util_load_json('test_data/test_search_url.json')
    return_value = test_data.get('url_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = search_url_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output
    assert (response[0].to_context())['Relationships'] == URL_RELATIONSHIP


def test_check_email_command(mocker):
    """
    Test case scenario for email command.

    Given:
        - email command args
    When:
        - run check_email_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'email': 'email@email.com'}
    test_data = util_load_json('test_data/test_search_email.json')
    return_value = test_data.get('email_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_email_command(client, mock_args, mock_params)
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_readable_outputs == response[0].readable_output
    assert (response[0].to_context())['Relationships'] == EMAIL_RELATIONSHIP


def test_check_ip_command(mocker):
    """
    Test case scenario for ip command.

    Given:
        - ip command args
    When:
        - run check_ip_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'ip': '127.0.0.1'}
    test_data = util_load_json('test_data/test_search_ip.json')
    return_value = test_data.get('ip_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_ip_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output
    assert (response[0].to_context())['Relationships'] == IP_RELATIONSHIP


def test_check_file_command_with_md5_hash(mocker):
    """
    Test case scenario for file command when md5 hash is provided as argument.

    Given:
        - file command args
    When:
        - run check_file_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'file': 'md5'}
    test_data = util_load_json('test_data/test_search_file.json')
    return_value = test_data.get('file_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_file_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output_md5')
    mock_readable_outputs = test_data.get('mock_readable_md5')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output
    assert (response[0].to_context())['Relationships'] == FILE_RELATIONSHIP_MD5
    assert response[0].indicator.md5 == mock_args['file']
    assert response[0].indicator.sha256 != mock_args['file']


def test_check_file_command_with_sha256_hash(mocker):
    """
    Test case scenario for file command when sha256 hash is provided as argument.

    Given:
        - file command args
    When:
        - run check_file_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'file': 'sha256'}
    test_data = util_load_json('test_data/test_search_file.json')
    return_value = test_data.get('file_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_file_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output_sha256')
    mock_readable_outputs = test_data.get('mock_readable_sha256')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output
    assert (response[0].to_context())['Relationships'] == FILE_RELATIONSHIP_SHA256
    assert response[0].indicator.sha256 == mock_args['file']
    assert response[0].indicator.md5 != mock_args['file']


def test_check_domain_command(mocker):
    """
    Test case scenario for domain command.

    Given:
        - domain command args
    When:
        - run check_domain_command
    Then:
        - Verify response outputs
        - verify response readable output
    """
    mock_args = {'domain': 'domain'}
    test_data = util_load_json('test_data/test_search_domain.json')
    return_value = test_data.get('domain_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_domain_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response[0].outputs)
    assert response[0].indicator.domain == "domain"
    assert (response[0].to_context())['Relationships'] == DOMAIN_RELATIONSHIP
    assert mock_readable_outputs == response[0].readable_output


def test_when_domain_not_specified():
    """
    Test case scenario where domain is not provided.

    Given:
        - invalid domain command args
    When:
        - run check_domain_command
    Then:
        - Returns the response message of invalid input arguments
    """
    with pytest.raises(ValueError) as de:
        check_domain_command(client, {'domain': []}, mock_params)
    assert str(de.value) == "Domain not specified"


def test_dummy_is_safe_domain_even_though_abc_dummy_is_malicious(mocker):
    """
    Test case scenario where domain is malicious and similar domain with different severity present in resposne.

    Given:
        - Domain dummy.com with Minor and abc.dummy.com with Major impact
          are present in the response.
    When:
        - Searching for the dummy.com domain should return Benign severity.
    Then:
        - Should return the dbot score of 1 indicating domain is 'Good'.
    """
    mock_args = {'domain': 'dummy.com'}
    mock_api_resp = util_load_json('test_data/test_google_safe_domain.json')
    mocker.patch.object(client, 'threat_search_call', return_value=mock_api_resp)
    response = check_domain_command(client, mock_args, mock_params)

    assert response[0].indicator.domain == "dummy.com"
    assert response[0].indicator.dbot_score.score == 1

    mock_args = {'domain': 'abc.dummy.com'}
    response = check_domain_command(client, mock_args, mock_params)

    assert response[0].indicator.domain == "abc.dummy.com"
    assert response[0].indicator.dbot_score.score == 3


def test_check_whether_dbot_score_is_updated_for_every_instance_present_in_response(mocker):
    """
    Test case to check updated dbot score.

    Given:
        - Domain dummy.com with Minor and abc.dummy.com with Major impact
          are present in the response.
    When:
        - Searching for the dummy.com domain should return Benign severity.
    Then:
        - Should return the dbot score of 1 indicating domain is 'Good'.
    """
    mock_args = {'domain': 'dummy.com'}
    mock_api_resp = util_load_json('test_data/test_google_safe_domain_miltiple_instance.json')
    mocker.patch.object(client, 'threat_search_call', return_value=mock_api_resp)
    response = check_domain_command(client, mock_args, mock_params)

    assert response[0].indicator.domain == "dummy.com"
    assert response[0].indicator.dbot_score.score == 3


def test_url_is_malicious_and_domain_is_safe(mocker):
    """
    Test case scenario where url is malicious and similar domain with different severity present in resposne.

    Given:
        - A domain dummy.com with minor severity present in response.
        - A domain abc.dummy.com with major severity present in response.
    When:
        - Searching for the dummy.com domain should return Benign severity.
    Then:
        - Should return the dbot score of 1 indicating domain is 'Good'.
    """
    mock_args = {'domain': 'dummy.com'}
    mock_api_resp = util_load_json('test_data/test_url_bad_and_domain_safe.json')
    mocker.patch.object(client, 'threat_search_call', return_value=mock_api_resp)
    response = check_domain_command(client, mock_args, mock_params)

    assert response[0].indicator.domain == "dummy.com"
    assert response[0].indicator.dbot_score.score == 1


def test_url_is_malicious_and_no_entry_in_domain(mocker):
    """
    Test case scenario where url is malicious and not present in resposne.

    Given:
        - A url with dummy.com with major severity present in response.
        - A domain named dummy.com is not present in the response.
    When:
        - Searching for the dummy.com domain.
    Then:
        - Should return dbot score of 0 indicating the domain is 'Unknown'.
    """
    mock_args = {'domain': 'dummy.com'}
    mock_api_resp = util_load_json('test_data/test_url_malicious_domain_safe.json')
    mocker.patch.object(client, 'threat_search_call', return_value=mock_api_resp)
    response = check_domain_command(client, mock_args, mock_params)

    assert response[0].indicator.domain == "dummy.com"
    assert response[0].indicator.dbot_score.score == 0


@pytest.fixture()
def mock_client():
    """Create a mock client object to work with."""
    from CofenseIntelligenceV2 import Client
    client = Client(
        base_url='https://www.threathq.com/',
        verify=True,
        headers=headers,
        proxy=False,
        score_mapping="None:0, Minor:1, Moderate:2, Major:3"
    )

    return client


def test_threat_report_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of cofense-threat-report-get command.

    Given:
        - command arguments for threat_report_command
    When:
        - Calling `threat_report_command` function
    Then:
        - Returns a valid output.
    """
    from CofenseIntelligenceV2 import threat_report_command

    mock_threat_report_endpoint = 'https://www.threathq.com/apiv1/t3/malware/111/html'
    mock_response = "some data"
    requests_mock.get(mock_threat_report_endpoint, text=mock_response, status_code=200)

    actual = threat_report_command(mock_client, {"report_id": "111"})

    assert actual["File"] == "111.html"


@pytest.mark.parametrize("args, error_msg",
                         [({"report_id": "111a"}, "Argument 'report_id' accepts only numeric literals."),
                          ({"report_id": "111", "report_format": "dummy"},
                           "Argument 'report_format' accepts only 'html' or 'pdf' as input.")])
def test_threat_report_command_invalid_arg(args, error_msg, mock_client):
    """
    Test case scenario where invalid arguments are provided.

    Given:
        - command arguments for threat_report_command
    When:
        - Calling `threat_report_command` function
    Then:
        - Raises an error.
    """
    from CofenseIntelligenceV2 import threat_report_command
    with pytest.raises(DemistoException) as e:
        threat_report_command(client, args)
    assert str(e.value) == error_msg


def test_threat_report_command_no_report_found_500(mock_client, requests_mock):
    """
    Test case scenario where no report exists for given report_id.

    Given:
        - command arguments for threat_report_command
    When:
        - Calling `threat_report_command` function
    Then:
        - Raises an error.
    """
    from CofenseIntelligenceV2 import threat_report_command

    mock_threat_report_endpoint = 'https://www.threathq.com/apiv1/t3/malware/11111111111/html'
    mock_response = ""
    requests_mock.get(mock_threat_report_endpoint, text=mock_response, status_code=500)

    with pytest.raises(DemistoException) as e:
        threat_report_command(mock_client, {"report_id": "11111111111"})
    assert str(e.value) == "No threat report found for given report_id."
