import io
from CofenseIntelligenceV2 import *

mock_params = {'url_threshold': 'Major', 'file_threshold': 'Major', 'email_threshold': 'Major', 'ip_threshold': 'Major',
               'days_back': 90}

mock_base_url = 'mock_base_url'
mock_username = 'mock_username'
mock_password = 'mock_password'

headers: Dict = {
    "Authorization": f"Basic {base64.b64encode(':'.join([mock_username, mock_password]).encode()).decode().strip()}"
}
client = Client(
    base_url=mock_base_url,
    verify=True,
    headers=headers,
    proxy=False)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_threats_analysis():
    """
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
    md_data, dbot_score = threats_analysis(mock_threats, indicator, threshold)
    assert mock_dbot_score == dbot_score
    assert mock_md_data == md_data


def test_create_threat_md_row():
    """
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
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = extracted_string(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_outputs')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response.outputs)
    assert mock_readable_outputs == response.readable_output


def test_search_url_command(mocker):
    """
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


def test_check_email_command(mocker):
    """
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


def test_check_ip_command(mocker):
    """
        Given:
            - ip command args
        When:
            - run check_ip_command
        Then:
            - Verify response outputs
            - verify response readable output
    """

    mock_args = {'ip': '1.1.1.1'}
    test_data = util_load_json('test_data/test_search_ip.json')
    return_value = test_data.get('ip_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_ip_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output


def test_check_md5_command(mocker):
    """
        Given:
            - file command args
        When:
            - run check_md5_command
        Then:
            - Verify response outputs
            - verify response readable output
    """

    mock_args = {'file': 'file'}
    test_data = util_load_json('test_data/test_search_file.json')
    return_value = test_data.get('file_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_md5_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output
