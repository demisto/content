"""TeamCymru for Cortex XSOAR - Unit Tests file"""

import json
import demistomock as demisto
import pytest
import TeamCymru
from TeamCymru import CymruClient


'''GLOBALS'''

client = CymruClient()
MOCK_ENTRY_ID = '@123'
MOCK_BULK_LIST = "1.1.1.1, b, 2.2.2, n, 3.3.3.3,2001:0db8:85a3:0000:0000:8a2e:0370:7334,a,\"8.8.8.8\"," \
                 "4.4.4.4, 1.1.2.2, 6,6.6.6.6, 1.1.2.2"
MOCK_IPS_LIST = ['1.1.1.1', 'b', '2.2.2', 'n',
                 '3.3.3.3', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'a', '8.8.8.8', '4.4.4.4',
                 '1.1.2.2', '6', '6.6.6.6', '1.1.2.2']
MOCK_INVALID_IPS = ['b', '2.2.2', 'n', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'a', '6']
MOCK_VALID_IPS = ['1.1.1.1', '3.3.3.3', '8.8.8.8', '4.4.4.4', '1.1.2.2', '6.6.6.6', '1.1.2.2']
MOCK_FILE_RES = {
    'id': 'test_id',
    'path': 'test_data/test_ips_file.csv',
    'name': 'test_ips_file.csv',
}
DEFAULT_RELIABILITY = 'B - Usually reliable'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


@pytest.mark.parametrize('args, expected_error',
                         [({'ip': None}, 'IP not specified'),
                          ({'ip': '172.16.0'}, 'The given IP address: 172.16.0 is not valid')])
def test_ip_command_invalid_ip(args, expected_error):
    """
    Given:
        - Invalid IP
    When:
        - Running the IP command
    Then:
        - Raise ValueError with the expected value
    """
    from TeamCymru import ip_command
    with pytest.raises(ValueError, match=expected_error):
        ip_command(client, args, reliability=DEFAULT_RELIABILITY)


def test_ip_command(mocker):
    """
    Given:
        - Command arguments: ip ip = 8.8.8.8 (valid IPv4)
    When:
        - Running the IP command
    Then:
        - Validate the output compared to the mock output
    """
    from TeamCymru import ip_command
    mock_arg = {'ip': '8.8.8.8'}
    test_data = load_test_data('test_data/test_ip_command.json')
    return_value = test_data.get('ip_command_response')
    mocker.patch.object(CymruClient, 'lookup', return_value=return_value)
    response = ip_command(client, mock_arg, reliability=DEFAULT_RELIABILITY)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == response[0].outputs
    assert mock_readable_outputs == response[0].readable_output
    assert response[0].indicator
    assert response[0].indicator.dbot_score.reliability == DEFAULT_RELIABILITY


@pytest.mark.parametrize("reliability",
                         ["A+ - 3rd party enrichment",
                          "A - Completely reliable",
                          "B - Usually reliable",
                          "C - Fairly reliable",
                          "D - Not usually reliable",
                          "E - Unreliable",
                          "F - Reliability cannot be judged"])
def test_ip_different_reliability(mocker, reliability):
    """
    Given:
        - Different source reliability param
    When:
        - Running ip command
    Then:
        - Ensure the reliability specified is returned.
    """
    from TeamCymru import ip_command
    mock_arg = {'ip': '8.8.8.8'}
    test_data = load_test_data('test_data/test_ip_command.json')
    return_value = test_data.get('ip_command_response')
    mocker.patch.object(CymruClient, 'lookup', return_value=return_value)
    response = ip_command(client, mock_arg, reliability=reliability)
    assert response[0].indicator.dbot_score.reliability == reliability


def test_ip_command_with_list(mocker):
    """
    Given:
        - List of IP addresses
    When:
        - Running the IP command
    Then:
        - Verify support list of IPs
        - Verify the result is as expected and returns the expected warning
    """
    from TeamCymru import ip_command
    mock_arg = {"ip": MOCK_BULK_LIST}
    test_data = load_test_data('test_data/test_cymru_bulk_whois_command.json')
    return_value = test_data.get('cymru_bulk_whois_command_response')
    mocker.patch.object(CymruClient, 'lookupmany_dict', return_value=return_value)
    warning = mocker.patch.object(TeamCymru, 'return_warning')
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')

    response = ip_command(client, mock_arg, reliability=DEFAULT_RELIABILITY)
    assert warning.call_args[0][0] == test_data.get("warning_message")
    assert warning.call_args[1] == {'exit': False}
    for i, res in enumerate(response):
        assert mock_outputs[i] == res.outputs
        assert res.indicator
        assert mock_readable_outputs[i] == res.readable_output


def test_cymru_bulk_whois_command_with_file(mocker):
    """
    Given:
        - File of IP addresses
    When:
        - Running the cymru_bulk_whois command
    Then:
        - Verify support file of IPs
        - Verify the result is as expected
    """
    from TeamCymru import cymru_bulk_whois_command
    mock_arg = {"entry_id": MOCK_ENTRY_ID}
    test_data = load_test_data('test_data/test_cymru_bulk_whois_command.json')
    return_value = test_data.get('cymru_bulk_whois_command_response')
    mocker.patch.object(CymruClient, 'lookupmany_dict', return_value=return_value)

    mocker.patch.object(demisto, 'getFilePath', return_value=MOCK_FILE_RES)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')

    response = cymru_bulk_whois_command(client, mock_arg, reliability=DEFAULT_RELIABILITY)

    for i, res in enumerate(response):
        assert mock_outputs[i] == res.outputs
        assert res.indicator
        assert mock_readable_outputs[i] == res.readable_output


@pytest.mark.parametrize('args, expected_error',
                         [({'entry_id': MOCK_ENTRY_ID}, 'No file was found for given entry_id'),
                          ({}, 'No entry_id specified.')])
def test_cymru_bulk_whois_invalid_bulk(args, expected_error, mocker):
    """
    Given:
        - Invalid given argument
    When:
        - Running the cymru-bulk-whois command
    Then:
        - Raise ValueError with the expected value
    """
    from TeamCymru import cymru_bulk_whois_command
    mocker.patch.object(demisto, 'getFilePath', return_value=None)
    with pytest.raises(ValueError, match=expected_error):
        cymru_bulk_whois_command(client, args, reliability=DEFAULT_RELIABILITY)


def test_team_cymru_parse_file():
    """
    Given:
        - get_file_path_res, dict: Object contains file ID, path and name
    When:
        - Running the parse_file function
    Then:
        - Return list of the elements in the file without spaces
    """
    from TeamCymru import parse_file
    mock_arg = {
        'id': 'test_id',
        'path': 'test_data/test_ips_file.csv',
        'name': 'test_ips_file.csv',
    }
    assert parse_file(mock_arg) == MOCK_IPS_LIST


def test_team_cymru_validate_ip_addresses():
    """
    Given:
        - Ips list
    When:
        - Running the validate_ip_addresses function
    Then:
        - Returns two list of invalid and valid IPv4 addresses
    """
    from TeamCymru import validate_ip_addresses
    invalid_ip_addresses, valid_ip_addresses = validate_ip_addresses(MOCK_IPS_LIST)
    assert invalid_ip_addresses == MOCK_INVALID_IPS
    assert valid_ip_addresses == MOCK_VALID_IPS


def test_team_cymru_parse_ip_result():
    """
    Given:
        - The function arguments: ip, ip_data
    When:
        - Running the parse_ip_result function
    Then:
        - Validate the returned value (commandResult) compared to the mock output
    """
    from TeamCymru import parse_ip_result
    from CommonServerPython import Common

    test_data = load_test_data('test_data/test_ip_command.json')
    ip_data = test_data.get('ip_command_response')
    ip = "8.8.8.8"
    mock_entry_context = test_data.get('mock_output')
    mock_readable = test_data.get('mock_readable')
    command_result = parse_ip_result(ip, ip_data, reliability=DEFAULT_RELIABILITY)

    assert command_result.outputs == mock_entry_context
    assert command_result.readable_output == mock_readable
    assert command_result.indicator
    assert command_result.raw_response == ip_data
    assert isinstance(command_result.indicator, Common.IP)


def test_empty_command_result(mocker):
    """
    Given:
        - Valid ip address, running the ip_command and cymru_bulk_whois_command functions
    When:
        - team_cymru_ip, team_cymru_bulk_whois functions return None
    Then:
        - Verify the functions doesn't fail and returns empty list
    """
    from TeamCymru import ip_command, cymru_bulk_whois_command
    mocker.patch.object(CymruClient, "lookup", return_value=None)
    result = ip_command(client, {'ip': '1.1.1.1'}, reliability=DEFAULT_RELIABILITY)
    assert not result
    mocker.patch.object(CymruClient, "lookupmany_dict", return_value=None)
    mocker.patch.object(demisto, 'getFilePath', return_value=MOCK_FILE_RES)
    result = cymru_bulk_whois_command(client, {'entry_id': MOCK_ENTRY_ID}, reliability=DEFAULT_RELIABILITY)
    assert not result


def assert_results_ok():
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'ok'


def test_test_command(mocker):
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='test-module')
    return_value = load_test_data('test_data/test_ip_command.json').get('ip_command_response')
    mocker.patch.object(CymruClient, "lookup", return_value=return_value)
    TeamCymru.main()
    assert_results_ok()
