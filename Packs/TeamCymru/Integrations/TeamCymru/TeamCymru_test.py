"""TeamCymru for Cortex XSOAR - Unit Tests file"""

import json
import io
from CommonServerPython import *
import demistomock as demisto
import pytest
from unittest.mock import MagicMock, patch
import TeamCymru

client = MagicMock()

def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)

# client = None #Client() #TODO IF NEED TO CALL THE CLIENT OF THE IMPORT

# TODO: REMOVE the following dummy unit test function
# def test_baseintegration_dummy():
#     """Tests helloworld-say-hello command function.
#
#     Checks the output of the command function with the expected output.
#
#     No mock is needed here because the say_hello_command does not call
#     any external API.
#     """
#     from BaseIntegration import Client, baseintegration_dummy_command
#
#     client = Client(base_url='some_mock_url', verify=False)
#     args = {
#         'dummy': 'this is a dummy response'
#     }
#     response = baseintegration_dummy_command(client, args)
#
#     mock_response = util_load_json('test_data/baseintegration-dummy.json')
#
#     assert response.outputs == mock_response
# TODO: ADD HERE unit tests for every command


# def test_get_whois_ip_proxy_param(mocker):
#     """
#     Given:
#         - valid ip address
#     When:
#         - running the ip_command function
#     Then:
#         - Verify the function return nothing
#     """
#     from TeamCymru import ip_command
#     mocker.patch("ipwhois.IPWhois.lookup_rdap", return_value=None)
#     result = ip_command('1.1.1.1')
#     assert result


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
        ip_command(client, args)


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
    mocker.patch.object(TeamCymru, 'team_cymru_ip', return_value=return_value)
    response = ip_command(client, mock_arg)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == response.outputs
    assert mock_readable_outputs == response.readable_output


def test_cymru_bulk_whois_command_with_list(mocker):
    """
    Given:
        - List of IP addresses
    When:
        - Running the cymru_bulk_whois command
    Then:
        - Verify support list of IPs
        - Verify the result is as expected
    """
    from TeamCymru import team_cymru_bulk_whois


#
# def test_cymru_bulk_whois_command_with_file(mocker):
#     """
#     Given:
#         - File of IP addresses
#     When:
#         - Running the cymru_bulk_whois command
#     Then:
#         - Verify support file of IPs
#         - Verify the result is as expected
#     """
#     from TeamCymru import team_cymru_bulk_whois
#
#
# def test_cymru_bulk_whois_valid_entry(mocker):
#     """
#
#     Given:
#         - Valid entry id of a file, str
#     When:
#         - When the user uploads a file for later conversion via entry
#     Then:
#         - Returns the response data
#
#     """
#
#     client = create_client()
#     mocker.patch.object(client, 'upload_entry_id',
#                         return_value=util_load_json('./test_data/upload_entry_response.json'))
#     results = upload_command(client, {'entry_id': MOCK_ENTRY_ID})
#     raw_response = util_load_json('./test_data/upload_entry_response.json')
#     raw_response['data']['operation'] = 'upload/entry'
#     readable_output = tableToMarkdown('Upload Results',
#                                       remove_empty_elements(raw_response.get('data')),
#                                       headers=('id', 'operation', 'created_at', 'status'),
#                                       headerTransform=string_to_table_header,
#                                       )
#
#     assert results.outputs == remove_empty_elements(raw_response.get('data'))
#     assert results.readable_output == readable_output
#
#
# def test_cymru_bulk_whois_invalid_entry(mocker):
#     """
#
#     Given:
#         - Invalid entry id of a file, str
#     When:
#         - When the user uploads a file for later conversion via entry
#     Then:
#         - Returns the response message of invalid input
#
#     """
#
#     client = create_client()
#     mocker.patch.object(demisto, 'getFilePath', return_value=None)
#     with pytest.raises(ValueError) as e:
#         upload_command(client, {'entry_id': MOCK_ENTRY_ID})
#         if not e:
#             assert False
#
#
# def test_team_cymru_parse_file():
#     """
#     Given:
#         -
#     When:
#         -
#     Then:
#         -
#     """
#
#
#
# def test_team_cymru_validate_ip_addresses():
#     """
#     Given:
#         -
#     When:
#         -
#     Then:
#         -
#     """
#
#
# def test_team_cymru_parse_ip_result():
#     """
#     Given:
#         -
#     When:
#         -
#     Then:
#         -
#     """