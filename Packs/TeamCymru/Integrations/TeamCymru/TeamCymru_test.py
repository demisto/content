"""TeamCymru for Cortex XSOAR - Unit Tests file"""

import json
import io
from CommonServerPython import *
import demistomock as demisto
import pytest

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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

def test_ip_command(mocker):
    """
    Given:
        - Command arguments: ip ip = 8.8.8.8
    When:
        - running the IP command
    Then:
        - Validate the output compared to the mock output
    """
    from TeamCymru import ip_command

    mock_args = {'ip': '8.8.8.8'}
    mock_response = util_load_json('test_data/ip_8.8.8.8_response.json')

    client = Client(api_key='',
                    base_url='https://ipinfo.io',
                    verify_certificate=False,
                    proxy=False,
                    reliability=DBotScoreReliability.C)
    mocker.patch.object(client, 'http_request', return_value=mock_response)

    command_results = mocker.patch('ipinfo_v2.CommandResults')
    ipinfo_ip_command(client, ip)

    expected_parsed_context = util_load_json('test_data/ip_1.1.1.1_command_results.json')
    assert command_results.call_args[1].get("readable_output") == expected_parsed_context[1].get("HumanReadable")
    assert command_results.call_args[1].get("outputs").get("Address") == "1.1.1.1"
    assert command_results.call_args[1].get("outputs").get("Hostname") == "one.one.one.one"

    mock_args = {'ip': '127.0.0.1'}
    test_data = util_load_json('test_data/test_search_ip.json')
    return_value = test_data.get('ip_search_response')
    mocker.patch.object(client, 'threat_search_call', return_value=return_value)
    response = check_ip_command(client, mock_args, mock_params)
    mock_outputs = test_data.get('mock_output')
    mock_readable_outputs = test_data.get('mock_readable')
    assert mock_outputs == str(response[0].outputs)
    assert mock_readable_outputs == response[0].readable_output
    assert IP_RELATIONSHIP == (response[0].to_context())['Relationships']


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
    response = load_test_data('./test_data/ip_output.json')
    mocker.patch.object(Whois, 'get_whois_ip', return_value=response)


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
    from TeamCymru import team_cymru_bulk_whois


def test_cymru_bulk_whois_valid_entry(mocker):
    """

    Given:
        - Valid entry id of a file, str
    When:
        - When the user uploads a file for later conversion via entry
    Then:
        - Returns the response data

    """

    client = create_client()
    mocker.patch.object(client, 'upload_entry_id',
                        return_value=util_load_json('./test_data/upload_entry_response.json'))
    results = upload_command(client, {'entry_id': MOCK_ENTRY_ID})
    raw_response = util_load_json('./test_data/upload_entry_response.json')
    raw_response['data']['operation'] = 'upload/entry'
    readable_output = tableToMarkdown('Upload Results',
                                      remove_empty_elements(raw_response.get('data')),
                                      headers=('id', 'operation', 'created_at', 'status'),
                                      headerTransform=string_to_table_header,
                                      )

    assert results.outputs == remove_empty_elements(raw_response.get('data'))
    assert results.readable_output == readable_output


def test_cymru_bulk_whois_invalid_entry(mocker):
    """

    Given:
        - Invalid entry id of a file, str
    When:
        - When the user uploads a file for later conversion via entry
    Then:
        - Returns the response message of invalid input

    """

    client = create_client()
    mocker.patch.object(demisto, 'getFilePath', return_value=None)
    with pytest.raises(ValueError) as e:
        upload_command(client, {'entry_id': MOCK_ENTRY_ID})
        if not e:
            assert False


def test_team_cymru_parse_file():
    """
    Given:
        -
    When:
        -
    Then:
        -
    """



def test_team_cymru_validate_ip_addresses():
    """
    Given:
        -
    When:
        -
    Then:
        -
    """


def test_team_cymru_parse_ip_result():
    """
    Given:
        -
    When:
        -
    Then:
        -
    """