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

def test_team_cymru_ip_command(mocker):
    """
    Given:
        - Command arguments: ip ip = 8.8.8.8
    When:
        - running the IP command
    Then:
        - Validate the output compared to the mock output
    """
    from TeamCymru import ip_command

    mock_response = util_load_json('test_data/view_host_response.json')
    requests_mock.get('https://search.censys.io/api/v2/hosts/8.8.8.8', json=mock_response)
    response = censys_view_command(client, args)
    assert '### Information for IP 8.8.8.8' in response.readable_output
    assert response.outputs == mock_response.get('result')


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