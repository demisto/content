"""IPinfo Integration for Cortex XSOAR - Unit Tests file"""

import json

from CommonServerPython import DBotScoreReliability
import demistomock as demisto
import pytest

from ipinfo_v2 import BRAND_NAME


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': BRAND_NAME}, 'integration': True})


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_ipinfo_ip_command(mocker):
    """
    Given:
        A mock response of a call to https://ipinfo.io/1.1.1.1/json,
        And a json of the expected output objects
    When:
        Calling ip on ip=1.1.1.1
    Then:
        Validate the output compared to the mock output
    """
    from ipinfo_v2 import Client, ipinfo_ip_command

    ip = '1.1.1.1'

    mock_response = util_load_json('test_data/ip_1.1.1.1_response.json')

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


def test_ipinfo_nultiple_ips_command(mocker, requests_mock):
    """
    Given:
        A mock response of a call to https://ipinfo.io/1.1.1.1/json,
        And a json of the expected output objects
    When:
        Calling ip on ip=1.1.1.1
    Then:
        Validate the output compared to the mock output
    """
    from ipinfo_v2 import Client, ipinfo_ip_command

    ip = '1.1.1.1,8.8.8.8'

    mock_response_1 = util_load_json('test_data/ip_1.1.1.1_response.json')
    mock_response_2 = util_load_json('test_data/ip_8.8.8.8_response.json')

    client = Client(api_key='',
                    base_url='https://ipinfo.io',
                    verify_certificate=False,
                    proxy=False,
                    reliability=DBotScoreReliability.C)
    requests_mock.get('https://ipinfo.io/1.1.1.1/json', json=mock_response_1)
    requests_mock.get('https://ipinfo.io/8.8.8.8/json', json=mock_response_2)

    command_results = mocker.patch('ipinfo_v2.CommandResults')
    ipinfo_ip_command(client, ip)

    expected_parsed_context_1111 = util_load_json('test_data/ip_1.1.1.1_command_results.json')
    assert command_results.call_args_list[1][1].get("readable_output") == expected_parsed_context_1111[1].get("HumanReadable")
    assert command_results.call_args_list[1][1].get("outputs").get("Address") == "1.1.1.1"
    assert command_results.call_args_list[1][1].get("outputs").get("Hostname") == "one.one.one.one"

    expected_parsed_context_8888 = util_load_json('test_data/ip_8.8.8.8_command_results.json')
    assert command_results.call_args_list[3][1].get("readable_output") == expected_parsed_context_8888[1].get("HumanReadable")
    assert command_results.call_args_list[3][1].get("outputs").get("Address") == "8.8.8.8"
    assert command_results.call_args_list[3][1].get("outputs").get("Hostname") == "dns.google"


def test_check_columns_exists(mocker):
    """
    Given:
        A mock response of a call to https://ipinfo.io/1.1.1.1/json,
        And a json of the expected output objects
    When:
        Calling ip on ip=1.1.1.1
    Then:
        Validate that the output have the desired columns that were missing from thr readable output.
        related issue: https://github.com/demisto/etc/issues/46061
    """
    from ipinfo_v2 import Client, ipinfo_ip_command

    ip = '1.1.1.1'

    mock_response = util_load_json('test_data/ip_1.1.1.1_response.json')
    client = Client(api_key='',
                    base_url='https://ipinfo.io',
                    verify_certificate=False,
                    proxy=False,
                    reliability=DBotScoreReliability.C)

    mocker.patch.object(client, 'http_request', return_value=mock_response)
    command_results = mocker.patch('ipinfo_v2.CommandResults')
    ipinfo_ip_command(client, ip)

    assert "lat|lng" in command_results.call_args[1].get("readable_output")
