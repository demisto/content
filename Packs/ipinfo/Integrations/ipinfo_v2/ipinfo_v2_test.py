"""IPinfo Integration for Cortex XSOAR - Unit Tests file"""

import json
import io

from CommonServerPython import DBotScoreReliability
import demistomock as demisto
import pytest

from ipinfo_v2 import BRAND_NAME


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': BRAND_NAME}, 'integration': True})


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_ipinfo_ip_command(requests_mock):
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
    requests_mock.get(f'https://ipinfo.io/{ip}/json', json=mock_response)

    client = Client(api_key='',
                    base_url='https://ipinfo.io',
                    verify_certificate=False,
                    proxy=False,
                    reliability=DBotScoreReliability.C)

    command_results = ipinfo_ip_command(client, ip)
    parsed_context = [command_result.to_context() for command_result in command_results]

    expected_parsed_context = util_load_json('test_data/ip_1.1.1.1_command_results.json')
    assert parsed_context == expected_parsed_context

def test_ip_command(requests_mock):
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
    requests_mock.get(f'https://ipinfo.io/{ip}/json', json=mock_response)

    client = Client(api_key='',
                    base_url='https://ipinfo.io',
                    verify_certificate=False,
                    proxy=False,
                    reliability=DBotScoreReliability.C)

    command_results = ipinfo_ip_command(client, ip)
    parsed_context = [command_result.to_context() for command_result in command_results]

    expected_parsed_context = util_load_json('test_data/ip_1.1.1.1_command_results.json')
    assert "lat|lng" in parsed_context[1].get("HumanReadable")
