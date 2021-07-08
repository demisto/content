"""Base Integration for Cortex XSOAR - Unit Tests file"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_domain(requests_mock):
    """Tests the domain reputation command function.

    Configures requests_mock instance to generate the appropriate
    domain reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HostIo import Client, domain_command
    from CommonServerPython import Common

    domain_to_check = 'google.com'
    mock_response = util_load_json('test_data/domain.json')
    requests_mock.get(f'https://test.com/api/full/{domain_to_check}',
                      json=mock_response)

    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        }
    )

    args = {
        'domain': domain_to_check
    }
    response = domain_command(client, args)

    mock_response['updated_date'] = '2021-01-26T01:33:56Z'

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == 'HostIo.Domain'
    assert response[0].outputs_key_field == 'domain'
    assert response[0].indicator.domain == domain_to_check

    assert isinstance(response[0].indicator, Common.Domain)


def test_search(requests_mock):
    """Tests the domain_search command function.

    Configures requests_mock instance to generate the appropriate
    domain search API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """

    from HostIo import Client, search_command

    field_to_check = 'googleanalytics'
    value_to_check = 'UA-61330992'
    mock_response = util_load_json('test_data/search.json')

    requests_mock.get(f'https://test.com/api/domains/{field_to_check}/{value_to_check}',
                      json=mock_response)

    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        }
    )

    args = {
        'field': field_to_check,
        'value': value_to_check,
        'limit': 25
    }
    response = search_command(client, args)

    context = {
        'Field': field_to_check,
        'Value': value_to_check,
        'Domains': mock_response.get('domains', []),
        'Total': mock_response.get('total')
    }

    assert response.outputs == context
    assert response.raw_response == mock_response
    assert response.outputs_prefix == 'HostIo.Search'
    assert response.outputs_key_field == ['Field', 'Value']
    assert response.raw_response == mock_response
