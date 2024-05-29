"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
from CSCDomainManager import *
from CSCDomainManager import Client

EXAMPLE_BASE_URL = 'https://test.com/api/v1'
VERIFY = True
ACCEPT_VAL = "example"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


GET_REQUEST_EXAMPLE1 = util_load_json('./test_data/get_domain.json')
GET_REQUEST_QUALIFIED_DOMAIN_NAME = util_load_json('./test_data/get_domain_qualified_domain_name.json')
GET_DOMAIN_AVAILABILITY_CHECK = util_load_json('./test_data/get_domain_availability_check.json')


def create_mock_client():
    return Client(
        base_url=EXAMPLE_BASE_URL,
        verify=VERIFY,
        headers={'test': 'test'}
    )

def test_csc_domains_search(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'csc-panw',
        'registryExpiryDate': '22-Apr-2025 UTC'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_EXAMPLE1)
    result = csc_domains_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 2
    assert result_output[1].get('Qualified Domain Name') == 'csc-panw.com'
    assert result_output[1].get('Registration Date') == '22-Apr-2024 UTC'
    assert result_output[1].get('Whois Contact first Name') == ['Domain', 'Domain', 'DNS']
    

def test_csc_domains_search_with_operator(mocker):
    client = create_mock_client()
    args = {
        'registration_date' : 'ge=22-Apr-2024'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_EXAMPLE1)
    result = csc_domains_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 2
    assert result_output[1].get('Qualified Domain Name') == 'csc-panw.com'
    assert result_output[1].get('Registration Date') == '22-Apr-2024 UTC'
    assert result_output[1].get('Whois Contact first Name') == ['Domain', 'Domain', 'DNS']
    
def test_csc_domains_search_with_qualified_domain_name(mocker):
    client = create_mock_client()
    args = {
        'domain_name' : 'csc-panw.com'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_QUALIFIED_DOMAIN_NAME)
    result = csc_domains_search_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 1
    assert result_output[0].get('Qualified Domain Name') == 'csc-panw.com'
    assert result_output[0].get('Registration Date') == '22-Apr-2024 UTC'
    assert result_output[0].get('Whois Contact first Name') == ['Domain', 'Domain', 'DNS']

def test_csc_domains_availability_check(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'cscpanw.org,csc-panw.info'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_DOMAIN_AVAILABILITY_CHECK)
    result = csc_domains_availability_check_command(client, args)
    result_output = result.to_context().get('Contents')
    assert len(result_output) == 2
    assert result_output[1].get('qualifiedDomainName') == 'csc-panw.info'
    assert result_output[1].get('message') == 'Domain already in portfolio'

def test_csc_domains_configuration_list():
    pass


def test_domain():
    pass
