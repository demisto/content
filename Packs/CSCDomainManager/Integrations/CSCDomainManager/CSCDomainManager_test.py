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


GET_REQUEST_EXAMPLE1 = util_load_json('./test_data/get_request_example1.json')


def create_mock_client():
    return Client(
        base_url=EXAMPLE_BASE_URL,
        verify=VERIFY,
        headers={'test': 'test'}
    )


def test_csc_domains_search(mocker):
    client = create_mock_client()
    args = {
        'domain_name': 'csc-panw'
    }
    mocker.patch.object(client, 'send_get_request', return_value=GET_REQUEST_EXAMPLE1)
    result = csc_domains_search_command(client, args)
    result.to_context().get('Contents')
    # print(result_output)


def test_csc_domains_availability_check():
    pass


def test_csc_domains_configuration_list():
    pass


def test_domain():
    pass
