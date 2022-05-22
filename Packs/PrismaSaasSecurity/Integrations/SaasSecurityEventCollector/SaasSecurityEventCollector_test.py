"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import pytest
import json
import io
from SaasSecurityEventCollector import Client


@pytest.fixture
def mock_client():
    return Client(base_url='https://test.com/api', client_id='', client_secret='', verify=False, proxy=False)


class MockedResponse:

    def __init__(self, status_code, text='{}'):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    'mocked_response', [MockedResponse(status_code=200), MockedResponse(status_code=204)]
)
def test_module(mocker, mock_client, mocked_response):
    """
    Given
       - a response which indicates an event was found.
       - a response which indicates that an event is still being searched

    When -
        testing the module

    Then -
        make sure the test module returns the 'ok' response.
    """
    from SaasSecurityEventCollector import test_module
    mocker.patch.object(Client, 'http_request', return_value=mocked_response)
    assert test_module(client=mock_client) == 'ok'
