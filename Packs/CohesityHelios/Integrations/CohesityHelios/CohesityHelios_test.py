"""Cohesity Helios Cortex XSOAR - Unit Tests file
"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests test-module command function.

    Checks the output of the command function with the expected output.
    """
    from CohesityHelios import Client, test_module

    client = Client(
        base_url='https://helios.cohesity.com',
        verify=False)

    # set up mock response.
    mock_response = {}
    requests_mock.get('https://helios.cohesity.com/mcm/alerts', json=mock_response)

    response = test_module(client)

    assert response == "ok"
