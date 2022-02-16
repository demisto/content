"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

from VaronisDataSecurityPlatform import Client, varonis_get_alerts_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


''' COMMAND UNIT TESTS '''


def test_varonis_get_alerts_command(mocker):
    """
        When:
            - Get alerts from Varonis api
        Then
            - Assert output prefix data is as expected
            - Assert mapping works as expected
    """
    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    mocker.patch.object(
        client,
        'varonis_search_alerts',
        return_value=util_load_json('test_data/search_alerts_response.json')
    )
    mocker.patch.object(
        client,
        'varonis_get_alerts',
        return_value=util_load_json('test_data/varonis_get_alerts_api_response.json')
    )

    result = varonis_get_alerts_command(client, {})
    expected_outputs = util_load_json('test_data/varonis_get_alerts_command_output.json')

    assert result.outputs_prefix == 'Varonis.Alert'
    assert result.outputs == expected_outputs
