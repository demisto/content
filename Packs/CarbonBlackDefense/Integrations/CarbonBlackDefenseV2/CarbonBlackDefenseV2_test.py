"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import pytest
import CarbonBlackDefenseV2 as cbdv2
from test_data.test_constants import *


@pytest.mark.parametrize('function, command_function, args, mocker_result, expected_result', PROCESS_CASES)
def test_functions(mocker, function, command_function, args, mocker_result, expected_result):
    client = cbdv2.Client(base_url='example.com',
                          verify=False,
                          proxies=1234,
                          api_secret_key="api_secret_key",
                          api_key="api_key",
                          organization_key="organization_key")
    mocker.patch.object(client, function, return_value=mocker_result)
    running_function = getattr(cbdv2, command_function)
    command_results = running_function(client, args)
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result

