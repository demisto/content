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
                          policy_api_key="policy_api_key",
                          policy_api_secret_key="policy_api_secret_key",
                          organization_key="organization_key")
    mocker.patch.object(client, function, return_value=mocker_result)
    running_function = getattr(cbdv2, command_function)
    command_results = running_function(client, args)
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result
