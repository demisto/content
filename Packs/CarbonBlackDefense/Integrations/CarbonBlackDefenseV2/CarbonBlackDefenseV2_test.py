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


# def test_get_alert_details(mocker):
#     """
#     Given:
#         - an id of an alert
#
#     When:
#         - searching an alert details
#
#     Then:
#         - return the data of the alert
#
#     """
#
#     client = cbdv2.Client(base_url='example.com',
#                           verify=False,
#                           proxies=1234,
#                           api_secret_key="api_secret_key",
#                           api_key="api_key",
#                           organization_key="organization_key")
#     return_data = GET_ALERT_BY_ID_MOCK_RES
#     mocker.patch.object(client, 'get_alert_by_id', return_value=return_data)
#     command_results = cbdv2.get_alert_details_command(client, args={'alertId': '1234'})
#     output = command_results.to_context().get('EntryContext', {})
#
#     assert output == ALERT_DETAILS_COMMAND_RES
#
#
# def test_check_connect(mocker):
#     """
#     Given:
#         - an empty dict
#
#     When:
#         - check the connection
#
#     Then:
#         - validating the authentication
#
#     """
#     client = cbdv2.Client(base_url='google.com',
#                           verify=False,
#                           proxies=1234,
#                           api_secret_key="api_secret_key",
#                           api_key="api_key",
#                           organization_key="organization_key")
#     return_data = {}
#     mocker.patch.object(client, 'get_alerts', return_value=return_data)
#     command_results = cbdv2.test_module(client)
#     assert command_results == "ok"


@pytest.mark.parametrize('function, command_function, args, mocker_result, expected_result', PROCESS_CASES)
def test_functions(mocker, function, command_function, args, mocker_result, expected_result):
    client = cbdv2.Client(base_url='example.com',
                          verify=False,
                          proxies=1234,
                          api_secret_key="api_secret_key",
                          api_key="api_key",
                          organization_key="organization_key")
    return_data = mocker_result
    mocker.patch.object(client, function, return_value=return_data)
    running_function = getattr(cbdv2, command_function)
    command_results = running_function(client, args)
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result

