"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

from VaronisDataSecurityPlatform import Client, varonis_get_alerts_command, varonis_update_alert_status_command


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

    result = varonis_get_alerts_command(client, util_load_json("test_data/demisto_args.json"))
    expected_outputs = util_load_json('test_data/varonis_get_alerts_command_output.json')

    assert result.outputs_prefix == 'Varonis.Alert'
    assert result.outputs == expected_outputs


def test_varonis_update_alert_status_command(requests_mock):
    requests_mock.post('https://test.com/api/alert/alert/SetStatusToAlerts', json="True")

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    args = {
        'Status': 'Under Investigation',
        'Alert_id': "C8CF4194-133F-4F5A-ACB1-FFFB00573468, F8F608A7-0256-42E0-A527-FFF4749C1A8B"
    }

    resp = varonis_update_alert_status_command(client, args)

    assert resp == "True"
