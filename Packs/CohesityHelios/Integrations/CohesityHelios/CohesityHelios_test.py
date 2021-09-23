"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: ADD HERE unit tests for every command
def test_cohesity_helios_get_was_alerts():
    """Tests cohesity-helios-get-was-alerts command function.

    Checks the output of the command function with the expected output.

    CohesityTBD: Add code for unit testsing.

    """
    # from BaseIntegration import Client, CohesityHelios_command

    # client = Client(base_url='some_mock_url', verify=False)
    # args = {
    #     'dummy': 'this is a dummy response'
    # }
    # response = baseintegration_dummy_command(client, args)

    # mock_response = util_load_json('test_data/baseintegration-dummy.json')

    # assert response.outputs == mock_response
