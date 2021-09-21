"""Base Integration for ShiftLeft CORE - Cortex XSOAR Extension
"""

import json
import io


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from BaseIntegration import Client, baseintegration_dummy_command

    client = Client(
        base_url="/orgs/2c089ac1-3378-44d5-94da-9507e84351c3/apps/shiftleft-java-example/findings",
        verify=False,
    )
    args = {"severity": "critical", "type": ["vuln"], "version": None}
    response = baseintegration_dummy_command(client, args)

    mock_response = util_load_json("test_data/baseintegration-dummy.json")

    assert response.outputs
