"""Base Integration for ShiftLeft CORE - Cortex XSOAR Extension
"""

import json
import io
from shiftleft import list_app_findings_command, ShiftLeftClient


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_list_app_findings_command(requests_mock):
    """Tests list_app_findings_command function.

    Checks the output of the command function with the expected output.
    """
    mock_response = util_load_json("test_data/test_list_findings.json")
    requests_mock.get(
        "https://www.shiftleft.io/orgs/2c089ac1-3378-44d5-94da-9507e84351c3/apps/shiftleft-java-example/findings",
        json=mock_response,
    )

    client = ShiftLeftClient(
        base_url="https://www.shiftleft.io",  # disable-secrets-detection
        verify=False,
    )
    args = {
        "app_name": "shiftleft-java-example",
        "severity": "critical",
        "type": ["vuln"],
        "version": None,
    }
    response = list_app_findings_command(
        client, "2c089ac1-3378-44d5-94da-9507e84351c3", args
    )
    assert response.outputs
