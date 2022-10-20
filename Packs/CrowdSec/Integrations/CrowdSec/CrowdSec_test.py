"""
    Cortex XSOAR CrowdSec Integration Unit Tests
"""

import json
import io
from unittest.mock import MagicMock


client = MagicMock()


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_ip_command(mocker):
    from CrowdSec import get_ip_command

    client = MagicMock()
    args = {"ip": "1.2.3.4"}
    test_data = util_load_json("test_data/test_ip_command.json")

    mocker.patch.object(
        Client, "get_ip_information", return_value=test_data.get("crowdsec_result")
    )
    response = ip_command(client, args)

    mock_response = test_data.get("mock_response")

    mock_outputs = mock_response.get("outputs")
    mock_readable_output = mock_response.get("readable_output")
    mock_outputs_prefix = mock_response.get("outputs_prefix")
    mock_outputs_key_field = mock_response.get("outputs_key_field")

    assert mock_outputs == response[0].outputs
    assert mock_readable_output == response[0].readable_output
    assert mock_outputs_prefix == response[0].outputs_prefix
    assert mock_outputs_key_field == response[0].outputs_key_field


def test_ip_command_no_ip(mocker):
    from CrowdSec import get_ip_command

    client = MagicMock()
    args = {}
    expected_error = "'ip' argument not specified"
    with pytest.raises(ValueError, match=expected_error):
        ip_command(client, args)


def test_ip_command_invalid_ip(mocker):
    from CrowdSec import get_ip_command

    client = MagicMock()
    args = {"ip": "1.1.1"}
    expected_error = "Invalid IP '1.1.1'"
    with pytest.raises(ValueError, match=expected_error):
        ip_command(client, args)
