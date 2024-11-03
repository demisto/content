"""
    Cortex XSOAR CrowdSec Integration Unit Tests
"""

import json
import pytest
from unittest.mock import MagicMock

from CrowdSec import Client

client = Client(
    base_url="dummy_url",
    verify=False,
    headers={},
    proxy=False,
)
RELIABILITY = "B - Usually reliable"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_ip_command(mocker):
    from CrowdSec import ip_command

    test_data = util_load_json("test_data/test_ip_command.json")
    args = test_data.get("args")
    mocker.patch(
        "CrowdSec.Client.get_ip_information",
        return_value=test_data.get("crowdsec_result"),
    )

    response = ip_command(client, RELIABILITY, args)
    mock_response = test_data.get("mock_response")

    mock_outputs = mock_response.get("outputs")
    mock_readable_output = mock_response.get("readable_output")
    mock_outputs_prefix = mock_response.get("outputs_prefix")
    mock_outputs_key_field = mock_response.get("outputs_key_field")

    assert mock_outputs == response[0].outputs
    assert mock_readable_output == response[0].readable_output
    assert mock_outputs_prefix == response[0].outputs_prefix
    assert mock_outputs_key_field == response[0].outputs_key_field


def test_unknown_ip_command(mocker):
    from CrowdSec import ip_command

    test_data = util_load_json("test_data/test_unknown_ip_command.json")

    args = test_data.get("args")

    mocker.patch(
        "CrowdSec.Client.get_ip_information",
        return_value=test_data.get("crowdsec_result"),
    )

    response = ip_command(client, RELIABILITY, args)
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
    from CrowdSec import ip_command

    expected_error = "'ip' argument not specified"
    with pytest.raises(ValueError, match=expected_error):
        ip_command(client, RELIABILITY, {})


def test_ip_command_invalid_ip(mocker):
    from CrowdSec import ip_command

    args = {"ip": "1.1.1"}
    expected_error = "Invalid IP '1.1.1'"
    with pytest.raises(ValueError, match=expected_error):
        ip_command(client, RELIABILITY, args)


def test_rate_limit(mocker):
    from CrowdSec import ip_command

    args = {"ip": "1.2.3.4"}
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_response.json.return_value = {
        "message": "Rate limited",
    }
    mocker.patch("CrowdSec.Client._http_request", return_value=mock_response)

    expected_error = (
        "You have been rate limited by CrowdSec CTI API. Please upgrade to Pro or wait."
    )
    with pytest.raises(Exception, match=expected_error):
        ip_command(client, RELIABILITY, args)


def test_test_module(mocker):
    from CrowdSec import test_module

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ip": "1.1.1.1", "ip_range": "1.1.1.0/24"}
    mocker.patch("CrowdSec.Client.test_module", return_value=mock_response)

    resp = test_module(client)

    assert resp == "ok"


def test_test_module_bad_apikey(mocker):
    from CrowdSec import test_module

    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"message": "Forbidden"}
    mocker.patch("CrowdSec.Client.test_module", return_value=mock_response)

    resp = test_module(client)

    assert resp == "Authorization Error: make sure API Key is correctly set"


def test_test_module_no_connection(mocker):
    from CrowdSec import test_module

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"message": "Something went wrong"}
    mocker.patch("CrowdSec.Client.test_module", return_value=mock_response)

    resp = test_module(client)

    assert resp == "Something went wrong"
