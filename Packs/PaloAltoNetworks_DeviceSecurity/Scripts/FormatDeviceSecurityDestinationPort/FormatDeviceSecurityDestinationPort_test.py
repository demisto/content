import json
from typing import Any

import pytest
from pytest_mock import MockerFixture

import FormatDeviceSecurityDestinationPort as destination_port


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"port": 443, "ipProto": "TCP"}, "443 (tcp)"),
        ({"port": "53", "ipProto": "UDP"}, "53 (udp)"),
        ({"port": 80}, "80"),
        ({"port": 0, "ipProto": "TCP"}, "0 (tcp)"),
        ({"port": 443, "ipProto": ""}, "443"),
        ({"port": None}, ""),
        (None, ""),
        ("invalid JSON", ""),
        ([None, 3, "invalid JSON"], ""),
        ({"connections": [{"port": 443, "ipProto": "TCP"}, {"port": 53, "ipProto": "UDP"}]}, "443 (tcp), 53 (udp)"),
        ([{"port": 443, "ipProto": "TCP"}, {"port": "443", "ipProto": "tcp"}], "443 (tcp)"),
        ([{"port": 443, "ipProto": "TCP"}, {"port": 443, "ipProto": "UDP"}], "443 (tcp), 443 (udp)"),
    ],
)
def test_format_destination_ports(value: Any, expected: str) -> None:
    assert destination_port.format_destination_ports(value) == expected


@pytest.mark.parametrize("encoding_count", [1, 2])
def test_formats_json_encoded_connections(encoding_count: int) -> None:
    value: Any = {"connections": [{"port": 443, "ipProto": "TCP"}]}
    for _ in range(encoding_count):
        value = json.dumps(value)
    assert destination_port.format_destination_ports(value) == "443 (tcp)"


def test_formats_individually_encoded_nested_connections() -> None:
    value = {"connections": [json.dumps({"port": 443, "ipProto": "TCP"}), {"nested": {"port": 53, "ipProto": "UDP"}}]}
    assert destination_port.format_destination_ports(value) == "443 (tcp), 53 (udp)"


def test_main_returns_formatted_ports(mocker: MockerFixture) -> None:
    mocker.patch.object(destination_port.demisto, "args", return_value={"value": {"port": 443, "ipProto": "TCP"}})
    results = mocker.patch.object(destination_port, "return_results")
    destination_port.main()
    results.assert_called_once_with("443 (tcp)")


@pytest.mark.parametrize("failure_source", ["args", "format_destination_ports", "return_results"])
def test_main_handles_unexpected_errors(mocker: MockerFixture, failure_source: str) -> None:
    args = mocker.patch.object(destination_port.demisto, "args", return_value={"value": {"port": 443}})
    formatter = mocker.patch.object(destination_port, "format_destination_ports", return_value="443")
    results = mocker.patch.object(destination_port, "return_results")
    error = mocker.patch.object(destination_port, "return_error")
    failing_call = {"args": args, "format_destination_ports": formatter, "return_results": results}[failure_source]
    failing_call.side_effect = RuntimeError("Unexpected failure")

    destination_port.main()

    error.assert_called_once_with("Failed to execute FormatDeviceSecurityDestinationPort. Error: Unexpected failure")
    if failure_source != "return_results":
        results.assert_not_called()
