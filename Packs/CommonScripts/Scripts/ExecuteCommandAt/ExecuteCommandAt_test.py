import demistomock as demisto
import pytest
from CommonServerPython import *
from pytest_mock import MockerFixture
from ExecuteCommandAt import main


@pytest.mark.parametrize(
    "command_name, incident_ids, arguments, expected",
    [
        pytest.param("Print", 54321, '{"Value": "Hello World"}', {'command': 'Print',
                     'incidents': '54321', 'arguments': {'Value': 'Hello World'}}, id="single int incident_ids"),
        pytest.param("Print", "54321", '{"Value": "Hello World"}', {'command': 'Print', 'incidents': '54321', 'arguments': {
                     'Value': 'Hello World'}}, id="single string incident_ids"),
        pytest.param("Print", "12345,54321", '{"Value": "Hello World"}', {'command': 'Print', 'incidents': '12345,54321', 'arguments': {
                     'Value': 'Hello World'}}, id="string incident_ids and arguments"),
        pytest.param("Print", [12345, 54321], {"Value": "Hello World"}, {'command': 'Print', 'incidents': '12345,54321', 'arguments': {
                     'Value': 'Hello World'}}, id="list of incidents and dict of arguments")
    ]
)
def test_main(mocker: MockerFixture, command_name, incident_ids, arguments, expected) -> None:
    execute_mock = mocker.patch("ExecuteCommandAt.execute_command", return_value="")

    # setup demisto.args()
    mocker.patch.object(demisto, "args", return_value={
                        'incident_ids': incident_ids, 'command': command_name, 'arguments': arguments})
    main()

    execute_mock.assert_called_once_with("executeCommandAt", expected)


@pytest.mark.parametrize(
    "command_name, incident_ids, arguments, expected_error",
    [
        pytest.param("Print", "12345,54321", '["value", "Hello World"]',
                     "Failed to execute ExecuteCommandAt. Error: Failed to execute ExecuteCommandAt. Argument 'arguments' must be in a dict format", id="string array for arguments"),
        pytest.param("Print", "12345,54321", [
                     "value", "Hello World"], "Failed to execute ExecuteCommandAt. Error: Failed to execute ExecuteCommandAt. Argument 'arguments' must be in a dict format", id="python array for arguments"),
        pytest.param("Print", "12345,54321", "plain string",
                     "Failed to execute ExecuteCommandAt. Error: Failed to parse Argument 'arguments' Expecting value: line 1 column 1 (char 0)", id="plain string for arguments")
    ]
)
def test_main_exception(mocker: MockerFixture, command_name, incident_ids, arguments, expected_error) -> None:

    # setup demisto.args()
    mocker.patch.object(demisto, "args", return_value={
                        'incident_ids': incident_ids, 'command': command_name, 'arguments': arguments})
    return_error_mocker = mocker.patch("ExecuteCommandAt.return_error")
    main()

    return_error_mocker.assert_called_once_with(expected_error)
