"""RubrikPushIRViolationStatus Script for Cortex XSOAR - Unit Tests file."""

from unittest.mock import patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from RubrikPushIRViolationStatus import main, sync_the_violation_status, ERROR_MESSAGES

VIOLATION_ID = "00000000-0000-0000-0000-000000000001"
VIOLATION_STATUS = "OPEN"


@pytest.fixture
def mock_execute_command():
    """Fixture to mock the `executeCommand` function from the `demisto` module."""
    with patch("RubrikPushIRViolationStatus.demisto.executeCommand") as mock:
        yield mock


@pytest.mark.parametrize("args", [({"violation_id": VIOLATION_ID}), ({}), ({"violation_status": VIOLATION_STATUS})])
def test_sync_the_violation_status_with_success(mock_execute_command, mocker, args):
    """Tests sync_the_violation_status command function with success.

    Checks the output of the command function with the expected output.
    """
    mock_execute_command.return_value = [{"Type": 1, "Contents": {"id": VIOLATION_ID, "status": "POLICY_VIOLATION_STATUS_OPEN"}}]
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"rubrikviolationid": VIOLATION_ID, "rubrikirviolationstatus": VIOLATION_STATUS}},
    )
    mocker.patch("CommonServerPython.isError", return_value=False)

    sync_the_violation_status(args)
    mock_execute_command.assert_called_once_with(
        "rubrik-identity-resilience-violation-status-update", {"violation_id": VIOLATION_ID, "status": VIOLATION_STATUS}
    )


def test_sync_the_violation_status_with_error(mock_execute_command, mocker, capfd):
    """Tests sync_the_violation_status command function with error response."""
    mock_execute_command.return_value = {"Type": 4, "Contents": {"error": "Internal Error"}}
    args = {"violation_id": VIOLATION_ID, "violation_status": VIOLATION_STATUS}
    mocker.patch("CommonServerPython.isError", return_value=True)

    mock_return_results = mocker.patch("RubrikPushIRViolationStatus.return_results")

    with capfd.disabled(), pytest.raises(ValueError) as err:
        sync_the_violation_status(args)

    assert "Failed to update violation status" in str(err)
    mock_execute_command.assert_called_once_with(
        "rubrik-identity-resilience-violation-status-update", {"violation_id": VIOLATION_ID, "status": VIOLATION_STATUS}
    )
    mock_return_results.assert_not_called()


@pytest.mark.parametrize(
    "args, error_message",
    [
        ({}, ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id")),
        ({"violation_id": VIOLATION_ID}, ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_status")),
    ],
)
def test_sync_the_violation_status_with_invalid_args(args, error_message, capfd):
    """Tests sync_the_violation_status command function with invalid arguments."""
    with capfd.disabled(), pytest.raises(ValueError) as err:
        sync_the_violation_status(args)

    assert error_message in str(err.value)


def test_main_with_exception(mock_execute_command, mocker, capfd):
    """Test case scenario for successful execution of the `main` function when an exception is raised."""
    mock_execute_command.side_effect = Exception("Some error message")

    mock_return_results = mocker.patch("RubrikPushIRViolationStatus.return_results")

    with capfd.disabled(), pytest.raises(SystemExit) as err:
        main()

    assert err.value.code == 0
    mock_return_results.assert_not_called()
