"""RubrikPullIRViolationInformation Script for Cortex XSOAR - Unit Tests file."""

from unittest.mock import patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from RubrikPullIRViolationInformation import main, sync_the_violation_information, ERROR_MESSAGES

VIOLATION_ID = "00000000-0000-0000-0000-000000000001"
POLICY_TYPE = "IDENTITY"
DATA_CATEGORIES = [{"dataCategoryName": "PII", "dataCategoryHits": {"totalViolatedHits": 5}}]


@pytest.fixture
def mock_execute_command():
    """Fixture to mock the `executeCommand` function from the `demisto` module."""
    with patch("RubrikPullIRViolationInformation.demisto.executeCommand") as mock:
        yield mock


@pytest.mark.parametrize(
    "args",
    [
        ({"violation_id": VIOLATION_ID, "policy_type": POLICY_TYPE}),
        ({"violation_id": VIOLATION_ID}),
        ({"policy_type": POLICY_TYPE}),
        ({}),
    ],
)
def test_sync_the_violation_information_with_success(mock_execute_command, mocker, args):
    """Tests sync_the_violation_information command function with success.

    Checks the output of the command function with the expected output.
    """
    mock_execute_command.return_value = [
        {
            "Type": 1,
            "Contents": {
                "data": {"policyViolation": {"id": VIOLATION_ID, "status": "POLICY_VIOLATION_STATUS_OPEN"}},
                "principal_summary_data": {"data": {"principalSummary": {"summary": {"dataCategoryResults": DATA_CATEGORIES}}}},
            },
        }
    ]
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"rubrikviolationid": VIOLATION_ID, "rubrikpolicytype": POLICY_TYPE}},
    )
    mocker.patch("CommonServerPython.isError", return_value=False)
    mocker.patch.object(
        demisto, "mapObject", return_value={"Rubrik Violation ID": VIOLATION_ID, "Rubrik IR Violation Status": "OPEN"}
    )

    _, response = sync_the_violation_information(args)

    assert response.readable_output == f"#### Violation {VIOLATION_ID} information has been synchronized successfully."
    mock_execute_command.assert_called_with(
        "setIncident",
        {
            "rubrikviolationid": VIOLATION_ID,
            "rubrikirviolationstatus": "OPEN",
            "rubriktotalriskhits": 0,
            "rubrikhighriskhits": 0,
            "rubrikmediumriskhits": 0,
            "rubriklowriskhits": 0,
            "rubriknoriskhits": 0,
            "rubrikdatacategories": [{"name": "PII", "totalViolatedHits": 5}],
        },
    )


def test_sync_the_violation_information_with_error(mock_execute_command, mocker, capfd):
    """Tests sync_the_violation_information command function with error response."""
    mock_execute_command.return_value = [{"Type": 4, "Contents": {"error": "Internal Error"}}]
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"rubrikviolationid": VIOLATION_ID, "rubrikpolicytype": POLICY_TYPE}},
    )
    mocker.patch("CommonServerPython.isError", return_value=True)

    mock_return_results = mocker.patch("RubrikPullIRViolationInformation.return_results")

    with capfd.disabled(), pytest.raises(ValueError) as err:
        sync_the_violation_information({})

    assert "Failed to sync the violation information" in str(err)
    mock_execute_command.assert_called_once_with(
        "rubrik-identity-resilience-violation-get", {"violation_id": VIOLATION_ID, "policy_type": POLICY_TYPE}
    )
    mock_return_results.assert_not_called()


@pytest.mark.parametrize(
    "args, error_message",
    [({}, ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id"))],
)
def test_sync_the_violation_information_with_invalid_args(args, error_message, capfd):
    """Tests sync_the_violation_information command function with invalid arguments."""
    with capfd.disabled(), pytest.raises(ValueError) as err:
        sync_the_violation_information(args)

    assert error_message in str(err.value)


def test_main_with_exception(mock_execute_command, mocker, capfd):
    """Test case scenario for successful execution of the `main` function when an exception is raised."""
    mock_execute_command.side_effect = Exception("Some error message")

    mock_return_results = mocker.patch("RubrikPullIRViolationInformation.return_results")

    with capfd.disabled(), pytest.raises(SystemExit) as err:
        main()

    assert err.value.code == 0
    mock_return_results.assert_not_called()
