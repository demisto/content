"""RubrikPullDSPMViolationFileInformation Script for Cortex XSOAR - Unit Tests file."""

from unittest.mock import patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from RubrikPullDSPMViolationFileInformation import ERROR_MESSAGES, main, sync_the_violation_file_information

VIOLATION_ID = "00000000-0000-0000-0000-000000000001"
OBJECT_ID = "00000000-0000-0000-0000-000000000002"
SNAPSHOT_ID = "00000000-0000-0000-0000-000000010001"


@pytest.fixture
def mock_execute_command():
    """Fixture to mock the `executeCommand` function from the `demisto` module."""
    with patch("RubrikPullDSPMViolationFileInformation.demisto.executeCommand") as mock:
        yield mock


@pytest.mark.parametrize(
    "args",
    [
        ({"violation_id": VIOLATION_ID, "object_id": OBJECT_ID, "snapshot_id": SNAPSHOT_ID}),
        ({}),
    ],
)
def test_sync_the_violation_file_information_with_success(mocker, args):
    mock_result = [
        {
            "Type": 1,
            "Contents": {
                "data": {"policyObj": {"fileResultConnection": {"edges": [{"node": {"stdPath": "file/path", "size": 100}}]}}}
            },
        }
    ]

    mock_execute_command = mocker.patch.object(
        demisto, "executeCommand", side_effect=[mock_result, [{"Type": 1, "Contents": ""}]]
    )

    mocker.patch.object(
        demisto,
        "incident",
        return_value={
            "CustomFields": {
                "rubrikviolationid": VIOLATION_ID,
                "rubrikpolarisobjectid": OBJECT_ID,
                "rubriksnapshotid": SNAPSHOT_ID,
            }
        },
    )
    mocker.patch("RubrikPullDSPMViolationFileInformation.isError", return_value=False)

    _, response = sync_the_violation_file_information(args)

    assert response.readable_output == (f"#### Violation {VIOLATION_ID} file information has been synchronized successfully.")

    mock_execute_command.assert_called_with(
        "setIncident",
        {
            "rubrikfilesatrisk": [
                {
                    "stdPath": "file/path",
                    "createdBy": "",
                    "lastModifiedTime": "",
                    "size": 100,
                    "totalHits": 0,
                    "highRiskHits": 0,
                    "mediumRiskHits": 0,
                    "lowRiskHits": 0,
                    "noRiskHits": 0,
                    "dataCategories": [],
                }
            ]
        },
    )


def test_sync_the_violation_file_information_with_error(mock_execute_command, mocker, capfd):
    """Tests sync_the_violation_file_information command function with success.

    Checks the output of the command function with the expected output.
    """

    # Mock the demisto.incident() function to return an incident with mocked values.
    mock_execute_command.return_value = [{"Type": 4, "Contents": {"error": "Internal Error"}}]
    mocker.patch.object(
        demisto,
        "incident",
        return_value={
            "CustomFields": {
                "rubrikviolationid": VIOLATION_ID,
                "rubrikpolarisobjectid": OBJECT_ID,
                "rubriksnapshotid": SNAPSHOT_ID,
            }
        },
    )
    mocker.patch("RubrikPullDSPMViolationFileInformation.isError", return_value=True)

    mock_return_results = mocker.patch("RubrikPullDSPMViolationFileInformation.return_results")

    # Act and Assert
    with capfd.disabled(), pytest.raises(SystemExit) as err:
        sync_the_violation_file_information({"limit": "5"})

    assert err.value.code == 0
    mock_execute_command.assert_called_once_with(
        "rubrik-data-security-violation-file-list",
        {"violation_id": VIOLATION_ID, "snapshot_id": SNAPSHOT_ID, "object_id": OBJECT_ID, "limit": 5},
    )
    mock_return_results.assert_not_called()


@pytest.mark.parametrize(
    "args, error_message",
    [
        ({}, ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id")),
        ({"violation_id": VIOLATION_ID}, ERROR_MESSAGES["MISSING_ARGUMENT"].format("object_id")),
        ({"violation_id": VIOLATION_ID, "object_id": OBJECT_ID}, ERROR_MESSAGES["MISSING_ARGUMENT"].format("snapshot_id")),
    ],
)
def test_sync_the_violation_file_information_with_invalid_args(args, error_message, capfd):
    """Tests sync_the_violation_file_information command function with invalid arguments."""

    # Act and Assert
    with capfd.disabled(), pytest.raises(ValueError) as err:
        sync_the_violation_file_information(args)

    assert error_message in str(err.value)


def test_main_with_exception(mock_execute_command, mocker, capfd):
    """Test case scenario for successful execution of the `main` function when an exception is raised."""
    # Test case: When an exception is raised
    # Arrange
    mock_execute_command.side_effect = Exception("Some error message")

    # Mock the return_results() function to capture the output
    mock_return_results = mocker.patch("RubrikPullDSPMViolationFileInformation.return_results")

    # Act and Assert
    with capfd.disabled(), pytest.raises(SystemExit) as err:
        main()

    assert err.value.code == 0
    mock_return_results.assert_not_called()
