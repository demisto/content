import json
import os
from unittest.mock import patch, MagicMock
import pytest
from ContrastSecurityDisplayIncidentIssues import (
    ISSUE_LIST_PAGE_SIZE,
    handle_error,
    get_issues_grid_data,
    main,
)

with open(os.path.join(os.path.dirname(__file__), "test_data", "display_incident_issues_test_data.json")) as _f:
    _TEST_DATA = json.load(_f)

SINGLE_ISSUE_DATA = _TEST_DATA["SINGLE_ISSUE_DATA"]
SINGLE_ISSUE_GRID_DATA = _TEST_DATA["SINGLE_ISSUE_GRID_DATA"]
PAGE1_RESULT = _TEST_DATA["PAGE1_RESULT"]
PAGE2_RESULT = _TEST_DATA["PAGE2_RESULT"]
SETINCIDENT_RESULT = _TEST_DATA["SETINCIDENT_RESULT"]
SINGLE_PAGE_RESULT = _TEST_DATA["SINGLE_PAGE_RESULT"]
EMPTY_CONTENT_RESULT = _TEST_DATA["EMPTY_CONTENT_RESULT"]
LARGE_PAGINATION_RESULT = _TEST_DATA["LARGE_PAGINATION_RESULT"]
HAS_MORE_EMPTY_CURSOR_RESULT = _TEST_DATA["HAS_MORE_EMPTY_CURSOR_RESULT"]
PAGE1_MULTI = _TEST_DATA["PAGE1_MULTI"]
PAGE2_MULTI = _TEST_DATA["PAGE2_MULTI"]
PAGE3_MULTI = _TEST_DATA["PAGE3_MULTI"]


def test_get_issues_grid_data_single_issue():
    """Test converting issues to grid format, including null values and a string environment."""
    result = get_issues_grid_data(SINGLE_ISSUE_DATA)

    assert result == SINGLE_ISSUE_GRID_DATA


@patch("ContrastSecurityDisplayIncidentIssues.return_error")
def test_handle_error_with_success_result(mock_return_error):
    """Test handle_error when command result is success."""
    command_result = [{"Type": 1, "Contents": {"data": "success"}}]

    handle_error(command_result)
    mock_return_error.assert_not_called()


@patch("ContrastSecurityDisplayIncidentIssues.return_error")
def test_handle_error_with_error_result(mock_return_error):
    """Test handle_error returns the error message from the command result entries."""
    command_result = [{"Type": 4, "Contents": "Error in API call [404] - Not Found"}]

    handle_error(command_result)
    mock_return_error.assert_called_once_with("Error in API call [404] - Not Found")


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
def test_main_no_incident_id(mock_cmd_results, mock_return_results, mock_demisto):
    """Test main function when incident_id is not provided."""
    mock_demisto.getArg.return_value = None
    mock_cmd_results.return_value = MagicMock()

    main()
    mock_return_results.assert_called_once()
    mock_cmd_results.assert_called_once()
    _, kwargs = mock_cmd_results.call_args
    assert "Contrast Security Incident ID not found" in kwargs.get("readable_output", "")


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
def test_main_successful_pagination(_handle_error, _timeout, mock_cmd_results, mock_return_results, mock_demisto):
    """Test main function with successful multi-page pagination."""
    mock_demisto.getArg.return_value = "incident-123"
    mock_cmd_results.return_value = MagicMock()

    mock_demisto.executeCommand.side_effect = [PAGE1_RESULT, PAGE2_RESULT, SETINCIDENT_RESULT]

    main()
    calls = mock_demisto.executeCommand.call_args_list
    assert len(calls) == 3
    assert calls[0].args == ("contrastsecurity-issue-list", {"incident_id": "incident-123", "page_size": ISSUE_LIST_PAGE_SIZE})
    assert calls[1].args == (
        "contrastsecurity-issue-list",
        {"incident_id": "incident-123", "page_size": ISSUE_LIST_PAGE_SIZE, "next_page_cursor": "cursor-2"},
    )
    set_incident_args = calls[2].args
    assert set_incident_args[0] == "setIncident"
    grid = set_incident_args[1]["contrastsecurityincidentrelatedissues"]
    assert [row["issueId"] for row in grid] == ["issue-1", "issue-2"]
    assert grid[0]["severity"] == "Critical"
    mock_return_results.assert_called()
    _, kwargs = mock_cmd_results.call_args
    assert "Successfully retrieved 2 issue(s)" in kwargs.get("readable_output", "")


# Pagination Tests


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@pytest.mark.parametrize(
    "command_result, expected_call_count",
    [
        (SINGLE_PAGE_RESULT, 2),
        (HAS_MORE_EMPTY_CURSOR_RESULT, 2),
        (LARGE_PAGINATION_RESULT, 3),
    ],
)
def test_pagination_break_on_last_page(
    _cmd_results, _return_results, _timeout, _handle_error, mock_demisto, command_result, expected_call_count
):
    """Test pagination breaks on the last page, on hasMore with an empty cursor, and on a repeated cursor."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.return_value = command_result
    main()
    assert mock_demisto.executeCommand.call_count == expected_call_count


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
def test_pagination_break_on_empty_issues(mock_cmd_results, mock_return_results, _timeout, _handle_error, mock_demisto):
    """Test pagination breaks when no issues returned."""
    mock_demisto.getArg.return_value = "incident-123"
    mock_cmd_results.return_value = MagicMock()

    mock_demisto.executeCommand.return_value = EMPTY_CONTENT_RESULT
    main()
    mock_return_results.assert_called()
    _, kwargs = mock_cmd_results.call_args
    assert "No issues found" in kwargs.get("readable_output", "")


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=True)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
def test_pagination_break_on_timeout(_cmd_results, _return_results, _timeout, _handle_error, mock_demisto):
    """Test pagination breaks when timeout is reached."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.return_value = LARGE_PAGINATION_RESULT
    main()
    mock_demisto.debug.assert_called()


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
def test_pagination_continue_to_next_page(_handle_error, _timeout, _cmd_results, _return_results, mock_demisto):
    """Test pagination continues when more pages are available."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.side_effect = [PAGE1_MULTI, PAGE2_MULTI, PAGE3_MULTI, SETINCIDENT_RESULT]
    main()
    assert mock_demisto.executeCommand.call_count >= 3


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_error")
def test_main_exception(mock_return_error, _timeout, mock_demisto):
    """Test main function returns an error when the issue list command raises an exception."""
    mock_demisto.getArg.return_value = "incident-123"
    mock_demisto.executeCommand.side_effect = Exception("API failure")

    main()
    mock_return_error.assert_called_once_with("Failed to execute ContrastSecurityDisplayIncidentIssues. Error: API failure")
