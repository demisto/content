import json
import os
from unittest.mock import patch, MagicMock
from ContrastSecurityDisplayIncidentIssues import (
    handle_error,
    get_issues_grid_data,
    main,
)

with open(os.path.join(os.path.dirname(__file__), "test_data", "display_incident_issues_test_data.json")) as _f:
    _TEST_DATA = json.load(_f)

SINGLE_ISSUE_DATA = _TEST_DATA["SINGLE_ISSUE_DATA"]
PAGE1_RESULT = _TEST_DATA["PAGE1_RESULT"]
PAGE2_RESULT = _TEST_DATA["PAGE2_RESULT"]
SETINCIDENT_RESULT = _TEST_DATA["SETINCIDENT_RESULT"]
SINGLE_PAGE_RESULT = _TEST_DATA["SINGLE_PAGE_RESULT"]
EMPTY_CONTENT_RESULT = _TEST_DATA["EMPTY_CONTENT_RESULT"]
LARGE_PAGINATION_RESULT = _TEST_DATA["LARGE_PAGINATION_RESULT"]
TWO_ISSUES_RESULT = _TEST_DATA["TWO_ISSUES_RESULT"]
FINAL_PAGE_RESULT = _TEST_DATA["FINAL_PAGE_RESULT"]
PAGE1_MULTI = _TEST_DATA["PAGE1_MULTI"]
PAGE2_MULTI = _TEST_DATA["PAGE2_MULTI"]
PAGE3_MULTI = _TEST_DATA["PAGE3_MULTI"]


def test_get_issues_grid_data_single_issue():
    """Test converting a single issue to grid format."""
    result = get_issues_grid_data(SINGLE_ISSUE_DATA)

    assert len(result) == 1
    assert result[0]["cvssScore"] == 9.5
    assert result[0]["title"] == "SQL Injection"
    assert result[0]["issueId"] == "issue-123"
    assert result[0]["status"] == "VERIFIED"
    assert result[0]["observationCount"] == "3"
    assert result[0]["deploymentTier"] == "Production, Staging"


@patch("ContrastSecurityDisplayIncidentIssues.is_error", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_error")
def test_handle_error_with_success_result(mock_return_error, _):
    """Test handle_error when command result is success."""
    command_result = {"Type": "note", "Contents": {"data": "success"}}

    handle_error(command_result)
    mock_return_error.assert_not_called()


@patch("ContrastSecurityDisplayIncidentIssues.is_error", return_value=True)
@patch("ContrastSecurityDisplayIncidentIssues.return_error")
def test_handle_error_missing_contents(mock_return_error, _):
    """Test handle_error when Contents key is missing."""
    command_result = {"Type": "error"}

    handle_error(command_result)
    mock_return_error.assert_called_once_with("Unknown error")


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
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_main_successful_pagination(_json_dumps, _handle_error, _timeout, mock_cmd_results, mock_return_results, mock_demisto):
    """Test main function with successful multi-page pagination."""
    mock_demisto.getArg.return_value = "incident-123"
    mock_cmd_results.return_value = MagicMock()

    mock_demisto.executeCommand.side_effect = [PAGE1_RESULT, PAGE2_RESULT, SETINCIDENT_RESULT]

    main()
    assert mock_demisto.executeCommand.call_count == 3
    mock_return_results.assert_called()
    _, kwargs = mock_cmd_results.call_args
    assert "Successfully retrieved 2 issue(s)" in kwargs.get("readable_output", "")


# Pagination Tests


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_pagination_break_on_last_page(_json_dumps, _cmd_results, _return_results, _timeout, _handle_error, mock_demisto):
    """Test pagination breaks when current_page >= total_pages - 1."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.return_value = SINGLE_PAGE_RESULT
    main()
    assert mock_demisto.executeCommand.call_count == 2


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_pagination_break_on_empty_issues(
    _json_dumps, mock_cmd_results, mock_return_results, _timeout, _handle_error, mock_demisto
):
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
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_pagination_break_on_timeout(_json_dumps, _cmd_results, _return_results, _timeout, _handle_error, mock_demisto):
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
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_pagination_continue_to_next_page(_json_dumps, _handle_error, _timeout, _cmd_results, _return_results, mock_demisto):
    """Test pagination continues when more pages are available."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.side_effect = [PAGE1_MULTI, PAGE2_MULTI, PAGE3_MULTI, SETINCIDENT_RESULT]
    main()
    assert mock_demisto.executeCommand.call_count >= 3


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_break_condition_total_elements_match(_json_dumps, _cmd_results, _return_results, _timeout, _handle_error, mock_demisto):
    """Test break when len(all_issues) == total_elements."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.return_value = TWO_ISSUES_RESULT
    main()
    assert mock_demisto.executeCommand.call_count == 2


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_break_condition_empty_current_page(_json_dumps, _cmd_results, _return_results, _timeout, _handle_error, mock_demisto):
    """Test break when current page returns no issues."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.return_value = EMPTY_CONTENT_RESULT
    main()
    mock_demisto.executeCommand.assert_called()


@patch("ContrastSecurityDisplayIncidentIssues.demisto")
@patch("ContrastSecurityDisplayIncidentIssues.handle_error")
@patch("ContrastSecurityDisplayIncidentIssues.has_passed_time_threshold", return_value=False)
@patch("ContrastSecurityDisplayIncidentIssues.return_results")
@patch("ContrastSecurityDisplayIncidentIssues.CommandResults")
@patch("ContrastSecurityDisplayIncidentIssues.json.dumps")
def test_break_condition_reached_last_page(_json_dumps, _cmd_results, _return_results, _timeout, _handle_error, mock_demisto):
    """Test break when current_page >= totalPages - 1 (on last page)."""
    mock_demisto.getArg.return_value = "incident-123"

    mock_demisto.executeCommand.return_value = FINAL_PAGE_RESULT
    main()
    mock_demisto.executeCommand.assert_called()
