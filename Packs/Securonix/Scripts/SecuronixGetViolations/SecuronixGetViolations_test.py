"""Unit test cases for SecuronixGetViolations script."""
import json
from unittest.mock import patch

from SecuronixGetViolations import main


@patch('SecuronixGetViolations.return_results')
def test_get_violations_command_when_no_violations(mock_return):
    """Test case for successful execution of script when no violations found."""
    main()

    assert mock_return.call_args.args[0].readable_output == "\n#### No violations information available for threat."


@patch('SecuronixGetViolations.demisto.context')
@patch('SecuronixGetViolations.return_results')
def test_get_violations_command_when_violations_found(mock_return, mock_context):
    """Test case for successful execution of script when violations found."""
    with open('test_data/get_violations_response.json', 'r') as f:
        mock_response = json.load(f)
    with open('test_data/get_violations_response_hr.md', 'r') as f:
        expected_table = f.read()
    mock_context.return_value = mock_response

    main()

    assert mock_return.call_args.args[0].readable_output == expected_table


@patch('SecuronixGetViolations.demisto.context')
@patch('SecuronixGetViolations.return_results')
def test_get_violations_command_for_different_violations_count(mock_return, mock_context):
    """Test case for successful execution of script when violations found."""
    with open('test_data/get_violations_response.json', 'r') as f:
        mock_response = json.load(f).get('Securonix', {}).get('ViolationData', [])

    # Test scenario for 1 violation.
    mock_context.return_value = {"Securonix": {"ViolationData": mock_response[0]}}
    main()
    assert "Latest 1 Violation Events:" in mock_return.call_args.args[0].readable_output

    # Test scenario for 10 violation.
    mock_context.return_value = {"Securonix": {"ViolationData": [mock_response[0]] * 10}}
    main()
    assert "Latest 10 Violation Events:" in mock_return.call_args.args[0].readable_output

    # Test scenario for 250 violation.
    mock_context.return_value = {"Securonix": {"ViolationData": [mock_response[0]] * 250}}
    main()
    assert "Latest 200 Violation Events:" in mock_return.call_args.args[0].readable_output
