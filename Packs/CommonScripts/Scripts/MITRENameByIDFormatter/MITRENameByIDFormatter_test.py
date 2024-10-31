from unittest.mock import patch

import pytest
import MITRENameByIDFormatter
from MITRENameByIDFormatter import main

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


@pytest.mark.parametrize('input, expected_response', [
    pytest.param('T1078',
                 (True, ['{"value": "Valid Accounts", "mitreid": "T1078"}']),
                 id="Valid MITRE technique ID"),
    pytest.param('T1078.001',
                 (True, ['{"value": "Valid Accounts: Default Accounts", "mitreid": "T1078.001"}']),
                 id="Valid MITRE technique ID with sub-technique")
])
@patch.object(demisto, "args")
@patch.object(MITRENameByIDFormatter, "return_results")
@patch.object(MITRENameByIDFormatter, "execute_command")
def test_mitre_name_by_id_formatter(mock_execute_command, mock_return_results, mock_args, input, expected_response):
    mock_args.return_value = {'input': input}
    mock_execute_command.return_value = expected_response
    main()
    mock_return_results.assert_called_once()
    args, kwargs = mock_return_results.call_args
    assert args[0][0] == json.loads(expected_response[1][0])["value"] or ""


@patch.object(demisto, "args")
@patch.object(MITRENameByIDFormatter, "return_results")
@patch.object(MITRENameByIDFormatter, "execute_command")
def test_invalid_mitre_id(mock_execute_command, mock_return_results, mock_args):
    input = 'T9999'
    expected_response = (True, [''])

    mock_args.return_value = {'input': input}
    mock_execute_command.return_value = expected_response
    main()
    mock_return_results.assert_called_once()
    args, kwargs = mock_return_results.call_args
    assert args[0][0] == ""
