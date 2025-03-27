import json
from unittest.mock import patch

import pytest
import SigmaConverttoQuery
from SigmaConverttoQuery import get_sigma_dictionary, main, replace_outer_quotes

import demistomock as demisto


def load_file(path: str) -> str:
    with open(path) as f:
        return f.read()


@pytest.mark.parametrize("indicator, result, expect_exception", [
    ("Okta User Account Locked Out", load_file("test_data/sigma_rule.yml"), False),
    ("No Indicator", "No indicator found with value No Indicator", True)
])
@patch.object(SigmaConverttoQuery, "return_error")
@patch.object(demisto, "executeCommand")
def test_get_sigma_dictionary(mock_executeCommand, mock_return_error, indicator, result, expect_exception):
    mock_executeCommand.side_effect = [json.loads(load_file('test_data/response.json')), []]

    if expect_exception:
        mock_return_error.side_effect = Exception(result)
        with pytest.raises(Exception, match=result):
            main()

    else:
        sigma_dict = get_sigma_dictionary(indicator)
        assert sigma_dict == result


@patch.object(demisto, "args")
@patch.object(SigmaConverttoQuery, "return_results")
@patch.object(SigmaConverttoQuery, "get_sigma_dictionary")
def test_main(mock_get_sigma_dictionary, mock_return_results, mock_args):
    mock_args.return_value = {'SIEM': "Splunk", "indicator": "Test"}
    mock_get_sigma_dictionary.return_value = load_file("test_data/sigma_rule.yml")
    main()
    args, kwargs = mock_return_results.call_args
    assert args[0].readable_output == 'displaymessage="Max sign in attempts exceeded"'


def test_replace_outer_quotes():
    """
    Given
    - Query with outer double quotes

    When
    - Running the function replace_outer_quotes()

    Then
    - validate that only the outer double quotes are being tripled
    """
    query = 'dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_WINDOWS and ((action_process_image_path in ("*\\powershell.exe", "*\\pwsh.exe")) and (action_process_image_command_line in ("*-f C:\\Users\\Public*", "*-f \"C:\\Users\\Public*", "*-f %Public%*", "*-fi C:\\Users\\Public*", "*-fi \"C:\\Users\\Public*", "*-fi %Public%*", "*-fil C:\\Users\\Public*", "*-fil \"C:\\Users\\Public*", "*-fil %Public%*", "*-file C:\\Users\\Public*", "*-file \"C:\\Users\\Public*", "*-file %Public%*"))))'  # noqa: E501
    result = replace_outer_quotes(query)
    assert result == 'dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_WINDOWS and ((action_process_image_path in ("""*\\powershell.exe""", """*\\pwsh.exe""")) and (action_process_image_command_line in ("""*-f C:\\Users\\Public*""", """*-f \"C:\\Users\\Public*""", """*-f %Public%*""", """*-fi C:\\Users\\Public*""", """*-fi \"C:\\Users\\Public*""", """*-fi %Public%*""", """*- fil C:\\Users\\Public*""", """*-fil \"C:\\Users\\Public*""", """*-fil %Public%*""", """*-file C:\\Users\\Public*""", """*-file \"C:\\Users\\Public*""", """*-file %Public%*"""))))'  # noqa: E501
