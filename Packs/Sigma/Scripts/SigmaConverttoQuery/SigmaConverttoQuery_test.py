import json
from typing import Any
from unittest.mock import patch

import pytest
import SigmaConverttoQuery
from SigmaConverttoQuery import get_sigma_dictionary, main

import demistomock as demisto


def load_file(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


@pytest.mark.parametrize("indicator, result, expect_exception", [
    ("DNS Query for Anonfiles.com Domain - Sysmon", load_file("test_data/expected_sigma_dict.json"), False),
    ("No Indicator", "No indicator found with value No Indicator", True)
])
@patch.object(SigmaConverttoQuery, "return_error")
@patch.object(demisto, "executeCommand")
def test_get_sigma_dictionary(mock_executeCommand, mock_return_error, indicator, result, expect_exception):
    mock_executeCommand.side_effect = [load_file("test_data/response.json"), []]

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
    mock_get_sigma_dictionary.return_value = load_file("test_data/expected_sigma_dict.json")
    main()
    args, kwargs = mock_return_results.call_args
    assert args[0].readable_output == 'QueryName="*.anonfiles.com*"'
