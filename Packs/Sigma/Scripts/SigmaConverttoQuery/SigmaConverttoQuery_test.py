import pytest
import json
import demistomock as demisto
from unittest.mock import patch
from typing import Any

import SigmaConverttoQuery
from SigmaConverttoQuery import main, get_sigma_dictionary

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
    
    