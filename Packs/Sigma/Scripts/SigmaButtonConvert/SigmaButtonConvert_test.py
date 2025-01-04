import json
from typing import Any
from unittest.mock import patch

import pytest
import SigmaButtonConvert
from SigmaButtonConvert import main

import demistomock as demisto


def load_file(path: str, json_file: bool) -> dict[str, Any] | str:
    with open(path) as f:
        if json_file:
            return json.load(f)
        else:
            return f.read()


rule_example = json.dumps(load_file("test_data/sigma_rule.json", json_file=True))

xql_query = load_file("test_data/xql_query.txt", json_file=False)

splunk_query = load_file("test_data/splunk_query.txt", json_file=False)


@pytest.mark.parametrize("siem_name, result, expect_exception", [
    ("xql", xql_query, False),
    ("splunk", splunk_query, False),
    ("bad_siem", "Unknown SIEM - bad_siem", True)
])
@patch.object(SigmaButtonConvert, 'return_error')
@patch.object(demisto, 'executeCommand')
def test_main(mock_executeCommand, mock_return_error, mocker, siem_name, result, expect_exception):
    mock_callingContext = {'args': {'indicator': {"value": "sigma",
                                                  "CustomFields": {"sigmaruleraw": rule_example}},
                                    'SIEM': siem_name}}

    mocker.patch.dict(demisto.callingContext, mock_callingContext)

    if expect_exception:
        mock_return_error.side_effect = Exception(result)
        with pytest.raises(Exception, match=result):
            main()

    else:
        main()
        assert mock_executeCommand.call_args.args[1]["sigmaconvertedquery"] == result


def test_main_transform_error(mocker):
    mock_callingContext = {'args': {'indicator': {"value": "sigma",
                                                  "CustomFields": {"sigmaruleraw": load_file("test_data/bad_xql_sigma_rule.yml",
                                                                                             json_file=False)}},
                                    'SIEM': 'xql'}}

    mocker.patch.dict(demisto.callingContext, mock_callingContext)

    mock_return_error = mocker.patch.object(SigmaButtonConvert, 'return_error')

    main()

    assert mock_return_error.called

    error_message = mock_return_error.call_args[0][0]
    assert "Failed to parse Sigma rule to xql language" in error_message
