import json
from pathlib import Path
from typing import Any

import demistomock as demisto
import pytest
import SigmaButtonConvert
from SigmaButtonConvert import main
from pytest_mock import MockerFixture


def load_file(path: str, json_file: bool) -> dict[str, Any] | str:
    file_path = Path(path)
    if json_file:
        return json.loads(file_path.read_text())
    else:
        return file_path.read_text()


RULE_EXAMPLE = json.dumps(load_file("test_data/sigma_rule.json", json_file=True))
XQL_QUERY = load_file("test_data/xql_query.txt", json_file=False)
SPLUNK_QUERY = load_file("test_data/splunk_query.txt", json_file=False)


@pytest.mark.parametrize(
    "siem_name, expected_query",
    [
        pytest.param("xql", XQL_QUERY, id="xql"),
        pytest.param("splunk", SPLUNK_QUERY, id="splunk"),
    ],
)
def test_main_successful_conversion(mocker: MockerFixture, siem_name: str, expected_query: str):
    """
    Test successful Sigma rule conversion to different SIEM queries.

    Given: A valid Sigma rule and a supported SIEM type
    When: The main function is called with the SIEM parameter
    Then: The Sigma rule should be successfully converted to the expected query format
    """
    # Mock the required objects using mocker
    mock_executeCommand = mocker.patch.object(demisto, "executeCommand")

    mock_callingContext = {
        "args": {"indicator": {"value": "sigma", "CustomFields": {"sigmaruleraw": RULE_EXAMPLE}}, "SIEM": siem_name}
    }

    mocker.patch.dict(demisto.callingContext, mock_callingContext)

    main()

    assert mock_executeCommand.call_args.args[1]["sigmaconvertedquery"] == expected_query


def test_main_unsupported_siem(mocker: MockerFixture):
    """
    Test error handling for unsupported SIEM types.

    Given: A valid Sigma rule and an unsupported SIEM type
    When: The main function is called with the unsupported SIEM parameter
    Then: An exception should be raised with an appropriate error message
    """
    # Mock the required objects using mocker
    mock_return_error = mocker.patch.object(SigmaButtonConvert, "return_error")

    mock_callingContext = {
        "args": {"indicator": {"value": "sigma", "CustomFields": {"sigmaruleraw": RULE_EXAMPLE}}, "SIEM": "bad_siem"}
    }

    mocker.patch.dict(demisto.callingContext, mock_callingContext)

    mock_return_error.side_effect = Exception("Unknown SIEM - bad_siem")

    with pytest.raises(Exception, match="Unknown SIEM - bad_siem"):
        main()


def test_main_transform_error(mocker: MockerFixture):
    """
    Test error handling when Sigma rule transformation fails.

    Given: An invalid Sigma rule that cannot be parsed and a valid SIEM type
    When: The main function is called to convert the malformed rule
    Then: An error should be returned indicating the parsing failure
    """
    mock_callingContext = {
        "args": {
            "indicator": {
                "value": "sigma",
                "CustomFields": {"sigmaruleraw": load_file("test_data/bad_xql_sigma_rule.yml", json_file=False)},
            },
            "SIEM": "xql",
        }
    }

    mocker.patch.dict(demisto.callingContext, mock_callingContext)

    mock_return_error = mocker.patch.object(SigmaButtonConvert, "return_error")

    main()

    assert mock_return_error.called

    error_message = mock_return_error.call_args[0][0]
    assert "Failed to parse Sigma rule to xql language" in error_message
