import pytest
from unittest.mock import patch

import demistomock as demisto
import CommonServerPython  # noqa: F401
import CortexListAppSecAssetCoverage as cc


@pytest.fixture
def mock_execute_command_success():
    """Mock demisto.executeCommand to return a normal successful response."""
    return [
        {
            "Type": 1,
            "Contents": {"reply": {}},
        }
    ]


@pytest.fixture
def mock_asset_coverage_data():
    """Sample get assets coverage data"""
    return {
        "DATA": [
            {
                "asset_id": "xxx",
                "asset_type": "CONTAINER IMAGE REPOSITORY",
                "asset_name": "xxx",
                "unified_provider": "AWS",
                "business_application_names": [],
                "is_scanned_by_vulnerabilities": "ENABLED",
                "is_scanned_by_code_weakness": "IRRELEVANT",
                "is_scanned_by_secrets": "ENABLED",
                "is_scanned_by_iac": "IRRELEVANT",
                "is_scanned_by_malware": "ENABLED",
                "is_scanned_by_cicd": "IRRELEVANT",
                "scanners_data": [],
                "last_scan_status": "COMPLETED",
                "status_coverage": "FULLY SCANNED",
                "asset_provider": "AWS",
            },
        ]
        * 6,
        "TOTAL_COUNT": 6,
        "FILTER_COUNT": 6,
    }


@pytest.fixture
def mock_histogram_data():
    """Sample histogram data for scanner and status coverage."""
    return {
        "is_scanned_by_vulnerabilities": [{"value": "ENABLED", "count": 6}],
        "is_scanned_by_code_weakness": [{"value": "IRRELEVANT", "count": 6}],
        "is_scanned_by_secrets": [{"value": "ENABLED", "count": 6}],
        "is_scanned_by_iac": [{"value": "IRRELEVANT", "count": 6}],
        "is_scanned_by_malware": [{"value": "ENABLED", "count": 6}],
        "status_coverage": [
            {"value": "PARTIALLY SCANNED", "count": 2, "percentage": 40.0},
            {"value": "FULLY SCANNED", "count": 3, "percentage": 60.0},
        ],
    }


# ----------------------------------------------------------------------
# Tests for get_command_results
# ----------------------------------------------------------------------


def test_get_command_results_success(mock_execute_command_success, monkeypatch):
    """
    GIVEN a successful demisto.executeCommand mock returning a valid list response
    WHEN get_command_results is called
    THEN it should return the parsed reply content as a dictionary
    """
    monkeypatch.setattr(demisto, "executeCommand", lambda c, a: mock_execute_command_success)

    res = cc.get_command_results("core-get-asset-coverage", {"some": "arg"})
    assert isinstance(res, dict)
    assert res == {}  # Reply was empty


def test_get_command_results_invalid_type(monkeypatch):
    """
    GIVEN an invalid demisto.executeCommand response (None or wrong type)
    WHEN get_command_results is executed
    THEN it should safely return an empty dictionary
    """
    monkeypatch.setattr(demisto, "executeCommand", lambda c, a: None)
    assert cc.get_command_results("cmd", {}) == {}

    monkeypatch.setattr(demisto, "executeCommand", lambda c, a: ["not a dict"])
    assert cc.get_command_results("cmd", {}) == {}


def test_get_command_results_error_entry(monkeypatch):
    """
    GIVEN a demisto.executeCommand response with Type=EntryType.ERROR
    WHEN get_command_results is called
    THEN it should raise an Exception with the error message
    """
    error_result = [{"Type": cc.EntryType.ERROR, "Contents": "Error message"}]
    monkeypatch.setattr(demisto, "executeCommand", lambda c, a: error_result)
    monkeypatch.setattr(demisto, "error", lambda c: error_result)

    with pytest.raises(Exception, match="Error message"):
        cc.get_command_results("cmd", {})


# ----------------------------------------------------------------------
# Tests for transform_scanner_histograms_outputs
# ----------------------------------------------------------------------


def test_transform_scanner_histograms_outputs(mock_histogram_data):
    """
    GIVEN valid histogram data where all scanners are ENABLED
    WHEN transform_scanner_histograms_outputs is called
    THEN it should compute 100% coverage for all scanners
    """
    output, coverage = cc.transform_scanner_histograms_outputs(mock_histogram_data)

    enabled_scanners = ["is_scanned_by_malware", "is_scanned_by_secrets", "is_scanned_by_vulnerabilities"]
    assert all(k in output for k in cc.SCANNER_COLUMNS)
    for k, v in output.items():
        if k in enabled_scanners:
            assert v["enabled"] == 6
            assert v["coverage_percentage"] == 1.0

        else:
            assert v["enabled"] == 0
            assert v["coverage_percentage"] == 0.0

        assert v["disabled"] == 0
    assert coverage == 1.0


def test_transform_scanner_histograms_outputs_partial():
    """
    GIVEN a mix of ENABLED and DISABLED scanner histogram entries
    WHEN transform_scanner_histograms_outputs runs
    THEN it should calculate correct partial coverage percentages
    """
    data = {
        "is_scanned_by_vulnerabilities": [
            {"value": "ENABLED", "count": 2},
            {"value": "DISABLED", "count": 2},
        ]
    }
    output, coverage = cc.transform_scanner_histograms_outputs(data)

    col = output["is_scanned_by_vulnerabilities"]
    assert col["enabled"] == 2
    assert col["disabled"] == 2
    assert col["coverage_percentage"] == 0.5
    assert 0 < coverage <= 1


# ----------------------------------------------------------------------
# Tests for transform_status_coverage_histogram_output
# ----------------------------------------------------------------------


def test_transform_status_coverage_histogram_output(mock_histogram_data):
    """
    GIVEN valid status_coverage histogram data
    WHEN transform_status_coverage_histogram_output is executed
    THEN it should flatten the data into a structured dictionary with counts and percentages
    """
    res = cc.transform_status_coverage_histogram_output(mock_histogram_data)
    sc = res["aspm_status_coverage"]

    assert sc["partially_scanned_count"] == 2
    assert sc["fully_scanned_count"] == 3
    assert sc["partially_scanned_percentage"] == 40.0
    assert sc["fully_scanned_percentage"] == 60.0


def test_transform_status_coverage_histogram_output_empty():
    """
    GIVEN no status_coverage key in the histogram data
    WHEN transform_status_coverage_histogram_output runs
    THEN it should return an empty structured dictionary
    """
    res = cc.transform_status_coverage_histogram_output({})
    assert res["aspm_status_coverage"] == {}


# ----------------------------------------------------------------------
# Tests for main()
# ----------------------------------------------------------------------


@patch("CortexListAppSecAssetCoverage.return_results")
@patch("CortexListAppSecAssetCoverage.get_command_results")
@patch("CortexListAppSecAssetCoverage.demisto")
def test_main_success(mock_demisto, mock_get_cmd, mock_return, mock_asset_coverage_data, mock_histogram_data):
    """
    GIVEN valid asset coverage and histogram responses
    WHEN main() is executed
    THEN it should aggregate results and call return_results with expected outputs
    """
    mock_demisto.args.return_value = {}
    mock_get_cmd.side_effect = [mock_asset_coverage_data, mock_histogram_data]

    cc.main()

    mock_return.assert_called_once()
    result_arg = mock_return.call_args[0][0]
    assert "coverage_percentage" in result_arg.outputs
    assert "Metrics" in result_arg.outputs
    assert "Asset" in result_arg.outputs
    assert result_arg.outputs["number_returned_assets"] == 6


@patch("CortexListAppSecAssetCoverage.return_error")
@patch("CortexListAppSecAssetCoverage.demisto")
def test_main_invalid_arg(mock_demisto, mock_return_error):
    """
    GIVEN unexpected input arguments to main()
    WHEN main() validates arguments
    THEN it should raise a ValueError and call return_error with an appropriate message
    """
    mock_demisto.args.return_value = {"invalid_arg": "123"}

    cc.main()

    mock_return_error.assert_called_once()
    assert "Unexpected args" in mock_return_error.call_args[0][0]


@patch("CortexListAppSecAssetCoverage.return_error")
@patch("CortexListAppSecAssetCoverage.get_command_results", side_effect=Exception("Boom"))
@patch("CortexListAppSecAssetCoverage.demisto")
def test_main_exception(mock_demisto, mock_get_cmd, mock_return_error):
    """
    GIVEN that get_command_results raises an exception
    WHEN main() runs
    THEN it should catch the error and call return_error with the error message
    """
    mock_demisto.args.return_value = {}

    cc.main()

    mock_return_error.assert_called_once()
    assert "Boom" in mock_return_error.call_args[0][0]
