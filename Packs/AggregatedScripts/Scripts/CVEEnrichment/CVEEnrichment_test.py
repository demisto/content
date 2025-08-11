import pytest
import demistomock as demisto
from CommonServerPython import *
from CVEEnrichment import validate_input_function, cve_enrichment_script




# -------------------------------------------------------------------------------------------------
# -- 1. Test Input Validation
# -------------------------------------------------------------------------------------------------

def test_validate_input_function_success(mocker):
    """
    Given:
        - An args dictionary with a list of valid CVE IDs.
    When:
        - The validate_input_function is called.
    Then:
        - The function runs without raising an exception.
    """
    mocker.patch("CVEEnrichment.auto_detect_indicator_type", return_value=FeedIndicatorType.CVE)
    args = {"cve_list": "CVE-2021-44228"}
    try:
        validate_input_function(args)
    except DemistoException:
        pytest.fail("validate_input_function raised an unexpected DemistoException.")


def test_validate_input_function_raises_error_on_empty_list():
    """
    Given:
        - An args dictionary where 'cve_list' is empty.
    When:
        - The validate_input_function is called.
    Then:
        - A DemistoException is raised with the correct message.
    """
    with pytest.raises(DemistoException, match="cve_list is required"):
        validate_input_function({"cve_list": ""})


def test_validate_input_function_raises_error_on_invalid_cve(mocker):
    """
    Given:
        - An args dictionary containing an item that is not a valid CVE ID.
    When:
        - The validate_input_function is called.
    Then:
        - A DemistoException is raised with the correct message.
    """
    mocker.patch("CVEEnrichment.auto_detect_indicator_type", return_value=FeedIndicatorType.URL)
    with pytest.raises(DemistoException, match=r"Invalid CVE ID: not-a-cve"):
        validate_input_function({"cve_list": "not-a-cve"})


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic
# -------------------------------------------------------------------------------------------------

def test_cve_enrichment_script_configures_and_runs_module(mocker):
    """
    Given:
        - A list of CVEs and script arguments.
    When:
        - The cve_enrichment_script function is called.
    Then:
        - It correctly initializes the ReputationAggregatedCommand with the right parameters.
        - It calls the main execution loop and returns its result.
    """
    mock_agg_command_class = mocker.patch("CVEEnrichment.ReputationAggregatedCommand")
    mock_instance = mock_agg_command_class.return_value
    mock_instance.aggregated_command_main_loop.return_value = "SUCCESSFUL_RESULTS"

    cve_list = ["CVE-2021-44228", "CVE-2022-22965"]
    brands = ["NVD"]

    result = cve_enrichment_script(
        cve_list=cve_list,
        enrichment_brands=brands,
        verbose=True
    )

    mock_agg_command_class.assert_called_once()
    init_kwargs = mock_agg_command_class.call_args.kwargs

    assert init_kwargs.get("brands") == brands
    assert init_kwargs.get("verbose") is True
    assert init_kwargs.get("data") == cve_list
    assert init_kwargs.get("indicator").type == "cve"
    assert init_kwargs.get("indicator").value_field == "ID"
    assert "CVEEnrichment(val.ID && val.ID == obj.ID)" in init_kwargs.get("final_context_path")

    commands_list = init_kwargs.get("commands", [])
    assert len(commands_list) == 2  # One reputation command for each CVE
    assert all(cmd.name == "cve" for cmd in commands_list)

    mock_instance.aggregated_command_main_loop.assert_called_once()
    assert result == "SUCCESSFUL_RESULTS"
