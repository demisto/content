import pytest
import demistomock as demisto
from CommonServerPython import *
from CVEEnrichment import validate_input_function, cve_enrichment_script


def util_load_json(path):
    """A helper function to load mock JSON files."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


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
    args = {"cve_list": "CVE-2021-44228"}
    try:
        validate_input_function(args)
    except ValueError:
        pytest.fail("validate_input_function raised an unexpected ValueError.")


def test_validate_input_function_raises_error_on_empty_list():
    """
    Given:
        - An args dictionary where 'cve_list' is empty.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct message.
    """
    with pytest.raises(ValueError, match="cve_list is required"):
        validate_input_function({"cve_list": ""})


def test_validate_input_function_raises_error_on_invalid_cve(mocker):
    """
    Given:
        - An args dictionary containing an item that is not a valid CVE ID.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct message.
    """
    with pytest.raises(ValueError, match=r"Invalid CVE ID: not-a-cve"):
        validate_input_function({"cve_list": "not-a-cve"})


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic end-to-end
# -------------------------------------------------------------------------------------------------


def test_cve_enrichment_script_end_to_end(mocker):
    """
    Given:
        - A list of CVEs to enrich, with mocked TIM and batch command data.
    When:
        - The cve_enrichment_script is called in an end-to-end fashion.
    Then:
        - The script should correctly merge TIM and batch results, prioritizing batch data.
        - The final context should be structured correctly with all expected data.
    """
    # --- Arrange ---
    mock_tim_results = util_load_json("test_data/mock_cve_tim_results.json")
    mock_batch_results = util_load_json("test_data/mock_cve_batch_results.json")

    cve_list = ["CVE-2023-1001", "CVE-2023-1002"]
    mocker.patch.object(demisto, "args", return_value={"cve_list": ",".join(cve_list)})

    # Mock the external dependencies to return our mock data
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute", return_value=mock_batch_results)
    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=mock_tim_results)
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "brand1": {"state": "active", "brand": "brand1"},
            "brand2": {"state": "active", "brand": "brand2"},
            "brand3": {"state": "active", "brand": "brand3"},
        },
    )

    # --- Act ---
    command_results = cve_enrichment_script(cve_list=cve_list, external_enrichment=True, enrichment_brands=[])
    outputs = command_results.outputs

    # --- Assert ---
    enrichment_map = {item["Value"]: item for item in outputs.get("CVEEnrichment(val.Value && val.Value == obj.Value)", [])}
    assert len(enrichment_map) == 2

    # 1. Verify results for CVE-2023-1001 (overlapping TIM and batch data)
    cve_result = enrichment_map.get("CVE-2023-1001")
    assert cve_result is not None
    assert len(cve_result["Results"]) == 3  # brand1 (from batch) + brand2 (from TIM) + TIM Itself

    # The brand1 result should be from the BATCH (CVSS: 9.8), not TIM (CVSS: 7.5)
    brand1_result = next(r for r in cve_result["Results"] if r["Brand"] == "brand1")
    assert brand1_result["CVSS"] == 9.8
    assert brand1_result["Description"] == "A critical vulnerability."

    # The brand2 result from TIM should still be present as it did not conflict
    brand2_result = next(r for r in cve_result["Results"] if r["Brand"] == "brand2")
    assert brand2_result["CVSS"] == 7.8

    # 2. Verify results for CVE-2023-1002 (batch only)
    cve2_result = enrichment_map.get("CVE-2023-1002")
    assert cve2_result is not None
    assert len(cve2_result["Results"]) == 1
    assert cve2_result["Results"][0]["Brand"] == "brand3"
    assert cve2_result["Results"][0]["CVSS"] == 5.3

    # The max CVSS should be 9.8 (from brand1)
    assert cve_result["MaxCVSS"] == 9.8
    # The max severity should be "Critical"
    assert cve_result["MaxSeverity"] == "Critical"

    # 3. Verify DBotScore context was populated and merged correctly
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    assert len(dbot_scores) == 3  # 1 from TIM, 2 from Batch
    assert {s["Vendor"] for s in dbot_scores} == {"brand1", "brand2", "brand3"}
