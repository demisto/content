import pytest
import demistomock as demisto
from CommonServerPython import Common
from IPEnrichment import ENDPOINT_PATH, validate_input_function, ip_enrichment_script
import json


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
        - An args dictionary with a list of valid IP addresses.
    When:
        - The validate_input_function is called.
    Then:
        - The function completes successfully without raising an exception.
    """
    args = {"ip_list": "8.8.8.8,2001:db8::"}
    try:
        validate_input_function(args)
    except ValueError:
        pytest.fail("validate_input_function raised an unexpected ValueError.")


def test_validate_input_function_raises_error_on_empty_list():
    """
    Given:
        - An args dictionary where 'ip_list' is missing or empty.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct message.
    """
    with pytest.raises(ValueError, match="ip_list is required"):
        validate_input_function({"ip_list": ""})


def test_validate_input_function_raises_error_on_invalid_ip(mocker):
    """
    Given:
        - An args dictionary containing an item that is not a valid IP address.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct error message.
    """
    with pytest.raises(ValueError, match=r"Invalid IP address: not-an-ip"):
        validate_input_function({"ip_list": "not-an-ip"})


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic end-to-end
# -------------------------------------------------------------------------------------------------
def test_ip_enrichment_script_end_to_end(mocker):
    """
    Given:
        - A list of IPs to enrich.
        - Mocked data from TIM.
        - Mocked data from commands.
    When:
        - The ip_enrichment_script is called in an end-to-end fashion.
    Then:
        - The script correctly merges TIM and batch results, prioritizing the batch results.
        - The script correctly maps outputs from internal commands.
        - The final context is structured correctly with all expected data.
    """
    # --- Arrange ---
    mock_tim_results = util_load_json("test_data/mock_ip_tim_results.json")
    mock_batch_results = util_load_json("test_data/mock_ip_batch_results.json")

    ip_list = ["8.8.8.8", "1.1.1.1"]
    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})

    # Mock the external dependencies to return our mock data
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute", return_value=mock_batch_results)
    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=mock_tim_results)

    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "brand1": {"state": "active", "brand": "brand1"},
            "brand2": {"state": "active", "brand": "brand2"},
            "Scripts": {"state": "active", "brand": "Scripts"},
            "Cortex Core - IR": {"state": "active", "brand": "Cortex Core - IR"},
        },
    )

    # --- Act ---
    command_results = ip_enrichment_script(
        ip_list=ip_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "Cortex Core - IR", "Core"],
    )
    outputs = command_results.outputs

    # --- Assert ---
    enrichment_map = {item["Value"]: item for item in outputs.get("IPEnrichment(val.Value && val.Value == obj.Value)", [])}
    assert len(enrichment_map) == 2

    # 1. Verify results for 8.8.8.8 (overlapping TIM and batch data)
    ip_result = enrichment_map.get("8.8.8.8")
    assert ip_result is not None
    assert len(ip_result["Results"]) == 3  # brand1 (batch) + brand2 (TIM) + TIM Itself

    # The brand1 result should be from the TIM (Score: 3), not Batch (Score: 2)
    vt_brand_result = next(r for r in ip_result["Results"] if r["Brand"] == "brand1")
    assert vt_brand_result["Score"] == 2
    assert vt_brand_result["PositiveDetections"] == 25

    # The max score should be 3 (from TIM), not 2 (from Batch)
    assert ip_result["MaxScore"] == 3
    assert ip_result["MaxVerdict"] == "Malicious"

    # 2. Verify internal command outputs were mapped correctly
    endpoint_data = outputs.get(ENDPOINT_PATH, {})
    assert endpoint_data.get("Hostname") == "test-host"

    ip_prevalence = outputs.get("Core.AnalyticsPrevalence.Ip", {})
    assert len(ip_prevalence) == 2
    assert ip_prevalence["total_count"] == 150

    # 3. Verify DBotScore context was populated from all sources
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    assert len(dbot_scores) == 3  # 2 from TIM, 2 from Batch, 1 is the same so 3
    assert {s["Vendor"] for s in dbot_scores} == {"brand1", "brand2", "brand3"}
