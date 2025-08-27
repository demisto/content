import pytest
import demistomock as demisto
from CommonServerPython import *
from DomainEnrichment import validate_input_function, domain_enrichment_script


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
        - A list of valid domain names.
    When:
        - The validate_input_function is called.
    Then:
        - The function completes without raising an exception.
    """
    args = {"domain_list": "google.com,example.com"}
    try:
        validate_input_function(args)
    except ValueError:
        pytest.fail("validate_input_function raised ValueError unexpectedly.")


def test_validate_input_function_no_domains():
    """
    Given:
        - An empty domain_list argument.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct message.
    """
    with pytest.raises(ValueError, match="domain_list is required"):
        validate_input_function({"domain_list": ""})


def test_validate_input_function_invalid_domain(mocker):
    """
    Given:
        - A list containing an invalid domain name.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct message.
    """
    args = {"domain_list": "8.8.8.8"}
    with pytest.raises(ValueError, match="Invalid domain name"):
        validate_input_function(args)


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic end-to-end
# -------------------------------------------------------------------------------------------------


def test_domain_enrichment_script_end_to_end(mocker):
    """
    Given:
        - A list of domains to enrich, with mocked TIM and batch command data.
    When:
        - The domain_enrichment_script is called in an end-to-end fashion.
    Then:
        - The script should correctly merge TIM and batch results, prioritizing batch data.
        - The script should correctly map outputs from internal commands.
        - The final context should be structured correctly with all expected data.
    """
    # --- Arrange ---
    mock_tim_results = util_load_json("test_data/mock_domain_tim_results.json")
    mock_batch_results = util_load_json("test_data/mock_domain_batch_results.json")

    domain_list = ["domain1.com", "domain2.com"]
    mocker.patch.object(demisto, "args", return_value={"domain_list": ",".join(domain_list)})

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
            "Cortex Core - IR": {"state": "active", "brand": "Cortex Core - IR"},
        },
    )

    # --- Act ---
    command_results = domain_enrichment_script(domain_list=domain_list, external_enrichment=True, enrichment_brands=[])
    outputs = command_results.outputs

    # --- Assert ---
    enrichment_map = {item["Value"]: item for item in outputs.get("DomainEnrichment(val.Value && val.Value == obj.Value)", [])}
    assert len(enrichment_map) == 2

    # 1. Verify results for domain1.com (overlapping TIM and batch data)
    domain_result = enrichment_map.get("domain1.com")
    assert domain_result is not None
    assert len(domain_result["Results"]) == 3  # brand1 (from batch) + brand2 (from TIM) + TIM Itself

    # The brand1 result should be from the BATCH (Score: 3), not TIM (Score: 1)
    brand1_result = next(r for r in domain_result["Results"] if r["Brand"] == "brand1")
    assert brand1_result["Score"] == 3
    assert brand1_result["PositiveDetections"] == 15

    # The max score should be 3 (from batch), not 2 (from TIM)
    assert domain_result["MaxScore"] == 3
    assert domain_result["MaxVerdict"] == "Malicious"

    # 2. Verify internal command output was mapped correctly
    prevalence_data = outputs.get("Core.AnalyticsPrevalence.Domain", {})
    assert len(prevalence_data) == 3
    assert prevalence_data["total_count"] == 500

    # 3. Verify DBotScore context was populated and merged correctly
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    assert len(dbot_scores) == 3  # 1 from TIM, 2 from Batch
    assert {s["Vendor"] for s in dbot_scores} == {"brand1", "brand2", "brand3"}

    # 4. TIM Score Updated
    tim_result = next(r for r in domain_result["Results"] if r["Brand"] == "TIM")
    assert tim_result["Score"] == 3
