import pytest
import demistomock as demisto
from CommonServerPython import Common
from URLEnrichment import validate_input_function, url_enrichment_script
import json

def util_load_json(path):
    """A helper function to load mock JSON files."""
    with open(path, encoding='utf-8') as f:
        return json.load(f)


# -------------------------------------------------------------------------------------------------
# -- 1. Test Input Validation
# -------------------------------------------------------------------------------------------------

def test_validate_input_function_success(mocker):
    """
    Given:
        - An args dictionary with a list of valid URLs.
    When:
        - The validate_input_function is called.
    Then:
        - The function completes successfully without raising an exception.
    """
    args = {"url_list": "https://google.com,https://example.com"}
    try:
        validate_input_function(args)
    except ValueError:
        pytest.fail("validate_input_function raised an unexpected ValueError.")


def test_validate_input_function_raises_error_on_missing_list():
    """
    Given:
        - An args dictionary where 'url_list' is missing.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct error message.
    """
    with pytest.raises(ValueError, match="url_list is required"):
        validate_input_function({"url_list": ""})


def test_validate_input_function_raises_error_on_invalid_url(mocker):
    """
    Given:
        - An args dictionary containing an item that is not a valid URL.
    When:
        - The validate_input_function is called.
    Then:
        - A ValueError is raised with the correct error message.
    """
    with pytest.raises(ValueError, match=r"URL '8.8.8.8' is invalid"):
        validate_input_function({"url_list": "8.8.8.8"})


# -------------------------------------------------------------------------------------------------
# -- 2. Test Main Script Logic end-to-end
# -------------------------------------------------------------------------------------------------

def test_url_enrichment_script_end_to_end(mocker):
    """
    Given:
        - A list of URLs to enrich.
        - Mocked data from TIM.
        - Mocked data from commands.
    When:
        - The url_enrichment_script is called in an end-to-end fashion.
    Then:
        - The script should correctly merge TIM and batch results, prioritizing batch.
        - The final context should be structured correctly.
        - Scores and verdicts should be calculated correctly.
    """
    # --- Arrange ---
    # Load tim results - 2 indicators
    mock_tim_results = util_load_json("test_data/mock_tim_results.json")
    # Load batch results - 1 new indicator + 1 overlapping indicator + wildfire results
    mock_batch_results = util_load_json("test_data/mock_batch_results.json")
    
    url_list = ["https://example.com", "https://example2.com"]
    mocker.patch.object(demisto, 'args', return_value={"url_list": ",".join(url_list)})

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute", return_value=mock_batch_results)
    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=mock_tim_results)
    
    mocker.patch.object(demisto, "getModules", return_value={
        "brand1": {"state": "active", "brand": "brand1"},
        "brand2": {"state": "active", "brand": "brand2"},
        "WildFire-v2": {"state": "active", "brand": "WildFire-v2"}
    })

    # --- Act ---
    command_results = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "WildFire-v2"]
    )
    outputs = command_results.outputs

    # --- Assert ---
    # Convert the list of results to a dictionary for easier access
    enrichment_map = {item["Data"]: item for item in outputs.get("URLEnrichment(val.Data && val.Data == obj.Data)", [])}
    assert len(enrichment_map) == 2  # We should have results for both URLs

    # 1. Verify the results for example.com (the one with overlapping data)
    vt_result = enrichment_map.get("https://example.com")
    assert vt_result is not None
    
    # It should have merged results from brand1 (batch), and brand2 (TIM)
    assert len(vt_result["results"]) == 2
    
    # The brand1 result should be the one from the BATCH (Score: 3), not TIM (Score: 1)
    vt_brand_result = next(r for r in vt_result["results"] if r["Brand"] == "brand1")
    assert vt_brand_result["Score"] == 3
    assert vt_brand_result["PositiveDetections"] == 5

    # The max score should be 3 (from the batch brand1 result), not 2 (from TIM brand2)
    assert vt_result["max_score"] == 3
    assert vt_result["max_verdict"] == "Malicious"

    # 2. Verify the wildfire-get-verdict results were mapped correctly
    wildfire_verdicts = outputs.get("WildFireVerdicts(val.url && val.url == obj.url)", [])
    assert len(wildfire_verdicts) == 1
    assert len(wildfire_verdicts[0]) == 2 # The list of verdicts is nested
    assert wildfire_verdicts[0][0]["verdict"] == 1

    # 3. Verify that DBotScore context was populated from all sources
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    assert len(dbot_scores) == 3 # 2 from TIM, 2 from Batch, 1 overlapping so 3
    assert {s['Vendor'] for s in dbot_scores} == {"brand1", "brand2","brand3"}