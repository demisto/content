import json
import pytest
import demistomock as demisto
from CommonServerPython import Common
from URLEnrichment import url_enrichment_script


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------------------
# 1) Validation tests (validate_input now lives inside the aggregated command .run())
# --------------------------------------------------------------------------------------


def test_validate_input_success(mocker):
    """
    Given:
        - A valid URL list.
        - extractIndicators returns both URLs under ExtractedIndicators.URL.
        - No batches executed; TIM returns nothing (we only care that validation passes).
    When:
        - url_enrichment_script is executed.
    Then:
        - No exception is raised.
    """
    url_list = ["https://google.com", "https://example.com"]

    # demisto.args() is read into the aggregated command (kept for completeness)
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # Patch extractIndicators (via AggregatedCommandApiModule.execute_command)
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"URL": url_list}}}],
    )

    # Make the aggregated pipeline do nothing else (no-op batches and no TIM results)
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())

    # Enabled modules (not used in this test but the code queries them)
    mocker.patch.object(demisto, "getModules", return_value={})

    # Should not raise
    res = url_enrichment_script(
        url_list=url_list, external_enrichment=False, verbose=False, enrichment_brands=[], additional_fields=False
    )
    assert res is not None


def test_validate_input_invalid_url(mocker):
    """
    Given:
        - A URL list containing an invalid item (8.8.8.8 for a URL type).
        - extractIndicators only returns the valid URL.
    When:
        - url_enrichment_script is executed.
    Then:
        - ValueError is raised by validate_input.
    """
    url_list = ["https://google.com", "8.8.8.8"]
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # Only the valid URL is extracted -> triggers ValueError
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"URL": ["https://google.com"]}}}],
    )

    # No-op the rest of the pipeline
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    with pytest.raises(ValueError, match=r"are not valid url"):
        url_enrichment_script(
            url_list=url_list, external_enrichment=False, verbose=False, enrichment_brands=[], additional_fields=False
        )


# --------------------------------------------------------------------------------------
# 2) End-to-end test with TIM + batches (WildFire + enrichIndicators side effect)
# --------------------------------------------------------------------------------------


def test_url_enrichment_script_end_to_end(mocker, tmp_path):
    """
    Given:
        - Two URLs.
        - TIM search returns:
            * example.com with TIM score 3, brand2 score 3, brand1 score 2 (brand1 has no DBotScore in TIM)
            * example2.com with TIM score 1, brand3 score 1
        - Batches:
            * createNewIndicator for each URL (no-op)
            * wildfire-get-verdict returns verdicts for both URLs (mapped)
            * enrichIndicators returns a DBotScore only for example.com (brand1)
    When:
        - url_enrichment_script runs end-to-end.
    Then:
        - URLEnrichment contains both URLs with 3 entries for example.com (TIM, brand1, brand2).
        - MaxScore=3, MaxVerdict=Malicious, TIMScore=3 for example.com.
        - WildFire verdicts mapped under the correct context key as a nested list (because of [] mapping).
        - DBotScore contains exactly 3 vendors: brand1, brand2, brand3.
    """
    # Load mock TIM pages from file
    tim_pages = util_load_json("test_data/mock_tim_results.json")["pages"]

    url_list = ["https://example.com", "https://example2.com"]
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # --- Validation: extractIndicators returns both URLs
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"URL": url_list}}}],
    )

    # --- Mock IndicatorsSearcher to yield our pages
    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))

    # --- Enabled modules/brands
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            "wf": {"state": "active", "brand": "WildFire-v2"},
        },
    )

    # --- Mock batch executor (returns *processed* tuples like BatchExecutor.process_results would)
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 1: createNewIndicator per URL -> no EntryContext (non-fatal)
        batch1_cmds = list_of_batches[0]
        batch1_results = []
        for _cmd in batch1_cmds:
            entry = {"Type": 1, "EntryContext": {}}
            batch1_results.append([(entry, "", "")])  # [(result_dict, hr, error)]
        out.append(batch1_results)

        # Batch 2: wildfire + enrichIndicators(url per URL)
        batch2_cmds = list_of_batches[1]
        batch2_results = []
        for cmd in batch2_cmds:
            if cmd.name == "wildfire-get-verdict":
                entry = {
                    "Type": 1,
                    "EntryContext": {
                        "WildFire.Verdicts(val.url && val.url == obj.url)": [
                            {"url": "https://example.com", "verdict": 1},
                            {"url": "https://example2.com", "verdict": 2},
                        ]
                    },
                }
                batch2_results.append([(entry, "wf-hr", "")])
            else:  # enrichIndicators per URL
                url = cmd.args.get("indicatorsValues")
                if url == "https://example.com":
                    # Provide only a brand1 DBotScore here; the brand2/brand3 DBotScores come from TIM
                    entry = {
                        "Type": 1,
                        "Metadata": {"brand": "brand1"},
                        "EntryContext": {
                            "DBotScore(val.Indicator && val.Vendor)": [{"Indicator": url, "Vendor": "brand1", "Score": 2}]
                        },
                    }
                else:
                    entry = {"Type": 1, "EntryContext": {}}
                batch2_results.append([(entry, "", "")])
        out.append(batch2_results)

        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # --- Act
    command_results = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "WildFire-v2"],
        additional_fields=False,
    )
    outputs = command_results.outputs

    # --- Assert: URLEnrichment indicators
    enrichment_list = outputs.get("URLEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(url_list)

    # example.com should have TIM + brand1 + brand2
    ex1 = enrichment_map["https://example.com"]
    assert len(ex1["Results"]) == 3

    # brand1 result (from TIM's insightCache context data)
    b1 = next(r for r in ex1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5

    # Max fields
    assert ex1["MaxScore"] == 3
    assert ex1["MaxVerdict"] == "Malicious"
    assert ex1["TIMScore"] == 3

    # WildFire mapping (note nested list due to [] in mapping)
    wildfire_verdicts = outputs.get("WildFire.Verdicts(val.url && val.url == obj.url)", [])
    assert len(wildfire_verdicts) == 1
    assert isinstance(wildfire_verdicts[0], list)
    assert len(wildfire_verdicts[0]) == 2
    assert wildfire_verdicts[0][0]["verdict"] == 1

    # DBotScore vendors exactly brand1, brand2, brand3
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    vendors = {s.get("Vendor") for s in dbot_scores}
    assert vendors == {"brand1", "brand2", "brand3"}
