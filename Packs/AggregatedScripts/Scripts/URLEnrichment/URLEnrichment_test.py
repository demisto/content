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

    # Patch execute_command with per-command behavior:
    # - extractIndicators → list with EntryContext (as validate_input expects)
    # - findIndicators    → (True, []) tuple (as search_indicators_in_tim expects)
    def _exec_side_effect(cmd, args=None, extract_contents=False, fail_on_error=True):
        if cmd == "extractIndicators":
            return [{"EntryContext": {"ExtractedIndicators": {"URL": url_list}}}]
        if cmd == "findIndicators":
            return (True, [])  # success, no hits
        return []

    mocker.patch("AggregatedCommandApiModule.execute_command", side_effect=_exec_side_effect)

    # Make the aggregated pipeline do nothing else (no-op batches)
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

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
def test_url_enrichment_script_end_to_end_with_files(mocker):
    """
    Given:
        - Two URLs.
        - TIM results from test_data/mock_tim_results.json
        - Batch results from test_data/mock_bathc_results.json
    When:
        - url_enrichment_script runs end-to-end.
    Then:
        - URLEnrichment contains both URLs.
        - For https://example.com:
            * Results has 2 entries (brand1, brand2) — TIM is summarized via TIMScore/Status, not inside Results.
            * MaxScore=3, MaxVerdict=Malicious, TIMScore=3.
        - WildFire verdicts mapped under the correct context key as a nested list ([] mapping).
        - (No DBotScore assertions; current code does not surface DBotScore from enrichIndicators or TIM.)
    """
    # ---------- Load fixtures ----------
    tim_pages = util_load_json("test_data/mock_tim_results.json")["pages"]
    batch_blob = util_load_json("test_data/mock_batch_results.json")

    # Flatten TIM iocs from pages
    tim_iocs = []
    for page in tim_pages:
        tim_iocs.extend(page.get("iocs", []))

    url_list = ["https://example.com", "https://example2.com"]

    # demisto.args() passthrough (used by ctor)
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # ---------- Mock execute_command for both extractIndicators and findIndicators ----------
    def _exec_side_effect(cmd, args=None, extract_contents=False, fail_on_error=True):
        if cmd == "extractIndicators":
            # validate_input expects list with EntryContext
            return [{"EntryContext": {"ExtractedIndicators": {"URL": url_list}}}]
        if cmd == "findIndicators":
            # search_indicators_in_tim expects (is_success, results)
            return (True, tim_iocs)
        return []

    mocker.patch("AggregatedCommandApiModule.execute_command", side_effect=_exec_side_effect)

    # ---------- Enabled modules/brands (BrandManager) ----------
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            "wf": {"state": "active", "brand": "WildFire-v2"},
        },
    )

    # ---------- Mock BatchExecutor.execute_list_of_batches using your JSON ----------
    # JSON has:
    #   - "wildfire":       [ { EntryContext: { WildFire.Verdicts[...] } } ]
    #   - "enrichIndicators":[ {...brand1 dbot...}, { empty } ]  # one per URL
    #   - "createNewIndicator":[{},{}}]  # you use a single CreateNewIndicatorsOnly command
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 0: CreateNewIndicatorsOnly -> one command in your code; turn first JSON item into a processed tuple
        create_items = list(batch_blob.get("createNewIndicator", []))
        batch0_cmds = list_of_batches[0]
        batch0_results = []
        for _ in batch0_cmds:
            item = create_items[0] if create_items else {"Type": 1, "EntryContext": {}}
            batch0_results.append([(item, "", "")])
        out.append(batch0_results)

        # Batch 1: wildfire + enrichIndicators per URL
        wf_items = list(batch_blob.get("wildfire", []))
        enrich_items = list(batch_blob.get("enrichIndicators", []))
        batch1_cmds = list_of_batches[1]
        batch1_results = []
        for cmd in batch1_cmds:
            if cmd.name == "wildfire-get-verdict":
                item = wf_items[0] if wf_items else {"Type": 1, "EntryContext": {}}
                batch1_results.append([(item, "wf-hr", "")])
            else:  # enrichIndicators per URL
                item = enrich_items.pop(0) if enrich_items else {"Type": 1, "EntryContext": {}}
                batch1_results.append([(item, "", "")])
        out.append(batch1_results)

        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # ---------- Act ----------
    command_results = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "WildFire-v2"],
        additional_fields=False,
    )
    outputs = command_results.outputs

    # ---------- Assert: URLEnrichment indicators ----------
    enrichment_key = "URLEnrichment(val.Value && val.Value == obj.Value)"
    enrichment_list = outputs.get(enrichment_key, [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(url_list)

    # https://example.com should have brand1 + brand2 (TIM is summarized via TIMScore)
    ex1 = enrichment_map["https://example.com"]
    assert len(ex1["Results"]) == 2

    # brand1 result
    b1 = next(r for r in ex1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5

    # brand2 result present and scored 3
    b2 = next(r for r in ex1["Results"] if r["Brand"] == "brand2")
    assert b2["Score"] == 3

    # Max fields + TIMScore
    assert ex1["MaxScore"] == 3
    assert ex1["MaxVerdict"] == "Malicious"
    assert ex1["TIMScore"] == 3

    # ---------- Assert: WildFire mapping (nested due to [] in mapping) ----------
    wf_key = "WildFire.Verdicts(val.url && val.url == obj.url)"
    wf_out = outputs.get(wf_key, [])
    assert len(wf_out) == 1
    assert isinstance(wf_out[0], list)
    assert len(wf_out[0]) == 2
    assert wf_out[0][0]["verdict"] == 1

    # Optional: ensure DBotScore not surfaced by current implementation
    # from CommonServerPython import Common
    # assert Common.DBotScore.CONTEXT_PATH not in outputs or not outputs[Common.DBotScore.CONTEXT_PATH]



