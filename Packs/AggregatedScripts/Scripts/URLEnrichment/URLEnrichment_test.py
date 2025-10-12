import json
import demistomock as demisto
from URLEnrichment import url_enrichment_script


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_url_enrichment_script_end_to_end_with_files(mocker):
    """
    Given:
        - Input is Two URLs: https://example.com, https://example2.com.
        - TIM results from test_data/mock_tim_results.json.
        - Batch results from test_data/mock_batch_results.json (only create + enrichIndicators).
    When:
        - url_enrichment_script runs end-to-end (external_enrichment=True).
    Then:
        - URLEnrichment contains both URLs.
        - For https://example.com:
            * Results has 3 entries (TIM + brand1 + brand2).
              - TIM is summarized via top-level TIMScore/Status/ModifiedTime.
              - TIM row in Results has NO Status/ModifiedTime (they're popped).
            * MaxScore=3, MaxVerdict=Malicious, TIMScore=3.
            * Vendor rows include All standard output fields.
            * Top-level Status == "Manual" (due to manuallyEditedFields.Score).
        - For https://example2.com:
            * Results has 2 entries (TIM + brand3), and brand3 Reliability is Low.
    """
    # ---------- Load fixtures ----------
    tim_pages = util_load_json("test_data/mock_tim_results.json")["pages"]
    batch_blob = util_load_json("test_data/mock_batch_results.json")

    url_list = ["https://example.com", "https://example2.com"]

    # demisto.args() passthrough (used by ctor)
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # ---------- Mock execute_command ONLY for extractIndicators ----------
    def extractIndicators_side_effect(cmd, args=None, extract_contents=False, fail_on_error=True):
        if cmd == "extractIndicators":
            return [{"EntryContext": {"ExtractedIndicators": {"URL": url_list}}}]
        return []

    mocker.patch("AggregatedCommandApiModule.execute_command", side_effect=extractIndicators_side_effect)

    # ---------- TIM search via IndicatorsSearcher ----------
    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))

    # ---------- Enabled modules/brands (BrandManager) ----------
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            # brand3 not enabled; still appears via TIM context (not enrichIndicators)
        },
    )

    # ---------- Mock BatchExecutor.execute_list_of_batches using JSON ----------
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 0: CreateNewIndicatorsOnly -> one command in the script
        batch0_cmds = list_of_batches[0]
        batch0_results = []
        create_items = list(batch_blob.get("createNewIndicator", []))
        for _ in batch0_cmds:
            item = create_items[0] if create_items else {"Type": 1, "EntryContext": {}}
            batch0_results.append([(item, "", "")])
        out.append(batch0_results)

        # Batch 1: enrichIndicators only (single command with 2 entries for 2 URLs)
        enrich_items = list(batch_blob.get("enrichIndicators", []))
        batch1_cmds = list_of_batches[1]
        batch1_results = []
        for cmd in batch1_cmds:
            assert cmd.name == "enrichIndicators"
            items = enrich_items if enrich_items else [{"Type": 1, "EntryContext": {}}]
            batch1_results.append([(e, "", "") for e in items])
        out.append(batch1_results)

        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # ---------- Act ----------
    command_results = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2"],
        additional_fields=False,
    )
    outputs = command_results.outputs

    # ---------- Assert: URLEnrichment indicators ----------
    enrichment_key = "URLEnrichment(val.Value && val.Value == obj.Value)"
    enrichment_list = outputs.get(enrichment_key, [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(url_list)

    # https://example.com should have TIM + brand1 + brand2
    ex1 = enrichment_map["https://example.com"]
    brands_present_ex1 = {r.get("Brand") for r in ex1["Results"]}
    assert brands_present_ex1 == {"TIM", "brand1", "brand2"}
    assert len(ex1["Results"]) == 3

    # vendor rows with reliability
    b1 = next(r for r in ex1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5
    assert b1.get("Reliability") == "High"

    b2 = next(r for r in ex1["Results"] if r["Brand"] == "brand2")
    assert b2["Score"] == 3
    assert b2["PositiveDetections"] == 37
    assert b2.get("Reliability") == "Medium"

    # TIM row present but without Status/ModifiedTime (popped to top-level)
    tim_row_ex1 = next(r for r in ex1["Results"] if r["Brand"] == "TIM")
    assert "Status" not in tim_row_ex1
    assert "ModifiedTime" not in tim_row_ex1

    # Max fields + TIMScore + top-level Status/ModifiedTime
    assert ex1["MaxScore"] == 3
    assert ex1["MaxVerdict"] == "Malicious"
    assert ex1["TIMScore"] == 3
    assert ex1.get("Status") == "Manual"
    assert ex1.get("ModifiedTime") == "2025-09-01T00:00:00Z"

    # https://example2.com should have TIM + brand3 (from TIM; brand3 not enabled)
    ex2 = enrichment_map["https://example2.com"]
    brands_present_ex2 = {r.get("Brand") for r in ex2["Results"]}
    assert brands_present_ex2 == {"TIM", "brand3"}
    b3 = next(r for r in ex2["Results"] if r["Brand"] == "brand3")
    assert b3["Score"] == 1
    assert b3.get("Reliability") == "Low"
