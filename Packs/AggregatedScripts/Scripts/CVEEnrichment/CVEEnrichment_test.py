import json
import demistomock as demisto
from CVEEnrichment import cve_enrichment_script


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# End-to-end: TIM + enrichIndicators (batch data from file)
def test_cve_enrichment_script_end_to_end_with_batch_file(mocker):
    r"""
    Given:
        - Two CVEs.
        - TIM returns pages from mock_cve_tim_results.json (with reliability + manual edit + modifiedTime).
        - Batches:
            * createNewIndicator (no-op)
            * enrichIndicators per CVE (DBotScore only for CVE-2024-0001 / brand1; not surfaced by mapping)
    When:
        - cve_enrichment_script runs end-to-end (external_enrichment=True).
    Then:
        - CVEEnrichment contains both CVEs.
        - For CVE-2024-0001:
            * Results include TIM + brand1 + brand2 (3 items).
              - TIM row has no Status/ModifiedTime (popped to top-level).
            * TIMScore == 2; Status == "Manual"; ModifiedTime == fixture value.
        - For CVE-2023-9999:
            * Results include TIM + brand3 (2 items), with brand3 Reliability == "Low".
        - We don't assert DBotScore path (not mapped in outputs).
    """
    tim_pages = util_load_json("test_data/mock_cve_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_cve_batch_results.json")

    cve_list = ["CVE-2024-0001", "CVE-2023-9999"]
    mocker.patch.object(demisto, "args", return_value={"cve_list": ",".join(cve_list)})

    # extractIndicators -> validates input
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"CVE": cve_list}}}],
    )

    # TIM search via IndicatorsSearcher
    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))

    # Enabled brands (external enrich runs for these)
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            "m3": {"state": "active", "brand": "brand3"},
        },
    )

    # Helpers
    def _wrap_all_in_one_command(entries, hr=""):
        return [[(e, hr, "") for e in entries]]

    # Batch executor mock → map fixtures to command batches
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # ----- Batch 1: createNewIndicator -----
        b1_entries = batch_data["batch1_createNewIndicator"]
        out.append(_wrap_all_in_one_command(b1_entries))

        # ----- Batch 2: enrichIndicators -----
        enrich_entries = batch_data["batch2_enrichIndicators"]
        out.append(_wrap_all_in_one_command(enrich_entries))

        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # Act
    res = cve_enrichment_script(
        cve_list=cve_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "brand3"],
        additional_fields=False,
    )
    outputs = res.outputs

    # CVEEnrichment indicators
    key = "CVEEnrichment(val.Value && val.Value == obj.Value)"
    enrichment_list = outputs.get(key, [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(cve_list)

    cve1 = enrichment_map["CVE-2024-0001"]

    # Results contains TIM + vendor rows
    assert {r.get("Brand") for r in cve1["Results"]} == {"TIM", "brand1", "brand2"}
    assert len(cve1["Results"]) == 3

    # TIM row present but Status/ModifiedTime popped to top-level
    tim_row = next(r for r in cve1["Results"] if r["Brand"] == "TIM")
    assert "Status" not in tim_row
    assert "ModifiedTime" not in tim_row

    # Vendor reliabilities
    b1 = next(r for r in cve1["Results"] if r["Brand"] == "brand1")
    assert b1.get("Reliability") == "High"
    b2 = next(r for r in cve1["Results"] if r["Brand"] == "brand2")
    assert b2.get("Reliability") == "Medium"

    # TIM summarization
    assert cve1.get("Status") == "Manual"
    assert cve1.get("ModifiedTime") == "2025-09-01T00:00:00Z"
    assert cve1.get("TIMCVSS") == 7.5

    # Second CVE: TIM + brand3, reliability Low
    cve2 = enrichment_map["CVE-2023-9999"]
    assert {r.get("Brand") for r in cve2["Results"]} == {"TIM", "brand3"}
    b3 = next(r for r in cve2["Results"] if r["Brand"] == "brand3")
    assert b3.get("Reliability") == "Low"

    # TIM summarization
    assert cve2.get("Status") is None
    assert cve2.get("ModifiedTime") is None
    assert cve2.get("TIMCVSS") == 1.2
