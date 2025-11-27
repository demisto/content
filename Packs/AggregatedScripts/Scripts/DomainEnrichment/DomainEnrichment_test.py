import json
import demistomock as demisto
from DomainEnrichment import domain_enrichment_script


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# End-to-end: TIM + core analytics + enrichIndicators (batch data from file)
def test_domain_enrichment_script_end_to_end_with_batch_file(mocker):
    r"""
    Given:
        - Two domains.
        - TIM pages from test_data/mock_domain_tim_results.json
          (includes per-vendor reliability, and for example.com a manual edit + modifiedTime).
        - Batch results from test_data/mock_domain_batch_results.json.
    When:
        - domain_enrichment_script runs end-to-end (external_enrichment=True).
    Then:
        - DomainEnrichment contains both domains.
        - For example.com:
            * Results has 3 entries: TIM + brand1 + brand2.
              - TIM row's Status/ModifiedTime are popped to top-level (TIM row itself should NOT contain them).
            * MaxScore=3, MaxVerdict=Malicious, TIMScore=3.
            * Top-level Status == 'Manual' and ModifiedTime matches fixture.
            * brand1 Reliability == 'High', brand2 Reliability == 'Medium'.
        - For example2.com:
            * Results has 2 entries: TIM + brand3 (brand3 Reliability == 'Low').
        - Core prevalence mapped under 'Core.AnalyticsPrevalence.Domain'.
    """
    # Load fixtures
    tim_pages = util_load_json("test_data/mock_domain_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_domain_batch_results.json")

    domain_list = ["example.com", "example2.com"]
    mocker.patch.object(demisto, "args", return_value={"domain_list": ",".join(domain_list)})

    mocker.patch("DomainEnrichment.is_xsiam", return_value=True)
    # extractIndicators -> validates input
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"Domain": domain_list}}}],
    )

    # TIM via IndicatorsSearcher
    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))

    # Enabled brands
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            "core": {"state": "active", "brand": "Cortex Core - IR"},
        },
    )

    # Helpers to wrap raw entries -> processed tuples [(entry, hr, err)]
    def _wrap_each_as_command(entries, hr=""):
        return [[(e, hr, "")] for e in entries]

    def _wrap_all_in_one_command(entries, hr=""):
        return [[(e, hr, "") for e in entries]]

    # Batch executor -> map fixtures to command batches
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # ----- Batch 1: createNewIndicator -----
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]
        if len(b1_cmds) == 1:
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            assert len(b1_entries) == len(b1_cmds), "batch1 size mismatch vs fixture"
            out.append(_wrap_each_as_command(b1_entries))

        # ----- Batch 2: core prevalence then enrichIndicators -----
        b2_cmds = list_of_batches[1]
        assert b2_cmds[0].name == "core-get-domain-analytics-prevalence"

        core_entries = batch_data["batch2_core"]
        assert len(core_entries) == 1, "expected one core analytics entry"
        batch2_results = _wrap_each_as_command(core_entries, hr="core-hr")

        enrich_entries = batch_data["batch2_enrichIndicators"]
        enrich_cmds_count = sum(1 for c in b2_cmds if c.name == "enrichIndicators")

        if enrich_cmds_count == 1:
            batch2_results.extend(_wrap_all_in_one_command(enrich_entries))
        else:
            assert len(enrich_entries) == enrich_cmds_count, "enrichIndicators size mismatch vs fixture"
            batch2_results.extend(_wrap_each_as_command(enrich_entries))

        out.append(batch2_results)
        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # Act
    res = domain_enrichment_script(
        domain_list=domain_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "Cortex Core - IR"],
        additional_fields=False,
    )
    outputs = res.outputs

    # DomainEnrichment indicators
    enrichment_key = "DomainEnrichment(val.Value && val.Value == obj.Value)"
    enrichment_list = outputs.get(enrichment_key, [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(domain_list)

    # example.com -> TIM + brand1 + brand2
    ex1 = enrichment_map["example.com"]
    assert {r.get("Brand") for r in ex1["Results"]} == {"TIM", "brand1", "brand2"}
    assert len(ex1["Results"]) == 3

    # vendor rows (reliability present)
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

    # example2.com -> TIM + brand3 (brand3 only via TIM; brand3 not enabled)
    ex2 = enrichment_map["example2.com"]
    assert {r.get("Brand") for r in ex2["Results"]} == {"TIM", "brand3"}
    b3 = next(r for r in ex2["Results"] if r["Brand"] == "brand3")
    assert b3["Score"] == 1
    assert b3.get("Reliability") == "Low"

    # Core prevalence mapped
    core_ctx = outputs.get("Core.AnalyticsPrevalence.Domain", [])
    assert isinstance(core_ctx, list)
    assert len(core_ctx) == 2
    assert {d["Domain"] for d in core_ctx} == {"example.com", "example2.com"}
