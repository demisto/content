import json
import demistomock as demisto
from CVEEnrichment import cve_enrichment_script  # <-- adjust if your file name differs


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# End-to-end: TIM + enrichIndicators (batch data from file)
def test_cve_enrichment_script_end_to_end_with_batch_file(mocker):
    """
    Given:
        - Two CVEs.
        - TIM returns pages from mock_cve_tim_results.json (with CVSS data in brand contexts).
        - Batches:
            * createNewIndicator (no-op)
            * enrichIndicators per CVE (DBotScore only for CVE-2024-0001 / brand1; not surfaced by current mapping)
    When:
        - cve_enrichment_script runs end-to-end.
    Then:
        - CVEEnrichment contains both CVEs.
        - For CVE-2024-0001:
            * Results include brand1 + brand2 (2 items) — TIM is summarized via TIMScore/Status.
            * MaxCVSS = 9.8 and MaxSeverity = "Critical".
            * No MaxScore/MaxVerdict (Score not in mapping).
            * TIMScore exists (summarized from TIM).
        - (DBotScore vendor checks omitted: enrichIndicators has no context_output_mapping.)
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

    # Enabled brands
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            "m3": {"state": "active", "brand": "brand3"},
        },
    )

    # Helper: wrap raw entries into processed tuples [(entry, hr, err)]
    def _wrap_each_as_command(entries, hr=""):
        # N commands, each with one entry
        return [[(e, hr, "")] for e in entries]

    def _wrap_all_in_one_command(entries, hr=""):
        # 1 command that yields N entries
        return [[(e, hr, "") for e in entries]]

    # Batch executor mock → map fixtures to command batches
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # ----- Batch 1: createNewIndicator -----
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]

        if len(b1_cmds) == 1:
            # aggregated: one command returns both entries
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            # per-CVE: N commands, each returns one entry
            assert len(b1_entries) == len(b1_cmds), "batch1 size mismatch vs fixture"
            out.append(_wrap_each_as_command(b1_entries))

        # ----- Batch 2: enrichIndicators -----
        b2_cmds = list_of_batches[1]
        enrich_entries = batch_data["batch2_enrichIndicators"]
        enrich_cmds_count = sum(1 for c in b2_cmds if c.name == "enrichIndicators")

        if enrich_cmds_count == 1:
            # aggregated: one enrichIndicators command yields multiple entries
            out.append(_wrap_all_in_one_command(enrich_entries))
        else:
            # per-CVE: one enrichIndicators command per entry
            assert len(enrich_entries) == enrich_cmds_count, "enrichIndicators size mismatch vs fixture"
            out.append(_wrap_each_as_command(enrich_entries))

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
    enrichment_list = outputs.get("CVEEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(cve_list)

    cve1 = enrichment_map["CVE-2024-0001"]

    # TIM is summarized (TIMScore/Status), not included in Results
    assert len(cve1["Results"]) == 2  # brand1 + brand2

    # MaxCVSS/MaxSeverity computed from mapped CVSS values
    assert "MaxScore" not in cve1
    assert "MaxVerdict" not in cve1
    assert "TIMScore" in cve1  # summarized from TIM presence
    assert cve1["MaxCVSS"] == 9.8
    assert cve1["MaxSeverity"] == "Critical"
