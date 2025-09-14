import json
import demistomock as demisto
from DomainEnrichment import domain_enrichment_script  # <-- adjust if your file name differs


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# End-to-end: TIM + core analytics + enrichIndicators (batch data from file)
def test_domain_enrichment_script_end_to_end_with_batch_file(mocker):
    """
    Given:
        - Two domains.
        - TIM pages from test_data/mock_domain_tim_results.json
        - Batch results from test_data/mock_domain_batch_results.json
    When:
        - domain_enrichment_script runs end-to-end.
    Then:
        - DomainEnrichment contains both domains.
        - For example.com:
            * Results has 2 entries (brand1, brand2) — TIM is summarized via TIMScore/Status.
            * MaxScore=3, MaxVerdict=Malicious, TIMScore=3.
        - Core prevalence mapped under 'Core.AnalyticsPrevalence.Domain'.
        - (No DBotScore assertions; current code does not surface DBotScore from enrichIndicators or TIM.)
    """
    # Load fixtures
    tim_pages = util_load_json("test_data/mock_domain_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_domain_batch_results.json")

    domain_list = ["example.com", "example2.com"]
    mocker.patch.object(demisto, "args", return_value={"domain_list": ",".join(domain_list)})

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

    # Helper: wrap raw entries into processed tuples: [(entry, hr, err)]
    def _wrap_each_as_command(entries, hr=""):
    # N commands, each with 1 entry
        return [[(e, hr, "")] for e in entries]

    def _wrap_all_in_one_command(entries, hr=""):
        # 1 command that yields N entries
        return [[(e, hr, "") for e in entries]]

    # Batch executor -> map fixtures to command batches
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # ----- Batch 1: createNewIndicator -----
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]

        if len(b1_cmds) == 1:
            # aggregated: one command returns two entries
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            # per-domain: N commands, each returns one entry
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
            # aggregated: one enrichIndicators command yields multiple entries
            batch2_results.extend(_wrap_all_in_one_command(enrich_entries))
        else:
            # per-domain: one command per entry
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
    enrichment_list = outputs.get("DomainEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(domain_list)

    ex1 = enrichment_map["example.com"]
    # TIM is summarized (TIMScore/Status), not included in Results
    assert len(ex1["Results"]) == 2  # brand1 + brand2

    b1 = next(r for r in ex1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5

    # Max fields and TIMScore
    assert ex1["MaxScore"] == 3
    assert ex1["MaxVerdict"] == "Malicious"
    assert ex1["TIMScore"] == 3

    # Core prevalence mapped
    core_ctx = outputs.get("Core.AnalyticsPrevalence.Domain", [])
    assert isinstance(core_ctx, list)
    assert len(core_ctx) == 2
    assert {d["Domain"] for d in core_ctx} == {"example.com", "example2.com"}
