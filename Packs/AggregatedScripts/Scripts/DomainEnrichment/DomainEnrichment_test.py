import json
import pytest
import demistomock as demisto
from CommonServerPython import Common
from DomainEnrichment import domain_enrichment_script  # <-- adjust if your file name differs


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------------------
# 1) Validation tests (validate_input is invoked inside AggregatedCommand.run())
# --------------------------------------------------------------------------------------


def test_validate_input_success(mocker):
    domain_list = ["example.com", "example2.com"]
    mocker.patch.object(demisto, "args", return_value={"domain_list": ",".join(domain_list)})

    # extractIndicators returns both domains
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"Domain": domain_list}}}],
    )

    # No-op the rest of the pipeline
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    res = domain_enrichment_script(
        domain_list=domain_list,
        external_enrichment=False,
        verbose=False,
        enrichment_brands=[],
        additional_fields=False,
    )
    assert res is not None


def test_validate_input_invalid_domain(mocker):
    domain_list = ["example.com", "8.8.8.8"]  # invalid for Domain type
    mocker.patch.object(demisto, "args", return_value={"domain_list": ",".join(domain_list)})

    # Only the valid domain is extracted -> should raise
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"Domain": ["example.com"]}}}],
    )

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    with pytest.raises(ValueError, match=r"are not valid domain"):
        domain_enrichment_script(
            domain_list=domain_list,
            external_enrichment=False,
            verbose=False,
            enrichment_brands=[],
            additional_fields=False,
        )


# --------------------------------------------------------------------------------------
# 2) End-to-end: TIM + core analytics + enrichIndicators (batch data from file)
# --------------------------------------------------------------------------------------


def test_domain_enrichment_script_end_to_end_with_batch_file(mocker):
    # Load TIM pages + batch entries from fixtures
    tim_pages = util_load_json("test_data/mock_domain_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_domain_batch_results.json")

    domain_list = ["example.com", "example2.com"]
    mocker.patch.object(demisto, "args", return_value={"domain_list": ",".join(domain_list)})

    # Validation: extractIndicators returns both domains
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"Domain": domain_list}}}],
    )

    # Mock IndicatorsSearcher to yield our TIM pages
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

    # Helper to wrap raw entries to the processed tuple shape: [(entry, hr, err)]
    def _wrap(entries, hr=""):
        return [[(e, hr, "")] for e in entries]

    # Mock executor: map file arrays to the command batches by order
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 1: createNewIndicator (one per domain)
        b1_expected = len(list_of_batches[0])
        b1_entries = batch_data["batch1_createNewIndicator"]
        assert len(b1_entries) == b1_expected, "batch1 size mismatch vs fixture"
        out.append(_wrap(b1_entries))

        # Batch 2: first core analytics (single), then enrichIndicators per domain
        b2_cmds = list_of_batches[1]
        assert b2_cmds[0].name == "core-get-domain-analytics-prevalence"
        core_entries = batch_data["batch2_core"]
        assert len(core_entries) == 1, "expected one core analytics entry"
        batch2_results = _wrap(core_entries, hr="core-hr")

        enrich_entries = batch_data["batch2_enrichIndicators"]
        # enrichIndicators count should match number of remaining commands in batch2
        assert len(enrich_entries) == (len(b2_cmds) - 1), "enrichIndicators size mismatch vs fixture"
        batch2_results.extend(_wrap(enrich_entries))
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

    # Assert: DomainEnrichment indicators
    enrichment_list = outputs.get("DomainEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(domain_list)

    ex1 = enrichment_map["example.com"]
    assert len(ex1["Results"]) == 3  # TIM + brand1 + brand2

    b1 = next(r for r in ex1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5

    assert ex1["MaxScore"] == 3
    assert ex1["MaxVerdict"] == "Malicious"
    assert ex1["TIMScore"] == 3

    core_ctx = outputs.get("Core.AnalyticsPrevalence.Domain", [])
    assert isinstance(core_ctx, list)
    assert len(core_ctx) == 2
    assert {d["Domain"] for d in core_ctx} == {"example.com", "example2.com"}

    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    vendors = {s.get("Vendor") for s in dbot_scores}
    assert vendors == {"brand1", "brand2", "brand3"}
