import json
import pytest
import demistomock as demisto
from CommonServerPython import Common
from CVEEnrichment import cve_enrichment_script  # <-- adjust if your file name differs


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------------------
# 1) Validation tests (validate_input is invoked inside AggregatedCommand.run())
# --------------------------------------------------------------------------------------


def test_validate_input_success(mocker):
    """
    Given:
        - Valid CVE list.
        - extractIndicators returns both under ExtractedIndicators.CVE.
    When:
        - cve_enrichment_script runs.
    Then:
        - No exception is raised.
    """
    cve_list = ["CVE-2024-0001", "CVE-2023-9999"]
    mocker.patch.object(demisto, "args", return_value={"cve_list": ",".join(cve_list)})

    # Patch extractIndicators via the execute_command wrapper
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"CVE": cve_list}}}],
    )

    # Make the pipeline a no-op beyond validation
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    res = cve_enrichment_script(
        cve_list=cve_list,
        external_enrichment=False,
        verbose=False,
        enrichment_brands=[],
        additional_fields=False,
    )
    assert res is not None


def test_validate_input_invalid_cve(mocker):
    """
    Given:
        - A list with an invalid item ("NOT-A-CVE").
        - extractIndicators only returns the valid CVE.
    When:
        - cve_enrichment_script runs.
    Then:
        - ValueError is raised by validate_input.
    """
    cve_list = ["CVE-2024-0001", "NOT-A-CVE"]
    mocker.patch.object(demisto, "args", return_value={"cve_list": ",".join(cve_list)})

    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"CVE": ["CVE-2024-0001"]}}}],
    )

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    with pytest.raises(ValueError, match=r"are not valid cve"):
        cve_enrichment_script(
            cve_list=cve_list,
            external_enrichment=False,
            verbose=False,
            enrichment_brands=[],
            additional_fields=False,
        )


# --------------------------------------------------------------------------------------
# 2) End-to-end: TIM + enrichIndicators (batch data from file)
# --------------------------------------------------------------------------------------


def test_cve_enrichment_script_end_to_end_with_batch_file(mocker):
    """
    Given:
        - Two CVEs.
        - TIM returns:
            * CVE-2024-0001 with TIM cvss 7.5, brand1 cvss {"Score": 9.8}, brand2 cvss "High"
            * CVE-2023-9999 with TIM cvss 1.2, brand3 cvss 1.0
        - Batches:
            * createNewIndicator (no-op)
            * enrichIndicators per CVE (DBotScore only for CVE-2024-0001 / brand1)
    When:
        - cve_enrichment_script runs end-to-end.
    Then:
        - CVEEnrichment contains both CVEs.
        - For CVE-2024-0001:
            * Results include TIM + brand1 + brand2 (3 items)
            * MaxCVSS = 9.8 and MaxSeverity = "Critical"
            * No MaxScore/MaxVerdict/TIMScore (Score not in mapping)
        - DBotScore vendors across both = {"brand1","brand2","brand3"}.
    """
    tim_pages = util_load_json("test_data/mock_cve_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_cve_batch_results.json")

    cve_list = ["CVE-2024-0001", "CVE-2023-9999"]
    mocker.patch.object(demisto, "args", return_value={"cve_list": ",".join(cve_list)})

    # Validation: extractIndicators returns both CVEs
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"CVE": cve_list}}}],
    )

    # IndicatorsSearcher -> TIM pages
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

    # Helper: wrap raw entries into processed tuple shape [(entry, hr, err)]
    def _wrap(entries, hr=""):
        return [[(e, hr, "")] for e in entries]

    # Batch executor mock (aligns fixture arrays to command batches)
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 1: createNewIndicator per CVE
        b1_expected = len(list_of_batches[0])
        b1_entries = batch_data["batch1_createNewIndicator"]
        assert len(b1_entries) == b1_expected, "batch1 size mismatch vs fixture"
        out.append(_wrap(b1_entries))

        # Batch 2: enrichIndicators per CVE
        b2_cmds = list_of_batches[1]
        enrich_entries = batch_data["batch2_enrichIndicators"]
        assert len(enrich_entries) == len(b2_cmds), "enrichIndicators size mismatch vs fixture"
        out.append(_wrap(enrich_entries))
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

    # Assert: CVEEnrichment indicators
    enrichment_list = outputs.get("CVEEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(cve_list)

    cve1 = enrichment_map["CVE-2024-0001"]
    # TIM + brand1 + brand2
    assert len(cve1["Results"]) == 3

    # MaxCVSS/MaxSeverity computed (Score not mapped => MaxScore absent)
    assert cve1.get("MaxScore") is None  # should not exist / be None after cleanup
    assert "MaxVerdict" not in cve1
    assert "TIMScore" not in cve1
    assert cve1["MaxCVSS"] == 9.8
    assert cve1["MaxSeverity"] == "Critical"

    # DBotScore vendors exactly brand1, brand2, brand3 (from TIM + batch)
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    vendors = {s.get("Vendor") for s in dbot_scores}
    assert vendors == {"brand1", "brand2", "brand3"}
