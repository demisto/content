import json
import pytest
import demistomock as demisto
from CommonServerPython import Common
from IPEnrichment import ip_enrichment_script  # <-- adjust if your file is named differently


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------------------
# 1) Validation tests (validate_input is invoked inside AggregatedCommand.run())
# --------------------------------------------------------------------------------------


def test_validate_input_success(mocker):
    """
    Given:
        - A valid IP list.
        - extractIndicators returns both IPs under ExtractedIndicators.IP.
    When:
        - ip_enrichment_script is executed.
    Then:
        - No exception is raised.
    """
    ip_list = ["1.1.1.1", "8.8.8.8"]

    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})

    # Patch extractIndicators (via AggregatedCommandApiModule.execute_command)
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"IP": ip_list}}}],
    )

    # No-op the rest of the pipeline
    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    res = ip_enrichment_script(
        ip_list=ip_list,
        external_enrichment=False,
        verbose=False,
        enrichment_brands=[],
        additional_fields=False,
    )
    assert res is not None


def test_validate_input_invalid_ip(mocker):
    """
    Given:
        - A list containing an invalid item for IP type (e.g., a domain).
        - extractIndicators returns only the valid IP.
    When:
        - ip_enrichment_script is executed.
    Then:
        - ValueError is raised by validate_input.
    """
    ip_list = ["1.1.1.1", "example.com"]  # invalid for IP
    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})

    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"IP": ["1.1.1.1"]}}}],
    )

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", return_value=[])

    class _EmptySearcher:
        def __iter__(self):
            return iter([])

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_EmptySearcher())
    mocker.patch.object(demisto, "getModules", return_value={})

    with pytest.raises(ValueError, match=r"are not valid ip"):
        ip_enrichment_script(
            ip_list=ip_list,
            external_enrichment=False,
            verbose=False,
            enrichment_brands=[],
            additional_fields=False,
        )


# --------------------------------------------------------------------------------------
# 2) End-to-end: TIM + Core lookups + enrichIndicators (batch data from file)
# --------------------------------------------------------------------------------------


def test_ip_enrichment_script_end_to_end_with_batch_file(mocker):
    """
    Given:
        - Two IPs.
        - TIM returns:
            * 1.1.1.1 with TIM score 3, brand2 score 3, brand1 score 2
            * 8.8.8.8 with TIM score 1, brand3 score 1
        - Batches:
            * createNewIndicator (no-op outputs)
            * get-endpoint-data (EndpointData passthrough)
            * core-get-IP-analytics-prevalence (Core.AnalyticsPrevalence.Ip)
            * enrichIndicators per IP (brand1 DBotScore for 1.1.1.1 only)
    When:
        - ip_enrichment_script runs end-to-end.
    Then:
        - IPEnrichment contains both IPs.
        - 1.1.1.1 has 3 Results items (TIM + brand1 + brand2).
        - MaxScore=3, MaxVerdict=Malicious, TIMScore=3 for 1.1.1.1.
        - EndpointData and Core prevalence are mapped/preserved.
        - DBotScore vendors are exactly brand1, brand2, brand3.
    """
    tim_pages = util_load_json("test_data/mock_ip_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_ip_batch_results.json")

    ip_list = ["1.1.1.1", "8.8.8.8"]
    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})

    # Validation: extractIndicators returns both IPs
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"IP": ip_list}}}],
    )

    # Mock IndicatorsSearcher to yield our TIM pages
    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))

    # Enabled brands/instances
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            "core": {"state": "active", "brand": "Core"},
            "coreir": {"state": "active", "brand": "Cortex Core - IR"},
        },
    )

    # Helper to wrap raw entries to processed tuple shape: [(entry, hr, err)]
    def _wrap(entries, hr=""):
        return [[(e, hr, "")] for e in entries]

    # Mock executor: map file arrays to batches/commands by order
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 1: createNewIndicator (one per IP)
        b1_expected = len(list_of_batches[0])
        b1_entries = batch_data["batch1_createNewIndicator"]
        assert len(b1_entries) == b1_expected, "batch1 size mismatch vs fixture"
        out.append(_wrap(b1_entries))

        # Batch 2: get-endpoint-data, core-get-IP-analytics-prevalence, then enrichIndicators per IP
        b2_cmds = list_of_batches[1]
        assert b2_cmds[0].name == "get-endpoint-data"
        assert b2_cmds[1].name == "core-get-IP-analytics-prevalence"

        endpoint_entries = batch_data["batch2_core_endpoint_data"]
        assert len(endpoint_entries) == 1, "expected one get-endpoint-data entry"
        batch2_results = _wrap(endpoint_entries, hr="endpoint-hr")

        prevalence_entries = batch_data["batch2_core_prevalence"]
        assert len(prevalence_entries) == 1, "expected one prevalence entry"
        batch2_results.extend(_wrap(prevalence_entries, hr="prevalence-hr"))

        enrich_entries = batch_data["batch2_enrichIndicators"]
        assert len(enrich_entries) == (len(b2_cmds) - 2), "enrichIndicators size mismatch vs fixture"
        batch2_results.extend(_wrap(enrich_entries))

        out.append(batch2_results)
        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # Act
    res = ip_enrichment_script(
        ip_list=ip_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "Core", "Cortex Core - IR"],
        additional_fields=False,
    )
    outputs = res.outputs

    # Assert: IPEnrichment indicators
    enrichment_list = outputs.get("IPEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(ip_list)

    # 1.1.1.1 should have TIM + brand1 + brand2
    ip1 = enrichment_map["1.1.1.1"]
    assert len(ip1["Results"]) == 3

    b1 = next(r for r in ip1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5

    assert ip1["MaxScore"] == 3
    assert ip1["MaxVerdict"] == "Malicious"
    assert ip1["TIMScore"] == 3

    # EndpointData passthrough
    endpoint_ctx = outputs.get(
        "EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID && val.Hostname && val.Hostname == obj.Hostname)",  # noqa: E501
        [],
    )
    assert isinstance(endpoint_ctx, list)
    assert len(endpoint_ctx) == 2
    assert {e["Brand"] for e in endpoint_ctx} == {"Core"}
    assert {e["Hostname"] for e in endpoint_ctx} == {"host-1", "host-2"}

    # Core prevalence mapped
    prevalence_ctx = outputs.get("Core.AnalyticsPrevalence.Ip", [])
    assert isinstance(prevalence_ctx, list)
    assert len(prevalence_ctx) == 2
    assert {d["Ip"] for d in prevalence_ctx} == {"1.1.1.1", "8.8.8.8"}

    # DBotScore vendors exactly brand1, brand2, brand3
    dbot_scores = outputs.get(Common.DBotScore.CONTEXT_PATH, [])
    vendors = {s.get("Vendor") for s in dbot_scores}
    assert vendors == {"brand1", "brand2", "brand3"}
