import json
import demistomock as demisto
from IPEnrichment import ip_enrichment_script  # <-- adjust if your file is named differently


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# End-to-end: TIM + Core lookups + enrichIndicators (batch data from file)
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
            * enrichIndicators per IP (brand1 DBotScore for 1.1.1.1 only; not surfaced by current mapping)
    When:
        - ip_enrichment_script runs end-to-end.
    Then:
        - IPEnrichment contains both IPs.
        - 1.1.1.1 has 2 Results items (brand1 + brand2). TIM is summarized via TIMScore.
        - MaxScore=3, MaxVerdict=Malicious, TIMScore=3 for 1.1.1.1.
        - EndpointData and Core prevalence are mapped/preserved.
        - (No DBotScore vendor assertions; not surfaced by current script.)
    """
    tim_pages = util_load_json("test_data/mock_ip_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_ip_batch_results.json")

    ip_list = ["1.1.1.1", "8.8.8.8"]
    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})

    # extractIndicators -> validates input
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": {"IP": ip_list}}}],
    )

    # IndicatorsSearcher -> yield TIM pages
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

    # Wrap raw entries into processed tuples: [(entry, hr, err)]
    # helpers
    def _wrap_each_as_command(entries, hr=""):
        # returns N commands, each with 1 entry
        return [[(e, hr, "")] for e in entries]

    def _wrap_all_in_one_command(entries, hr=""):
        # returns 1 command, with N entries
        return [[(e, hr, "") for e in entries]]

    # Batch executor -> map fixtures to command batches
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # ----- Batch 1: createNewIndicator -----
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]

        if len(b1_cmds) == 1:
            # aggregated: one command that yields both entries
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            # per-IP: one command per entry
            assert len(b1_entries) == len(b1_cmds), "batch1 size mismatch vs fixture"
            out.append(_wrap_each_as_command(b1_entries))

        # ----- Batch 2: endpoint, prevalence, enrichIndicators -----
        b2_cmds = list_of_batches[1]
        assert b2_cmds[0].name == "get-endpoint-data"
        assert b2_cmds[1].name == "core-get-IP-analytics-prevalence"

        batch2_results = []

        endpoint_entries = batch_data["batch2_core_endpoint_data"]
        assert len(endpoint_entries) == 1, "expected one get-endpoint-data entry"
        batch2_results.extend(_wrap_each_as_command(endpoint_entries, hr="endpoint-hr"))

        prevalence_entries = batch_data["batch2_core_prevalence"]
        assert len(prevalence_entries) == 1, "expected one prevalence entry"
        batch2_results.extend(_wrap_each_as_command(prevalence_entries, hr="prevalence-hr"))

        enrich_entries = batch_data["batch2_enrichIndicators"]
        enrich_cmds_count = sum(1 for c in b2_cmds if c.name == "enrichIndicators")

        if enrich_cmds_count == 1:
            # aggregated: one enrichIndicators command with multiple entries
            batch2_results.extend(_wrap_all_in_one_command(enrich_entries))
        else:
            # per-IP: one enrichIndicators command per entry
            assert len(enrich_entries) == enrich_cmds_count, "enrichIndicators size mismatch vs fixture"
            batch2_results.extend(_wrap_each_as_command(enrich_entries))

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

    # IPEnrichment indicators
    enrichment_list = outputs.get("IPEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(ip_list)

    # 1.1.1.1 should have brand1 + brand2 (TIM is summarized)
    ip1 = enrichment_map["1.1.1.1"]
    assert len(ip1["Results"]) == 2

    b1 = next(r for r in ip1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5

    # Max fields and TIMScore
    assert ip1["MaxScore"] == 3
    assert ip1["MaxVerdict"] == "Malicious"
    assert ip1["TIMScore"] == 3

    # EndpointData passthrough
    endpoint_ctx = outputs.get(
        "EndpointData(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID "
        "&& val.Hostname && val.Hostname == obj.Hostname)",
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
