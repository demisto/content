import json
import demistomock as demisto
from FileEnrichment import file_enrichment_script


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_file_enrichment_script_end_to_end_with_files(mocker):
    """
    Given:
        - Two file hashes (both SHA256).
        - TIM file results from test_data/mock_file_tim_results.json.
        - Batch results from test_data/mock_file_batch_results.json (create + enrich + core-get-hash-analytics-prevalence).
    When:
        - file_enrichment_script runs end-to-end (external_enrichment=True).
    Then:
        - FileEnrichmentV2 contains both hashes.
        - For file1:
            * Results has 2 entries (TIM + WildFire-v2).
            * Hashes contain MD5 + SHA256.
            * TIMScore=3, MaxScore=3, MaxVerdict=Malicious.
            * Top-level Status == "Manual" (due to manuallyEditedFields.Score).
            * TIM row in Results has NO Status/ModifiedTime (popped to top-level).
        - For file2:
            * Results has 2 entries (TIM + WildFire-v2), reliability Low.
    """
    # ---------- Load fixtures ----------
    tim_pages = util_load_json("test_data/mock_file_tim_results.json")["pages"]
    batch_blob = util_load_json("test_data/mock_file_batch_results.json")

    file_list = [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # file1 SHA256
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",  # file2 SHA256
    ]

    mocker.patch.object(demisto, "args", return_value={"file_hash": ",".join(file_list)})

    # ---------- Mock execute_command ONLY for extractIndicators ----------
    def extractIndicators_side_effect(cmd, args=None, extract_contents=False, fail_on_error=True):
        if cmd == "extractIndicators":
            return [{"EntryContext": {"ExtractedIndicators": {"File": file_list}}}]
        return []

    mocker.patch("AggregatedCommandApiModule.execute_command", side_effect=extractIndicators_side_effect)

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
            "wf": {"state": "active", "brand": "WildFire-v2"},
            "core": {"state": "active", "brand": "Cortex Core - IR"},
        },
    )

    # ---------- Mock BatchExecutor.execute_list_of_batches using JSON ----------
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        create_items = list(batch_blob.get("createNewIndicator", []))
        enrich_items = list(batch_blob.get("enrichIndicators", []))
        core_items = list(batch_blob.get("coreGetHashAnalyticsPrevalence", []))

        # Batch 0: CreateNewIndicatorsOnly
        batch0_cmds = list_of_batches[0]
        batch0_results = []
        for _ in batch0_cmds:
            item = create_items.pop(0) if create_items else {"Type": 1, "EntryContext": {}}
            batch0_results.append([(item, "", "")])
        out.append(batch0_results)

        # Batch 1: enrichIndicators + core-get-hash-analytics-prevalence (one per SHA256)
        batch1_cmds = list_of_batches[1]
        batch1_results = []
        for cmd in batch1_cmds:
            if cmd.name == "enrichIndicators":
                items = enrich_items or [{"Type": 1, "EntryContext": {}, "Metadata": {"brand": "WildFire-v2"}}]
                batch1_results.append([(e, "", "") for e in items])
            elif cmd.name == "core-get-hash-analytics-prevalence":
                item = (
                    core_items.pop(0)
                    if core_items
                    else {
                        "Type": 1,
                        "EntryContext": {},
                        "Metadata": {"brand": "Cortex Core - IR"},
                    }
                )
                batch1_results.append([(item, "", "")])
            else:
                batch1_results.append([({"Type": 1, "EntryContext": {}}, "", "")])
        out.append(batch1_results)

        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # ---------- Act ----------
    command_results = file_enrichment_script(
        file_list=file_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["WildFire-v2"],
        additional_fields=False,
    )
    outputs = command_results.outputs

    # ---------- Assert: FileEnrichmentV2 indicators ----------
    enrichment_key = "FileEnrichment(val.Value && val.Value == obj.Value)"
    enrichment_list = outputs.get(enrichment_key, [])
    assert len(enrichment_list) == 2

    enrichment_map = {item["Value"]: item for item in enrichment_list}
    # In this scenario, Value will be the canonical TIM "value" (sha256) → same as file_list
    assert set(enrichment_map.keys()) == set(file_list)

    # ---- file1 assertions ----
    f1 = enrichment_map[file_list[0]]
    brands_present_f1 = {r.get("Brand") for r in f1["Results"]}
    assert brands_present_f1 == {"TIM", "WildFire-v2"}
    assert len(f1["Results"]) == 2

    # Hashes aggregated from TIM indicator
    hashes1 = f1.get("Hashes", {})
    assert hashes1.get("MD5") is not None
    assert hashes1.get("SHA256") == file_list[0]

    # TIM row present but without Status/ModifiedTime (popped to top-level)
    tim_row_f1 = next(r for r in f1["Results"] if r["Brand"] == "TIM")
    assert "Status" not in tim_row_f1
    assert "ModifiedTime" not in tim_row_f1

    # Top-level scores & status
    assert f1["TIMScore"] == 3
    assert f1["MaxScore"] == 3
    assert f1["MaxVerdict"] == "Malicious"
    assert f1["Status"] == "Manual"  # due to manuallyEditedFields.Score in TIM IOC

    # ---- file2 assertions ----
    f2 = enrichment_map[file_list[1]]
    brands_present_f2 = {r.get("Brand") for r in f2["Results"]}
    assert brands_present_f2 == {"TIM", "WildFire-v2"}
    assert len(f2["Results"]) == 2

    wf2 = next(r for r in f2["Results"] if r["Brand"] == "WildFire-v2")
    assert wf2["Score"] == 1
    assert wf2.get("Reliability") == "Low"
