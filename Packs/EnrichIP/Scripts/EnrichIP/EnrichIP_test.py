import json
from unittest.mock import patch

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException

from EnrichIP import ip_enrichment_script, main


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Helpers for shaping BatchExecutor output into (result, hr, err) tuples
# ---------------------------------------------------------------------------

def _wrap_each_as_command(entries: list[dict], hr: str = "") -> list[list[tuple]]:
    return [[(e, hr, "")] for e in entries]


def _wrap_all_in_one_command(entries: list[dict], hr: str = "") -> list[list[tuple]]:
    return [[(e, hr, "") for e in entries]]


# ---------------------------------------------------------------------------
# Test 1: Happy path — two valid IPs, end-to-end enrichment
# ---------------------------------------------------------------------------

def test_ip_enrichment_happy_path(mocker):
    """
    Given:
        - Two IPs: 1.1.1.1 and 8.8.8.8.
        - create_and_extract_indicators_batch returns both as valid.
        - TIM returns score data for both IPs.
        - Batch commands execute successfully.
    When:
        - ip_enrichment_script runs end-to-end.
    Then:
        - IPEnrichment contains both IPs.
        - 1.1.1.1 has TIM + brand1 + brand2 results.
        - MaxScore, MaxVerdict, TIMScore are correct for 1.1.1.1.
        - Core prevalence data is mapped and preserved.
    """
    tim_pages = util_load_json("test_data/mock_ip_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_ip_batch_results.json")

    ip_list = ["1.1.1.1", "8.8.8.8"]
    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})

    # Mock create_and_extract_indicators_batch to return valid IPs
    mocker.patch("EnrichIP.create_and_extract_indicators_batch", return_value=ip_list)

    # is_xsiam
    mocker.patch("EnrichIP.is_xsiam", return_value=True)

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

    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 1: createNewIndicator
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]
        if len(b1_cmds) == 1:
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            out.append(_wrap_each_as_command(b1_entries))

        # Batch 2: prevalence + enrichIndicators (no internal IPs → no get-endpoint-data)
        b2_cmds = list_of_batches[1]
        assert "get-endpoint-data" not in [c.name for c in b2_cmds]
        assert b2_cmds[0].name == "core-get-IP-analytics-prevalence"

        batch2_results = []

        prevalence_entries = batch_data["batch2_core_prevalence"]
        batch2_results.extend(_wrap_each_as_command(prevalence_entries, hr="prevalence-hr"))

        enrich_entries = batch_data["batch2_enrichIndicators"]
        enrich_cmds_count = sum(1 for c in b2_cmds if c.name == "enrichIndicators")
        if enrich_cmds_count == 1:
            batch2_results.extend(_wrap_all_in_one_command(enrich_entries))
        else:
            batch2_results.extend(_wrap_each_as_command(enrich_entries))

        out.append(batch2_results)
        return out

    mocker.patch(
        "AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches",
        _fake_execute_list_of_batches,
    )

    # Act
    res = ip_enrichment_script(
        ip_list=ip_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2", "Core", "Cortex Core - IR"],
        additional_fields=False,
    )
    assert res is not None
    outputs = res.outputs
    assert outputs is not None

    # IPEnrichment indicators
    enrichment_list = outputs.get("IPEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(ip_list)

    # 1.1.1.1 should have TIM + brand1 + brand2
    ip1 = enrichment_map["1.1.1.1"]
    brands_present = {r.get("Brand") for r in ip1["Results"]}
    assert brands_present == {"TIM", "brand1", "brand2"}
    assert len(ip1["Results"]) == 3

    # Vendor results with reliability
    b1 = next(r for r in ip1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5
    assert b1.get("Reliability") == "High"

    b2 = next(r for r in ip1["Results"] if r["Brand"] == "brand2")
    assert b2["Score"] == 3
    assert b2["PositiveDetections"] == 37
    assert b2.get("Reliability") == "Medium"

    # TIM line present but without Status/ModifiedTime (popped to top-level)
    tim_row = next(r for r in ip1["Results"] if r["Brand"] == "TIM")
    assert "Status" not in tim_row
    assert "ModifiedTime" not in tim_row

    # Max fields and TIMScore
    assert ip1["MaxScore"] == 3
    assert ip1["MaxVerdict"] == "Malicious"
    assert ip1["TIMScore"] == 3

    # Status should be Manual (manuallyEditedFields set)
    assert ip1.get("Status") == "Manual"

    # Core prevalence mapped
    prevalence_ctx = outputs.get("Core.AnalyticsPrevalence.Ip", [])
    assert isinstance(prevalence_ctx, list)
    assert len(prevalence_ctx) == 2
    assert {d["Ip"] for d in prevalence_ctx} == {"1.1.1.1", "8.8.8.8"}


# ---------------------------------------------------------------------------
# Test 2: No valid indicators — create_and_extract_indicators_batch returns []
# ---------------------------------------------------------------------------

def test_ip_enrichment_no_valid_indicators(mocker):
    """
    Given:
        - create_and_extract_indicators_batch returns an empty list (no valid IPs).
    When:
        - ip_enrichment_script is called.
    Then:
        - The function returns None.
        - return_results is called with a friendly message (not an error).
    """
    mocker.patch("EnrichIP.create_and_extract_indicators_batch", return_value=[])
    mock_return_results = mocker.patch("EnrichIP.return_results")

    result = ip_enrichment_script(ip_list=["not-an-ip"])

    assert result is None
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert call_args.readable_output == "No valid IP indicators were found in the provided input."


# ---------------------------------------------------------------------------
# Test 3: extractIndicators failure — DemistoException raised
# ---------------------------------------------------------------------------

def test_ip_enrichment_extract_indicators_failure(mocker):
    """
    Given:
        - create_and_extract_indicators_batch raises a DemistoException.
    When:
        - main() is called.
    Then:
        - return_error is called with the error message.
    """
    mocker.patch.object(
        demisto, "args", return_value={"ip_list": "1.1.1.1"}
    )
    mocker.patch(
        "EnrichIP.create_and_extract_indicators_batch",
        side_effect=DemistoException("Failed to validate input using extractIndicators."),
    )
    mock_return_error = mocker.patch("EnrichIP.return_error")

    main()

    mock_return_error.assert_called_once()
    error_msg = mock_return_error.call_args[0][0]
    assert "Failed to execute !ip-enrichment" in error_msg
    assert "Failed to validate input using extractIndicators" in error_msg


# ---------------------------------------------------------------------------
# Test 4: Empty input — no IPs provided
# ---------------------------------------------------------------------------

def test_ip_enrichment_empty_input(mocker):
    """
    Given:
        - Empty ip_list argument (no IPs provided).
    When:
        - ip_enrichment_script is called with an empty list.
    Then:
        - create_and_extract_indicators_batch is called with an empty list.
        - The function returns None (batch function returns [] for empty input).
        - return_results is called with a friendly message.
    """
    mocker.patch("EnrichIP.create_and_extract_indicators_batch", return_value=[])
    mock_return_results = mocker.patch("EnrichIP.return_results")

    result = ip_enrichment_script(ip_list=[])

    assert result is None
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert call_args.readable_output == "No valid IP indicators were found in the provided input."


# ---------------------------------------------------------------------------
# Test 5: Multiple IPs — all enriched, including internal IP with endpoint data
# ---------------------------------------------------------------------------

def test_ip_enrichment_multiple_ips_with_internal(mocker):
    """
    Given:
        - One internal IP (192.168.1.1) and one external IP (8.8.8.8).
        - create_and_extract_indicators_batch returns both as valid.
    When:
        - ip_enrichment_script runs.
    Then:
        - get-endpoint-data command is included for the internal IP.
        - EndpointData is mapped and preserved.
        - Both IPs appear in the enrichment output.
    """
    batch_data = util_load_json("test_data/mock_ip_batch_results.json")
    ip_list = ["192.168.1.1", "8.8.8.8"]

    mocker.patch.object(demisto, "args", return_value={"ip_list": ",".join(ip_list)})
    mocker.patch("EnrichIP.create_and_extract_indicators_batch", return_value=ip_list)
    mocker.patch("EnrichIP.is_xsiam", return_value=True)

    # TIM returns data for 8.8.8.8 only
    tim_pages = [
        {
            "iocs": [
                {
                    "value": "8.8.8.8",
                    "score": 1,
                    "CustomFields": {
                        "address": "8.8.8.8",
                        "detectionengines": 10,
                        "positivedetections": 1,
                        "score": 1,
                    },
                    "insightCache": {"scores": {}},
                }
            ]
        }
    ]

    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "core": {"state": "active", "brand": "Core"},
            "coreir": {"state": "active", "brand": "Cortex Core - IR"},
        },
    )

    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 1: createNewIndicator
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]
        if len(b1_cmds) == 1:
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            out.append(_wrap_each_as_command(b1_entries))

        # Batch 2: get-endpoint-data + prevalence + enrichIndicators
        b2_cmds = list_of_batches[1]
        assert b2_cmds[0].name == "get-endpoint-data"

        batch2_results = []

        # Endpoint data
        endpoint_entries = batch_data["batch2_core_endpoint_data"]
        batch2_results.extend(_wrap_each_as_command(endpoint_entries, hr="endpoint-hr"))

        # Prevalence
        prevalence_entries = batch_data["batch2_core_prevalence"]
        batch2_results.extend(_wrap_each_as_command(prevalence_entries, hr="prevalence-hr"))

        # enrichIndicators
        enrich_entries = batch_data["batch2_enrichIndicators"]
        enrich_cmds_count = sum(1 for c in b2_cmds if c.name == "enrichIndicators")
        if enrich_cmds_count == 1:
            batch2_results.extend(_wrap_all_in_one_command(enrich_entries))
        else:
            batch2_results.extend(_wrap_each_as_command(enrich_entries))

        out.append(batch2_results)
        return out

    mocker.patch(
        "AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches",
        _fake_execute_list_of_batches,
    )

    res = ip_enrichment_script(
        ip_list=ip_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["Core", "Cortex Core - IR"],
        additional_fields=False,
    )
    assert res is not None
    outputs = res.outputs
    assert outputs is not None

    # EndpointData should be present
    endpoint_ctx = outputs.get(
        "EndpointData"
        "(val.Brand && val.Brand == obj.Brand && val.ID && val.ID == obj.ID "
        "&& val.Hostname && val.Hostname == obj.Hostname)",
        [],
    )
    assert isinstance(endpoint_ctx, list)
    assert len(endpoint_ctx) == 2
    assert {e["Brand"] for e in endpoint_ctx} == {"Core"}
    assert {e["Hostname"] for e in endpoint_ctx} == {"host-1", "host-2"}


# ---------------------------------------------------------------------------
# Test 6: main() happy path — verifies return_results is called with result
# ---------------------------------------------------------------------------

def test_main_happy_path(mocker):
    """
    Given:
        - Valid args with one IP.
        - ip_enrichment_script returns a CommandResults object.
    When:
        - main() is called.
    Then:
        - return_results is called with the CommandResults.
        - return_error is NOT called.
    """
    mocker.patch.object(
        demisto, "args",
        return_value={"ip_list": "1.1.1.1", "external_enrichment": "false", "verbose": "false"},
    )

    from CommonServerPython import CommandResults
    mock_cmd_results = CommandResults(readable_output="test output")
    mocker.patch("EnrichIP.ip_enrichment_script", return_value=mock_cmd_results)
    mock_return_results = mocker.patch("EnrichIP.return_results")
    mock_return_error = mocker.patch("EnrichIP.return_error")

    main()

    mock_return_results.assert_called_once_with(mock_cmd_results)
    mock_return_error.assert_not_called()


# ---------------------------------------------------------------------------
# Test 7: main() when ip_enrichment_script returns None (no valid indicators)
# ---------------------------------------------------------------------------

def test_main_no_valid_indicators_does_not_call_return_results(mocker):
    """
    Given:
        - ip_enrichment_script returns None (no valid indicators found).
    When:
        - main() is called.
    Then:
        - return_results is NOT called from main() (it was already called inside
          ip_enrichment_script).
        - return_error is NOT called.
    """
    mocker.patch.object(
        demisto, "args",
        return_value={"ip_list": "not-an-ip"},
    )
    mocker.patch("EnrichIP.ip_enrichment_script", return_value=None)
    mock_return_results = mocker.patch("EnrichIP.return_results")
    mock_return_error = mocker.patch("EnrichIP.return_error")

    main()

    mock_return_results.assert_not_called()
    mock_return_error.assert_not_called()
