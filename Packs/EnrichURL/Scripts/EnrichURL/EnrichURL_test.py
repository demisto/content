import json

import demistomock as demisto
from CommonServerPython import CommandResults, DemistoException

from EnrichURL import main, url_enrichment_script


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
# Test 1: Happy path — two valid URLs, end-to-end enrichment
# ---------------------------------------------------------------------------

def test_url_enrichment_happy_path(mocker):
    """
    Given:
        - Two URLs: https://example.com and https://malicious.test/path.
        - create_and_extract_indicators_batch returns both as valid.
        - TIM returns score data for both URLs.
        - Batch commands execute successfully.
    When:
        - url_enrichment_script runs end-to-end.
    Then:
        - URLEnrichment contains both URLs.
        - https://example.com has TIM + brand1 + brand2 results.
        - MaxScore, MaxVerdict, TIMScore are correct for https://example.com.
    """
    tim_pages = util_load_json("test_data/mock_url_tim_results.json")["pages"]
    batch_data = util_load_json("test_data/mock_url_batch_results.json")

    url_list = ["https://example.com", "https://malicious.test/path"]
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # Mock create_and_extract_indicators_batch to return valid URLs
    mocker.patch("EnrichURL.create_and_extract_indicators_batch", return_value=url_list)

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

        # Batch 2: enrichIndicators
        b2_cmds = list_of_batches[1]
        batch2_results = []

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
    res = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2"],
        additional_fields=False,
    )
    assert res is not None
    outputs = res.outputs
    assert outputs is not None

    # URLEnrichment indicators
    enrichment_list = outputs.get("URLEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(url_list)

    # https://example.com should have TIM + brand1 + brand2
    url1 = enrichment_map["https://example.com"]
    brands_present = {r.get("Brand") for r in url1["Results"]}
    assert brands_present == {"TIM", "brand1", "brand2"}
    assert len(url1["Results"]) == 3

    # Vendor results with reliability
    b1 = next(r for r in url1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5
    assert b1.get("Reliability") == "High"

    b2 = next(r for r in url1["Results"] if r["Brand"] == "brand2")
    assert b2["Score"] == 3
    assert b2["PositiveDetections"] == 37
    assert b2.get("Reliability") == "Medium"

    # TIM line present but without Status/ModifiedTime (popped to top-level)
    tim_row = next(r for r in url1["Results"] if r["Brand"] == "TIM")
    assert "Status" not in tim_row
    assert "ModifiedTime" not in tim_row

    # Max fields and TIMScore
    assert url1["MaxScore"] == 3
    assert url1["MaxVerdict"] == "Malicious"
    assert url1["TIMScore"] == 3

    # Status should be Manual (manuallyEditedFields set)
    assert url1.get("Status") == "Manual"


# ---------------------------------------------------------------------------
# Test 2: No valid indicators — create_and_extract_indicators_batch returns []
# ---------------------------------------------------------------------------

def test_url_enrichment_no_valid_indicators(mocker):
    """
    Given:
        - create_and_extract_indicators_batch returns an empty list (no valid URLs).
    When:
        - url_enrichment_script is called.
    Then:
        - The function returns None.
        - return_results is called with a friendly message (not an error).
    """
    mocker.patch("EnrichURL.create_and_extract_indicators_batch", return_value=[])
    mock_return_results = mocker.patch("EnrichURL.return_results")

    result = url_enrichment_script(url_list=["not-a-url"])

    assert result is None
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert call_args.readable_output == "No valid URL indicators were found in the provided input."


# ---------------------------------------------------------------------------
# Test 3: extractIndicators failure — DemistoException raised
# ---------------------------------------------------------------------------

def test_url_enrichment_extract_indicators_failure(mocker):
    """
    Given:
        - create_and_extract_indicators_batch raises a DemistoException.
    When:
        - main() is called.
    Then:
        - return_error is called with the error message.
    """
    mocker.patch.object(
        demisto, "args", return_value={"url_list": "https://example.com"}
    )
    mocker.patch(
        "EnrichURL.create_and_extract_indicators_batch",
        side_effect=DemistoException("Failed to validate input using extractIndicators."),
    )
    mock_return_error = mocker.patch("EnrichURL.return_error")

    main()

    mock_return_error.assert_called_once()
    error_msg = mock_return_error.call_args[0][0]
    assert "Failed to execute !url-enrichment" in error_msg
    assert "Failed to validate input using extractIndicators" in error_msg


# ---------------------------------------------------------------------------
# Test 4: Empty input — no URLs provided
# ---------------------------------------------------------------------------

def test_url_enrichment_empty_input(mocker):
    """
    Given:
        - Empty url_list argument (no URLs provided).
    When:
        - url_enrichment_script is called with an empty list.
    Then:
        - create_and_extract_indicators_batch is called with an empty list.
        - The function returns None (batch function returns [] for empty input).
        - return_results is called with a friendly message.
    """
    mocker.patch("EnrichURL.create_and_extract_indicators_batch", return_value=[])
    mock_return_results = mocker.patch("EnrichURL.return_results")

    result = url_enrichment_script(url_list=[])

    assert result is None
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert call_args.readable_output == "No valid URL indicators were found in the provided input."


# ---------------------------------------------------------------------------
# Test 5: Multiple URLs — all enriched
# ---------------------------------------------------------------------------

def test_url_enrichment_multiple_urls(mocker):
    """
    Given:
        - Multiple URLs to enrich.
        - create_and_extract_indicators_batch returns all of them as valid.
    When:
        - url_enrichment_script runs.
    Then:
        - All URLs appear in the URLEnrichment output.
        - The CreateNewIndicatorsOnly batch is called with all valid URL values.
    """
    batch_data = util_load_json("test_data/mock_url_batch_results.json")
    url_list = ["https://example.com", "https://another.example.org/page", "http://third.example.net"]

    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})
    mocker.patch("EnrichURL.create_and_extract_indicators_batch", return_value=url_list)

    # TIM returns no rich data — only minimal entries
    tim_pages = [
        {
            "iocs": [
                {
                    "value": url,
                    "score": 0,
                    "CustomFields": {"data": url},
                    "insightCache": {"scores": {}},
                }
                for url in url_list
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
            "m1": {"state": "active", "brand": "brand1"},
        },
    )

    captured_batches: dict = {}

    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        captured_batches["list_of_batches"] = list_of_batches
        out = []

        # Batch 1: createNewIndicator
        b1_cmds = list_of_batches[0]
        b1_entries = batch_data["batch1_createNewIndicator"]
        if len(b1_cmds) == 1:
            out.append(_wrap_all_in_one_command(b1_entries))
        else:
            out.append(_wrap_each_as_command(b1_entries))

        # Batch 2: enrichIndicators
        b2_cmds = list_of_batches[1]
        batch2_results = []
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

    res = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=False,
        enrichment_brands=["brand1"],
        additional_fields=False,
    )
    assert res is not None
    outputs = res.outputs
    assert outputs is not None

    # All URLs should appear in URLEnrichment output
    enrichment_list = outputs.get("URLEnrichment(val.Value && val.Value == obj.Value)", [])
    enrichment_values = {item["Value"] for item in enrichment_list}
    assert enrichment_values == set(url_list)

    # The CreateNewIndicatorsOnly batch should have been called with all valid URLs
    create_indicator_cmd = captured_batches["list_of_batches"][0][0]
    assert create_indicator_cmd.name == "CreateNewIndicatorsOnly"
    assert create_indicator_cmd.args["type"] == "URL"
    assert set(create_indicator_cmd.args["indicator_values"]) == set(url_list)


# ---------------------------------------------------------------------------
# Test 6: main() happy path — verifies return_results is called with result
# ---------------------------------------------------------------------------

def test_main_happy_path(mocker):
    """
    Given:
        - Valid args with one URL.
        - url_enrichment_script returns a CommandResults object.
    When:
        - main() is called.
    Then:
        - return_results is called with the CommandResults.
        - return_error is NOT called.
    """
    mocker.patch.object(
        demisto, "args",
        return_value={"url_list": "https://example.com", "external_enrichment": "false", "verbose": "false"},
    )

    mock_cmd_results = CommandResults(readable_output="test output")
    mocker.patch("EnrichURL.url_enrichment_script", return_value=mock_cmd_results)
    mock_return_results = mocker.patch("EnrichURL.return_results")
    mock_return_error = mocker.patch("EnrichURL.return_error")

    main()

    mock_return_results.assert_called_once_with(mock_cmd_results)
    mock_return_error.assert_not_called()


# ---------------------------------------------------------------------------
# Test 7: main() when url_enrichment_script returns None (no valid indicators)
# ---------------------------------------------------------------------------

def test_main_no_valid_indicators_does_not_call_return_results(mocker):
    """
    Given:
        - url_enrichment_script returns None (no valid indicators found).
    When:
        - main() is called.
    Then:
        - return_results is NOT called from main() (it was already called inside
          url_enrichment_script).
        - return_error is NOT called.
    """
    mocker.patch.object(
        demisto, "args",
        return_value={"url_list": "not-a-url"},
    )
    mocker.patch("EnrichURL.url_enrichment_script", return_value=None)
    mock_return_results = mocker.patch("EnrichURL.return_results")
    mock_return_error = mocker.patch("EnrichURL.return_error")

    main()

    mock_return_results.assert_not_called()
    mock_return_error.assert_not_called()
