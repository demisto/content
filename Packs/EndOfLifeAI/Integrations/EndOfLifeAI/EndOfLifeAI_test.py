"""Unit tests for the endoflife.ai integration.

All HTTP traffic is mocked with requests-mock: no test reaches the network.
The files in test_data are answers of the endoflife.ai API in the shape the API returns them.
"""

import json
import re
from pathlib import Path
from typing import Any

import demistomock as demisto
import pytest
import requests
from CommonServerPython import CommandResults, DemistoException

import EndOfLifeAI
from EndOfLifeAI import (
    FREE_KEY_URL,
    Client,
    build_version,
    format_date,
    kev_exposed,
    parse_pairs,
    product_get_command,
    retry_after_text,
    version_batch_get_command,
    version_get_command,
)

BASE_URL = "https://api.endoflife.ai"
API_KEY = "unit-test-key"


def util_load_json(name: str) -> Any:
    return json.loads((Path(__file__).parent / "test_data" / name).read_text(encoding="utf-8"))


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key=API_KEY, verify=True, proxy=False)


""" CONNECTIVITY TEST """


def test_test_module_ok(client, requests_mock):
    """
    Given:
        - A valid API key.
    When:
        - Running the connectivity test.
    Then:
        - The API key is sent in the X-API-Key header and the test returns ok.
    """
    mocked = requests_mock.get(f"{BASE_URL}/v1/products", json=util_load_json("products.json"))

    assert EndOfLifeAI.test_module(client) == "ok"
    assert mocked.last_request.headers["X-API-Key"] == API_KEY


@pytest.mark.parametrize(
    "fixture, headers, expected",
    [
        ("error_401_no_key.json", {}, "No valid API key was sent."),
        ("error_401_unknown_key.json", {"X-EOL-Key-Status": "unknown"}, "The API key was not recognised."),
    ],
)
def test_test_module_unauthorized(client, requests_mock, fixture, headers, expected):
    """
    Given:
        - A missing or unknown API key (the API answers 401).
    When:
        - Running the connectivity test.
    Then:
        - The test returns a message that says why and where to get a free API key, instead of raising.
    """
    requests_mock.get(f"{BASE_URL}/v1/products", status_code=401, json=util_load_json(fixture), headers=headers)

    message = EndOfLifeAI.test_module(client)

    assert message.startswith("Authorization Error")
    assert expected in message
    assert FREE_KEY_URL in message


def test_unauthorized_inactive_key(client, requests_mock):
    """
    Given:
        - A deactivated API key (the 401 answer carries key_status inactive).
    When:
        - Running a command.
    Then:
        - The error says the key has been deactivated and where to get a free API key.
    """
    body = {**util_load_json("error_401_unknown_key.json"), "key_status": "inactive"}
    requests_mock.get(f"{BASE_URL}/v1/score/nodejs/18", status_code=401, json=body)

    with pytest.raises(DemistoException) as e:
        version_get_command(client, {"product": "nodejs", "version": "18"})

    assert "The API key has been deactivated." in str(e.value)
    assert FREE_KEY_URL in str(e.value)


""" endoflife-ai-product-get """


def test_product_get(client, requests_mock):
    """
    Given:
        - A tracked product slug and a limit of 3.
    When:
        - Running endoflife-ai-product-get.
    Then:
        - The context holds the product with the first 3 versions and the documented fields.
        - The table says how many versions are shown.
    """
    raw = util_load_json("product_nodejs.json")
    requests_mock.get(f"{BASE_URL}/v1/product/nodejs", json=raw)

    result = product_get_command(client, {"product": "nodejs", "limit": "3"})

    assert result.outputs_prefix == "EndOfLifeAI.Product"
    assert result.outputs_key_field == "product"
    assert result.outputs["product"] == "nodejs"
    assert result.outputs["version_count"] == raw["version_count"]
    assert result.outputs["product_url"] == "https://endoflife.ai/nodejs"
    assert "alias_of" not in result.outputs
    assert [item["version"] for item in result.outputs["versions"]] == [item["version"] for item in raw["versions"][:3]]
    first = result.outputs["versions"][0]
    assert first["eol_date"] == raw["versions"][0]["eol_date"]
    assert first["score"] == raw["versions"][0]["score"]
    assert first["kev_exposed"] is True
    assert "extended_support_vendor" not in first
    assert result.raw_response == raw
    assert "endoflife.ai lifecycle of nodejs" in result.readable_output
    assert f"Showing 3 of {raw['version_count']} versions" in result.readable_output


def test_product_get_default_limit(client, requests_mock):
    """
    Given:
        - A tracked product with fewer versions than the default limit.
    When:
        - Running endoflife-ai-product-get without a limit.
    Then:
        - All versions are returned and no truncation note is shown.
    """
    raw = util_load_json("product_nodejs.json")
    requests_mock.get(f"{BASE_URL}/v1/product/nodejs", json=raw)

    result = product_get_command(client, {"product": "nodejs"})

    assert len(result.outputs["versions"]) == raw["version_count"]
    assert "Showing" not in result.readable_output


def test_product_get_alias(client, requests_mock):
    """
    Given:
        - A slug that is an alias of a tracked product.
    When:
        - Running endoflife-ai-product-get.
    Then:
        - The context holds the tracked slug and the alias, and the output says so.
    """
    raw = util_load_json("product_nodejs.json")
    raw = {"alias_of": "node", **raw, "versions": raw["versions"][:2], "version_count": 2}
    requests_mock.get(f"{BASE_URL}/v1/product/node", json=raw)

    result = product_get_command(client, {"product": "node"})

    assert result.outputs["product"] == "nodejs"
    assert result.outputs["alias_of"] == "node"
    assert "The slug node is an alias of the tracked product nodejs." in result.readable_output


def test_product_get_not_found_did_you_mean(client, requests_mock):
    """
    Given:
        - A slug that is not tracked but is close to a tracked one (404 with did_you_mean).
    When:
        - Running endoflife-ai-product-get.
    Then:
        - The command does not fail, returns no context and lists the closest tracked slugs.
    """
    requests_mock.get(
        f"{BASE_URL}/v1/product/windows-server-2012", status_code=404, json=util_load_json("error_404_did_you_mean.json")
    )

    result = product_get_command(client, {"product": "windows-server-2012"})

    assert result.outputs is None
    assert "windows-server-2012 was not found" in result.readable_output
    assert "Did you mean: windows-server?" in result.readable_output


def test_product_get_not_tracked(client, requests_mock):
    """
    Given:
        - A slug with no close match (404 with not_tracked and no did_you_mean).
    When:
        - Running endoflife-ai-product-get.
    Then:
        - The command does not fail and says the product is not tracked.
    """
    requests_mock.get(f"{BASE_URL}/v1/product/pyton", status_code=404, json=util_load_json("error_404_not_tracked.json"))

    result = product_get_command(client, {"product": "pyton"})

    assert result.outputs is None
    assert "Did you mean" not in result.readable_output
    assert "endoflife.ai does not track a product with this slug." in result.readable_output


@pytest.mark.parametrize("args", [{}, {"product": "  "}, {"product": "nodejs", "limit": "0"}])
def test_product_get_invalid_arguments(client, args):
    """
    Given:
        - A missing product or a limit below 1.
    When:
        - Running endoflife-ai-product-get.
    Then:
        - A ValueError is raised before any request is sent.
    """
    with pytest.raises(ValueError):
        product_get_command(client, args)


""" endoflife-ai-version-get """


def test_version_get(client, requests_mock):
    """
    Given:
        - A tracked product and version.
    When:
        - Running endoflife-ai-version-get.
    Then:
        - The context holds the status, dates, risk score and the source of the date.
        - The API key is sent in the X-API-Key header.
    """
    raw = util_load_json("version_nodejs_18.json")
    mocked = requests_mock.get(f"{BASE_URL}/v1/score/nodejs/18", json=raw)

    result = version_get_command(client, {"product": "nodejs", "version": "18"})

    assert mocked.last_request.headers["X-API-Key"] == API_KEY
    assert result.outputs_prefix == "EndOfLifeAI.Version"
    assert result.outputs_key_field == ["product", "version"]
    outputs = result.outputs
    assert outputs["product"] == "nodejs"
    assert outputs["version"] == "18"
    assert outputs["status"] == "eol"
    assert outputs["is_supported"] is False
    assert outputs["eol_date"] == "2025-04-30"
    assert outputs["days_past_eol"] == raw["days_past_eol"]
    assert outputs["score"] == raw["score"]
    assert outputs["grade"] == raw["grade"]
    assert outputs["band"] == raw["band"]
    assert outputs["factors"] == raw["factors"]
    assert outputs["kev_exposed"] is True
    assert outputs["eol_date_source"] == "vendor-fetched"
    assert outputs["eol_date_source_url"] == raw["eol_date_source_url"]
    assert "alias_of" not in outputs
    assert "requested_version" not in outputs
    assert "extended_support_vendor" not in outputs
    assert result.raw_response == raw
    assert "endoflife.ai status of nodejs 18" in result.readable_output
    assert "End of life" in result.readable_output
    assert "2025-04-30" in result.readable_output
    assert raw["eol_date_source_url"] in result.readable_output


def test_version_get_alias_and_release_line(client, requests_mock):
    """
    Given:
        - An alias slug and a build number that the API resolves to its release line.
    When:
        - Running endoflife-ai-version-get.
    Then:
        - The context keeps alias_of, requested_version and version_matched_by, and the output explains both.
        - The build number is sent as one URL path segment.
    """
    raw = util_load_json("version_alias_release_line.json")
    mocked = requests_mock.get(f"{BASE_URL}/v1/score/sqlserver/15.0.4430", json=raw)

    result = version_get_command(client, {"product": "sqlserver", "version": "15.0.4430"})

    assert mocked.called_once
    assert result.outputs["product"] == "mssqlserver"
    assert result.outputs["alias_of"] == "sqlserver"
    assert result.outputs["version"] == "15.0"
    assert result.outputs["requested_version"] == "15.0.4430"
    assert result.outputs["version_matched_by"] == "release-line"
    assert "The slug sqlserver is an alias of the tracked product mssqlserver." in result.readable_output
    assert "The version 15.0.4430 was resolved to 15.0 (release-line match)." in result.readable_output


def test_version_get_month_precision(client, requests_mock):
    """
    Given:
        - A version whose end-of-life date the vendor publishes to the month only.
    When:
        - Running endoflife-ai-version-get.
    Then:
        - The table shows the month, not the stored last day of the month, and no day count.
        - The context keeps the values exactly as the API returned them.
    """
    raw = util_load_json("version_month_precision.json")
    requests_mock.get(f"{BASE_URL}/v1/score/infinispan/15.2", json=raw)

    result = version_get_command(client, {"product": "infinispan", "version": "15.2"})

    assert result.outputs["eol_date"] == "2026-11-30"
    assert result.outputs["eol_date_precision"] == "month"
    assert result.outputs["days_until_eol"] == raw["days_until_eol"]
    table = result.readable_output.split("\n\n")[0]
    assert "November 2026" in table
    assert "2026-11-30" not in table
    assert "Days Until EOL" not in table
    assert raw["date_precision_note"] in result.readable_output


def test_version_get_version_not_found(client, requests_mock):
    """
    Given:
        - A tracked product and a version that does not exist (404).
    When:
        - Running endoflife-ai-version-get.
    Then:
        - The command does not fail, returns no context and repeats the API's message.
    """
    requests_mock.get(f"{BASE_URL}/v1/score/nodejs/999", status_code=404, json=util_load_json("error_404_version.json"))

    result = version_get_command(client, {"product": "nodejs", "version": "999"})

    assert isinstance(result, CommandResults)
    assert result.outputs is None
    assert "nodejs 999 was not found" in result.readable_output
    assert 'Version "999" not found for "nodejs"' in result.readable_output


def test_version_get_split_line_candidates(client, requests_mock):
    """
    Given:
        - A version on a release line that is split into several cycles (404 with reason and candidates).
    When:
        - Running endoflife-ai-version-get.
    Then:
        - The output gives the reason and the candidate cycles.
    """
    body = {
        "error": 'Version "10.50.6000" not found for "mssqlserver"',
        "reason": "Version line is split into several cycles",
        "candidates": ["10.50-sp3", "10.50-sp2"],
        "docs": "https://endoflife.ai/api",
    }
    requests_mock.get(f"{BASE_URL}/v1/score/mssqlserver/10.50.6000", status_code=404, json=body)

    result = version_get_command(client, {"product": "mssqlserver", "version": "10.50.6000"})

    assert "Reason: Version line is split into several cycles" in result.readable_output
    assert "Candidates: 10.50-sp3, 10.50-sp2" in result.readable_output


def test_version_get_encodes_path_segments(client, requests_mock):
    """
    Given:
        - A version that contains a slash and a space.
    When:
        - Running endoflife-ai-version-get.
    Then:
        - The version is percent-encoded so that it stays one URL path segment.
    """
    mocked = requests_mock.get(re.compile(r".*/v1/score/.*"), status_code=404, json=util_load_json("error_404_version.json"))

    version_get_command(client, {"product": "nodejs", "version": "18/../x y"})

    assert mocked.called_once
    assert mocked.last_request.url == f"{BASE_URL}/v1/score/nodejs/18%2F..%2Fx%20y"


@pytest.mark.parametrize("args", [{}, {"product": "nodejs"}, {"version": "18"}])
def test_version_get_missing_arguments(client, args):
    """
    Given:
        - A missing product or version.
    When:
        - Running endoflife-ai-version-get.
    Then:
        - A ValueError is raised before any request is sent.
    """
    with pytest.raises(ValueError):
        version_get_command(client, args)


""" endoflife-ai-version-batch-get """


def test_version_batch_get(client, requests_mock):
    """
    Given:
        - Five entries: three that resolve, an unknown product and an unknown version.
    When:
        - Running endoflife-ai-version-batch-get.
    Then:
        - One request is sent with the entries in order.
        - The resolved versions go to EndOfLifeAI.Version and the others to EndOfLifeAI.BatchError.
    """
    raw = util_load_json("batch.json")
    mocked = requests_mock.post(f"{BASE_URL}/v1/batch", json=raw)

    results = version_batch_get_command(
        client, {"products": "nodejs:18, python:3.8,ubuntu:20.04,not-a-product,nodejs:999"}
    )

    assert mocked.call_count == 1
    assert mocked.last_request.headers["X-API-Key"] == API_KEY
    assert mocked.last_request.json() == {
        "products": [
            {"slug": "nodejs", "version": "18"},
            {"slug": "python", "version": "3.8"},
            {"slug": "ubuntu", "version": "20.04"},
            {"slug": "not-a-product"},
            {"slug": "nodejs", "version": "999"},
        ]
    }
    resolved, unresolved = results
    assert resolved.outputs_prefix == "EndOfLifeAI.Version"
    assert resolved.outputs_key_field == ["product", "version"]
    assert [(item["product"], item["version"]) for item in resolved.outputs] == [
        ("nodejs", "18"),
        ("python", "3.8"),
        ("ubuntu", "20.04"),
    ]
    assert [item["kev_exposed"] for item in resolved.outputs] == [True, False, True]
    assert resolved.outputs[2]["extended_support_date"] == "2030-05-31"
    assert "endoflife.ai batch check" in resolved.readable_output
    assert unresolved.outputs_prefix == "EndOfLifeAI.BatchError"
    assert unresolved.outputs == [
        {"product": "not-a-product", "error": "Product not found"},
        {"product": "nodejs", "version": "999", "error": "Version not found"},
    ]
    assert "items that were not resolved" in unresolved.readable_output


def test_version_batch_get_chunks(client, requests_mock):
    """
    Given:
        - Seven entries and the default chunk size of 5.
    When:
        - Running endoflife-ai-version-batch-get.
    Then:
        - Two requests are sent, with 5 and 2 entries, and all seven answers are returned.
    """
    score = util_load_json("version_nodejs_18.json")

    def answer(request, context):
        sent = request.json()["products"]
        return {"count": len(sent), "results": [{**score, "version": item["version"]} for item in sent], "tier": "free"}

    mocked = requests_mock.post(f"{BASE_URL}/v1/batch", json=answer)

    results = version_batch_get_command(client, {"products": [f"nodejs:{number}" for number in range(10, 17)]})

    assert [len(call.json()["products"]) for call in mocked.request_history] == [5, 2]
    assert len(results) == 1
    assert [item["version"] for item in results[0].outputs] == [str(number) for number in range(10, 17)]


def test_version_batch_get_over_key_allowance(client, requests_mock):
    """
    Given:
        - A chunk size above what the API key accepts in one request (the API answers 403).
    When:
        - Running endoflife-ai-version-batch-get.
    Then:
        - The error tells the user to lower the chunk_size argument.
    """
    requests_mock.post(f"{BASE_URL}/v1/batch", status_code=403, json=util_load_json("error_403_batch_limit.json"))

    with pytest.raises(DemistoException) as e:
        version_batch_get_command(client, {"products": "a:1,b:2,c:3,d:4,e:5,f:6", "chunk_size": "6"})

    assert "Lower the chunk_size argument" in str(e.value)


@pytest.mark.parametrize("products", ["", " , ", ":18", "nodejs:18,:20"])
def test_version_batch_get_invalid_entries(client, products):
    """
    Given:
        - An empty list or an entry without a product slug.
    When:
        - Running endoflife-ai-version-batch-get.
    Then:
        - A ValueError is raised before any request is sent.
    """
    with pytest.raises(ValueError):
        version_batch_get_command(client, {"products": products})


def test_version_batch_get_all_unresolved(client, requests_mock):
    """
    Given:
        - Entries that do not resolve.
    When:
        - Running endoflife-ai-version-batch-get.
    Then:
        - Only the EndOfLifeAI.BatchError result is returned.
    """
    raw = {"count": 1, "results": [{"slug": "not-a-product", "error": "Product not found"}], "tier": "free"}
    requests_mock.post(f"{BASE_URL}/v1/batch", json=raw)

    results = version_batch_get_command(client, {"products": "not-a-product"})

    assert len(results) == 1
    assert results[0].outputs_prefix == "EndOfLifeAI.BatchError"
    assert results[0].raw_response == [raw]


""" ERROR HANDLING """


def test_rate_limit(client, requests_mock):
    """
    Given:
        - An API key whose daily allowance is used up (429 with a Retry-After header).
    When:
        - Running a command.
    Then:
        - The error says the rate limit was reached and when the counter resets.
    """
    requests_mock.get(
        f"{BASE_URL}/v1/score/nodejs/18",
        status_code=429,
        json=util_load_json("error_429.json"),
        headers={"Retry-After": "7200"},
    )

    with pytest.raises(DemistoException) as e:
        version_get_command(client, {"product": "nodejs", "version": "18"})

    assert "Rate limit reached" in str(e.value)
    assert "resets at 00:00 UTC, in about 2 hours" in str(e.value)


@pytest.mark.parametrize("exception", [requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout])
def test_timeout(client, requests_mock, exception):
    """
    Given:
        - An API that does not answer in time.
    When:
        - Running a command.
    Then:
        - The error says the API did not answer and what to check.
    """
    requests_mock.get(f"{BASE_URL}/v1/score/nodejs/18", exc=exception)

    with pytest.raises(DemistoException) as e:
        version_get_command(client, {"product": "nodejs", "version": "18"})

    assert "did not answer within 30 seconds" in str(e.value)


def test_server_error_without_json(client, requests_mock):
    """
    Given:
        - A 502 answer whose body is not JSON.
    When:
        - Running a command.
    Then:
        - The error carries the status code.
    """
    requests_mock.get(f"{BASE_URL}/v1/product/nodejs", status_code=502, text="<html>Bad Gateway</html>", reason="Bad Gateway")

    with pytest.raises(DemistoException) as e:
        product_get_command(client, {"product": "nodejs"})

    assert "endoflife.ai API error [502]: Bad Gateway" in str(e.value)


def test_answer_that_is_not_an_object(client, requests_mock):
    """
    Given:
        - A 200 answer whose JSON body is a list.
    When:
        - Running a command.
    Then:
        - A DemistoException is raised.
    """
    requests_mock.get(f"{BASE_URL}/v1/product/nodejs", json=["unexpected"])

    with pytest.raises(DemistoException):
        product_get_command(client, {"product": "nodejs"})


""" HELPERS """


@pytest.mark.parametrize(
    "date_value, precision, expected",
    [
        ("2025-04-30", "day", "2025-04-30"),
        ("2025-04-30", None, "2025-04-30"),
        ("2026-11-30", "month", "November 2026"),
        ("2026-12-31", "quarter", "Q4 2026"),
        ("2026-03-31", "quarter", "Q1 2026"),
        ("not-a-date", "month", "not-a-date"),
        (None, "day", None),
        ("", "month", None),
    ],
)
def test_format_date(date_value, precision, expected):
    assert format_date(date_value, precision) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ({"factors": {"cisa_kev_exposure": 20}}, True),
        ({"factors": {"cisa_kev_exposure": 10}}, True),
        ({"factors": {"cisa_kev_exposure": 0}}, False),
        ({"factors": {}}, None),
        ({}, None),
    ],
)
def test_kev_exposed(raw, expected):
    assert kev_exposed(raw) is expected


def test_build_version_keeps_documented_fields_only():
    """
    Given:
        - A Score object of the API with a field the integration does not document.
    When:
        - Building the context object.
    Then:
        - Only the documented fields are kept, and fields the API always sends are present.
    """
    raw = {**util_load_json("version_nodejs_18.json"), "extended_support_vendor": {"name": "Example"}, "new_field": 1}

    version = build_version(raw)

    assert "extended_support_vendor" not in version
    assert "new_field" not in version
    assert version["eol_boolean"] is None
    assert version["extended_support_date"] is None
    assert version["cpe"] == raw["cpe"]


def test_version_row_without_date():
    """
    Given:
        - A version with no end-of-life date and eol_boolean set.
    When:
        - Building the table row.
    Then:
        - The row says what the API says instead of showing an empty date.
    """
    assert EndOfLifeAI.version_row({"eol_boolean": True})["EOL Date"] == "End of life, no date published"
    assert EndOfLifeAI.version_row({"eol_boolean": False})["EOL Date"] == "No end-of-life date published"
    assert EndOfLifeAI.version_row({})["EOL Date"] is None


@pytest.mark.parametrize(
    "retry_after, expected",
    [
        ("7200", ", in about 2 hours"),
        ("3600", ", in about 1 hour"),
        ("600", ", in about 10 minutes"),
        ("20", ", in about 1 minute"),
        ("0", ""),
        (None, ""),
        ("soon", ""),
    ],
)
def test_retry_after_text(retry_after, expected):
    assert retry_after_text(retry_after) == expected


def test_parse_pairs():
    assert parse_pairs(["nodejs:18", " python : 3.8 ", "ubuntu", ""]) == [
        {"slug": "nodejs", "version": "18"},
        {"slug": "python", "version": "3.8"},
        {"slug": "ubuntu"},
    ]


""" MAIN """


def test_main_runs_command(mocker, requests_mock):
    """
    Given:
        - Instance parameters with an API key and the endoflife-ai-version-get command.
    When:
        - Running main.
    Then:
        - The command result is returned.
    """
    mocker.patch.object(demisto, "params", return_value={"url": f"{BASE_URL}/", "credentials": {"password": API_KEY}})
    mocker.patch.object(demisto, "command", return_value="endoflife-ai-version-get")
    mocker.patch.object(demisto, "args", return_value={"product": "nodejs", "version": "18"})
    return_results_mock = mocker.patch.object(EndOfLifeAI, "return_results")
    requests_mock.get(f"{BASE_URL}/v1/score/nodejs/18", json=util_load_json("version_nodejs_18.json"))

    EndOfLifeAI.main()

    assert return_results_mock.call_args[0][0].outputs["version"] == "18"


def test_main_without_api_key(mocker):
    """
    Given:
        - Instance parameters without an API key.
    When:
        - Running main.
    Then:
        - An error says the key is missing and where to get a free API key. No request is sent.
    """
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL, "credentials": {"password": ""}})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    return_error_mock = mocker.patch.object(EndOfLifeAI, "return_error")

    EndOfLifeAI.main()

    message = return_error_mock.call_args[0][0]
    assert "The API Key field is empty" in message
    assert FREE_KEY_URL in message


def test_main_unknown_command(mocker):
    """
    Given:
        - A command the integration does not implement.
    When:
        - Running main.
    Then:
        - An error is returned.
    """
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL, "credentials": {"password": API_KEY}})
    mocker.patch.object(demisto, "command", return_value="endoflife-ai-unknown")
    mocker.patch.object(demisto, "args", return_value={})
    return_error_mock = mocker.patch.object(EndOfLifeAI, "return_error")

    EndOfLifeAI.main()

    assert "is not implemented" in return_error_mock.call_args[0][0]
