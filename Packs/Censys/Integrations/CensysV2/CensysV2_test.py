import json
import pytest
from CensysV2 import (
    Client,
    censys_view_command,
    censys_search_command,
    ip_command,
    domain_command,
    censys_search_with_pagination,
    get_dbot_score,
    handle_exceptions,
    test_module as censys_test_module,
    main,
    ExecutionMetrics,
)
from CommonServerPython import DemistoException, Common


def util_load_json(path):
    with open(f"test_data/{path}", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(base_url="https://api.platform.censys.io", api_token="test_token")


def test_censys_view_command_host(client, requests_mock):
    """
    Given:
        - A query for an IPv4 asset.
    When:
        - Running the cen-view command.
    Then:
        - Ensure the API is called with the correct parameters.
        - Ensure the command results contain the expected outputs and indicator data.
    """
    # Given
    args = {"index": "ipv4", "query": "127.0.0.1"}
    mock_res = util_load_json("view_host_response.json")
    requests_mock.get("https://api.platform.censys.io/v3/global/asset/host/127.0.0.1", json=mock_res)

    # When
    result = censys_view_command(client, args)

    # Then
    assert result.outputs_prefix == "Censys.View"
    assert result.outputs_key_field == "ip"
    assert result.outputs["ip"] == "127.0.0.1"  # type: ignore
    assert result.indicator.ip == "127.0.0.1"  # type: ignore


def test_censys_view_command_host_with_malicious_labels(client, requests_mock, mocker):
    """
    Given:
        - A query for an IPv4 asset with malicious labels.
        - Malicious labels configured in params.
    When:
        - Running the cen-view command.
    Then:
        - Ensure the DBotScore is BAD.
        - Ensure the malicious_description is properly set.
    """
    # Given
    import demistomock as demisto

    args = {"index": "ipv4", "query": "127.0.0.1"}
    params = {
        "integration_reliability": "C - Fairly reliable",
        "malicious_labels": "malicious,bad",
        "malicious_labels_threshold": 1,
    }
    # Mock demisto.params() to return our test params
    mocker.patch.object(demisto, "params", return_value=params)

    mock_res = util_load_json("view_host_response.json")
    # Add malicious labels to the response
    mock_res["result"]["resource"]["labels"] = [{"value": "malicious"}, {"value": "bad"}]
    requests_mock.get("https://api.platform.censys.io/v3/global/asset/host/127.0.0.1", json=mock_res)

    # When
    result = censys_view_command(client, args)

    # Then
    assert result.outputs_prefix == "Censys.View"
    assert result.indicator.ip == "127.0.0.1"  # type: ignore
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description is not None
    assert "Matched malicious labels:" in result.indicator.dbot_score.malicious_description
    assert "bad" in result.indicator.dbot_score.malicious_description
    assert "malicious" in result.indicator.dbot_score.malicious_description


def test_censys_view_command_cert(client, requests_mock):
    """
    Given:
        - A query for a certificate asset.
    When:
        - Running the cen-view command.
    Then:
        - Ensure the API is called with the correct parameters.
        - Ensure the command results contain the expected outputs.
    """
    # Given
    sha256 = "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f6622cc"
    args = {"index": "certificates", "query": sha256}
    mock_res = util_load_json("view_cert_response.json")
    requests_mock.get(f"https://api.platform.censys.io/v3/global/asset/certificate/{sha256}", json=mock_res)

    # When
    result = censys_view_command(client, args)

    # Then
    assert result.outputs_prefix == "Censys.View"
    assert result.outputs_key_field == "fingerprint_sha256"
    assert result.outputs["fingerprint_sha256"] == sha256  # type: ignore


def test_censys_search_command_host(client, requests_mock):
    """
    Given:
        - A search query for IPv4 assets.
    When:
        - Running the cen-search command.
    Then:
        - Ensure the API is called with the correct parameters.
        - Ensure the command results contain the expected outputs.
    """
    # Given
    args = {"index": "ipv4", "query": "host.services.port:443", "limit": 1}
    mock_res = util_load_json("search_host_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    result = censys_search_command(client, args)

    # Then
    assert result.outputs_prefix == "Censys.Search"
    assert result.outputs_key_field == "ip"
    assert len(result.outputs) == 1  # type: ignore
    assert result.outputs[0]["ip"] == "127.0.0.1"  # type: ignore


def test_censys_search_command_certs(client, requests_mock):
    """
    Given:
        - A search query for certificate assets.
    When:
        - Running the cen-search command.
    Then:
        - Ensure the API is called with the correct parameters.
        - Ensure the command results contain the expected outputs.
    """
    # Given
    args = {"index": "certificates", "query": "cert.parsed.subject.common_name:google.com", "limit": 1}
    mock_res = util_load_json("search_certs_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    result = censys_search_command(client, args)

    # Then
    assert result.outputs_prefix == "Censys.Search"
    assert result.outputs_key_field == "fingerprint_sha256"
    assert len(result.outputs) == 1  # type: ignore
    assert result.outputs[0]["fingerprint_sha256"] == "0003da4aee3b252097bfc7f871ab6fbe3e08eb94c34ff5cea91aaa29248d3c8b"  # type: ignore


def test_ip_command(client, requests_mock):
    """
    Given:
        - An IP address to check.
        - Malicious labels and threshold in params.
    When:
        - Running the ip command.
    Then:
        - Ensure the API is called with the correct parameters.
        - Ensure the command results contain the expected indicator and reputation data.
        - Ensure the DBotScore is calculated based on labels.
        - Ensure the malicious_description is properly set.
    """
    # Given
    args = {"ip": "127.0.0.1"}
    params = {
        "integration_reliability": "C - Fairly reliable",
        "malicious_labels": "malicious",
        "malicious_labels_threshold": 1,
    }
    mock_res = util_load_json("ip_command_response.json")
    # Ensure the mock response has the malicious label
    mock_res["result"]["hits"][0]["host_v1"]["resource"]["labels"] = [{"value": "malicious"}]
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    results = ip_command(client, args, params)

    # Then
    assert len(results) >= 1
    result = results[0]
    assert result.outputs_prefix == "Censys.IP"
    assert result.indicator.ip == "127.0.0.1"  # type: ignore
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description is not None
    assert "Matched malicious labels:" in result.indicator.dbot_score.malicious_description
    assert "malicious" in result.indicator.dbot_score.malicious_description


def test_domain_command(client, requests_mock):
    """
    Given:
        - A domain to check.
    When:
        - Running the domain command.
    Then:
        - Ensure the API is called with the correct parameters.
        - Ensure the command results contain the expected indicator and relationship data.
    """
    # Given
    args = {"domain": "facebook.com"}
    params = {}
    mock_res = util_load_json("domain_command_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    results = domain_command(client, args, params)

    # Then
    assert len(results) >= 1
    result = results[0]
    assert result.outputs_prefix == "Censys.Domain"
    assert result.indicator.domain == "facebook.com"  # type: ignore
    assert result.indicator.dbot_score.score == Common.DBotScore.NONE
    assert len(result.relationships) > 0  # type: ignore


def test_domain_command_with_malicious_labels(client, requests_mock):
    """
    Given:
        - A domain to check with malicious labels.
        - Malicious labels configured in params.
    When:
        - Running the domain command.
    Then:
        - Ensure the DBotScore is BAD.
        - Ensure the malicious_description is properly set.
    """
    # Given
    args = {"domain": "malicious.com"}
    params = {
        "integration_reliability": "C - Fairly reliable",
        "malicious_labels": "malicious,phishing",
        "malicious_labels_threshold": 1,
    }
    mock_res = util_load_json("domain_command_response.json")
    # Modify the response to include malicious labels
    mock_res["result"]["hits"][0]["host_v1"]["resource"]["labels"] = [{"value": "malicious"}, {"value": "phishing"}]
    # Update the domain in the response
    mock_res["result"]["hits"][0]["host_v1"]["resource"]["dns"]["names"] = ["malicious.com"]
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    results = domain_command(client, args, params)

    # Then
    assert len(results) >= 1
    result = results[0]
    assert result.outputs_prefix == "Censys.Domain"
    assert result.indicator.domain == "malicious.com"  # type: ignore
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description is not None
    assert "Matched malicious labels:" in result.indicator.dbot_score.malicious_description
    assert (
        "malicious" in result.indicator.dbot_score.malicious_description
        or "phishing" in result.indicator.dbot_score.malicious_description
    )


def test_domain_command_with_suspicious_labels(client, requests_mock):
    """
    Given:
        - A domain to check with suspicious labels.
        - Suspicious labels configured in params.
    When:
        - Running the domain command.
    Then:
        - Ensure the DBotScore is SUSPICIOUS.
        - Ensure the malicious_description is properly set.
    """
    # Given
    args = {"domain": "suspicious.com"}
    params = {
        "integration_reliability": "C - Fairly reliable",
        "suspicious_labels": "suspicious,spam",
        "suspicious_labels_threshold": 1,
    }
    mock_res = util_load_json("domain_command_response.json")
    # Modify the response to include suspicious labels
    mock_res["result"]["hits"][0]["host_v1"]["resource"]["labels"] = [{"value": "suspicious"}]
    # Update the domain in the response
    mock_res["result"]["hits"][0]["host_v1"]["resource"]["dns"]["names"] = ["suspicious.com"]
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    results = domain_command(client, args, params)

    # Then
    assert len(results) >= 1
    result = results[0]
    assert result.outputs_prefix == "Censys.Domain"
    assert result.indicator.domain == "suspicious.com"  # type: ignore
    assert result.indicator.dbot_score.score == Common.DBotScore.SUSPICIOUS
    assert result.indicator.dbot_score.malicious_description is not None
    assert "Matched suspicious labels:" in result.indicator.dbot_score.malicious_description
    assert "suspicious" in result.indicator.dbot_score.malicious_description


def test_censys_search_with_pagination(client, requests_mock):
    """
    Given:
        - A search query that returns multiple pages.
    When:
        - Running censys_search_with_pagination.
    Then:
        - Ensure all hits are collected across pages.
        - Ensure the page size is adjusted correctly.
    """
    query = "test query"

    # Mock multiple pages
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        [
            {
                "json": {
                    "result": {
                        "hits": [{"host_v1": {"resource": {"ip": "1.1.1.1"}}}],
                        "total_hits": 2,
                        "next_page_token": "token2",
                    }
                }
            },
            {
                "json": {
                    "result": {"hits": [{"host_v1": {"resource": {"ip": "2.2.2.2"}}}], "total_hits": 2, "next_page_token": ""}
                }
            },
        ],
    )

    result = censys_search_with_pagination(client, query, page_size=1, limit=2)

    assert len(result["result"]["hits"]) == 2
    assert result["result"]["hits"][0]["host_v1"]["resource"]["ip"] == "1.1.1.1"
    assert result["result"]["hits"][1]["host_v1"]["resource"]["ip"] == "2.2.2.2"


def test_censys_search_with_pagination_remaining(client, requests_mock):
    """
    Given:
        - A search query with a limit that requires adjusting page_size.
    When:
        - Running censys_search_with_pagination.
    Then:
        - Ensure page_size is adjusted for the last page.
    """
    query = "test query"
    # First page returns 1 hit, limit is 2, so remaining is 1.
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        [
            {
                "json": {
                    "result": {
                        "hits": [{"host_v1": {"resource": {"ip": "1.1.1.1"}}}],
                        "total_hits": 2,
                        "next_page_token": "token2",
                    }
                }
            },
            {
                "json": {
                    "result": {"hits": [{"host_v1": {"resource": {"ip": "8.8.8.8"}}}], "total_hits": 2, "next_page_token": ""}
                }
            },
        ],
    )

    result = censys_search_with_pagination(client, query, page_size=10, limit=2)
    assert len(result["result"]["hits"]) == 2


def test_censys_search_with_pagination_limit_trim(client, requests_mock):
    """
    Given:
        - A search query with a limit.
        - API returns more hits than the limit.
    When:
        - Running censys_search_with_pagination.
    Then:
        - Ensure hits are trimmed to the limit.
    """
    query = "test query"
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        json={
            "result": {
                "hits": [{"host_v1": {"resource": {"ip": "1.1.1.1"}}}, {"host_v1": {"resource": {"ip": "2.2.2.2"}}}],
                "total_hits": 2,
                "next_page_token": "",
            }
        },
    )

    result = censys_search_with_pagination(client, query, limit=1)
    assert len(result["result"]["hits"]) == 1


def test_get_dbot_score():
    """
    Given:
        - Different sets of labels and thresholds.
    When:
        - Running get_dbot_score.
    Then:
        - Ensure the correct DBot score and description are returned.
    """
    params = {
        "malicious_labels": "malicious,bad",
        "suspicious_labels": "suspicious,warn",
        "malicious_labels_threshold": 1,
        "suspicious_labels_threshold": 1,
    }

    # Test BAD - single malicious label
    score, description = get_dbot_score(params, ["malicious"])
    assert score == Common.DBotScore.BAD
    assert description == "Matched malicious labels: malicious"

    # Test BAD - multiple malicious labels (should be sorted alphabetically)
    score, description = get_dbot_score(params, ["malicious", "bad"])
    assert score == Common.DBotScore.BAD
    assert description == "Matched malicious labels: bad, malicious"

    # Test SUSPICIOUS - single suspicious label
    score, description = get_dbot_score(params, ["suspicious"])
    assert score == Common.DBotScore.SUSPICIOUS
    assert description == "Matched suspicious labels: suspicious"

    # Test SUSPICIOUS - multiple suspicious labels (should be sorted alphabetically)
    score, description = get_dbot_score(params, ["warn", "suspicious"])
    assert score == Common.DBotScore.SUSPICIOUS
    assert description == "Matched suspicious labels: suspicious, warn"

    # Test NONE - clean label
    score, description = get_dbot_score(params, ["clean"])
    assert score == Common.DBotScore.NONE
    assert description is None

    # Test threshold - malicious threshold not met
    params["malicious_labels_threshold"] = 2
    score, description = get_dbot_score(params, ["malicious"])
    assert score == Common.DBotScore.NONE
    assert description is None

    # Test threshold - malicious threshold met
    score, description = get_dbot_score(params, ["malicious", "bad"])
    assert score == Common.DBotScore.BAD
    assert description == "Matched malicious labels: bad, malicious"

    # Test threshold - suspicious threshold
    params["suspicious_labels_threshold"] = 2
    score, description = get_dbot_score(params, ["suspicious"])
    assert score == Common.DBotScore.NONE
    assert description is None

    # Test threshold - suspicious threshold met
    score, description = get_dbot_score(params, ["suspicious", "warn"])
    assert score == Common.DBotScore.SUSPICIOUS
    assert description == "Matched suspicious labels: suspicious, warn"


def test_handle_exceptions():
    """
    Given:
        - Different types of exceptions.
    When:
        - Running handle_exceptions.
    Then:
        - Ensure exceptions are handled correctly and metrics are updated.
    """
    import requests

    # Given
    results = []
    execution_metrics = ExecutionMetrics()

    # When / Then - Test quota error (403 with "quota")
    mock_res = requests.Response()
    mock_res.status_code = 403
    e = DemistoException("quota exceeded", res=mock_res)
    assert handle_exceptions(e, results, execution_metrics, "item1") is True
    assert execution_metrics.quota_error == 1
    assert "Quota exceeded" in results[0].readable_output

    # When / Then - Test rate limit error (429)
    mock_res.status_code = 429
    e = DemistoException("too many requests", res=mock_res)
    handle_exceptions(e, results, execution_metrics, "item2")
    assert execution_metrics.general_error == 1
    assert "Too many requests" in results[1].readable_output

    # When / Then - Test non-premium access error (403 with "specific fields")
    mock_res.status_code = 403
    e = DemistoException("specific fields", res=mock_res)
    with pytest.raises(DemistoException, match="Your user does not have permission for premium features"):
        handle_exceptions(e, results, execution_metrics, "item3")

    # When / Then - Test general error
    e = Exception("general error")
    assert handle_exceptions(e, results, execution_metrics, "item4") is False
    assert execution_metrics.general_error == 2
    assert "An error occurred" in results[2].readable_output

    # When / Then - Test unauthorized error (401)
    mock_res = requests.Response()
    mock_res.status_code = 401
    e = DemistoException("unauthorized", res=mock_res)
    with pytest.raises(DemistoException):
        handle_exceptions(e, results, execution_metrics, "item5")


def test_test_module_success(client, requests_mock):
    """
    Given:
        - Valid parameters.
    When:
        - Running test-module.
    Then:
        - Ensure "ok" is returned.
    """
    params = {"api_token": {"password": "test_token"}}
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {"hits": []}})
    assert censys_test_module(client, params) == "ok"


def test_test_module_premium_error(client):
    """
    Given:
        - Premium labels selected without premium access.
    When:
        - Running test-module.
    Then:
        - Ensure DemistoException is raised.
    """
    params = {"premium_access": False, "malicious_labels": "bad"}
    with pytest.raises(
        DemistoException, match="The 'Determine IP score by label' feature only works for Censys paid subscribers"
    ):
        censys_test_module(client, params)


def test_test_module_general_demisto_error(client, mocker):
    """
    Given:
        - A general DemistoException during test-module.
    When:
        - Running test-module.
    Then:
        - Ensure the exception is re-raised.
    """
    # Given
    params = {"premium_access": False}
    mocker.patch("CensysV2.censys_search_with_pagination", side_effect=DemistoException("general error"))

    # When / Then
    with pytest.raises(DemistoException, match="general error"):
        censys_test_module(client, params)


def test_test_module_premium_permission_error(client, requests_mock):
    """
    Given:
        - A 403 error with "specific fields" during test-module.
    When:
        - Running test-module.
    Then:
        - Ensure a descriptive DemistoException is raised.
    """
    params = {"premium_access": True}
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        status_code=403,
        json={"error": "Your query contains specific fields that require premium access"},
    )
    with pytest.raises(DemistoException, match="Your user does not have permission for premium features"):
        censys_test_module(client, params)


def test_test_module_unauthorized_error(client, requests_mock):
    """
    Given:
        - A 401 error during test-module.
    When:
        - Running test-module.
    Then:
        - Ensure a descriptive DemistoException is raised.
    """
    params = {"premium_access": False}
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        status_code=401,
        json={"error": {"code": 401, "status": "Unauthorized", "message": "Access credentials are invalid"}},
    )
    with pytest.raises(DemistoException, match="401 Unauthorized: Access credentials are invalid"):
        censys_test_module(client, params)


def test_test_module_forbidden_error(client, requests_mock):
    """
    Given:
        - A 403 error (not premium) during test-module.
    When:
        - Running test-module.
    Then:
        - Ensure a descriptive DemistoException is raised.
    """
    params = {"premium_access": False}
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        status_code=403,
        json={"error": "Forbidden"},
    )
    with pytest.raises(DemistoException, match="403 Forbidden: The provided Organization ID is incorrect"):
        censys_test_module(client, params)


def test_test_module_unprocessable_entity_error(client, requests_mock):
    """
    Given:
        - A 422 error during test-module.
    When:
        - Running test-module.
    Then:
        - Ensure a descriptive DemistoException is raised.
    """
    params = {"premium_access": False}
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        status_code=422,
        json={"error": "Unprocessable Entity"},
    )
    with pytest.raises(DemistoException, match="422 Unprocessable Entity: The provided Organization ID is malformed"):
        censys_test_module(client, params)


def test_ip_command_no_hits(client, requests_mock):
    """
    Given:
        - An IP that returns no hits (missing 'hits' field).
    When:
        - Running ip_command.
    Then:
        - Ensure an error message is returned in results.
    """
    args = {"ip": "1.1.1.1"}
    params = {}
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {}})
    results = ip_command(client, args, params)
    # When hits field is missing (None), it triggers an error that gets caught and handled
    # The exception handler reports it as an error
    assert (
        "Unexpected response: 'hits' path not found" in results[0].readable_output
        or "No results found for IP: 1.1.1.1" in results[0].readable_output
    )


def test_domain_command_no_results(client, requests_mock):
    """
    Given:
        - A domain that returns no results (hits is empty list).
    When:
        - Running domain_command.
    Then:
        - Ensure "No results found" message is returned.
    """
    args = {"domain": "nonexistent.com"}
    params = {}
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {"hits": []}})
    results = domain_command(client, args, params)
    # When hits is an empty list, it should return "No results found"
    assert "No results found for domain: nonexistent.com" in results[0].readable_output


def test_domain_command_single_domain(client, requests_mock):
    """
    Given:
        - A single domain (not a list).
    When:
        - Running domain_command.
    Then:
        - Ensure the query is built correctly.
    """
    args = {"domain": "facebook.com"}
    params = {}
    mock_res = util_load_json("domain_command_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    results = domain_command(client, args, params)
    assert results[0].indicator.domain == "facebook.com"


def test_domain_command_no_match(client, requests_mock):
    """
    Given:
        - A domain that has hits but none match the requested domain.
    When:
        - Running domain_command.
    Then:
        - Ensure "No results found" is in the output.
    """
    args = {"domain": "nonexistent.com"}
    params = {}
    # Return a hit for a different domain
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        json={"result": {"hits": [{"host_v1": {"resource": {"dns": {"names": ["other.com"]}, "ip": "1.1.1.1"}}}]}},
    )
    results = domain_command(client, args, params)
    assert "No results found for domain: nonexistent.com" in results[0].readable_output


def test_ip_command_not_found(client, requests_mock):
    """
    Given:
        - An IP address that is not found in search results.
    When:
        - Running ip_command.
    Then:
        - Ensure "No results found for IP" message is returned.
    """
    # Given
    args = {"ip": "192.168.1.1"}
    params = {}
    # Return empty hits
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {"hits": []}})

    # When
    results = ip_command(client, args, params)

    # Then
    assert len(results) >= 1
    assert "No results found for IP: 192.168.1.1" in results[0].readable_output


def test_ip_command_multiple_ips_partial_found(client, requests_mock):
    """
    Given:
        - Multiple IP addresses where only some are found in search results.
    When:
        - Running ip_command.
    Then:
        - Ensure results are returned for found IPs.
        - Ensure "No results found" messages are returned for IPs not found.
    """
    # Given
    args = {"ip": ["127.0.0.1", "192.168.1.1", "10.0.0.1"]}
    params = {"integration_reliability": "C - Fairly reliable"}
    # Return hits only for 127.0.0.1
    mock_res = util_load_json("ip_command_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    results = ip_command(client, args, params)

    # Then
    # Should have: 1 result for found IP + 2 "not found" messages
    assert len(results) >= 3

    # Check that we have a result for the found IP
    found_result = None
    not_found_results = []
    for result in results:
        if hasattr(result, "outputs_prefix") and result.outputs_prefix == "Censys.IP":
            found_result = result
        elif (
            hasattr(result, "readable_output") and result.readable_output and "No results found for IP:" in result.readable_output
        ):
            not_found_results.append(result)

    assert found_result is not None
    assert found_result.indicator.ip == "127.0.0.1"
    assert len(not_found_results) == 2
    assert any("192.168.1.1" in r.readable_output for r in not_found_results)
    assert any("10.0.0.1" in r.readable_output for r in not_found_results)


def test_ip_command_multiple_ips_all_found(client, requests_mock):
    """
    Given:
        - Multiple IP addresses that are all found in search results.
    When:
        - Running ip_command.
    Then:
        - Ensure results are returned for all IPs.
        - Ensure no "not found" messages are returned.
    """
    # Given
    args = {"ip": ["127.0.0.1", "8.8.8.8"]}
    params = {"integration_reliability": "C - Fairly reliable"}
    # Return hits for both IPs
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        json={
            "result": {
                "hits": [
                    {"host_v1": {"resource": {"ip": "127.0.0.1", "labels": [], "services": []}}},
                    {"host_v1": {"resource": {"ip": "8.8.8.8", "labels": [], "services": []}}},
                ]
            }
        },
    )

    # When
    results = ip_command(client, args, params)

    # Then
    # Should have results for both IPs, no "not found" messages
    ip_results = [r for r in results if hasattr(r, "outputs_prefix") and r.outputs_prefix == "Censys.IP"]
    not_found_results = [
        r
        for r in results
        if hasattr(r, "readable_output") and r.readable_output and "No results found for IP:" in r.readable_output
    ]

    assert len(ip_results) == 2
    assert len(not_found_results) == 0
    assert any(r.indicator.ip == "127.0.0.1" for r in ip_results)
    assert any(r.indicator.ip == "8.8.8.8" for r in ip_results)


def test_domain_command_multiple_domains_partial_found(client, requests_mock):
    """
    Given:
        - Multiple domains where only some are found in search results.
    When:
        - Running domain_command.
    Then:
        - Ensure results are returned for found domains.
        - Ensure "No results found" messages are returned for domains not found.
    """
    # Given
    args = {"domain": ["facebook.com", "nonexistent1.com", "nonexistent2.com"]}
    params = {"integration_reliability": "C - Fairly reliable"}
    # Return hits only for facebook.com
    mock_res = util_load_json("domain_command_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    # When
    results = domain_command(client, args, params)

    # Then
    # Should have: 1 result for found domain + 2 "not found" messages
    assert len(results) >= 3

    # Check that we have a result for the found domain
    found_result = None
    not_found_results = []
    for result in results:
        if hasattr(result, "outputs_prefix") and result.outputs_prefix == "Censys.Domain":
            found_result = result
        elif (
            hasattr(result, "readable_output")
            and result.readable_output
            and "No results found for domain:" in result.readable_output
        ):
            not_found_results.append(result)

    assert found_result is not None
    assert found_result.indicator.domain == "facebook.com"
    assert len(not_found_results) == 2
    assert any("nonexistent1" in r.readable_output for r in not_found_results)
    assert any("nonexistent2" in r.readable_output for r in not_found_results)


def test_domain_command_multiple_domains_all_found(client, requests_mock):
    """
    Given:
        - Multiple domains that are all found in search results.
    When:
        - Running domain_command.
    Then:
        - Ensure results are returned for all domains.
        - Ensure no "not found" messages are returned.
    """
    # Given
    args = {"domain": ["facebook.com", "google.com"]}
    params = {"integration_reliability": "C - Fairly reliable"}
    # Return hits for both domains
    requests_mock.post(
        "https://api.platform.censys.io/v3/global/search/query",
        json={
            "result": {
                "hits": [
                    {"host_v1": {"resource": {"dns": {"names": ["facebook.com"]}, "ip": "1.1.1.1", "labels": []}}},
                    {"host_v1": {"resource": {"dns": {"names": ["google.com"]}, "ip": "2.2.2.2", "labels": []}}},
                ]
            }
        },
    )

    # When
    results = domain_command(client, args, params)

    # Then
    # Should have results for both domains, no "not found" messages
    domain_results = [r for r in results if hasattr(r, "outputs_prefix") and r.outputs_prefix == "Censys.Domain"]
    not_found_results = [
        r
        for r in results
        if hasattr(r, "readable_output") and r.readable_output and "No results found for domain:" in r.readable_output
    ]

    assert len(domain_results) == 2
    assert len(not_found_results) == 0
    assert any(r.indicator.domain == "facebook.com" for r in domain_results)
    assert any(r.indicator.domain == "google.com" for r in domain_results)


def test_domain_command_multiple_domains_none_found(client, requests_mock):
    """
    Given:
        - Multiple domains where none are found in search results.
    When:
        - Running domain_command.
    Then:
        - Ensure "No results found" messages are returned for all domains.
    """
    # Given
    args = {"domain": ["nonexistent1.com", "nonexistent2.com"]}
    params = {}
    # Return empty hits
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {"hits": []}})

    # When
    results = domain_command(client, args, params)

    # Then
    # Should have "not found" messages for both domains
    not_found_results = [
        r
        for r in results
        if hasattr(r, "readable_output") and r.readable_output and "No results found for domain:" in r.readable_output
    ]
    assert len(not_found_results) == 2
    assert any("nonexistent1" in r.readable_output for r in not_found_results)
    assert any("nonexistent2" in r.readable_output for r in not_found_results)


def test_ip_command_multiple_ips_none_found(client, requests_mock):
    """
    Given:
        - Multiple IP addresses where none are found in search results.
    When:
        - Running ip_command.
    Then:
        - Ensure "No results found" messages are returned for all IPs.
    """
    # Given
    args = {"ip": ["192.168.1.1", "10.0.0.1"]}
    params = {}
    # Return empty hits
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {"hits": []}})

    # When
    results = ip_command(client, args, params)

    # Then
    # Should have "not found" messages for both IPs
    not_found_results = [
        r
        for r in results
        if hasattr(r, "readable_output") and r.readable_output and "No results found for IP:" in r.readable_output
    ]
    assert len(not_found_results) == 2
    assert any("192.168.1.1" in r.readable_output for r in not_found_results)
    assert any("10.0.0.1" in r.readable_output for r in not_found_results)


def test_main_test_module(mocker):
    """
    Given:
        - The test-module command.
    When:
        - Running main.
    Then:
        - Ensure test_module is called and results are returned.
    """
    # Given
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value={"api_token": {"password": "token"}})
    mocker.patch.object(demisto, "results")
    mocker.patch("CensysV2.test_module", return_value="ok")

    # When
    main()

    # Then
    demisto.results.assert_called_with("ok")


def test_main_cen_view(mocker):
    """
    Given:
        - The cen-view command.
    When:
        - Running main.
    Then:
        - Ensure censys_view_command is called and results are returned.
    """
    # Given
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="cen-view")
    mocker.patch.object(demisto, "args", return_value={"index": "ipv4", "query": "8.8.8.8"})
    mocker.patch.object(demisto, "params", return_value={"api_token": {"password": "token"}})
    mocker.patch.object(demisto, "results")
    mocker.patch("CensysV2.censys_view_command", return_value="view_results")

    # When
    main()

    # Then
    demisto.results.assert_called_with("view_results")


def test_main_cen_search(mocker):
    """
    Given:
        - The cen-search command.
    When:
        - Running main.
    Then:
        - Ensure censys_search_command is called and results are returned.
    """
    # Given
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="cen-search")
    mocker.patch.object(demisto, "args", return_value={"index": "ipv4", "query": "test"})
    mocker.patch.object(demisto, "params", return_value={"api_token": {"password": "token"}})
    mocker.patch.object(demisto, "results")
    mocker.patch("CensysV2.censys_search_command", return_value="search_results")

    # When
    main()

    # Then
    demisto.results.assert_called_with("search_results")


def test_main_ip(mocker):
    """
    Given:
        - The ip command.
    When:
        - Running main.
    Then:
        - Ensure ip_command is called and results are returned.
    """
    # Given
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(demisto, "args", return_value={"ip": "8.8.8.8"})
    mocker.patch.object(demisto, "params", return_value={"api_token": {"password": "token"}})
    mocker.patch.object(demisto, "results")
    mocker.patch("CensysV2.ip_command", return_value="ip_results")

    # When
    main()

    # Then
    demisto.results.assert_called_with("ip_results")


def test_main_domain(mocker):
    """
    Given:
        - The domain command.
    When:
        - Running main.
    Then:
        - Ensure domain_command is called and results are returned.
    """
    # Given
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="domain")
    mocker.patch.object(demisto, "args", return_value={"domain": "google.com"})
    mocker.patch.object(demisto, "params", return_value={"api_token": {"password": "token"}})
    mocker.patch.object(demisto, "results")
    mocker.patch("CensysV2.domain_command", return_value="domain_results")

    # When
    main()

    # Then
    demisto.results.assert_called_with("domain_results")


def test_main_error(mocker):
    """
    Given:
        - A command that raises an exception.
    When:
        - Running main.
    Then:
        - Ensure return_error is called.
    """
    # Given
    import demistomock as demisto

    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(demisto, "params", return_value={"api_token": {"password": "token"}})
    mocker.patch.object(demisto, "results")
    # Mock return_error in CensysV2 namespace to avoid SystemExit
    mock_return_error = mocker.patch("CensysV2.return_error")
    mocker.patch("CensysV2.ip_command", side_effect=Exception("unexpected error"))

    # When
    main()

    # Then
    mock_return_error.assert_called()


def test_search_certs_command_with_fields(client, requests_mock):
    """
    Given:
        - A search query for certificates with extra fields.
    When:
        - Running search_certs_command (via censys_search_command).
    Then:
        - Ensure the API is called and results are processed.
    """
    args = {"index": "certificates", "query": "test", "fields": "cert.parsed.issuer.common_name", "limit": 1}
    mock_res = util_load_json("search_certs_response.json")
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json=mock_res)

    result = censys_search_command(client, args)
    assert result.outputs_prefix == "Censys.Search"


def test_search_certs_command_error(client, requests_mock):
    """
    Given:
        - A search query for certificates that returns an unexpected response.
    When:
        - Running search_certs_command.
    Then:
        - Ensure ValueError is raised.
    """
    from CensysV2 import search_certs_command

    args = {"fields": ""}
    requests_mock.post("https://api.platform.censys.io/v3/global/search/query", json={"result": {}})
    with pytest.raises(ValueError, match="Unexpected response: 'hits' path not found"):
        search_certs_command(client, args, "query", 1)
