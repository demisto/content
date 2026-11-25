import json

import pytest
from CommonServerPython import DemistoException

from DarkEye import (
    BREACH_HOUSE,
    BREACH_HOUSE_URL,
    HAVEIBEENRANSOM,
    HAVEIBEENRANSOM_URL,
    build_lookups,
    domain_search_command,
    is_about,
    normalize_domain,
    search_domain,
)
from DarkEye import test_module as run_test_module

HIBR_KEY = "hibr-secret-key"
BH_KEY = "bh-secret-key"
HIBR_PAGE_1 = f"{HAVEIBEENRANSOM_URL}/api/metadata/domain/example.com"
HIBR_PAGE_2 = f"{HAVEIBEENRANSOM_URL}/api/metadata/domain/example.com/2"
BH_SEARCH = f"{BREACH_HOUSE_URL}/api/v1/search"
BH_ME = f"{BREACH_HOUSE_URL}/api/v1/me"


def util_load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def make_params(hibr: str = HIBR_KEY, breach_house: str = BH_KEY) -> dict:
    return {
        "haveibeenransom_credentials": {"identifier": "", "password": hibr},
        "breachhouse_credentials": {"identifier": "", "password": breach_house},
        "insecure": False,
        "proxy": False,
    }


@pytest.fixture
def both_products(requests_mock):
    requests_mock.get(HIBR_PAGE_1, json=util_load_json("test_data/hibr_domain_page_1.json"))
    requests_mock.get(HIBR_PAGE_2, json=util_load_json("test_data/hibr_domain_page_2.json"))
    requests_mock.get(BH_SEARCH, json=util_load_json("test_data/breachhouse_search.json"))
    return requests_mock


def test_search_merges_both_products(both_products):
    """
    Given: keys for both products and listings in both.
    When: searching example.com.
    Then: one DarkEye result with product and category per record, duplicates and unrelated listings dropped.
    """
    result = search_domain(build_lookups(make_params()), "example.com", {})

    assert result["Found"] is True
    assert result["Products"] == [HAVEIBEENRANSOM, BREACH_HOUSE]
    assert result["CountsByProduct"] == {HAVEIBEENRANSOM: 3, BREACH_HOUSE: 4}
    assert result["CountsByCategory"] == {"ransomware": 3, "breach": 2, "combolist": 1, "stealer": 1}
    assert result["Truncated"] is False
    assert result["Errors"] == []
    expected_ids = ["1001", "1002", "1003", "AbCdEf123456", "MnOpQr345678", "b-77", "s-9"]
    assert [record["ID"] for record in result["Records"]] == expected_ids
    assert result["Records"][0] == {
        "Product": HAVEIBEENRANSOM,
        "Category": "ransomware",
        "ID": "1001",
        "Title": "Example Corp",
        "Website": "example.com",
        "Group": "examplegroup",
        "Country": "US",
        "Discovered": "2026-01-15",
    }
    assert both_products.call_count == 3


def test_search_never_keeps_leak_details(both_products):
    """
    Given: responses that carry descriptions, leak-site URLs and download links.
    When: searching.
    Then: none of them reach the result.
    """
    text = json.dumps(search_domain(build_lookups(make_params()), "example.com", {}))

    for value in ("onion", "Not kept", "Identities Found", "download"):
        assert value not in text


def test_search_sends_each_key_to_its_product(both_products):
    search_domain(build_lookups(make_params()), "example.com", {"limit": "10"})

    for request in both_products.request_history:
        expected = HIBR_KEY if request.url.startswith(HAVEIBEENRANSOM_URL) else BH_KEY
        assert request.headers["Authorization"] == f"Bearer {expected}"
        assert request.headers["User-Agent"]
    assert both_products.request_history[-1].qs == {"q": ["example.com"], "limit": ["10"]}


def test_hibr_pages_are_bounded(requests_mock):
    """
    Given: HaveIBeenRansom always claims a next page.
    When: searching with max_pages=3.
    Then: exactly 3 requests and the result is marked truncated.
    """
    page = util_load_json("test_data/hibr_domain_page_1.json")
    requests_mock.get(f"{HAVEIBEENRANSOM_URL}/api/metadata/domain/example.com", json=page)
    for number in (2, 3, 4):
        requests_mock.get(f"{HAVEIBEENRANSOM_URL}/api/metadata/domain/example.com/{number}", json=page)

    result = search_domain(build_lookups(make_params(breach_house="")), "example.com", {"max_pages": "3"})

    assert requests_mock.call_count == 3
    assert result["Truncated"] is True
    assert result["Count"] == 2


def test_max_records_truncates(both_products):
    result = search_domain(build_lookups(make_params()), "example.com", {"max_records": "1"})

    assert result["CountsByProduct"] == {HAVEIBEENRANSOM: 1, BREACH_HOUSE: 1}
    assert result["Truncated"] is True
    # HaveIBeenRansom stops after the first page once the cap is reached.
    assert both_products.call_count == 2


def test_only_breach_house_key(requests_mock):
    requests_mock.get(BH_SEARCH, json=util_load_json("test_data/breachhouse_search.json"))

    result = search_domain(build_lookups(make_params(hibr="")), "example.com", {})

    assert result["Products"] == [BREACH_HOUSE]
    assert all(request.url.startswith(BREACH_HOUSE_URL) for request in requests_mock.request_history)


def test_one_product_failing_keeps_the_other(requests_mock):
    """
    Given: HaveIBeenRansom answers and Breach House returns 429.
    When: searching.
    Then: the HaveIBeenRansom records are kept and the Breach House failure is listed.
    """
    requests_mock.get(HIBR_PAGE_1, json=util_load_json("test_data/hibr_domain_page_1.json"))
    requests_mock.get(HIBR_PAGE_2, json=util_load_json("test_data/hibr_domain_page_2.json"))
    requests_mock.get(BH_SEARCH, status_code=429, json={"error": "rate_limited"})

    result = search_domain(build_lookups(make_params()), "example.com", {})

    assert result["Products"] == [HAVEIBEENRANSOM]
    assert result["Count"] == 3
    assert result["Errors"] == [{"Product": BREACH_HOUSE, "Error": "Breach House quota or rate limit reached; retry later."}]


def test_every_product_failing_is_an_error(requests_mock):
    requests_mock.get(HIBR_PAGE_1, status_code=401, json={"error": "invalid_token"})
    requests_mock.get(BH_SEARCH, status_code=500, text="error")

    with pytest.raises(DemistoException) as e:
        search_domain(build_lookups(make_params()), "example.com", {})

    assert "HaveIBeenRansom authentication failed" in str(e.value)
    assert "Breach House returned HTTP 500" in str(e.value)
    assert HIBR_KEY not in str(e.value)
    assert BH_KEY not in str(e.value)


@pytest.mark.parametrize(
    "response",
    [
        {"status_code": 302, "headers": {"Location": "https://elsewhere.example.org/"}},
        {"status_code": 200, "text": "not json"},
        {"status_code": 200, "json": {"success": False, "error": "bad"}},
        {"status_code": 200, "json": {"sources": "not a list"}},
    ],
)
def test_unexpected_hibr_responses_are_failures(requests_mock, response):
    requests_mock.get(HIBR_PAGE_1, **response)

    with pytest.raises(DemistoException):
        search_domain(build_lookups(make_params(breach_house="")), "example.com", {})

    assert requests_mock.call_count == 1


def test_no_key_is_a_configuration_error():
    with pytest.raises(DemistoException, match="Configure a HaveIBeenRansom API key"):
        build_lookups(make_params(hibr=" ", breach_house=""))


@pytest.mark.parametrize("value", ["*.example.com", "exa?mple.com", "10.0.0.1", "example", "example.com/path", ""])
def test_invalid_domains_are_rejected(value):
    with pytest.raises(DemistoException):
        normalize_domain(value)


def test_domain_is_normalized():
    assert normalize_domain(" Example.COM. ") == "example.com"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "website, title, expected",
    [
        ("example.com", "", True),
        ("Mail.Example.com.", "", True),
        ("notexample.com", "", False),
        ("example.com.other.org", "", False),
        ("", "example.com user table", True),
        ("", "Leak of mail.example.com", True),
        ("", "notexample.com dump", False),
        ("", "example.com.other.org dump", False),
        ("", "", False),
    ],
)
def test_is_about(website, title, expected):
    assert is_about({"Website": website, "Title": title}, "example.com") is expected


def test_domain_search_command_outputs(both_products):
    results = domain_search_command(build_lookups(make_params()), {"domain": "example.com,Example.com"})

    assert len(results) == 2
    assert results[0].outputs_prefix == "DarkEye.Domain"
    assert results[0].outputs_key_field == "Name"
    assert results[0].outputs["Name"] == "example.com"
    assert "### DarkEye search for example.com" in results[0].readable_output
    assert "7 record(s) for example.com from HaveIBeenRansom, Breach House." in results[0].readable_output
    assert "| Breach House | stealer |" in results[0].readable_output


def test_test_module_ok(requests_mock):
    requests_mock.get(HIBR_PAGE_1, json=util_load_json("test_data/hibr_domain_page_1.json"))
    requests_mock.get(BH_ME, json=util_load_json("test_data/breachhouse_me.json"))

    assert run_test_module(build_lookups(make_params())) == "ok"
    assert requests_mock.call_count == 2


def test_test_module_reports_the_failing_product(requests_mock):
    requests_mock.get(HIBR_PAGE_1, json=util_load_json("test_data/hibr_domain_page_1.json"))
    requests_mock.get(BH_ME, status_code=401, json={"error": "invalid_token"})

    message = run_test_module(build_lookups(make_params()))

    assert message.startswith("Breach House authentication failed")
    assert BH_KEY not in message
