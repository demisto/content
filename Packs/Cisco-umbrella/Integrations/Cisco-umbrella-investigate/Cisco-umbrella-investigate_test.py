import json
import os
from http import HTTPStatus
from urllib.parse import urljoin
import pytest
import CommonServerPython
import importlib

BASE_URL = "http://example.com"
module = importlib.import_module("Cisco-umbrella-investigate")


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client() -> module.Client:
    """Create a test client for DataBee.

    Returns:
        Client: Cisco Umbrella Investigate API Client.
    """
    return module.Client(
        base_url=BASE_URL,
        verify=False,
        proxy=False,
        api_key="test",
        api_secret="test",
        reliability=CommonServerPython.DBotScoreReliability.A,
    )


def test_get_domain_categorization_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get the status, security and content category IDs for domain.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-domain-categorization
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
     - Ensure that outputs contains indicator.
    """
    json_response = load_mock_response("domain_categorization.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/domains/categorization/test.com?showLabels",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.get_domain_categorization_command(
        mock_client,
        {
            "domain": "test.com",
        },
    )
    assert result.outputs_prefix == "Domain"
    assert result.outputs_key_field == "Name"
    assert isinstance(result.outputs, dict)
    assert {"Name", "SecurityCategories", "ContentCategories"}.issubset(result.outputs)
    assert result.indicator


def test_search_domain_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Search for newly seen domains that match a regular expression pattern.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-domain-search
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
     - Ensure that outputs contains indicator.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/search/exa%5Ba-z%5Dple.com?start=1711450998000"
            + "&stop=1711450998000&includeCategory=False&limit=50",
        ),
        json=load_mock_response("search_domain.json"),
    )
    result = module.search_domain_command(
        mock_client,
        {
            "regex": "exa[a-z]ple.com",
            "start": "2024-03-26T11:03:18Z",
            "stop": "2024-03-26T11:03:18Z",
            "include_category": "false",
            "page": "0",
            "limit": "50",
        },
    )
    assert result.outputs_prefix == "Domain"
    assert result.outputs_key_field == "Name"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1
    assert {"Name", "FirstSeen", "FirstSeenISO", "SecurityCategories"}.issubset(result.outputs[0])


def test_list_domain_co_occurens_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: List the co-occurences for the specified domain.

    Given:
     - User has provided correct parameters.
    When:
     - umbrella-domain-co-occurrences
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("domain_co_occurence.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/recommendations/name/test.com.json",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.list_domain_co_occurences_command(
        mock_client,
        {
            "domain": "test.com",
        },
    )
    assert result.outputs_prefix == "Domain"
    assert result.outputs_key_field == "Name"
    assert isinstance(result.outputs, dict)
    assert "CoOccurrences" in result.outputs
    assert isinstance(result.outputs["CoOccurrences"], list)
    assert len(result.outputs["CoOccurrences"]) == 2
    assert ["Name", "Score"] == list(result.outputs["CoOccurrences"][0])


def test_list_related_domain_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: List domain names that are frequently requested around the same time.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-domain-related
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("domain_related_domains.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/links/name/test.com",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.list_related_domain_command(
        mock_client,
        {
            "domain": "test.com",
        },
    )
    assert result.outputs_prefix == "Domain"
    assert result.outputs_key_field == "Name"
    assert isinstance(result.outputs, dict)
    assert "Related" in result.outputs
    assert isinstance(result.outputs["Related"], list)
    assert len(result.outputs["Related"]) == 2
    assert ["Name", "Score"] == list(result.outputs["Related"][0])


def test_get_domain_security_score_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get multiple scores or security features for a domain.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-domain-security
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/security/name/test.com",
        ),
        json=load_mock_response("domain_security.json"),
    )
    result = module.get_domain_security_score_command(
        mock_client,
        {
            "domain": "test.com",
        },
    )
    assert result.outputs_prefix == "Domain"
    assert result.outputs_key_field == "Name"
    assert isinstance(result.outputs, dict)
    assert {
        "Name",
        "Security",
        "tld_geodiversity",
        "GeodiversityNormalized",
        "Geodiversity",
    }.issubset(result.outputs)
    assert isinstance(result.outputs["Security"], dict)
    assert {
        "DGA",
        "Perplexity",
        "Entropy",
        "SecureRank",
        "PageRank",
        "ASNScore",
        "PrefixScore",
        "RipScore",
        "Popularity",
        "GeoScore",
        "KolmoorovSmirnov",
        "AttackName",
        "ThreatType",
    }.issubset(result.outputs["Security"])


def test_get_domain_risk_score_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get the domain risk score.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-domain-risk-score
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields.
     - Ensure that outputs contains indicator.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/domains/risk-score/test.com",
        ),
        json=load_mock_response("domain_risk_score.json"),
    )
    result = module.get_domain_risk_score_command(
        mock_client,
        {
            "domain": "test.com",
        },
    )
    assert result.outputs_prefix == "Umbrella.Domain"
    assert result.outputs_key_field == "name"
    assert isinstance(result.outputs, dict)
    assert "Indicator" in result.outputs
    assert {
        "name",
        "risk_score",
        "Indicator",
    }.issubset(result.outputs)
    assert isinstance(result.outputs["Indicator"], list)
    assert len(result.outputs["Indicator"]) == 1
    assert {
        "score",
        "normalized_score",
        "indicator_id",
        "indicator",
    }.issubset(result.outputs["Indicator"][0])
    assert result.indicator


def test_list_resource_record_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    List the Resource Record (RR) data for DNS responses.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-list-resource-record
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/pdns/Domain/test.com?sortorder=desc&includefeatures=False&limit=50&offset=0",
        ),
        json=load_mock_response("resource_records.json"),
    )
    result = module.list_resource_record_command(
        mock_client,
        {
            "value": "test.com",
            "limit": "50",
            "page": "0",
            "type": "Domain",
            "sort_order": "desc",
        },
    )
    assert result.outputs_prefix == "Umbrella.ResourceRecord"
    assert result.outputs_key_field == "rr"
    assert isinstance(result.outputs, list)
    assert {
        "value",
        "last_seen_iso",
        "first_seen_iso",
        "content_categories",
        "security_categories",
        "type",
        "name",
        "rr",
        "last_seen",
        "first_seen",
        "max_ttl",
        "min_ttl",
    }.issubset(result.outputs[0])


def test_list_sub_domain_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: List sub-domains of a given domain.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-list-domain-subdomian
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/subdomains/test.com?limit=50",
        ),
        json=load_mock_response("domain_sub_domain.json"),
    )
    result = module.list_sub_domain_command(
        mock_client,
        {"domain": "test.com", "all_results": "false", "limit": "50"},
    )
    assert result.outputs_prefix == "Umbrella.Domain"
    assert result.outputs_key_field == "name"
    assert isinstance(result.outputs, dict)
    assert {
        "name",
        "SubDomain",
    }.issubset(result.outputs)
    assert isinstance(result.outputs["SubDomain"], list)
    assert len(result.outputs["SubDomain"]) == 2
    assert {
        "name",
        "first_seen",
        "security_categories",
    }.issubset(result.outputs["SubDomain"][0])


def test_get_ip_bgp_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get data about ASN and IP relationships,
    showing how IP addresses are related to each other and to the regional registries.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-ip-bgp
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/bgp_routes/ip/8.8.8.8/as_for_ip.json",
        ),
        json=load_mock_response("ip_bgp.json"),
    )
    result = module.get_ip_bgp_command(
        mock_client,
        {
            "ip": "8.8.8.8",
        },
    )
    assert result.outputs_prefix == "Umbrella.BGPInformation"
    assert result.outputs_key_field == "cidr"
    assert isinstance(result.outputs, list)
    assert {
        "ip",
        "creation_date",
        "ir",
        "description",
        "asn",
        "cidr",
    }.issubset(result.outputs[0])


def test_get_asn_bgp_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get BGP Route Information for ASN.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-asn-bgp
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/bgp_routes/asn/1234/prefixes_for_asn.json",
        ),
        json=load_mock_response("asn_bgp.json"),
    )
    result = module.get_asn_bgp_command(
        mock_client,
        {
            "asn": "1234",
        },
    )
    assert result.outputs_prefix == "Umbrella.BGPInformation"
    assert result.outputs_key_field == "cidr"
    assert isinstance(result.outputs, list)
    assert {
        "asn",
        "Geo",
        "cidr",
    }.issubset(result.outputs[0])


def test_get_top_seen_domain_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: List the most seen domains in Umbrella.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-top-most-seen-domain
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/topmillion?limit=50",
        ),
        json=load_mock_response("top_domain.json"),
    )
    result = module.get_top_seen_domain_command(
        mock_client,
        {"all_results": "false", "limit": "50"},
    )
    assert result.outputs_prefix == "Umbrella.MostSeenDomain"
    assert result.outputs_key_field == "domain"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 4


def test_get_domain_volume_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: List the query volume for a domain over the last 30 days.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-list-domain-volume
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("domain_volume.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/domains/volume/test.com?start=1711450998000&stop=1711450998000",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.get_domain_volume_command(
        mock_client,
        {"domain": "test.com", "start": "2024-03-26T11:03:18Z", "stop": "2024-03-26T11:03:18Z", "all_results": "true"},
    )
    assert result.outputs_prefix == "Umbrella.QueryVolume"
    assert result.outputs_key_field == "name"
    assert isinstance(result.outputs, dict)
    assert {
        "name",
        "Domain",
        "Data",
        "QueriesInfo",
    }.issubset(result.outputs)
    assert {
        "StartDate",
        "StopDate",
    }.issubset(result.outputs["Data"])
    assert isinstance(result.outputs["QueriesInfo"], list)
    assert len(result.outputs["QueriesInfo"]) == 4
    assert {
        "QueryHour",
        "Queries",
    }.issubset(result.outputs["QueriesInfo"][0])


def test_list_timeline(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: List the historical tagging timeline for a given IP, domain, or URL.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-list-timeline
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/timeline/test.com",
        ),
        json=load_mock_response("list_timeline.json"),
    )
    result = module.list_timeline_command(
        mock_client,
        {
            "domain": "test.com",
            "all_results": "false",
            "limit": "50",
        },
        "Domain"
    )
    assert result.outputs_prefix == "Umbrella.Timeline"
    assert result.outputs_key_field == "Domain"
    assert isinstance(result.outputs, dict)
    assert {
        "Domain",
        "Data",
    }.issubset(result.outputs)
    assert isinstance(result.outputs["Data"], list)
    assert len(result.outputs["Data"]) == 2
    assert {
        "MalwareCategories",
        "Attacks",
        "ThreatTypes",
        "Timestamp",
    }.issubset(result.outputs["Data"][0])


def test_get_domain_who_is_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get the WHOIS information for the specified domains.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-whois-for-domain
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/security/name/test.com",
        ),
        json=load_mock_response("domain_security.json"),
    )
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/whois/test.com",
        ),
        json=load_mock_response("domain_whois.json"),
    )
    result = module.get_domain_who_is_command(
        mock_client,
        {
            "domain": "test.com",
            "all_results": "false",
            "limit": "50",
        },
    )
    assert result.outputs_prefix == "Umbrella.WHOIS"
    assert result.outputs_key_field == "name"
    assert result.indicator
    assert isinstance(result.outputs, dict)
    assert {
        "name",
        "Domain",
        "Data",
    }.issubset(result.outputs)
    assert {
        "RegistrarName",
        "LastRetrieved",
        "Created",
        "Updated",
        "Expires",
        "IANAID",
        "Emails",
        "Nameservers",
        "LastObserved",
    }.issubset(result.outputs["Data"])


def test_get_domain_who_is_history_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get a WHOIS response record for a single domain with available historical WHOIS data.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-domain-whois-history
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("whois_history.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/whois/test.com/history?limit=50",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.get_domain_who_is_history_command(
        mock_client,
        {
            "domain": "test.com",
            "all_results": "false",
            "limit": "50",
        },
    )
    assert result.outputs_prefix == "Umbrella.WHOIS"
    assert result.outputs_key_field == "name"


def test_get_nameserver_who_is_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get WHOIS information for the nameserver.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-nameserver-whois
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("nameserver_whois.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/whois/nameservers/test.com?limit=50&offset=0",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.get_nameserver_who_is_command(
        mock_client,
        {"nameserver": "test.com", "page": "0", "limit": "50"},
    )
    assert result.outputs_prefix == "Umbrella.WHOIS.Nameserver"
    assert result.outputs_key_field == "name"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1
    assert {
        "name",
        "Domain",
    }.issubset(result.outputs[0])


def test_get_email_who_is_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get WHOIS information for the email address.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-email-whois
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("email_whois.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/whois/emails/test@test.com?limit=50&offset=0",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.get_email_who_is_command(
        mock_client,
        {
            "email": "test@test.com",
            "page": "0",
            "limit": "50",
        },
    )
    assert result.outputs_prefix == "Umbrella.WHOIS.Email"
    assert result.outputs_key_field == "name"
    assert isinstance(result.outputs, dict)
    assert {
        "name",
        "Domain",
    }.issubset(result.outputs)


def test_get_regex_who_is_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Performs a regular expression (RegEx) search on the WHOIS data
    (domain, nameserver, and email fields) that was updated or created in the specified time range.
    Given:
     - User has provided correct parameters.
    When:
     - umbrella-get-regex-whois
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    json_response = load_mock_response("regex_whois.json")
    url = urljoin(
        BASE_URL,
        "investigate/v2/whois/search/Domain/exa%5Ba-z%5Dple.com"
        + "?start=1711450998000&stop=1711450998000&limit=50&offset=0",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = module.get_regex_who_is_command(
        mock_client,
        {
            "regex": "exa[a-z]ple.com",
            "search_field": "Domain",
            "start": "2024-03-26T11:03:18Z",
            "stop": "2024-03-26T11:03:18Z",
            "page": "0",
            "limit": "50",
        },
    )
    assert result.outputs_prefix == "Umbrella.WHOIS.Regex"
    assert result.outputs_key_field == "domain_name"


def test_domain_command(
    requests_mock,
    mock_client: module.Client,
):
    """
    Scenario: Get the WHOIS information for the specified domains.
    You can search by multiple email addresses or multiple nameservers.
    Given:
     - User has provided correct parameters.
    When:
     - domain
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/whois/test.com",
        ),
        json=load_mock_response("domain_whois.json"),
    )
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/domains/risk-score/test.com",
        ),
        json=load_mock_response("domain_risk_score.json"),
    )
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/domains/categorization/test.com",
        ),
        json=load_mock_response("domain_categorization.json"),
    )
    requests_mock.get(
        url=urljoin(
            BASE_URL,
            "investigate/v2/security/name/test.com",
        ),
        json=load_mock_response("domain_security.json"),
    )
    result = module.domain_command(
        mock_client,
        {
            "domain": "test.com",
        },
    )
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0].outputs_prefix == "Domain"
    assert result[0].outputs_key_field == "Name"


@pytest.mark.parametrize(
    ("status", "securerank", "risk_score", "expected_result"),
    (
        (1, None, None, CommonServerPython.Common.DBotScore.GOOD),
        (-1, None, None, CommonServerPython.Common.DBotScore.BAD),
        (0, None, None, CommonServerPython.Common.DBotScore.NONE),
        (None, -1, None, CommonServerPython.Common.DBotScore.SUSPICIOUS),
        (None, 7, None, CommonServerPython.Common.DBotScore.GOOD),
        (None, -7, None, CommonServerPython.Common.DBotScore.SUSPICIOUS),
        (None, -100, 0, CommonServerPython.Common.DBotScore.BAD),
        (None, None, 1, CommonServerPython.Common.DBotScore.GOOD),
        (None, None, 51, CommonServerPython.Common.DBotScore.SUSPICIOUS),
        (None, None, 97, CommonServerPython.Common.DBotScore.BAD),
    ),
)
def test_calculate_domain_dbot_score(status, securerank, risk_score, expected_result):
    """
    Scenario: Get the WHOIS information for the specified domains.
    You can search by multiple email addresses or multiple nameservers.
    Given:
     - User has provided correct parameters.
    When:
     - domain
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs fields correct.
    """
    result = module.calculate_domain_dbot_score(
        status=status, secure_rank=securerank, risk_score=risk_score
    )
    assert result == expected_result
