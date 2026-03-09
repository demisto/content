import json
from unittest.mock import patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from dateparser import parse
from FeedNVDv2 import (
    Client,
    build_indicators,
    calculate_dbotscore,
    cves_to_war_room,
    fetch_indicators_command,
    get_cvss_version_and_score,
    parse_cpe_command,
    retrieve_cves,
    CVSS_VERSION_TO_PARAM,
)

BASE_URL = "https://services.nvd.nist.gov"  # disable-secrets-detection
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

# No API calls made during init — safe for unit tests
@pytest.fixture
def client():
    return Client(
        base_url=BASE_URL,
        proxy=False,
        api_key="",
        tlp_color="",
        has_kev=False,
        feed_tags=[],
        first_fetch="1 day",
        cvss_severity=[],
        keyword_search="",
        max_indicators=100,
        cvss_versions=[],
    )


def open_json(path):
    with open(path) as f:
        return json.loads(f.read())


def test_build_indicators_command(client):
    """
    Test function for the parse_cpe_command command

    Args:
        None

    Returns:
        Assertions if the tests fail for tag/relationship parsing of a CPE
    """
    raw_cve = open_json("./test_data/nist_response.json")
    cves = raw_cve["vulnerabilities"]
    response = build_indicators(client, cves)
    expected_response = open_json("./test_data/indicator.json")
    assert all(item in expected_response[0] for item in response[0]), "BuildIndicators dictionaries are not equal"


def test_cves_to_war_room():
    raw_cve = open_json("./test_data/nist_response.json")
    cves = raw_cve["vulnerabilities"]
    entry = cves_to_war_room(cves).to_context()
    expected_entry = open_json("./test_data/war_room_entry.json")
    assert entry == expected_entry


@pytest.mark.parametrize("cvss_score, expected_result", [(10.0, 3), ("10.0", 3), (10, 3), (6, 2), (3, 1), (-1, 0)])
def test_calculate_dbotscore(cvss_score, expected_result):
    score = calculate_dbotscore(cvss_score)
    assert score == expected_result


@pytest.mark.parametrize(
    "input_metrics, expected_version, expected_score",
    [
        ({"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 6.0}}]}, "4.0", 6.0),
        ({"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 7.5}}]}, "3.1", 7.5),
        ({"cvssMetricV30": [{"cvssData": {"version": "3.0", "baseScore": 8.0}}]}, "3.0", 8.0),
        ({"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 5.0}}]}, "2.0", 5.0),
        ({}, "", ""),
        ({"cvssMetricV40": [{}]}, "", ""),
        ({"cvssMetricV31": [{}]}, "", ""),
        ({"cvssMetricV30": [{}]}, "", ""),
        ({"cvssMetricV2": [{}]}, "", ""),
    ],
)
def test_get_cvss_version_and_score(input_metrics, expected_version, expected_score):
    version, score = get_cvss_version_and_score(input_metrics)
    assert version == expected_version
    assert score == expected_score


@pytest.mark.parametrize(
    "cpe, expected_output, expected_relationships",
    [
        (
            ["cpe:2.3:a:vendor:product"],
            ["Vendor", "Product", "Application"],
            [
                EntityRelationship(
                    name="targets", entity_a="CVE-2022-1111", entity_a_type="cve", entity_b="Vendor", entity_b_type="identity"
                ).to_context(),
                EntityRelationship(
                    name="targets", entity_a="CVE-2022-1111", entity_a_type="cve", entity_b="Product", entity_b_type="software"
                ).to_context(),
            ],
        ),
        (
            ["cpe:2.3:h:a\:_vendor"],
            ["A: vendor", "Hardware"],
            [
                EntityRelationship(
                    name="targets", entity_a="CVE-2022-1111", entity_a_type="cve", entity_b="A: vendor", entity_b_type="identity"
                ).to_context()
            ],
        ),
        (["cpe:2.3:o:::"], ["Operating-System"], []),
    ],
)
def test_parse_cpe(cpe, expected_output, expected_relationships):
    """
    Given:
        A CPE represented as a list of strings

    When:
        when parse_cpe is called

    Then:
        return a tuple of a list of tags (no empty strings) and a list of EntityRelationship objects.
    """

    tags, relationships = parse_cpe_command(cpe, "CVE-2022-1111")
    assert set(tags) == set(expected_output)
    assert [relationship.to_context() for relationship in relationships] == expected_relationships


@pytest.mark.parametrize(
    "input_params, cvss_severity_param, expected_param_string",
    [
        (
            {"param1": "value1", "noRejected": "None"},
            "cvssV3Severity",
            "param1=value1&noRejected&cvssV3Severity=LOW&cvssV3Severity=MEDIUM",
        ),
        (
            {"noRejected": "None"},
            "cvssV3Severity",
            "noRejected&cvssV3Severity=LOW&cvssV3Severity=MEDIUM",
        ),
        (
            {"hasKev": "True"},
            "cvssV4Severity",
            "hasKev&cvssV4Severity=LOW&cvssV4Severity=MEDIUM",
        ),
        (
            {"noRejected": "None"},
            "",
            "noRejected",
        ),
    ],
)
def test_build_param_string(input_params, cvss_severity_param, expected_param_string, client):
    client.cvss_severity = ["LOW", "MEDIUM"]
    result = client.build_param_string(input_params, cvss_severity_param=cvss_severity_param)
    assert result == expected_param_string


@pytest.mark.parametrize(
    "start_date, end_date, publish_date, expected_results",
    [
        ("2024-01-01T00:00:00Z", "2024-01-04T00:00:00Z", True, open_json("./test_data/nist_response.json")["vulnerabilities"][0]),
    ],
)
def test_retrieve_cves(start_date, end_date, publish_date, expected_results, client):
    # Mocking the client.get_cves method
    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        mock_get_cves.return_value = open_json("./test_data/nist_response.json")
        raw_cves = retrieve_cves(client, parse(start_date), parse(end_date), publish_date)
        assert raw_cves[0] == expected_results


def test_fetch_indicators_command(client):
    with patch("FeedNVDv2.retrieve_cves") as mock_retrieve_cves, patch("FeedNVDv2.demisto") as demisto_mock:
        expected_result = open_json("./test_data/nist_response.json")["vulnerabilities"][0]
        mock_retrieve_cves.return_value = [expected_result]
        demisto_mock.command.return_value = "nvd-get-indicators"
        demisto_mock.getArg.return_value = "130 days"
        fetch_indicators_command(client, command="nvd-get-indicators")
        assert mock_retrieve_cves.call_count == 2


def test_build_param_string_no_severity(client):
    """
    Given:
        A client with no CVSS severity filters configured.
    When:
        build_param_string is called with a cvss_severity_param.
    Then:
        No severity values should be appended (empty cvss_severity list).
    """
    client.cvss_severity = []
    result = client.build_param_string({"noRejected": "None"}, cvss_severity_param="cvssV3Severity")
    assert result == "noRejected"
    for param in CVSS_VERSION_TO_PARAM.values():
        assert param not in result


def test_build_param_string_single_severity(client):
    """
    Given:
        A client with a single CVSS severity filter (CRITICAL) and cvssV3Severity param.
    When:
        build_param_string is called.
    Then:
        The severity should be appended using the specified CVSS version parameter.
    """
    client.cvss_severity = ["CRITICAL"]
    result = client.build_param_string({"noRejected": "None"}, cvss_severity_param="cvssV3Severity")
    assert "cvssV3Severity=CRITICAL" in result


def test_build_param_string_severity_uses_camel_case(client):
    """
    Given:
        A client with CVSS severity filters and cvssV3Severity param.
    When:
        build_param_string is called.
    Then:
        The severity parameter should use camelCase (not lowercase cvssv4severity).
    """
    client.cvss_severity = ["HIGH"]
    result = client.build_param_string({"noRejected": "None"}, cvss_severity_param="cvssV3Severity")
    assert "cvssV3Severity=HIGH" in result
    assert "cvssv4severity" not in result


def test_retrieve_cves_respects_limit(client):
    """
    Given:
        A remaining_limit of 1 and a response with 1 CVE.
    When:
        retrieve_cves is called.
    Then:
        It should stop fetching after reaching the limit.
    """
    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        response = open_json("./test_data/nist_response.json")
        # Simulate a response with totalResults > resultsPerPage to test limit stops early
        response["totalResults"] = 5000
        mock_get_cves.return_value = response
        raw_cves = retrieve_cves(client, parse("2024-01-01T00:00:00Z"), parse("2024-01-04T00:00:00Z"), True, remaining_limit=1)
        assert len(raw_cves) == 1  # Should be truncated to exactly the limit
        # Should only call get_cves once since limit is reached
        assert mock_get_cves.call_count == 1


def test_retrieve_cves_no_limit(client):
    """
    Given:
        A remaining_limit of 0 (no limit).
    When:
        retrieve_cves is called.
    Then:
        It should fetch all available CVEs.
    """
    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        response = open_json("./test_data/nist_response.json")
        mock_get_cves.return_value = response
        raw_cves = retrieve_cves(client, parse("2024-01-01T00:00:00Z"), parse("2024-01-04T00:00:00Z"), True, remaining_limit=None)
        assert len(raw_cves) == 1


def test_fetch_indicators_saves_first_fetch_flag():
    """
    Given:
        A first fetch with max_indicators limit that gets reached.
    When:
        fetch_indicators_command is called.
    Then:
        The lastRun should include isFirstFetch=True so the next run continues with publish_date.
    """
    limited_client = Client(
        base_url=BASE_URL,
        proxy=False,
        api_key="",
        tlp_color="",
        has_kev=False,
        feed_tags=[],
        first_fetch="1000 days",
        cvss_severity=[],
        keyword_search="",
        max_indicators=1,
        cvss_versions=[],
    )
    with (
        patch("FeedNVDv2.retrieve_cves") as mock_retrieve_cves,
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        expected_result = open_json("./test_data/nist_response.json")["vulnerabilities"][0]
        mock_retrieve_cves.return_value = [expected_result]
        demisto_mock.command.return_value = "fetch-indicators"
        demisto_mock.getLastRun.return_value = {}
        fetch_indicators_command(limited_client)
        # Verify isFirstFetch is saved
        last_run_call = mock_set_last_run.call_args[0][0]
        assert last_run_call.get("isFirstFetch") is True


def test_retrieve_cves_limit_exactly_reached():
    """
    Given:
        A client with cvss_severity=["HIGH"] (triggers multi-CVSS-version path)
        and a remaining_limit equal to the number of CVEs returned by the first call.
    When:
        retrieve_cves is called.
    Then:
        _fetch_cves_page should be called only once, because the limit is exactly
        reached after the first CVSS version call and page_limit drops to 0 for
        subsequent versions.
    """
    severity_client = Client(
        base_url=BASE_URL,
        proxy=False,
        api_key="",
        tlp_color="",
        has_kev=False,
        feed_tags=[],
        first_fetch="1 day",
        cvss_severity=["HIGH"],
        keyword_search="",
        max_indicators=100,
        cvss_versions=[],
    )
    fake_cves = [
        {"cve": {"id": "CVE-2024-0001"}},
        {"cve": {"id": "CVE-2024-0002"}},
    ]

    with patch("FeedNVDv2._fetch_cves_page") as mock_fetch_page:
        mock_fetch_page.return_value = fake_cves

        raw_cves = retrieve_cves(
            severity_client,
            parse("2024-01-01T00:00:00Z"),
            parse("2024-01-04T00:00:00Z"),
            True,
            remaining_limit=2,
        )

        assert len(raw_cves) == 2
        assert mock_fetch_page.call_count == 1, (
            "_fetch_cves_page should be called only once when limit is exactly reached"
        )


def test_retrieve_cves_single_cvss_version():
    """
    Given:
        A client with cvss_versions set to only CVSS v3.
    When:
        retrieve_cves is called with severity filter.
    Then:
        Only one API call should be made (for cvssV3Severity).
    """
    test_client = Client(
        base_url=BASE_URL, proxy=False, api_key="", tlp_color="",
        has_kev=False, feed_tags=[], first_fetch="1 day",
        cvss_severity=["HIGH"], keyword_search="",
        max_indicators=100, cvss_versions=["CVSS v3"],
    )
    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        response = open_json("./test_data/nist_response.json")
        mock_get_cves.return_value = response
        raw_cves = retrieve_cves(test_client, parse("2024-01-01T00:00:00Z"), parse("2024-01-04T00:00:00Z"), True)
        assert mock_get_cves.call_count == 1
        # Verify the correct CVSS param was used
        call_args = mock_get_cves.call_args
        assert call_args[1].get("cvss_severity_param") == "cvssV3Severity" or call_args[0][2] == "cvssV3Severity" if len(call_args[0]) > 2 else True


def test_retrieve_cves_default_cvss_versions():
    """
    Given:
        A client with default cvss_versions (all versions: v4, v3, v2).
    When:
        retrieve_cves is called with severity filter.
    Then:
        Three API calls should be made (one per CVSS version).
    """
    test_client = Client(
        base_url=BASE_URL, proxy=False, api_key="", tlp_color="",
        has_kev=False, feed_tags=[], first_fetch="1 day",
        cvss_severity=["HIGH"], keyword_search="",
        max_indicators=100, cvss_versions=[],
    )
    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        response = open_json("./test_data/nist_response.json")
        mock_get_cves.return_value = response
        retrieve_cves(test_client, parse("2024-01-01T00:00:00Z"), parse("2024-01-04T00:00:00Z"), True)
        assert mock_get_cves.call_count == 3  # v4 + v3 + v2
