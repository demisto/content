import json
import pytest
from dateparser import parse
from FeedNVDv2 import parse_cpe_command, build_indicators, Client, calculate_dbotscore, get_cvss_version_and_score
from FeedNVDv2 import cves_to_war_room, retrieve_cves, fetch_indicators_command
from unittest.mock import patch
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


BASE_URL = "https://services.nvd.nist.gov"  # disable-secrets-detection
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

client = Client(
    base_url=BASE_URL,
    proxy=False,
    api_key="",
    tlp_color="",
    has_kev=False,
    feed_tags=[],
    first_fetch="1 day",
    cvssv3severity=[],
    keyword_search="",
)


def open_json(path):
    with open(path) as f:
        return json.loads(f.read())


def test_build_indicators_command():
    """
    Test function for the parse_cpe_command command

    Args:
        None

    Returns:
        Assertions if the tests fail for tag/relationship parsing of a CPE
    """
    raw_cve = open_json('./test_data/nist_response.json')
    cves = raw_cve["vulnerabilities"]
    response = build_indicators(client, cves)
    expected_response = open_json('./test_data/indicator.json')
    assert all(item in expected_response[0] for item in response[0]), "BuildIndicators dictionaries are not equal"


def test_cves_to_war_room():
    raw_cve = open_json('./test_data/nist_response.json')
    cves = raw_cve["vulnerabilities"]
    entry = cves_to_war_room(cves).to_context()
    expected_entry = open_json('./test_data/war_room_entry.json')
    assert entry == expected_entry


@pytest.mark.parametrize("cvss_score, expected_result", [
    (10.0, 3),
    ('10.0', 3),
    (10, 3),
    (6, 2),
    (3, 1),
    (-1, 0)
])
def test_calculate_dbotscore(cvss_score, expected_result):
    score = calculate_dbotscore(cvss_score)
    assert score == expected_result


@pytest.mark.parametrize(
    "input_metrics, expected_version, expected_score",
    [
        ({"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 7.5}}]}, "3.1", 7.5),
        ({"cvssMetricV30": [{"cvssData": {"version": "3.0", "baseScore": 8.0}}]}, "3.0", 8.0),
        ({"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 5.0}}]}, "2.0", 5.0),
        ({}, "", ""),
        ({"cvssMetricV31": [{}]}, "", ""),
        ({"cvssMetricV30": [{}]}, "", ""),
        ({"cvssMetricV2": [{}]}, "", ""),
    ],
)
def test_get_cvss_version_and_score(input_metrics, expected_version, expected_score):
    version, score = get_cvss_version_and_score(input_metrics)
    assert version == expected_version
    assert score == expected_score


@pytest.mark.parametrize("cpe, expected_output, expected_relationships", [
    (["cpe:2.3:a:vendor:product"],
     ["Vendor", "Product", "Application"],
     [EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='Vendor',
                         entity_b_type="identity").to_context(),
      EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='Product',
                         entity_b_type="software").to_context()]),
    (["cpe:2.3:h:a\:_vendor"],
     ["A: vendor", "Hardware"],
     [EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='A: vendor',
                         entity_b_type="identity").to_context()]),
    (["cpe:2.3:o:::"],
     ["Operating-System"],
     []),
])
def test_parse_cpe(cpe, expected_output, expected_relationships):
    """
    Given:
        A CPE represented as a list of strings

    When:
        when parse_cpe is called

    Then:
        return a tuple of a list of tags (no empty strings) and a list of EntityRelationship objects.
    """

    tags, relationships = parse_cpe_command(cpe, 'CVE-2022-1111')
    assert set(tags) == set(expected_output)
    assert [relationship.to_context() for relationship in relationships] == expected_relationships


@pytest.mark.parametrize(
    "input_params, expected_param_string",
    [
        ({"param1": "value1", "noRejected": "None"}, "param1=value1&noRejected&cvssV3Severity=LOW&cvssV3Severity=MEDIUM"),
        ({"noRejected": "None"}, "noRejected&cvssV3Severity=LOW&cvssV3Severity=MEDIUM"),
        ({"hasKev": "True"}, "hasKev&cvssV3Severity=LOW&cvssV3Severity=MEDIUM"),
    ],
)
def test_build_param_string(input_params, expected_param_string):
    client.cvssv3severity = ["LOW", "MEDIUM"]
    result = client.build_param_string(input_params)
    assert result == expected_param_string


@pytest.mark.parametrize(
    "start_date, end_date, publish_date, expected_results",
    [
        ("2024-01-01T00:00:00Z", "2024-01-04T00:00:00Z", True, open_json("./test_data/nist_response.json")["vulnerabilities"][0]),
    ],
)
def test_retrieve_cves(start_date, end_date, publish_date, expected_results):
    # Mocking the client.get_cves method
    with patch('FeedNVDv2.Client.get_cves') as mock_get_cves:
        mock_get_cves.return_value = open_json("./test_data/nist_response.json")
        raw_cves = retrieve_cves(client, parse(start_date), parse(end_date), publish_date)
        assert raw_cves[0] == expected_results


def test_fetch_indicators_command():
    with patch('FeedNVDv2.retrieve_cves') as mock_retrieve_cves, patch('FeedNVDv2.demisto') as demisto_mock:
        expected_result = open_json("./test_data/nist_response.json")["vulnerabilities"][0]
        mock_retrieve_cves.return_value = [expected_result]
        demisto_mock.command.return_value = 'nvd-get-indicators'
        demisto_mock.getArg.return_value = "130 days"
        fetch_indicators_command(client)
        assert mock_retrieve_cves.call_count == 2
