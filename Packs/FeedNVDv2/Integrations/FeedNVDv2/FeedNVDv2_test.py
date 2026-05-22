import json
from unittest.mock import patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from dateparser import parse
from FeedNVDv2 import (
    Client,
    _fetch_cves_in_windows,
    _ingest_batch,
    _resolve_auto_fetch_window,
    _retrieve_cves_single_query,
    _select_primary_cvss_entry,
    build_indicators,
    calculate_dbotscore,
    cves_to_war_room,
    get_cvss_version_and_score,
    manual_get_indicators_command,
    parse_cpe_command,
    retrieve_cves,
)
from datetime import UTC

BASE_URL = "https://services.nvd.nist.gov"  # disable-secrets-detection
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR


@pytest.fixture
def client():
    """Return a fresh Client instance for each test."""
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
        cvss_versions=["CVSS v4", "CVSS v3"],
        max_indicators=10000,
    )


def open_json(path):
    with open(path) as f:
        return json.loads(f.read())


def test_build_indicators_command(client):
    """
    Test function for the parse_cpe_command command

    Args:
        client: pytest fixture providing a Client instance.

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
    result = cves_to_war_room(cves)
    entry = result.to_context()
    expected_entry = open_json("./test_data/war_room_entry.json")

    assert entry["HumanReadable"] == expected_entry["HumanReadable"]
    # raw_response is now passed through, so Contents holds the raw CVE dicts.
    assert entry["Contents"] == cves
    # EntryContext key uses outputs_key_field="id".
    context_values = list(entry["EntryContext"].values())
    expected_context_values = list(expected_entry["EntryContext"].values())
    assert context_values == expected_context_values


def test_cves_to_war_room_empty():
    """When no CVEs match, outputs should be None with a descriptive message."""
    result = cves_to_war_room([])
    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == "No CVE indicators were found for the given parameters."
    assert result.raw_response == []


@pytest.mark.parametrize("cvss_score, expected_result", [(10.0, 3), ("10.0", 3), (10, 3), (6, 2), (3, 1), (-1, 0)])
def test_calculate_dbotscore(cvss_score, expected_result):
    score = calculate_dbotscore(cvss_score)
    assert score == expected_result


@pytest.mark.parametrize(
    "input_metrics, expected_version, expected_score, expected_severity",
    [
        ({"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 6.0, "baseSeverity": "MEDIUM"}}]}, "4.0", 6.0, "MEDIUM"),
        ({"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}}]}, "3.1", 7.5, "HIGH"),
        ({"cvssMetricV30": [{"cvssData": {"version": "3.0", "baseScore": 8.0, "baseSeverity": "HIGH"}}]}, "3.0", 8.0, "HIGH"),
        ({"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}, "2.0", 5.0, "MEDIUM"),
        ({}, "", "", ""),
        ({"cvssMetricV40": [{}]}, "", "", ""),
        ({"cvssMetricV31": [{}]}, "", "", ""),
        ({"cvssMetricV30": [{}]}, "", "", ""),
        ({"cvssMetricV2": [{}]}, "", "", ""),
        # Multi-source: CNA first, Primary second — should pick Primary
        (
            {
                "cvssMetricV31": [
                    {
                        "source": "cna@vendor.com",
                        "type": "Secondary",
                        "cvssData": {"version": "3.1", "baseScore": 6.3, "baseSeverity": "MEDIUM"},
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"},
                    },
                ]
            },
            "3.1",
            9.8,
            "CRITICAL",
        ),
    ],
)
def test_get_cvss_version_and_score(input_metrics, expected_version, expected_score, expected_severity):
    version, score, severity = get_cvss_version_and_score(input_metrics)
    assert version == expected_version
    assert score == expected_score
    assert severity == expected_severity


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
    "input_params, severity_param, severity_value, expected_param_string",
    [
        (
            {"param1": "value1", "noRejected": "None"},
            "cvssV3Severity",
            "HIGH",
            "param1=value1&noRejected&cvssV3Severity=HIGH",
        ),
        (
            {"noRejected": "None"},
            "cvssV4Severity",
            "LOW",
            "noRejected&cvssV4Severity=LOW",
        ),
        (
            {"hasKev": "True"},
            "cvssV2Severity",
            "MEDIUM",
            "hasKev&cvssV2Severity=MEDIUM",
        ),
        (
            {"param1": "value1", "noRejected": "None"},
            "",
            "",
            "param1=value1&noRejected",
        ),
    ],
)
def test_build_param_string(client, input_params, severity_param, severity_value, expected_param_string):
    client.cvss_severity = ["LOW", "MEDIUM"]
    result = client.build_param_string(input_params, severity_param=severity_param, severity_value=severity_value)
    assert result == expected_param_string


@pytest.mark.parametrize(
    "start_date, end_date, expected_results",
    [
        ("2024-01-01T00:00:00Z", "2024-01-04T00:00:00Z", open_json("./test_data/nist_response.json")["vulnerabilities"][0]),
    ],
)
def test_retrieve_cves(client, start_date, end_date, expected_results):
    # Mocking the client.get_cves method
    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        mock_get_cves.return_value = open_json("./test_data/nist_response.json")
        raw_cves = retrieve_cves(client, parse(start_date), parse(end_date), use_pub_date=True)
        assert raw_cves[0] == expected_results


def test_manual_get_indicators_command(client):
    """
    Given:
        A manual fetch (nvd-get-indicators) spanning 130 days.

    When:
        manual_get_indicators_command is called.

    Then:
        retrieve_cves is called twice (130 days > 120-day NVD limit → two batches)
        and a CommandResults object is returned.
    """
    with patch("FeedNVDv2.retrieve_cves") as mock_retrieve_cves, patch("FeedNVDv2.demisto") as demisto_mock:
        expected_result = open_json("./test_data/nist_response.json")["vulnerabilities"][0]
        mock_retrieve_cves.return_value = [expected_result]
        demisto_mock.getArg.side_effect = lambda key: {
            "history": "130 days",
            "keyword": None,
            "limit": "10000",
            "cvss_severity": None,
            "cvss_versions": None,
        }.get(key)
        result = manual_get_indicators_command(client)
        assert mock_retrieve_cves.call_count == 2
        assert isinstance(result, CommandResults)


def test_manual_get_indicators_command_override_filters(client):
    """
    Given:
        A manual fetch with cvss_severity and cvss_versions overrides.

    When:
        manual_get_indicators_command is called.

    Then:
        The client's cvss_severity and cvss_versions are overridden.
    """
    with patch("FeedNVDv2.retrieve_cves") as mock_retrieve_cves, patch("FeedNVDv2.demisto") as demisto_mock:
        mock_retrieve_cves.return_value = []
        demisto_mock.getArg.side_effect = lambda key: {
            "history": "7 days",
            "keyword": None,
            "limit": "100",
            "cvss_severity": "CRITICAL,HIGH",
            "cvss_versions": "CVSS v3,CVSS v2",
        }.get(key)
        manual_get_indicators_command(client)
        assert client.cvss_severity == ["CRITICAL", "HIGH"]
        assert client.cvss_versions == ["CVSS v3", "CVSS v2"]


def test_resolve_auto_fetch_window_first_run(client):
    """
    Given:
        No lastRun data (first run).

    When:
        _resolve_auto_fetch_window is called.

    Then:
        Returns a start_date derived from first_fetch and use_pub_date=True.
    """
    with patch("FeedNVDv2.demisto") as demisto_mock:
        demisto_mock.getLastRun.return_value = {}
        start_date, use_pub_date = _resolve_auto_fetch_window(client)
        assert start_date is not None
        assert use_pub_date is True


def test_resolve_auto_fetch_window_resume(client):
    """
    Given:
        lastRun data with a resumeFrom key and usePubDate=True.

    When:
        _resolve_auto_fetch_window is called.

    Then:
        Returns the resume date and the saved usePubDate flag.
    """
    with patch("FeedNVDv2.demisto") as demisto_mock:
        demisto_mock.getLastRun.return_value = {
            "lastRun": "2024-01-01T00:00:00Z",
            "resumeFrom": "2024-03-01T00:00:00Z",
            "usePubDate": True,
        }
        start_date, use_pub_date = _resolve_auto_fetch_window(client)
        assert start_date == parse("2024-03-01T00:00:00Z")
        assert use_pub_date is True


def test_ingest_batch_creates_indicators(client):
    """
    Given:
        A batch of raw CVEs.

    When:
        _ingest_batch is called.

    Then:
        All indicators are created and the count is returned.
    """
    raw_cves = open_json("./test_data/nist_response.json")["vulnerabilities"]
    with patch("FeedNVDv2.demisto") as demisto_mock:
        created = _ingest_batch(client, raw_cves)
        assert created == len(raw_cves)
        assert demisto_mock.createIndicators.called


def test_ingest_batch_empty(client):
    """
    Given:
        An empty list of raw CVEs.

    When:
        _ingest_batch is called.

    Then:
        Returns 0 created.
    """
    created = _ingest_batch(client, [])
    assert created == 0


def test_fetch_cves_in_windows_caps_results(client):
    """
    Given:
        A max_results of 1 and retrieve_cves returns 3 CVEs.

    When:
        _fetch_cves_in_windows is called.

    Then:
        Only 1 CVE is returned and limit_reached is True.
    """
    with patch("FeedNVDv2.retrieve_cves") as mock_retrieve_cves:
        cves = open_json("./test_data/nist_response.json")["vulnerabilities"]
        mock_retrieve_cves.return_value = cves
        result, _, limit_reached = _fetch_cves_in_windows(
            client,
            start_date=parse("2024-01-01T00:00:00Z"),
            end_date=parse("2024-01-05T00:00:00Z"),
            use_pub_date=True,
            max_results=1,
        )
        assert len(result) == 1
        assert limit_reached is True


@pytest.mark.parametrize(
    "entries, expected",
    [
        # Primary first — returns Primary
        (
            [
                {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8}},
                {"source": "cna@vendor.com", "type": "Secondary", "cvssData": {"baseScore": 6.3}},
            ],
            {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8}},
        ),
        # CNA first, Primary second — still returns Primary (the actual bug scenario)
        (
            [
                {"source": "cna@vendor.com", "type": "Secondary", "cvssData": {"baseScore": 6.3}},
                {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8}},
            ],
            {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8}},
        ),
        # No Primary — falls back to first entry
        (
            [
                {"source": "cna@vendor.com", "type": "Secondary", "cvssData": {"baseScore": 6.3}},
            ],
            {"source": "cna@vendor.com", "type": "Secondary", "cvssData": {"baseScore": 6.3}},
        ),
        # Empty list — returns empty dict
        ([], {}),
    ],
)
def test_select_primary_cvss_entry(entries, expected):
    """
    Given:
        A list of CVSS metric entries from the NVD API.

    When:
        _select_primary_cvss_entry is called.

    Then:
        The Primary (NIST/NVD) entry is returned when available,
        otherwise the first entry, or an empty dict for empty input.
    """
    assert _select_primary_cvss_entry(entries) == expected


def test_build_indicators_prefers_primary_score(client):
    """
    Given:
        A CVE with two cvssMetricV31 entries where the CNA entry (MEDIUM, 6.3)
        appears before the NIST Primary entry (CRITICAL, 9.8).

    When:
        build_indicators is called.

    Then:
        The indicator uses the Primary (NIST) score of 9.8, not the CNA score of 6.3.
    """
    raw_cves = [
        {
            "cve": {
                "id": "CVE-2024-99999",
                "descriptions": [{"lang": "en", "value": "Test CVE"}],
                "lastModified": "2024-01-01T00:00:00Z",
                "published": "2024-01-01T00:00:00Z",
                "weaknesses": [],
                "references": [],
                "configurations": [],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "cna@vendor.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                                "baseScore": 6.3,
                                "baseSeverity": "MEDIUM",
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 3.4,
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9,
                        },
                    ]
                },
            }
        }
    ]
    indicators = build_indicators(client, raw_cves)
    assert len(indicators) == 1
    assert indicators[0]["fields"]["cvssscore"] == 9.8
    assert indicators[0]["fields"]["cvssversion"] == "3.1"


def test_build_indicators_respects_preferred_versions(client):
    """
    Given:
        A CVE with both cvssMetricV40 (MEDIUM, 6.9) and cvssMetricV31 (CRITICAL, 9.8).

    When:
        build_indicators is called with preferred_versions=["CVSS v3"].

    Then:
        The indicator uses the v3 score (9.8) and version ("3.1"), not the v4 score (6.9).
    """
    raw_cves = [
        {
            "cve": {
                "id": "CVE-2024-11111",
                "descriptions": [{"lang": "en", "value": "Test CVE with v3 and v4 scores"}],
                "lastModified": "2024-01-01T00:00:00Z",
                "published": "2024-01-01T00:00:00Z",
                "weaknesses": [],
                "references": [],
                "configurations": [],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
                                "baseScore": 6.9,
                                "baseSeverity": "MEDIUM",
                            },
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9,
                        }
                    ],
                },
            }
        }
    ]
    indicators = build_indicators(client, raw_cves, preferred_versions=["CVSS v3"])
    assert len(indicators) == 1
    assert indicators[0]["fields"]["cvssscore"] == 9.8, "Expected v3 score (9.8), got v4 score instead"
    assert indicators[0]["fields"]["cvssversion"] == "3.1", "Expected v3 version string"
    assert indicators[0]["fields"]["cvssvector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _make_cve_with_v2_and_v31(cve_id: str = "CVE-2024-55555") -> dict:
    """Helper: build a raw CVE wrapper with both CVSS v2 and v3.1 metrics."""
    return {
        "_matched_cvss_version": "CVSS v2",
        "_matched_cvss_severity": "HIGH",
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": "Test CVE with v2 and v3 scores"}],
            "lastModified": "2024-06-01T00:00:00Z",
            "published": "2024-06-01T00:00:00Z",
            "weaknesses": [],
            "references": [],
            "configurations": [],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }
                ],
                "cvssMetricV2": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "2.0",
                            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "baseScore": 7.5,
                        },
                        "baseSeverity": "HIGH",
                        "exploitabilityScore": 10.0,
                        "impactScore": 6.4,
                    }
                ],
            },
        },
    }


def test_build_indicators_uses_matched_cvss_version(client):
    """
    Given:
        A CVE tagged with _matched_cvss_version="CVSS v2" (from severity-filter dedup),
        which also has a CVSS v3.1 score.

    When:
        build_indicators is called with preferred_versions=["CVSS v3", "CVSS v2"].

    Then:
        The indicator uses the v2 score (7.5) because the CVE was matched via v2,
        NOT the v3 score (9.8) which would normally win by preference order.
    """
    raw_cves = [_make_cve_with_v2_and_v31()]
    indicators = build_indicators(client, raw_cves, preferred_versions=["CVSS v3", "CVSS v2"])
    assert len(indicators) == 1
    assert indicators[0]["fields"]["cvssscore"] == 7.5, "Expected v2 score (7.5), got v3 score instead"
    assert indicators[0]["fields"]["cvssversion"] == "2.0", "Expected v2 version string"


def test_build_indicators_falls_back_without_matched_version(client):
    """
    Given:
        A CVE without _matched_cvss_version (no severity filter was used),
        which has both CVSS v2 and v3.1 scores.

    When:
        build_indicators is called with preferred_versions=["CVSS v3", "CVSS v2"].

    Then:
        The indicator uses the v3 score (9.8) per the normal preference order.
    """
    raw_cve = _make_cve_with_v2_and_v31()
    del raw_cve["_matched_cvss_version"]
    del raw_cve["_matched_cvss_severity"]
    indicators = build_indicators(client, [raw_cve], preferred_versions=["CVSS v3", "CVSS v2"])
    assert len(indicators) == 1
    assert indicators[0]["fields"]["cvssscore"] == 9.8, "Expected v3 score (9.8) as fallback"
    assert indicators[0]["fields"]["cvssversion"] == "3.1"


def test_cves_to_war_room_uses_matched_cvss_version():
    """
    Given:
        A CVE tagged with _matched_cvss_version="CVSS v2" (from severity-filter dedup),
        which also has a CVSS v3.1 score.

    When:
        cves_to_war_room is called with preferred_versions=["CVSS v3", "CVSS v2"].

    Then:
        The war room entry uses the v2 score (7.5) because the CVE was matched via v2.
    """
    raw_cves = [_make_cve_with_v2_and_v31()]
    result = cves_to_war_room(raw_cves, preferred_versions=["CVSS v3", "CVSS v2"])
    outputs = result.outputs
    assert len(outputs) == 1
    assert outputs[0]["CVSS"] == 7.5, "Expected v2 score (7.5)"
    assert outputs[0]["CVSSVersion"] == "2.0"
    assert outputs[0]["Severity"] == "HIGH"


def test_cves_to_war_room_falls_back_without_matched_version():
    """
    Given:
        A CVE without _matched_cvss_version (no severity filter was used),
        which has both CVSS v2 and v3.1 scores.

    When:
        cves_to_war_room is called with preferred_versions=["CVSS v3", "CVSS v2"].

    Then:
        The war room entry uses the v3 score (9.8) per the normal preference order.
    """
    raw_cve = _make_cve_with_v2_and_v31()
    del raw_cve["_matched_cvss_version"]
    del raw_cve["_matched_cvss_severity"]
    result = cves_to_war_room([raw_cve], preferred_versions=["CVSS v3", "CVSS v2"])
    outputs = result.outputs
    assert len(outputs) == 1
    assert outputs[0]["CVSS"] == 9.8, "Expected v3 score (9.8) as fallback"
    assert outputs[0]["CVSSVersion"] == "3.1"


def test_include_rejected_false_adds_no_rejected_param(client):
    """
    Given:
        A Client with include_rejected=False (the default).

    When:
        _retrieve_cves_single_query is called.

    Then:
        The NVD API is called with the noRejected flag in the query string.
    """
    from datetime import datetime
    from unittest.mock import patch

    client.include_rejected = False
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 1, 2, tzinfo=UTC)

    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        mock_get_cves.return_value = {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 2000, "startIndex": 0}
        _retrieve_cves_single_query(client, start, end, use_pub_date=True)

    # get_cves signature: get_cves(path, params, severity_param="", severity_value="")
    # params is the second positional argument → call_args.args[1]
    params: dict = mock_get_cves.call_args.args[1]
    assert "noRejected" in params, "noRejected should be present when include_rejected=False"


def test_include_rejected_true_omits_no_rejected_param(client):
    """
    Given:
        A Client with include_rejected=True.

    When:
        _retrieve_cves_single_query is called.

    Then:
        The NVD API is called WITHOUT the noRejected flag so rejected CVEs are returned.
    """
    from datetime import datetime
    from unittest.mock import patch

    client.include_rejected = True
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 1, 2, tzinfo=UTC)

    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        mock_get_cves.return_value = {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 2000, "startIndex": 0}
        _retrieve_cves_single_query(client, start, end, use_pub_date=True)

    # get_cves signature: get_cves(path, params, severity_param="", severity_value="")
    # params is the second positional argument → call_args.args[1]
    params: dict = mock_get_cves.call_args.args[1]
    assert "noRejected" not in params, "noRejected should be absent when include_rejected=True"
