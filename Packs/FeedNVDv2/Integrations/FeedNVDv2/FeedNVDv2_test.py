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
    fetch_indicators_command,
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
        Returns a start_date derived from first_fetch, use_pub_date=True,
        and no resume bucket info (cvss_version / severity both None).
    """
    with patch("FeedNVDv2.demisto") as demisto_mock:
        demisto_mock.getLastRun.return_value = {}
        (
            start_date,
            use_pub_date,
            resume_ids,
            resume_start_index,
            resume_cvss_version,
            resume_severity,
        ) = _resolve_auto_fetch_window(client)
        assert start_date is not None
        assert use_pub_date is True
        assert resume_ids == []
        assert resume_start_index == 0
        assert resume_cvss_version is None
        assert resume_severity is None


def test_resolve_auto_fetch_window_resume(client):
    """
    Given:
        lastRun data with a resumeFrom key and usePubDate=True (no bucket
        info – simulates a resume from an older lastRun that predates the
        bucket-aware persistence).

    When:
        _resolve_auto_fetch_window is called.

    Then:
        Returns the resume date and the saved usePubDate flag, with
        bucket identifiers defaulting to None.
    """
    with patch("FeedNVDv2.demisto") as demisto_mock:
        demisto_mock.getLastRun.return_value = {
            "lastRun": "2024-01-01T00:00:00Z",
            "resumeFrom": "2024-03-01T00:00:00Z",
            "usePubDate": True,
        }
        (
            start_date,
            use_pub_date,
            resume_ids,
            resume_start_index,
            resume_cvss_version,
            resume_severity,
        ) = _resolve_auto_fetch_window(client)
        assert start_date == parse("2024-03-01T00:00:00Z")
        assert resume_start_index == 0
        assert use_pub_date is True
        assert resume_ids == []
        assert resume_cvss_version is None
        assert resume_severity is None


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


# --- Budget accounting tests ---


def test_budget_consumed_when_single_page_complete(client):
    """
    Given:
        An API call budget of 1 and an NVD response that fits in a single page
        (total_results <= results_per_page).

    When:
        _retrieve_cves_single_query is called.

    Then:
        The call budget IS decremented, because every non-empty API call
        counts toward the budget to ensure the integration respects rate limits.
    """
    from datetime import datetime
    from unittest.mock import patch

    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 1, 2, tzinfo=UTC)
    remaining_calls: list[int] = [1]

    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        mock_get_cves.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}],
            "totalResults": 1,
            "resultsPerPage": 2000,
            "startIndex": 0,
        }
        _retrieve_cves_single_query(client, start, end, use_pub_date=True, remaining_calls=remaining_calls)

    assert remaining_calls[0] == 0, "Budget must be consumed for every non-empty API response to respect rate limits."


def test_budget_consumed_when_more_pages_remain(client):
    """
    Given:
        An API call budget of 2 and an NVD response indicating more pages
        are waiting (total_results > results_per_page).

    When:
        _retrieve_cves_single_query is called.

    Then:
        The call budget IS decremented, since the fetch is a partial first
        page of a larger result set — this is the genuine "exhaustion"
        scenario that should trigger the resume cursor on stop.
    """
    from datetime import datetime
    from unittest.mock import patch

    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 6, 1, tzinfo=UTC)
    remaining_calls: list[int] = [2]

    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        # First call returns a full page with more pages remaining,
        # second call returns the budget-zero short-circuit (no third call).
        page = [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(2000)]
        mock_get_cves.return_value = {
            "vulnerabilities": page,
            "totalResults": 5000,
            "resultsPerPage": 2000,
            "startIndex": 0,
        }
        _retrieve_cves_single_query(client, start, end, use_pub_date=True, remaining_calls=remaining_calls)

    # First page consumed 1 from budget (more pages waiting after it).
    # Second iteration tried to fetch page 2: response still claims 5000 total,
    # so more_to_process stays True → also consumes 1.  Budget should be 0.
    assert remaining_calls[0] == 0, (
        f"Budget should be 0 after two pages with more results remaining, " f"got {remaining_calls[0]}"
    )


def test_budget_not_consumed_on_empty_response(client):
    """
    Given:
        An API call budget of 1 and an empty NVD response (totalResults == 0).

    When:
        _retrieve_cves_single_query is called.

    Then:
        The call budget is NOT decremented.  Empty responses are lightweight
        probes (e.g. sparse KEV-filter 120-day windows) and must not count
        against the budget.
    """
    from datetime import datetime
    from unittest.mock import patch

    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 1, 2, tzinfo=UTC)
    remaining_calls: list[int] = [1]

    with patch("FeedNVDv2.Client.get_cves") as mock_get_cves:
        mock_get_cves.return_value = {
            "vulnerabilities": [],
            "totalResults": 0,
            "resultsPerPage": 2000,
            "startIndex": 0,
        }
        _retrieve_cves_single_query(client, start, end, use_pub_date=True, remaining_calls=remaining_calls)

    assert remaining_calls[0] == 1, "Empty response must not consume the budget"


# --- Same-timestamp dedup tests (XSUP-68648) ---


def _make_raw_cve(cve_id: str, last_modified: str, published: str | None = None) -> dict:
    """Helper: build a minimal raw CVE wrapper for dedup tests."""
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"Test {cve_id}"}],
            "lastModified": last_modified,
            "published": published or last_modified,
            "weaknesses": [],
            "references": [],
            "configurations": [],
            "metrics": {},
        }
    }


def test_resolve_auto_fetch_window_returns_resume_ids(client):
    """
    Given:
        lastRun data with resumeFrom, usePubDate, resumeIds, and the
        bucket identifiers persisted from a prior budget-exhausted run.

    When:
        _resolve_auto_fetch_window is called.

    Then:
        Returns the resume_ids, start index, and the ``(cvss_version,
        severity)`` bucket the cursor belongs to.
    """
    with patch("FeedNVDv2.demisto") as demisto_mock:
        demisto_mock.getLastRun.return_value = {
            "lastRun": "2024-01-01T00:00:00Z",
            "resumeFrom": "2024-01-01T00:00:00Z",
            "usePubDate": False,
            "resumeIds": ["CVE-2024-0001", "CVE-2024-0002"],
            "resumeStartIndex": 42,
            "resumeCvssVersion": "CVSS v3",
            "resumeSeverity": "CRITICAL",
        }
        (
            start_date,
            use_pub_date,
            resume_ids,
            resume_start_index,
            resume_cvss_version,
            resume_severity,
        ) = _resolve_auto_fetch_window(client)
        assert resume_ids == ["CVE-2024-0001", "CVE-2024-0002"]
        assert resume_start_index == 42
        assert use_pub_date is False
        assert resume_cvss_version == "CVSS v3"
        assert resume_severity == "CRITICAL"


def test_fetch_indicators_skips_already_processed_cves_on_resume(client):
    """
    Given:
        A resume scenario where lastRun contains resumeIds with CVE IDs
        already processed at the boundary timestamp.

    When:
        fetch_indicators_command runs and the API returns the same CVEs again.

    Then:
        The already-processed CVEs are filtered out and not re-ingested.
    """
    boundary_ts = "2024-06-01T12:00:00Z"
    # CVEs at the boundary timestamp — 2 already processed, 1 new
    cves = [
        _make_raw_cve("CVE-2024-0001", boundary_ts),
        _make_raw_cve("CVE-2024-0002", boundary_ts),
        _make_raw_cve("CVE-2024-0003", boundary_ts),
    ]

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves", return_value=cves),
        patch("FeedNVDv2._ingest_batch", return_value=1) as mock_ingest,
    ):
        demisto_mock.getLastRun.return_value = {
            "lastRun": boundary_ts,
            "resumeFrom": boundary_ts,
            "usePubDate": False,
            "resumeIds": ["CVE-2024-0001", "CVE-2024-0002"],
        }
        demisto_mock.params.return_value = {}

        fetch_indicators_command(client)

        # _ingest_batch should receive only the 1 new CVE (CVE-2024-0003)
        ingested_cves = mock_ingest.call_args[0][1]
        ingested_ids = [c["cve"]["id"] for c in ingested_cves]
        assert "CVE-2024-0001" not in ingested_ids, "Already-processed CVE should be skipped"
        assert "CVE-2024-0002" not in ingested_ids, "Already-processed CVE should be skipped"
        assert "CVE-2024-0003" in ingested_ids, "New CVE should be ingested"


def test_fetch_indicators_saves_resume_ids_on_budget_exhaustion(client):
    """
    Given:
        A fetch where the API call budget is exhausted and all CVEs
        share the same lastModified timestamp.

    When:
        fetch_indicators_command persists progress.

    Then:
        The lastRun includes resumeIds with all CVE IDs at the boundary
        timestamp, preventing re-ingestion on the next cycle.
    """
    boundary_ts = "2024-06-01T12:00:00Z"
    cves = [
        _make_raw_cve("CVE-2024-0001", boundary_ts),
        _make_raw_cve("CVE-2024-0002", boundary_ts),
        _make_raw_cve("CVE-2024-0003", boundary_ts),
    ]

    # Use a very small max_indicators to force budget exhaustion
    client.max_indicators = 2000

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves", return_value=cves) as mock_retrieve,
        patch("FeedNVDv2._ingest_batch", return_value=3),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {}
        demisto_mock.params.return_value = {}

        # Make retrieve_cves consume the entire budget (remaining_calls[0] → 0)
        def exhaust_budget(*args, remaining_calls=None, **kwargs):
            if remaining_calls is not None:
                remaining_calls[0] = 0
            return cves

        mock_retrieve.side_effect = exhaust_budget

        fetch_indicators_command(client)

        # Verify set_feed_last_run was called with resumeIds
        last_run_arg = mock_set_last_run.call_args[0][0]
        assert "resumeIds" in last_run_arg, "resumeIds should be saved when budget is exhausted"
        assert set(last_run_arg["resumeIds"]) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
        # resumeFrom should be the exact boundary timestamp (not advanced by 1 ms).
        assert last_run_arg["resumeFrom"] == "2024-06-01T12:00:00.000000Z"
        # Boundary advanced from the fresh-fetch start_date to the CVE timestamp, so
        # the cursor must reset (startIndex is only valid within a fixed query window).
        assert last_run_arg["resumeStartIndex"] == 0


def test_fetch_indicators_accumulates_resume_ids_when_timestamp_unchanged(client):
    """
    Given:
        A resume scenario where the timestamp hasn't advanced (same as start_date)
        and there are already some processed IDs from the previous run.

    When:
        fetch_indicators_command runs and finds more CVEs at the same timestamp.

    Then:
        The new CVE IDs are accumulated with the previous ones in resumeIds.
    """
    # Use NVD_DATE_FORMAT-compatible timestamp so the boundary comparison works.
    boundary_ts = "2024-06-01T12:00:00.000000Z"
    # Previous run already processed CVE-0001 and CVE-0002
    previous_ids = ["CVE-2024-0001", "CVE-2024-0002"]
    # This run finds CVE-0003 (new) at the same timestamp
    cves = [
        _make_raw_cve("CVE-2024-0003", boundary_ts),
    ]

    client.max_indicators = 2000

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves") as mock_retrieve,
        patch("FeedNVDv2._ingest_batch", return_value=1),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {
            "lastRun": boundary_ts,
            "resumeFrom": boundary_ts,
            "usePubDate": False,
            "resumeIds": previous_ids,
            "resumeStartIndex": 2,
        }
        demisto_mock.params.return_value = {}

        def exhaust_budget(*args, remaining_calls=None, **kwargs):
            if remaining_calls is not None:
                remaining_calls[0] = 0
            return cves

        mock_retrieve.side_effect = exhaust_budget

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        assert "resumeIds" in last_run_arg
        # Should contain both previous and new IDs
        assert set(last_run_arg["resumeIds"]) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
        assert last_run_arg["resumeStartIndex"] == 3


def test_fetch_indicators_clears_resume_ids_when_timestamp_advances(client):
    """
    Given:
        A fetch where the API returns CVEs with a newer timestamp than
        the resume point.

    When:
        fetch_indicators_command completes without exhausting the budget.

    Then:
        The lastRun does NOT contain resumeIds (clean state, no dedup needed).
    """
    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves", return_value=[]),
        patch("FeedNVDv2._ingest_batch", return_value=0),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {
            "lastRun": "2024-01-01T00:00:00Z",
        }
        demisto_mock.params.return_value = {}

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        # When budget is NOT exhausted, no resumeIds should be saved
        assert "resumeIds" not in last_run_arg


def test_fetch_indicators_saves_resume_ids_with_variable_precision_timestamp(client):
    """
    Given:
        NVD returns CVEs whose ``lastModified`` field uses variable precision
        (3-digit fractional seconds, no trailing ``Z``) — different from the
        6-digit ``NVD_DATE_FORMAT`` rendering produced by ``strftime``.

    When:
        fetch_indicators_command exhausts the call budget so that
        ``resumeFrom`` equals the last CVE's ``lastModified`` boundary.

    Then:
        ``resumeIds`` in the saved ``lastRun`` contains the CVE IDs at that
        boundary timestamp — proving the comparison parses both sides to
        datetimes instead of comparing raw strings.
    """
    # Variable-precision timestamp as actually emitted by NVD (3-digit ms, no 'Z').
    boundary_ts = "2024-06-01T12:00:00.287"
    cves = [
        _make_raw_cve("CVE-2024-1001", boundary_ts),
        _make_raw_cve("CVE-2024-1002", boundary_ts),
        _make_raw_cve("CVE-2024-1003", boundary_ts),
    ]

    client.max_indicators = 2000

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves") as mock_retrieve,
        patch("FeedNVDv2._ingest_batch", return_value=3),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {}
        demisto_mock.params.return_value = {}

        def exhaust_budget(*args, remaining_calls=None, **kwargs):
            if remaining_calls is not None:
                remaining_calls[0] = 0
            return cves

        mock_retrieve.side_effect = exhaust_budget

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        # All three boundary-timestamp CVE IDs should be saved, despite the
        # API's 3-digit-precision timestamp not equaling the 6-digit
        # NVD_DATE_FORMAT string rendering of the same instant.
        assert set(last_run_arg["resumeIds"]) == {"CVE-2024-1001", "CVE-2024-1002", "CVE-2024-1003"}


def test_fetch_indicators_resets_start_index_when_boundary_advances(client):
    """
    Given:
        A resume scenario where the previous run saved a ``resumeFrom`` of
        ``2024-06-01T12:00:00.000000Z`` with ``resumeStartIndex == 5``, and
        the new fetch returns CVEs whose newest ``lastModified`` is strictly
        greater than that resume timestamp.

    When:
        fetch_indicators_command exhausts the call budget mid-fetch.

    Then:
        ``resumeStartIndex`` is reset to ``0`` (the cursor is only valid
        within a fixed ``lastModStartDate`` query and the boundary just
        advanced), ``resumeFrom`` equals the new boundary timestamp, and
        ``resumeIds`` contains ONLY the CVE IDs whose ``lastModified``
        equals that new boundary.
    """
    prev_resume_ts = "2024-06-01T12:00:00.000000Z"
    older_ts = "2024-06-02T08:00:00.000000Z"
    new_boundary_ts = "2024-06-02T09:30:15.287000Z"
    cves = [
        _make_raw_cve("CVE-2024-2001", older_ts),
        _make_raw_cve("CVE-2024-2002", new_boundary_ts),
        _make_raw_cve("CVE-2024-2003", new_boundary_ts),
    ]

    client.max_indicators = 2000

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves") as mock_retrieve,
        patch("FeedNVDv2._ingest_batch", return_value=3),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {
            "lastRun": prev_resume_ts,
            "resumeFrom": prev_resume_ts,
            "usePubDate": False,
            "resumeIds": [],
            "resumeStartIndex": 5,
        }
        demisto_mock.params.return_value = {}

        def exhaust_budget(*args, remaining_calls=None, **kwargs):
            if remaining_calls is not None:
                remaining_calls[0] = 0
            return cves

        mock_retrieve.side_effect = exhaust_budget

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        # Boundary advanced past the resume timestamp → cursor must reset.
        assert last_run_arg["resumeStartIndex"] == 0
        assert last_run_arg["resumeFrom"] == new_boundary_ts
        # Only IDs at the new boundary timestamp should be persisted for dedup.
        assert set(last_run_arg["resumeIds"]) == {"CVE-2024-2002", "CVE-2024-2003"}


def test_fetch_indicators_advances_cursor_by_pre_dedup_count(client):
    """
    Given:
        A resume scenario where ``resumeIds`` overlaps with the CVEs that
        ``retrieve_cves`` returns at the same boundary timestamp and bucket,
        so the post-dedup list is strictly shorter than what NVD actually
        returned (e.g. 3 dedup'd out of 5).

    When:
        ``fetch_indicators_command`` exhausts the call budget and persists
        ``resumeStartIndex``.

    Then:
        ``resumeStartIndex`` advances by the **pre-dedup** count (what NVD
        returned), not by the post-dedup count (what we emitted). Otherwise
        the next run would re-fetch the already-skipped items because
        ``startIndex`` is a position in the NVD result set, not a count of
        items we processed.
    """
    boundary_ts = "2024-06-01T12:00:00.000000Z"
    previous_ids = ["CVE-A", "CVE-B", "CVE-C"]
    # NVD returns 5 CVEs at the boundary — A/B/C overlap with resumeIds
    # (dedup removes 3), D/E are new and get emitted.
    cves = [
        _make_raw_cve("CVE-A", boundary_ts),
        _make_raw_cve("CVE-B", boundary_ts),
        _make_raw_cve("CVE-C", boundary_ts),
        _make_raw_cve("CVE-D", boundary_ts),
        _make_raw_cve("CVE-E", boundary_ts),
    ]

    client.max_indicators = 2000

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves") as mock_retrieve,
        patch("FeedNVDv2._ingest_batch", return_value=2),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {
            "lastRun": boundary_ts,
            "resumeFrom": boundary_ts,
            "usePubDate": False,
            "resumeIds": previous_ids,
            "resumeStartIndex": 10,
        }
        demisto_mock.params.return_value = {}

        def exhaust_budget(*args, remaining_calls=None, **kwargs):
            if remaining_calls is not None:
                remaining_calls[0] = 0
            return cves

        mock_retrieve.side_effect = exhaust_budget

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        # 10 (previous startIndex) + 5 (pre-dedup count from NVD) == 15.
        # The buggy behaviour would yield 10 + 2 == 12 (post-dedup count).
        assert last_run_arg["resumeStartIndex"] == 15


def test_retrieve_cves_resumes_only_matching_bucket(client):
    """
    Given:
        A severity-filtered fetch spanning multiple (cvss_version, severity)
        buckets, with ``resume_cvss_version="CVSS v3"`` and
        ``resume_severity="CRITICAL"`` and ``start_index=42``.

    When:
        retrieve_cves is called.

    Then:
        Only the (CVSS v3, CRITICAL) sub-query is issued with
        ``startIndex=42``; every other bucket uses ``startIndex=0``.
        Buckets ordered before the resume bucket are NOT called.
    """
    client.cvss_severity = ["CRITICAL", "HIGH"]
    client.cvss_versions = ["CVSS v3", "CVSS v2"]

    captured: list[dict] = []

    def fake_get_cves(url_suffix, params, severity_param="", severity_value=""):
        captured.append(
            {
                "startIndex": params.get("startIndex"),
                "severity_param": severity_param,
                "severity_value": severity_value,
            }
        )
        # Return zero results so pagination stops after one call per bucket.
        return {"totalResults": 0, "vulnerabilities": []}

    with patch("FeedNVDv2.Client.get_cves", side_effect=fake_get_cves):
        retrieve_cves(
            client,
            parse("2024-01-01T00:00:00Z"),
            parse("2024-01-04T00:00:00Z"),
            use_pub_date=True,
            start_index=42,
            resume_cvss_version="CVSS v3",
            resume_severity="CRITICAL",
        )

    by_bucket = {(c["severity_param"], c["severity_value"]): c["startIndex"] for c in captured}
    # The resume bucket uses startIndex=42; the only other bucket called
    # after it (in iteration order) is (CVSS v3, HIGH) and both CVSS v2 ones.
    assert by_bucket[("cvssV3Severity", "CRITICAL")] == 42
    # Every OTHER bucket that ran must have used startIndex=0.
    for bucket, start_index in by_bucket.items():
        if bucket != ("cvssV3Severity", "CRITICAL"):
            assert start_index == 0, f"bucket {bucket} should use startIndex=0, got {start_index}"


def test_retrieve_cves_skips_buckets_before_resume(client):
    """
    Given:
        A severity-filtered fetch with ``resume_cvss_version="CVSS v3"``
        and ``resume_severity="HIGH"``. Iteration order is
        versions=[CVSS v3, CVSS v2], severities=[CRITICAL, HIGH] so the
        bucket (CVSS v3, CRITICAL) is BEFORE the resume bucket and must
        be skipped entirely (already processed in a prior run).

    When:
        retrieve_cves is called.

    Then:
        No API call is issued for (CVSS v3, CRITICAL). Calls begin at
        the resume bucket and continue to subsequent buckets.
    """
    client.cvss_severity = ["CRITICAL", "HIGH"]
    client.cvss_versions = ["CVSS v3", "CVSS v2"]

    captured: list[tuple] = []

    def fake_get_cves(url_suffix, params, severity_param="", severity_value=""):
        captured.append((severity_param, severity_value))
        return {"totalResults": 0, "vulnerabilities": []}

    with patch("FeedNVDv2.Client.get_cves", side_effect=fake_get_cves):
        retrieve_cves(
            client,
            parse("2024-01-01T00:00:00Z"),
            parse("2024-01-04T00:00:00Z"),
            use_pub_date=True,
            start_index=10,
            resume_cvss_version="CVSS v3",
            resume_severity="HIGH",
        )

    # (CVSS v3, CRITICAL) is ordered BEFORE the resume bucket → must be skipped.
    assert ("cvssV3Severity", "CRITICAL") not in captured
    # Resume bucket and everything after it must be called.
    assert ("cvssV3Severity", "HIGH") in captured
    assert ("cvssV2Severity", "CRITICAL") in captured
    assert ("cvssV2Severity", "HIGH") in captured


def test_retrieve_cves_populates_last_bucket(client):
    """
    Given:
        A severity-filtered fetch.

    When:
        retrieve_cves is invoked with a mutable ``last_bucket`` list.

    Then:
        On return, ``last_bucket`` holds the (cvss_version, severity) of
        the most-recently-queried bucket, allowing the caller to persist
        the exhausted bucket on budget exhaustion.
    """
    client.cvss_severity = ["CRITICAL"]
    client.cvss_versions = ["CVSS v3"]
    last_bucket: list = []

    with patch("FeedNVDv2.Client.get_cves", return_value={"totalResults": 0, "vulnerabilities": []}):
        retrieve_cves(
            client,
            parse("2024-01-01T00:00:00Z"),
            parse("2024-01-04T00:00:00Z"),
            use_pub_date=True,
            last_bucket=last_bucket,
        )

    assert last_bucket == ["CVSS v3", "CRITICAL"]


def test_fetch_indicators_saves_bucket_with_resume_state(client):
    """
    Given:
        A severity-filtered fetch that exhausts the call budget while
        paginating the (CVSS v3, HIGH) bucket.

    When:
        fetch_indicators_command persists lastRun.

    Then:
        ``resumeCvssVersion`` and ``resumeSeverity`` in the saved state
        match the bucket that was active when the budget ran out, so
        the next run can correctly resume that exact sub-query.
    """
    boundary_ts = "2024-06-01T12:00:00Z"
    cves = [_make_raw_cve("CVE-2024-9001", boundary_ts)]
    client.max_indicators = 2000
    client.cvss_severity = ["HIGH"]
    client.cvss_versions = ["CVSS v3"]

    def exhaust_budget(*args, remaining_calls=None, last_bucket=None, **kwargs):
        if remaining_calls is not None:
            remaining_calls[0] = 0
        if last_bucket is not None:
            last_bucket[:] = ["CVSS v3", "HIGH"]
        return cves

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves", side_effect=exhaust_budget),
        patch("FeedNVDv2._ingest_batch", return_value=1),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {}
        demisto_mock.params.return_value = {}

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        assert last_run_arg["resumeCvssVersion"] == "CVSS v3"
        assert last_run_arg["resumeSeverity"] == "HIGH"


def test_fetch_indicators_saves_lastrun_with_microsecond_precision(client):
    """
    Given:
        A normal fetch that completes without exhausting the call budget
        (so the ``else`` branch in ``fetch_indicators_command`` persists
        ``lastRun`` with the end-of-window timestamp).

    When:
        ``fetch_indicators_command`` saves ``lastRun``.

    Then:
        The saved ``lastRun`` timestamp uses microsecond precision
        (``NVD_DATE_FORMAT``: ``%Y-%m-%dT%H:%M:%S.%fZ``), matching the
        format used by the budget-exhaustion ``resumeFrom`` path. Format
        consistency protects future code that does string comparison.
    """
    import re

    client.max_indicators = 2000

    with (
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves", return_value=[]),
        patch("FeedNVDv2._ingest_batch", return_value=0),
        patch("FeedNVDv2.set_feed_last_run") as mock_set_last_run,
    ):
        demisto_mock.getLastRun.return_value = {}
        demisto_mock.params.return_value = {}

        fetch_indicators_command(client)

        last_run_arg = mock_set_last_run.call_args[0][0]
        # Microsecond-precision ISO8601 with trailing Z, e.g.
        # ``2024-06-01T12:00:00.123456Z``.
        assert re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", last_run_arg["lastRun"]
        ), f"lastRun {last_run_arg['lastRun']!r} does not match NVD_DATE_FORMAT pattern"


def test_fetch_indicators_only_applies_resume_to_first_window(client):
    """
    Given:
        A resume scenario where the fetch range spans more than 120 days
        so ``fetch_indicators_command``'s outer loop slices into multiple
        windows, and ``lastRun`` carries a ``resumeStartIndex`` plus a
        bucket. The ``startIndex`` belongs to the *first* window's query
        — applying it to subsequent windows would silently skip CVEs.

    When:
        The outer loop in ``fetch_indicators_command`` walks the windows.

    Then:
        The first ``retrieve_cves`` call receives ``start_index`` /
        ``resume_cvss_version`` / ``resume_severity`` from lastRun;
        every subsequent window's call receives ``start_index=0`` and
        ``None`` resume bucket identifiers.
    """
    from freezegun import freeze_time

    # 200-day span → at least two 120-day windows.
    resume_from = "2024-01-01T00:00:00.000000Z"

    calls: list[dict] = []

    def capture(*args, **kwargs):
        calls.append(
            {
                "start_index": kwargs.get("start_index"),
                "resume_cvss_version": kwargs.get("resume_cvss_version"),
                "resume_severity": kwargs.get("resume_severity"),
            }
        )
        return []

    with (
        freeze_time("2024-07-20T00:00:00Z"),  # ~201 days after resume_from
        patch("FeedNVDv2.demisto") as demisto_mock,
        patch("FeedNVDv2.retrieve_cves", side_effect=capture),
        patch("FeedNVDv2._ingest_batch", return_value=0),
        patch("FeedNVDv2.set_feed_last_run"),
    ):
        demisto_mock.getLastRun.return_value = {
            "lastRun": resume_from,
            "resumeFrom": resume_from,
            "usePubDate": False,
            "resumeIds": [],
            "resumeStartIndex": 42,
            "resumeCvssVersion": "CVSS v3",
            "resumeSeverity": "CRITICAL",
        }
        demisto_mock.params.return_value = {}

        fetch_indicators_command(client)

    # The outer loop must have made at least two window calls.
    assert len(calls) >= 2, f"expected multi-window iteration, got {len(calls)} call(s)"
    # First window: resume params propagated.
    assert calls[0]["start_index"] == 42
    assert calls[0]["resume_cvss_version"] == "CVSS v3"
    assert calls[0]["resume_severity"] == "CRITICAL"
    # All subsequent windows: fresh cursor, no bucket scoping.
    for i, c in enumerate(calls[1:], start=1):
        assert c["start_index"] == 0, f"window #{i} should have start_index=0, got {c['start_index']}"
        assert c["resume_cvss_version"] is None, f"window #{i} should have resume_cvss_version=None"
        assert c["resume_severity"] is None, f"window #{i} should have resume_severity=None"
