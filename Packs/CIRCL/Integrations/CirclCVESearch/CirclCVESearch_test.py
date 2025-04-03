import json
import os
from pathlib import Path

import pytest
from CirclCVESearch import (Client, cve_command, generate_indicator, parse_cpe, valid_cve_id_format, get_cvss_version,
                            extract_cvss_info_from_vector, detect_format,
                            handle_cve_5_1, handle_ghsa, handle_NVD_cve_5_1, handle_legacy, create_cve_summary)

from CommonServerPython import DemistoException, EntityRelationship, argToList

BASE_URL = "https://cve.circl.lu/api/"


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_wrong_path():
    bad_url = "https://cve.bad_url"
    client = Client(base_url=bad_url, verify=False, proxy=False)

    with pytest.raises(DemistoException) as excinfo:
        cve_command(client, {"cve": "cve-2000-1234"})

    expected_exception_message = "Verify that the server URL parameter is correct"
    assert expected_exception_message in str(excinfo.value), "Bad error response when bad URL is given"


def test_bad_cve_id():
    bad_cve_id = "CVE-bad-cve"
    client = Client(base_url=BASE_URL, verify=False, proxy=False)

    with pytest.raises(DemistoException) as excinfo:
        cve_command(client, {"cve": bad_cve_id})

    expected_exception_message = f'"{bad_cve_id}" is not a valid cve ID'
    assert str(excinfo.value) == expected_exception_message


def test_cve_id_validation():
    test_cases = [
        ("cve-2000-1234", True),
        ("CVE-2000-1234", True),
        ("sdfsdf", False),
        ("cve-2000-01111", False),
        ("cve-2000-0111", True),
        ("2014-1111", False),
    ]
    for cve_id, is_valid in test_cases:
        assert (
            valid_cve_id_format(cve_id) == is_valid
        ), f"validation results for {cve_id}: {valid_cve_id_format(cve_id)} != {is_valid}"


TEST_DATA = [
    ({"cve": "cve-2000-1234,CVE-2020-155555"}, ["response.json", "empty_response.json"], 2),
    ({"cve": "cve-2000-1234"}, ["response.json"], 1),
]


def test_indicator_creation():
    """
    Given:
        A valid response from the server

    When:
        indicator_creation is being called.

    Then:
        return a Common.CVE indicator type.
    """

    response = util_load_json(os.path.join(Path.cwd(), "test_data", "response.json"))
    correct_indicator = util_load_json(os.path.join(Path.cwd(), "test_data", "indicator.json"))
    indicator = generate_indicator(response).to_context()
    assert set(indicator["CVE(val.ID && val.ID == obj.ID)"]["Tags"]) == set(
        correct_indicator["CVE(val.ID && val.ID == obj.ID)"]["Tags"]
    )


@pytest.mark.parametrize(
    "cvss_vector, expected_output",
    [("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 3.0), ("", 0), ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 2.0)],
)
def test_parse_cvss_version(cvss_vector, expected_output):
    version = get_cvss_version(cvss_vector)
    assert version == expected_output


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

    tags, relationships = parse_cpe(cpe, "CVE-2022-1111")
    assert set(tags) == set(expected_output)
    assert [relationship.to_context() for relationship in relationships] == expected_relationships


@pytest.mark.parametrize("cve_id_arg,response_data,expected", TEST_DATA)
def test_multiple_cve(cve_id_arg, response_data, expected, requests_mock):
    """
    Given:
        a multiple or single CVE to fetch.

    When:
        cve_command is being called.

    Then:
        return a List of commandResults - each item representing a CVE.
    """
    cves = argToList(cve_id_arg.get("cve"))
    for test_file, cve in zip(response_data, cves):
        response = util_load_json(os.path.join(os.path.join(Path.cwd(), "test_data", test_file)))
        url_for_mock = os.path.join("https://cve.circl.lu/api/cve", cve)
        requests_mock.get(url_for_mock, json=response)
    client = Client(base_url=BASE_URL, verify=False, proxy=False)
    command_results = cve_command(client, cve_id_arg)
    assert isinstance(command_results, list)
    assert len(command_results) == expected

def test_detect_format():
    test_cases = [
        # CVE 5.1 format
        ({"cveMetadata": {"cveId": "CVE-2025-1234"}}, "cve_5_1"),

        # CSAF format
        ({
            "document": {"title": "Example"},
            "vulnerabilities": []
        }, "csaf"),

        # GHSA format
        ({
            "schema_version": "1.4.0",
            "id": "GHSA-xxxx-yyyy-zzzz"
        }, "ghsa"),

        # NVD CVE 5.1 format
        ({
            "sourceIdentifier": "example@vendor.com",
            "id": "CVE-2025-5678"
        }, "nvd_cve_5_1"),

        # Legacy format
        ({
            "id": "CVE-2021-0001",
            "summary": "Some legacy format CVE"
        }, "legacy"),

        # Unrecognized format (should raise)
        ({}, "ValueError"),
    ]

    for i, (input_data, expected) in enumerate(test_cases):
        if expected == "ValueError":
            try:
                detect_format(input_data)
                pytest.fail(f"Test case {i} expected ValueError but none was raised")
            except ValueError:
                pass  # Expected
        else:
            result = detect_format(input_data)
            assert result == expected, f"Test case {i} failed: expected {expected}, got {result}"

def test_extract_cvss_info_from_vector_cases():
    test_cases = [
        # Valid vector, scope = U
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"),
        
        # Valid vector, scope = C (should apply 1.08 multiplier)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "10.0"),
        
        # Valid vector with low impact
        ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "0.0"),
        
        # Invalid prefix (not 3.1)
        ("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "N\\A"),
        
        # Malformed vector (missing metrics)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U", "N\\A"),
        
        # Missing critical fields
        ("CVSS:3.1/AV:N/AC:L", "N\\A"),
        
        # Empty string
        ("", "N\\A"),
        
        # Non-string input
        (None, "N\\A"),  # type: ignore
    ]

    for vector, expected in test_cases:
        result = extract_cvss_info_from_vector(vector)  # type: ignore
        assert result == expected, f"Failed on vector: {vector}, expected: {expected}, got: {result}"

def test_handle_cve_5_1():
    test_file_path = os.path.join("test_data", "5_1.json")

    with open(test_file_path, encoding="utf-8") as f:
        cve_data = json.load(f)

    result = handle_cve_5_1(cve_data)

    assert isinstance(result, dict), "Result should be a dictionary"

    assert result["id"].startswith("CVE-"), "CVE ID should start with 'CVE-'"
    assert result["summary"], "Summary should not be empty"
    assert result["cvss"] != "", "CVSS should be present or marked as 'N\\A'"
    assert isinstance(result["references"], list), "References should be a list"
    assert isinstance(result["vulnerable_product"], list), "vulnerable_product should be a list"
    assert isinstance(result["vulnerable_configuration"], list), "vulnerable_configuration should be a list"
    assert isinstance(result["access"], dict), "access should be a dictionary"
    assert isinstance(result["impact"], dict), "impact should be a dictionary"

def test_create_cve_summary():
    cve_data = {
        "id": "CVE-2025-12345",
        "cvss": "7.8",
        "Published": "2025-03-01T10:00:00Z",
        "Modified": "2025-03-05T15:00:00Z",
        "summary": "Some vulnerability affecting X system..."
    }

    summary = create_cve_summary(cve_data)

    assert summary["ID"] == "CVE-2025-12345"
    assert summary["CVSS"] == "7.8"
    assert summary["Published"] == "2025-03-01T10:00:00"
    assert summary["Modified"] == "2025-03-05T15:00:00"
    assert summary["Description"].startswith("Some vulnerability")
    
def test_handle_ghsa_from_file():
    ghsa_path = os.path.join(os.path.dirname(__file__), "test_data", "ghsa.json")
    with open(ghsa_path, encoding="utf-8") as f:
        ghsa_data = json.load(f)

    result = handle_ghsa(ghsa_data)

    assert result["id"] == "GHSA-q92j-grw3-h492"
    assert result["summary"].startswith("Loading a malicious schema definition")
    assert result["Published"] == "2025-03-12T19:28:00Z"
    assert result["Modified"] == "2025-03-24T14:49:01Z"
    assert result["cvss-vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert result["cvss"] == "8.9"  # assuming extract_cvss_info_from_vector is accurate
    assert result["cwe"] == "CWE-94"
    assert len(result["references"]) == 14
    assert "cpe:2.3:a:rubygems:graphql:*:*:*:*:*:*:*:*" in result["vulnerable_product"]
    assert {"id": "cpe:2.3:a:rubygems:graphql:*:*:*:*:*:*:*:*",
            "title": "cpe:2.3:a:rubygems:graphql:*:*:*:*:*:*:*:*"} in result["vulnerable_configuration"]
    assert result["access"] == {
        "vector": "N",
        "complexity": "H",
        "authentication": "NONE"
    }
    assert result["impact"] == {
        "confidentiality": "H",
        "integrity": "H",
        "availability": "H"
    }

def test_handle_legacy_from_file():
    # Load the response.json file
    file_path = os.path.join(os.path.dirname(__file__), "test_data", "response.json")
    with open(file_path, encoding="utf-8") as f:
        legacy_input = json.load(f)

    result = handle_legacy(legacy_input)

    expected = {
        "id": "CVE-2020-17106",
        "cvss": 9.3,
        "cvss-vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
        "Published": "2020-11-11T07:15:00",
        "Modified": "2020-11-19T21:04:00",
        "summary": ("HEVC Video Extensions Remote Code Execution Vulnerability This CVE ID"
                    " is unique from CVE-2020-17107, CVE-2020-17108, CVE-2020-17109, CVE-2020-17110."),
        "cwe": "NVD-CWE-noinfo",
        "references": [
            "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-17106"
        ],
        "vulnerable_product": [
            "cpe:2.3:a:microsoft:hevc_video_extensions:*:*:*:*:*:*:*:*"
        ],
        "vulnerable_configuration": [
            {
                "id": "cpe:2.3:a:microsoft:hevc_video_extensions:*:*:*:*:*:*:*:*",
                "title": "cpe:2.3:a:microsoft:hevc_video_extensions:*:*:*:*:*:*:*:*"
            }
        ],
        "impact": {
            "availability": "COMPLETE",
            "confidentiality": "COMPLETE",
            "integrity": "COMPLETE"
        },
        "access": {
            "authentication": "NONE",
            "complexity": "MEDIUM",
            "vector": "NETWORK"
        },
    }

    assert result == expected

    def test_handle_nvd_cve_5_1(self):
        
        file_path = os.path.join(os.path.dirname(__file__), "test_data", "Nvd_5_1.json")
        with open(file_path, encoding="utf-8") as f:
            legacy_input = json.load(f)

        # Call the function to be tested
        result = handle_NVD_cve_5_1(legacy_input)
        
        expected = {
                "id": "CVE-2025-24176",
                "cvss": "7.1",
                "cvss-vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "Published": "2025-01-27T22:15:20.643",
                "Modified": "2025-03-24T14:59:58.437",
                "summary": ("A permissions issue was addressed with improved validation."
                            " This issue is fixed in macOS Ventura 13.7.3, macOS Sequoia 15.3, macOS Sonoma 14.7.3."
                            " A local attacker may be able to elevate their privileges."),
                "cwe": "CWE-276",
                "references": [
                    "https://support.apple.com/en-us/122068",
                    "https://support.apple.com/en-us/122069",
                    "https://support.apple.com/en-us/122070"
                ],
                "vulnerable_product": [
                    "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"
                ],
                "vulnerable_configuration": [
                    {
                    "id": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                    "title": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                    "version_end_excluding": "13.7.3"
                    },
                    {
                    "id": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                    "title": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                    "version_start_including": "14.0",
                    "version_end_excluding": "14.7.3"
                    },
                    {
                    "id": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                    "title": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
                    "version_start_including": "15.0",
                    "version_end_excluding": "15.3"
                    }
                ],
                "impact": {
                    "confidentiality": "H",
                    "integrity": "H",
                    "availability": "N"
                },
                "access": {
                    "vector": "L",
                    "complexity": "L",
                    "authentication": "L"
                }
                }
        
        assert result == expected