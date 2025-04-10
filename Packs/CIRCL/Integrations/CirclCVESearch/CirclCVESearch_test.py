import json
import os
from pathlib import Path

import pytest
from CirclCVESearch import (Client, cve_command, generate_indicator, parse_cpe, valid_cve_id_format, get_cvss_version,
                            detect_format, handle_cve_5_1, create_cve_summary)

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

@pytest.mark.parametrize("input_data, expected", [
    ({"cveMetadata": {"cveId": "CVE-2025-1234"}}, "cve_5_1"),
    ({"document": {"title": "Example"}, "vulnerabilities": []}, "csaf"),
    ({"schema_version": "1.4.0", "id": "GHSA-xxxx-yyyy-zzzz"}, "ghsa"),
    ({"sourceIdentifier": "example@vendor.com", "id": "CVE-2025-5678"}, "nvd_cve_5_1"),
    ({"id": "CVE-2021-0001", "summary": "Some legacy format CVE"}, "legacy"),
])
def test_detect_format_valid(input_data, expected):
    """
    Given: A valid CVE data structure in a known format (e.g., CVE 5.1, CSAF, GHSA, etc.)
    When:  The `detect_format` function is called with this input
    Then:  It should return the correct format identifier as a string
    """
    result = detect_format(input_data)
    assert result == expected

def test_detect_format_invalid():
    """
    Given: An empty or unrecognized CVE data dictionary
    When:  The `detect_format` function is called with this input
    Then:  It should return 'unknown' or None to indicate unsupported format
    """
    result = detect_format({})
    assert result == "Unknown"

        
def test_handle_cve_5_1():
    """
    Given: A valid CVE 5.1 JSON file loaded from test data
    When:  The `handle_cve_5_1` function is called to normalize the data
    Then:  It should return a dictionary with all required normalized fields:
           - id starting with 'CVE-'
           - non-empty summary and CVSS
           - references, vulnerable_product, and vulnerable_configuration as lists
           - access and impact as dictionaries
    """
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
    """
    Given: A normalized CVE dictionary with keys for id, cvss, published/modified dates, and summary
    When:  The `create_cve_summary` function is called
    Then:  It should return a dictionary summary with correct mappings:
           - 'ID' matching the CVE ID
           - 'CVSS' matching the score
           - 'Published' and 'Modified' trimmed to ISO format
           - 'Description' starting with the CVE summary text
    """
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