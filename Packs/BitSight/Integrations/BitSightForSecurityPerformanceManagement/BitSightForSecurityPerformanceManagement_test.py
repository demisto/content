"""Test File for BitSightForSecurityPerformanceManagement Integration."""

import json
import os
from datetime import datetime, timedelta
from unittest.mock import patch

import BitSightForSecurityPerformanceManagement as bitsight
import demistomock as demisto
import pytest
from CommonServerPython import BaseClient, DemistoException, EntryType

BASE_URL = "https://test.com"
DEFAULT_FINDINGS_GRADE = "WARN,GOOD"
RISK_VECTOR_INPUT = "SSL Certificates"


def util_load_json(path):
    """Load file in JSON format."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_companies_guid_command(mocker):
    """Tests success for companies_guid_get_command."""
    # Positive Scenario
    client = bitsight.Client(base_url=BASE_URL)

    res = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/companies_guid_get_response.json"))
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/companies_guid_get_success.md"), encoding="utf-8"
    ) as f:
        hr = f.read()
    mocker.patch.object(BaseClient, "_http_request", return_value=res["raw_response"])

    companies_guid_get_command_results = bitsight.companies_guid_get_command(client)

    assert companies_guid_get_command_results.outputs == res["outputs"]
    assert companies_guid_get_command_results.readable_output == hr


def test_company_details_get_command(mocker):
    """Tests success for company_details_get_command."""
    inp_args = {"guid": "123"}
    client = bitsight.Client(base_url=BASE_URL)

    res = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_details_get_response.json"))
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_details_get_success.md"), encoding="utf-8"
    ) as f:
        hr = f.read()

    mocker.patch.object(BaseClient, "_http_request", return_value=res["raw_response"])

    company_details_get_command_results = bitsight.company_details_get_command(client, inp_args)

    assert company_details_get_command_results.outputs == res["outputs"]
    assert company_details_get_command_results.readable_output == hr


def test_company_details_get_command_when_invalid_arguments_are_provided(requests_mock):
    """Test failure for company_details_get_command."""
    inp_args = {"guid": "non-existing-guid"}
    client = bitsight.Client(base_url=BASE_URL)

    requests_mock.get(BASE_URL + "/v1/companies/non-existing-guid", json={"detail": "Not found."}, status_code=404)
    with pytest.raises(DemistoException) as e:
        bitsight.company_details_get_command(client, inp_args)

    assert str(e.value) == 'Error in API call [404] - None\n{"detail": "Not found."}'


def test_company_findings_get_command(mocker):
    """Tests success for company_findings_get_command."""
    inp_args = {
        "guid": "123",
        "first_seen": "2021-01-01",
        "last_seen": "2022-02-21",
        "risk_vector_label": "Open Ports",
        "severity": "minor",
        "grade": "warn,good,bad",
    }

    client = bitsight.Client(base_url=BASE_URL)

    res = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_findings_get_response.json")
    )
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/company_findings_get_success.md"), encoding="utf-8"
    ) as f:
        hr = f.read()
    mocker.patch.object(BaseClient, "_http_request", return_value=res["raw_response"])

    company_findings_get_command_results = bitsight.company_findings_get_command(client, inp_args)

    assert company_findings_get_command_results.outputs == res["outputs"]
    assert company_findings_get_command_results.readable_output == hr


company_findings_get_on_failure_params = [
    (
        "invalid-severity",
        None,
        None,
        None,
        None,
        bitsight.ERROR_MESSAGES["INVALID_SELECT"].format(
            "invalid-severity", "severity", ", ".join(bitsight.SEVERITY_MAPPING.keys())
        ),
    ),
    (
        None,
        "invalid-asset-category",
        "",
        None,
        None,
        bitsight.ERROR_MESSAGES["INVALID_SELECT"].format(
            "invalid-asset-category", "asset_category", ", ".join(bitsight.ASSET_CATEGORY_MAPPING.keys())
        ),
    ),
    (
        None,
        None,
        "invalid-risk-vector",
        None,
        None,
        bitsight.ERROR_MESSAGES["INVALID_SELECT"].format(
            "invalid-risk-vector", "risk_vector_label", ", ".join(bitsight.RISK_VECTOR_MAPPING.keys())
        ),
    ),
    (
        None,
        None,
        "breaches,invalid-risk-vector",
        None,
        None,
        bitsight.ERROR_MESSAGES["INVALID_SELECT"].format(
            "invalid-risk-vector", "risk_vector_label", ", ".join(bitsight.RISK_VECTOR_MAPPING.keys())
        ),
    ),
    (None, None, None, "abc", None, 'Invalid number: "limit"="abc"'),
    (None, None, None, None, "abc", 'Invalid number: "offset"="abc"'),
    (None, None, None, bitsight.MAX_LIMIT + 1, None, bitsight.ERROR_MESSAGES["LIMIT_GREATER_THAN_ALLOWED"]),
]


@pytest.mark.parametrize(
    "severity, asset_category, risk_vector_label, limit, offset, error", company_findings_get_on_failure_params
)
def test_company_findings_get_command_when_invalid_arguments_are_provided(
    severity, asset_category, risk_vector_label, limit, offset, error
):
    """Test failure for company_findings_get_command."""
    inp_args = {
        "guid": "123",
        "first_seen": "2021-01-01",
        "last_seen": "2022-02-21",
        "risk_vector_label": risk_vector_label,
        "severity": severity,
        "asset_category": asset_category,
        "limit": limit,
        "offset": offset,
    }
    client = bitsight.Client(base_url=BASE_URL)

    with pytest.raises(ValueError) as e:
        bitsight.company_findings_get_command(client, inp_args)

    assert str(e.value) == error


def test_fetch_incidents_success_without_last_run(mocker):
    """Tests success for fetch_incidents when called for the first time."""
    inp_args = {
        "guid": "123",
        "first_fetch": "2",
        "findings_min_severity": "severe",
        "findings_grade": DEFAULT_FINDINGS_GRADE,
        "findings_asset_category": "low",
        "risk_vector": RISK_VECTOR_INPUT,
        "findings_affect_rating_reason": " ",
    }
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, "params", return_value=inp_args)

    res = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incidents_response.json"))
    mocker.patch.object(BaseClient, "_http_request", return_value=res["response"])

    last_run, events = bitsight.fetch_incidents(client=client, last_run={}, params=inp_args)

    curr_date = (datetime.now() - timedelta(days=int(inp_args["first_fetch"]))).strftime("%Y-%m-%d")
    assert curr_date == last_run["first_fetch"]
    assert res["response"]["count"] == last_run["offset"]
    assert events == res["incidents"]


def test_fetch_incidents_success_with_last_run(mocker):
    """Tests success for fetch_incidents when called with last run."""
    inp_args = {
        "guid": "123",
        "first_fetch": "2",
        "findings_min_severity": "severe",
        "findings_grade": DEFAULT_FINDINGS_GRADE,
        "findings_asset_category": "low",
        "risk_vector": RISK_VECTOR_INPUT,
        "findings_affect_rating_reason": "Yes,No: Grace Period,No: Incubation Period",
    }
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, "params", return_value=inp_args)

    res = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incidents_response.json"))
    mocker.patch.object(BaseClient, "_http_request", return_value=res["response"])

    last_run, events = bitsight.fetch_incidents(
        client=client, last_run={"first_fetch": "2022-03-27", "offset": 2}, params=inp_args
    )

    assert res["response"]["count"] + 2 == last_run["offset"]
    assert last_run["first_fetch"] == "2022-03-27"
    assert events == res["incidents"]


def test_fetch_incidents_with_duplicate_findings(mocker):
    """Tests fetch_incidents when duplicate findings are encountered."""
    inp_args = {
        "guid": "123",
        "first_fetch": "2",
        "findings_min_severity": "severe",
        "findings_grade": DEFAULT_FINDINGS_GRADE,
        "findings_asset_category": "low",
        "risk_vector": RISK_VECTOR_INPUT,
    }
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, "params", return_value=inp_args)

    # Mock response with duplicate findings (same temporary_id)
    res = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incidents_response.json"))
    mocker.patch.object(BaseClient, "_http_request", return_value=res["response"])

    # Test with last_run containing already_fetched_findings with one of the duplicate IDs
    last_run_with_duplicates = {
        "first_fetch": "2025-10-05",
        "offset": 1,
        "already_fetched_findings": [
            "dummy_rolledup_observation_id_1-#-2022-03-27"
        ],  # dummy_rolledup_observation_id_1 is already fetched
    }

    last_run, events = bitsight.fetch_incidents(client=client, last_run=last_run_with_duplicates, params=inp_args)

    # Assertions
    # Should only create 1 event for dummy_rolledup_observation_id_2
    assert len(events) == 1
    assert events[0]["name"] == "Bitsight Finding - SSL Certificates - dummy.com - 2022-03-27"

    # Verify last_run is updated correctly
    assert last_run["first_fetch"] == "2025-10-05"
    assert last_run["offset"] == 3
    assert "dummy_rolledup_observation_id_1-#-2022-03-27" in last_run["already_fetched_findings"]
    assert "dummy_rolledup_observation_id_2-#-2022-03-27" in last_run["already_fetched_findings"]
    assert len(last_run["already_fetched_findings"]) == 2


def test_fetch_incidents_when_empty_response(mocker):
    """Tests for fetch_incidents when empty response is returned."""
    inp_args = {
        "guid": "123",
        "first_fetch": "2",
        "findings_min_severity": "severe",
        "findings_grade": DEFAULT_FINDINGS_GRADE,
        "findings_asset_category": "low",
        "risk_vector": RISK_VECTOR_INPUT,
    }
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, "params", return_value=inp_args)
    mocker.patch.object(BaseClient, "_http_request", return_value={"count": 3, "results": []})

    last_run, events = bitsight.fetch_incidents(
        client=client, last_run={"first_fetch": "2022-03-27", "offset": 3}, params=inp_args
    )

    assert last_run["offset"] == 3
    assert last_run["first_fetch"] == "2022-03-27"


def test_fetch_incidents_with_invalid_affect_rating_reason(mocker, capfd):
    """Tests for fetch_incidents when invalid findings_affect_rating_reason is provided."""
    inp_args = {
        "guid": "123",
        "first_fetch": "2",
        "findings_min_severity": "severe",
        "findings_grade": DEFAULT_FINDINGS_GRADE,
        "findings_asset_category": "low",
        "risk_vector": RISK_VECTOR_INPUT,
        "findings_affect_rating_reason": "Invalid Reason",
    }
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch.object(demisto, "params", return_value=inp_args)

    with capfd.disabled():
        with pytest.raises(ValueError) as e:
            bitsight.fetch_incidents(client=client, last_run={}, params=inp_args)

        assert str(e.value) == bitsight.ERROR_MESSAGES["INVALID_SELECT"].format(
            "Invalid Reason", "Findings Affect Rating Reason", ", ".join(bitsight.VALID_AFFECT_RATING_REASON)
        )


@patch("BitSightForSecurityPerformanceManagement.return_results")  # noqa: F821
def test_test_module(mock_return, mocker):
    """Tests success for test_module."""
    # Positive Scenario
    res = util_load_json(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/companies_guid_get_response.json"))
    mocker.patch.object(BaseClient, "_http_request", return_value=res["raw_response"])
    mocker.patch.object(demisto, "params", return_value={"apikey": "123"})
    mocker.patch.object(demisto, "command", return_value="test-module")

    bitsight.main()

    assert mock_return.call_args.args[0] == "ok"


def test_get_modified_remote_command_successful_retrieval(mocker, requests_mock):
    """
    Given:
    - A client object.
    - Mock data for company findings.

    When:
    - Mocking the 'dateparser.parse' function to return a specific datetime.
    - Mocking the 'get_company_findings' function to return findings data.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    - Verify the function returns the expected modified incident IDs.
    """
    # Mock dateparser and get_company_findings
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch("BitSightForSecurityPerformanceManagement.dateparser.parse", return_value=datetime(2025, 9, 14, 10))
    # Mock the HTTP request using requests_mock
    mock_response = {
        "results": [
            {"temporary_id": "A9jq", "rolledup_observation_id": "dummy_id_1", "first_seen": "2025-09-14"},
            {"temporary_id": "A9jr", "rolledup_observation_id": "dummy_id_2", "first_seen": "2025-09-14"},
        ]
    }
    requests_mock.get(
        f"{BASE_URL}/v1/companies/test-guid/findings?limit=5000&sort=-last_seen&last_remediation_status_date_gte=2025-09-14",
        json=mock_response,
        status_code=200,
    )

    args = {"lastUpdate": "2025-09-14T10:00:00+00:00", "guid": "test-guid"}
    result = bitsight.get_modified_remote_data_command(client, args)

    # Assertions
    # Verify the HTTP request was made correctly
    assert requests_mock.called

    bitsight.dateparser.parse.assert_called_with("2025-09-14T10:00:00+00:00", settings={"TIMEZONE": "UTC"})
    assert "dummy_id_1-#-2025-09-14" in result.modified_incident_ids
    assert "dummy_id_2-#-2025-09-14" in result.modified_incident_ids


def test_get_modified_remote_command_with_empty_results(mocker):
    """
    Given:
    - A client object.

    When:
    - Mocking the 'dateparser.parse' function to return a specific datetime.
    - Mocking the 'get_company_findings' function to return empty results.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    - Verify the function returns an empty list of modified incident IDs.
    """
    # Mock dateparser and get_company_findings
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch("BitSightForSecurityPerformanceManagement.dateparser.parse", return_value=datetime(2025, 9, 14, 10))
    mocker.patch.object(client, "get_company_findings", return_value={"results": []})

    args = {"lastUpdate": "2025-09-14T10:00:00+00:00", "guid": "test-guid"}
    result = bitsight.get_modified_remote_data_command(client, args)

    # Assertions
    bitsight.dateparser.parse.assert_called_with("2025-09-14T10:00:00+00:00", settings={"TIMEZONE": "UTC"})
    client.get_company_findings.assert_called_once_with(
        guid="test-guid",
        first_seen=None,
        last_seen=None,
        optional_params={"limit": 5000, "sort": "-last_seen", "last_remediation_status_date_gte": "2025-09-14"},
    )
    assert result.modified_incident_ids == []


def test_get_modified_remote_data_command_with_duplicate_findings(mocker):
    """
    Given:
    - A client object.
    - Mock data for company findings with duplicate IDs.

    When:
    - Mocking the 'dateparser.parse' function to return a specific datetime.
    - Mocking the 'get_company_findings' function to return findings with duplicate IDs.

    Then:
    - Calling the 'get_modified_remote_data_command' function with the provided client and arguments.
    - Verify the function returns unique modified incident IDs (duplicates filtered out).
    """
    # Mock dateparser and get_company_findings
    client = bitsight.Client(base_url=BASE_URL)
    mocker.patch("BitSightForSecurityPerformanceManagement.dateparser.parse", return_value=datetime(2025, 9, 14, 10))
    mocker.patch.object(
        client,
        "get_company_findings",
        return_value={
            "results": [
                {"temporary_id": "A9jq", "rolledup_observation_id": "dummy_id_1", "first_seen": "2025-09-14"},
                {"temporary_id": "A9jq", "rolledup_observation_id": "dummy_id_1", "first_seen": "2025-09-14"},  # Duplicate
                {"temporary_id": "A9jr", "rolledup_observation_id": "dummy_id_2", "first_seen": "2025-09-14"},
            ]
        },
    )

    args = {"lastUpdate": "2025-09-14T10:00:00+00:00", "guid": "test-guid"}
    result = bitsight.get_modified_remote_data_command(client, args)

    # Assertions
    client.get_company_findings.assert_called_once_with(
        guid="test-guid",
        first_seen=None,
        last_seen=None,
        optional_params={"limit": 5000, "sort": "-last_seen", "last_remediation_status_date_gte": "2025-09-14"},
    )
    # Should have unique IDs only
    assert len(result.modified_incident_ids) == 2
    assert "dummy_id_1-#-2025-09-14" in result.modified_incident_ids
    assert "dummy_id_2-#-2025-09-14" in result.modified_incident_ids


def test_get_remote_data_command_successful_retrieval(requests_mock, mocker):
    """
    Given:
    - A client object.
    - Valid mirror ID and arguments.

    When:
    - Mocking the 'get_company_findings' function to return finding data.
    - Mocking the 'get_remediations' function to return remediation status.
    - Mocking the 'get_finding_comments' function to return comments.

    Then:
    - Calling the 'get_remote_data_command' function with the provided client and arguments.
    - Verify the function returns the expected finding data and new entries.
    """
    client = bitsight.Client(base_url=BASE_URL)
    inp_args = {
        "guid": "123",
        "close_status_of_bitsight": "Closed",
        "open_status_of_bitsight": "Work In Progress",
    }
    mocker.patch.object(demisto, "params", return_value=inp_args)

    # Mock finding data
    finding_data = {
        "temporary_id": "A9jq",
        "affects_rating": True,
        "rolledup_observation_id": "dummy_id_1",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
        "severity": 5.0,
        "first_seen": "2025-09-14",
    }

    # Mock HTTP requests using requests_mock
    # Mock get_company_findings request
    requests_mock.get(
        f"{BASE_URL}/v1/companies/test-guid/findings?rolledup_observation_id=dummy_id_1&sort=-last_seen&first_seen=2025-09-14",
        json={"results": [finding_data]},
        status_code=200,
    )

    # Mock get_remediations request
    remediations_url = (
        f"{BASE_URL}/ratings/v1/remediations?"
        "company_guid=test-guid&rolledup_observation_id=dummy_id_1&evidence_key=test.com&risk_vector=ssl_certificates"
    )
    requests_mock.get(
        remediations_url,
        json={"results": [{"status": {"value": "Open"}}]},
        status_code=200,
    )

    mock_comments_response = {
        "results": [
            {
                "guid": "comment-1",
                "message": "Test comment",
                "author": {"name": "Test User"},
                "created_time": "2025-09-14T10:00:00Z",
                "last_update_time": "2025-09-14T11:00:00Z",
            }
        ]
    }
    # Mock get_finding_comments request
    requests_mock.get(
        f"{BASE_URL}/ratings/v1/companies/test-guid/findings/dummy_id_1/comments",
        json=mock_comments_response,
        status_code=200,
    )

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    # Assertions
    # Verify HTTP requests were made correctly
    assert requests_mock.call_count == 3  # get_company_findings, get_remediations, get_finding_comments

    # Verify the results
    assert result.mirrored_object["temporary_id"] == "A9jq"
    assert result.mirrored_object["remediation_status"] == "Open"
    assert len(result.entries) == 1
    assert "Test comment" in result.entries[0]["Contents"]
    assert result.entries[0]["Type"] == EntryType.NOTE


def test_get_remote_data_command_finding_not_found(mocker):
    """
    Given:
    - A client object.
    - Valid mirror ID but finding doesn't exist.

    When:
    - Mocking the 'get_company_findings' function to return empty results.

    Then:
    - Calling the 'get_remote_data_command' function should return empty GetRemoteDataResponse object.
    """
    client = bitsight.Client(base_url=BASE_URL)

    mocker.patch.object(client, "get_company_findings", return_value={"results": []})

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    assert result.mirrored_object == {}
    assert result.entries == []


def test_get_remote_data_command_with_remediations_error(mocker):
    """
    Given:
    - A client object.
    - Valid finding data but remediations API fails.

    When:
    - Mocking the 'get_company_findings' function to return finding data.
    - Mocking the 'get_remediations' function to raise an exception.

    Then:
    - Function should continue without remediation data.
    """
    client = bitsight.Client(base_url=BASE_URL)

    finding_data = {
        "temporary_id": "A9jq",
        "affects_rating": True,
        "rolledup_observation_id": "dummy_id_1",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
    }

    mocker.patch.object(client, "get_company_findings", return_value={"results": [finding_data]})

    mocker.patch.object(client, "get_remediations", side_effect=DemistoException("API Error"))
    mocker.patch.object(client, "get_finding_comments", return_value={"results": []})

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    # Should not have remediation_status due to error
    assert "remediation_status" not in result.mirrored_object
    assert result.mirrored_object["temporary_id"] == "A9jq"


def test_get_remote_data_command_with_comments_error(mocker):
    """
    Given:
    - A client object.
    - Valid finding data but comments API fails.

    When:
    - Mocking the 'get_company_findings' function to return finding data.
    - Mocking the 'get_finding_comments' function to raise an exception.

    Then:
    - Function should continue without comment entries.
    """
    client = bitsight.Client(base_url=BASE_URL)
    inp_args = {
        "guid": "123",
        "close_status_of_bitsight": "Closed",
        "open_status_of_bitsight": "Work In Progress",
    }
    mocker.patch.object(demisto, "params", return_value=inp_args)

    finding_data = {
        "temporary_id": "A9jq",
        "affects_rating": True,
        "rolledup_observation_id": "dummy_id_1",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
    }

    mocker.patch.object(client, "get_company_findings", return_value={"results": [finding_data]})

    mocker.patch.object(client, "get_remediations", return_value={"results": []})
    mocker.patch.object(client, "get_finding_comments", side_effect=DemistoException("API Error"))

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    # Should have no comment entries due to error
    assert len(result.entries) == 0
    assert result.mirrored_object["temporary_id"] == "A9jq"


def test_get_remote_data_command_with_old_comments_filtered(mocker):
    """
    Given:
    - A client object.
    - Comments that are older than lastUpdate timestamp.

    When:
    - Mocking functions to return comments with timestamps before lastUpdate.

    Then:
    - Old comments should be filtered out.
    """
    client = bitsight.Client(base_url=BASE_URL)
    inp_args = {
        "guid": "123",
        "close_status_of_bitsight": "Closed",
        "open_status_of_bitsight": "Work In Progress",
        "close_active_incident": False,
        "reopen_closed_incident": False,
    }
    mocker.patch.object(demisto, "params", return_value=inp_args)

    finding_data = {
        "temporary_id": "A9jq",
        "affects_rating": True,
        "rolledup_observation_id": "dummy_id_1",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
    }

    mocker.patch.object(client, "get_company_findings", return_value={"results": [finding_data]})

    mocker.patch.object(client, "get_remediations", return_value={"results": []})

    # Comments with timestamps before lastUpdate (2025-09-14T10:00:00Z)
    mocker.patch.object(
        client,
        "get_finding_comments",
        return_value={
            "results": [
                {
                    "guid": "old-comment",
                    "message": "Old comment",
                    "author": {"name": "Test User"},
                    "created_time": "2025-09-13T10:00:00Z",  # Before lastUpdate
                    "last_update_time": "2025-09-13T11:00:00Z",
                },
                {
                    "guid": "old-comment-2",
                    "message": "Old comment",
                    "author": {"name": "Test User"},
                    "created_time": "2025-09-13T10:00:00Z",  # Before lastUpdate
                    "last_update_time": None,
                },
                {
                    "guid": "new-comment",
                    "message": "New comment",
                    "author": {"name": "Test User"},
                    "created_time": "2025-09-14T11:00:00Z",  # After lastUpdate
                    "last_update_time": None,
                },
            ]
        },
    )

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    # Should only have the new comment
    assert len(result.entries) == 1
    assert "New comment" in result.entries[0]["Contents"]
    assert result.entries[0]["Type"] == EntryType.NOTE


def test_get_remote_data_command_with_invalid_mirror_id(mocker):
    """
    Given:
    - A client object.
    - Invalid mirror ID format.

    When:
    - Providing mirror ID without proper format.

    Then:
    - Function should handle gracefully with empty identifiers.
    """
    client = bitsight.Client(base_url=BASE_URL)

    mocker.patch.object(client, "get_company_findings", return_value={"results": []})

    args = {
        "id": "invalid_id",  # Missing second part after split
        "lastUpdate": "2025-09-14T10:00:00Z",
        "guid": "test-guid",
    }

    result = bitsight.get_remote_data_command(client, args)

    assert result.mirrored_object == {}
    assert result.entries == []


@pytest.mark.parametrize(
    "close_active_incident,expected_entries",
    [
        (True, 1),  # Should close incident when enabled
        (False, 0),  # Should NOT close incident when disabled
    ],
)
def test_get_remote_data_command_with_incident_closure(mocker, close_active_incident, expected_entries):
    """
    Given:
    - A client object.
    - Remediation status matches close status.
    - Finding is in processed findings list.
    - close_active_incident parameter varies.

    When:
    - Calling get_remote_data_command with matching close status.

    Then:
    - Incident closure behavior should depend on checkbox parameter.
    """
    client = bitsight.Client(base_url=BASE_URL)
    inp_args = {
        "guid": "123",
        "close_status_of_bitsight": "Resolved",
        "open_status_of_bitsight": "Open",
        "close_active_incident": close_active_incident,
        "reopen_closed_incident": False,
    }
    mocker.patch.object(demisto, "params", return_value=inp_args)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": ["dummy_id_1-#-2025-09-14"]})
    mocker.patch.object(demisto, "setIntegrationContext")

    finding_data = {
        "temporary_id": "A9jq",
        "affects_rating": True,
        "rolledup_observation_id": "dummy_id_1",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
    }

    mocker.patch.object(client, "get_company_findings", return_value={"results": [finding_data]})
    mocker.patch.object(client, "get_remediations", return_value={"results": [{"status": {"value": "Resolved"}}]})
    mocker.patch.object(client, "get_finding_comments", return_value={"results": []})

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    # Verify behavior based on parameter
    assert len(result.entries) == expected_entries
    if expected_entries > 0:
        assert result.entries[0]["Contents"]["dbotIncidentClose"] is True
    assert result.mirrored_object["remediation_status"] == "Resolved"


@pytest.mark.parametrize(
    "reopen_closed_incident,expected_entries",
    [
        (True, 1),  # Should reopen incident when enabled
        (False, 0),  # Should NOT reopen incident when disabled
    ],
)
def test_get_remote_data_command_with_incident_reopen(mocker, reopen_closed_incident, expected_entries):
    """
    Given:
    - A client object.
    - Remediation status matches open status.
    - Finding is NOT in processed findings list.
    - reopen_closed_incident parameter varies.

    When:
    - Calling get_remote_data_command with matching open status.

    Then:
    - Incident reopen behavior should depend on checkbox parameter.
    """
    client = bitsight.Client(base_url=BASE_URL)
    inp_args = {
        "guid": "123",
        "close_status_of_bitsight": "Resolved",
        "open_status_of_bitsight": "Open",
        "close_active_incident": False,
        "reopen_closed_incident": reopen_closed_incident,
    }
    mocker.patch.object(demisto, "params", return_value=inp_args)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": []})
    mocker.patch.object(demisto, "setIntegrationContext")

    finding_data = {
        "temporary_id": "A9jq",
        "affects_rating": True,
        "rolledup_observation_id": "dummy_id_1",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
    }

    mocker.patch.object(client, "get_company_findings", return_value={"results": [finding_data]})
    mocker.patch.object(client, "get_remediations", return_value={"results": [{"status": {"value": "Open"}}]})
    mocker.patch.object(client, "get_finding_comments", return_value={"results": []})

    args = {"id": "dummy_id_1-#-2025-09-14", "lastUpdate": "2025-09-14T10:00:00Z", "guid": "test-guid"}

    result = bitsight.get_remote_data_command(client, args)

    # Verify behavior based on parameter
    assert len(result.entries) == expected_entries
    if expected_entries > 0:
        assert result.entries[0]["Contents"]["dbotIncidentReopen"] is True
    assert result.mirrored_object["remediation_status"] == "Open"


def test_update_remote_system_command_incident_closed(mocker):
    """
    Given:
    - A client object.
    - Incident status is DONE (closed).
    - Incident has changed.

    When:
    - Calling update_remote_system_command with closed incident.

    Then:
    - Should call update_external_status with close_status_of_bitsight.
    - Should return the remote incident ID.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "dummy_id_1-#-2025-09-14"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-123",
        "bitsightriskvector": "ssl_certificates",
        "bitsightevidencekey": "test.com",
        "id": "xsoar-456",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.DONE
    mock_parsed_args.delta = {}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": ["dummy_id_1-#-2025-09-14"]})
    mocker.patch.object(client, "update_external_status")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Assertions
    expected_body = {
        "rolledup_observation_id": "obs-123",
        "evidence_key": "test.com",
        "risk_vector": "ssl_certificates",
        "status": {"value": "Closed", "public": False},
    }
    client.update_external_status.assert_called_once_with(company_guid="company-guid", body=expected_body)
    assert result == "dummy_id_1-#-2025-09-14"


def test_update_remote_system_command_with_comments(mocker):
    """
    Given:
    - A client object.
    - New entries (comments) to mirror to BitSight.
    - Existing comments in BitSight for thread_guid.

    When:
    - Calling update_remote_system_command with new entries.

    Then:
    - Should call get_finding_comments to get existing comments.
    - Should call create_finding_comment for each new entry.
    - Should format comment content properly with XSOAR metadata.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs with new entries
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "dummy_id_1-#-2025-09-14"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-456",
        "bitsightriskvector": "ssl_certificates",
        "bitsightevidencekey": "test.com",
        "id": "xsoar-789",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = [
        {
            "id": "entry-1",
            "type": "note",
            "contents": "This is a test comment from XSOAR",
            "user": "admin",
        },
        {
            "id": "entry-2",
            "type": "note",
            "contents": "Another comment\nwith multiple lines",
            "user": "admin",
        },
    ]

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": ["dummy_id_1-#-2025-09-14"]})
    mocker.patch.object(demisto, "setIntegrationContext")

    # Mock existing comments response
    existing_comments = {"results": [{"thread_guid": "thread-123", "guid": "comment-1", "message": "Existing comment"}]}
    mocker.patch.object(client, "get_finding_comments", return_value=existing_comments)
    mocker.patch.object(client, "create_finding_comment")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Verify get_finding_comments was called
    client.get_finding_comments.assert_called_once_with(company_guid="company-guid", rolledup_observation_id="obs-456")

    # Verify create_finding_comment was called for each entry
    assert client.create_finding_comment.call_count == 2

    # Check first comment call
    expected_message_1 = (
        "[Mirrored From XSOAR] XSOAR Incident ID: xsoar-789\n\nNote: This is a test comment from XSOAR\n\nAdded By: admin"
    )
    first_call_args = client.create_finding_comment.call_args_list[0]
    assert first_call_args.kwargs["company_guid"] == "company-guid"
    assert first_call_args.kwargs["rolledup_observation_id"] == "obs-456"
    assert first_call_args.kwargs["thread_guid"] == "thread-123"
    # Check the body contains the expected comment structure
    body_1 = first_call_args.kwargs["body"]
    assert body_1["author_guid"] == "user-123"
    assert body_1["message"] == expected_message_1
    assert body_1["public"] is False

    # Check second comment call
    expected_message_2 = (
        "[Mirrored From XSOAR] XSOAR Incident ID: xsoar-789\n\nNote: Another comment\n\nwith multiple lines\n\nAdded By: admin"
    )
    second_call_args = client.create_finding_comment.call_args_list[1]
    assert second_call_args.kwargs["company_guid"] == "company-guid"
    assert second_call_args.kwargs["rolledup_observation_id"] == "obs-456"
    assert second_call_args.kwargs["thread_guid"] == "thread-123"
    # Check the body contains the expected comment structure
    body_2 = second_call_args.kwargs["body"]
    assert body_2["author_guid"] == "user-123"
    assert body_2["message"] == expected_message_2
    assert body_2["public"] is False

    assert result == "dummy_id_1-#-2025-09-14"


def test_update_remote_system_command_with_comments_no_existing_thread(mocker):
    """
    Given:
    - A client object.
    - New entries to mirror to BitSight.
    - No existing comments in BitSight (empty thread_guid).

    When:
    - Calling update_remote_system_command with new entries.

    Then:
    - Should call create_finding_comment with empty thread_guid.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs with new entries
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "dummy_id_1-#-2025-09-14"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-789",
        "bitsightriskvector": "ssl_certificates",
        "bitsightevidencekey": "test.com",
        "id": "xsoar-123",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {}
    mock_parsed_args.incident_changed = False
    mock_parsed_args.entries = [
        {
            "id": "entry-1",
            "type": "note",
            "contents": "First comment in new thread",
            "user": "dbot",
        }
    ]

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": []})
    mocker.patch.object(demisto, "setIntegrationContext")

    # Mock empty comments response
    mocker.patch.object(client, "get_finding_comments", return_value={"results": []})
    mocker.patch.object(client, "create_finding_comment")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Verify create_finding_comment was called with empty thread_guid
    expected_message = "[Mirrored From XSOAR] XSOAR Incident ID: xsoar-123\n\nNote: First comment in new thread\n\nAdded By: dbot"
    call_args = client.create_finding_comment.call_args
    assert call_args.kwargs["company_guid"] == "company-guid"
    assert call_args.kwargs["rolledup_observation_id"] == "obs-789"
    assert call_args.kwargs["thread_guid"] == ""  # Empty thread_guid for new thread
    # Check the body contains the expected comment structure
    body = call_args.kwargs["body"]
    assert body["comments"][0]["author_guid"] == "user-123"
    assert body["comments"][0]["message"] == expected_message
    assert body["comments"][0]["public"] is False

    assert result == "dummy_id_1-#-2025-09-14"


def test_update_remote_system_command_incident_active_no_delta(mocker):
    """
    Given:
    - A client object.
    - Incident status is ACTIVE.
    - No delta (no changes).
    - Incident has changed.

    When:
    - Calling update_remote_system_command with active incident and no delta.

    Then:
    - Should call update_external_status with open_status_of_bitsight.
    - Should return the remote incident ID.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "dummy_id_1-#-2025-09-14"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-456",
        "bitsightriskvector": "open_ports",
        "bitsightevidencekey": "0.0.0.1",
        "id": "xsoar-789",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {}  # No changes
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(client, "update_external_status")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Assertions
    expected_body = {
        "rolledup_observation_id": "obs-456",
        "evidence_key": "0.0.0.1",
        "risk_vector": "open_ports",
        "status": {"value": "Open", "public": False},
    }
    client.update_external_status.assert_called_once_with(company_guid="company-guid", body=expected_body)
    assert result == "dummy_id_1-#-2025-09-14"


def test_update_remote_system_command_incident_active_with_delta(mocker):
    """
    Given:
    - A client object.
    - Incident status is ACTIVE.
    - Has delta (changes present).
    - Incident has changed.

    When:
    - Calling update_remote_system_command with active incident and delta.

    Then:
    - Should NOT call update_external_status (should_update_status is False).
    - Should return the remote incident ID.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "dummy_id_1-#-2025-09-14"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-789",
        "bitsightriskvector": "malware",
        "bitsightevidencekey": "malware.com",
        "id": "xsoar-101",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {"severity": "high"}  # Has changes
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(client, "update_external_status")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Assertions - should NOT call update_external_status
    client.update_external_status.assert_not_called()
    assert result == "dummy_id_1-#-2025-09-14"


def test_update_remote_system_command_incident_not_changed(mocker):
    """
    Given:
    - A client object.
    - Incident status is DONE.
    - Incident has NOT changed.

    When:
    - Calling update_remote_system_command with unchanged incident.

    Then:
    - Should NOT call update_external_status (incident_changed is False).
    - Should return the remote incident ID.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "remote-999"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-999",
        "bitsightriskvector": "ssl_certificates",
        "bitsightevidencekey": "test.com",
        "id": "xsoar-999",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.DONE
    mock_parsed_args.delta = {}
    mock_parsed_args.incident_changed = False  # Not changed
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(client, "update_external_status")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Assertions - should NOT call update_external_status
    client.update_external_status.assert_not_called()
    assert result == "remote-999"


def test_update_remote_system_command_with_missing_data_fields(mocker):
    """
    Given:
    - A client object.
    - Missing some data fields in parsed_args.data.

    When:
    - Calling update_remote_system_command with missing fields.

    Then:
    - Should handle missing fields gracefully with empty strings.
    - Should call update_external_status with empty values.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs with missing fields
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "remote-empty"
    mock_parsed_args.data = {
        "id": "xsoar-empty"
        # Missing bitsightrolledupobservationid, bitsightriskvector, bitsightevidencekey
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(client, "update_external_status")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Assertions - should handle missing fields with empty strings
    expected_body = {
        "rolledup_observation_id": "",
        "evidence_key": "",
        "risk_vector": "",
        "status": {"value": "Open", "public": False},
    }
    client.update_external_status.assert_called_once_with(company_guid="company-guid", body=expected_body)
    assert result == "remote-empty"


def test_update_remote_system_command_api_error(mocker):
    """
    Given:
    - A client object.
    - update_external_status raises an exception.

    When:
    - Calling update_remote_system_command and API fails.

    Then:
    - Should propagate the exception.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "remote-error"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-error",
        "bitsightriskvector": "ssl_certificates",
        "bitsightevidencekey": "test.com",
        "id": "xsoar-error",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")
    mocker.patch.object(client, "update_external_status", side_effect=DemistoException("API Error"))

    args = {"guid": "company-guid", "user_email": "test@example.com"}
    close_status = "Closed"
    open_status = "Open"

    # Should raise the exception
    with pytest.raises(DemistoException):
        bitsight.update_remote_system_command(client, args, close_status, open_status)


def test_update_remote_system_command_incident_reopen(mocker):
    """
    Given:
    - A client object.
    - Incident status is ACTIVE and incident has been reopened after being closed.
    - Delta contains closingUserId="" and runStatus="" indicating reopen.

    When:
    - Calling update_remote_system_command with reopened incident.

    Then:
    - Should call update_external_status with open_status_of_bitsight.
    - Should return the remote incident ID.
    """
    client = bitsight.Client(base_url=BASE_URL)

    # Mock UpdateRemoteSystemArgs
    mock_parsed_args = mocker.MagicMock()
    mock_parsed_args.remote_incident_id = "remote-reopen-123"
    mock_parsed_args.data = {
        "bitsightrolledupobservationid": "obs-reopen-456",
        "bitsightriskvector": "web_application_security",
        "bitsightevidencekey": "example.com",
        "id": "xsoar-reopen-789",
    }
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {"closingUserId": "", "runStatus": ""}  # Indicates incident reopen
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch.object(client, "update_external_status")
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")

    args = {"guid": "company-guid-reopen"}
    close_status = "Risk Accepted"
    open_status = "Open"

    result = bitsight.update_remote_system_command(client, args, close_status, open_status)

    # Assertions
    expected_body = {
        "rolledup_observation_id": "obs-reopen-456",
        "evidence_key": "example.com",
        "risk_vector": "web_application_security",
        "status": {"value": "Open", "public": False},
    }
    client.update_external_status.assert_called_once_with(company_guid="company-guid-reopen", body=expected_body)
    assert result == "remote-reopen-123"


def test_get_current_user_guid_success_with_valid_email(mocker, requests_mock):
    """
    Given:
    - A client object and valid user email address.

    When:
    - Calling get_current_user_guid with valid email.

    Then:
    - Should return the user GUID from API response and cache it.
    """
    from BitSightForSecurityPerformanceManagement import get_current_user_guid

    client = bitsight.Client(base_url=BASE_URL)
    user_email = "test@example.com"
    expected_guid = "user-guid-123"

    # Mock HTTP request using requests_mock
    mock_response = {"results": [{"guid": expected_guid, "email": user_email}]}
    requests_mock.get(f"{BASE_URL}/ratings/v2/users?email={user_email}", json=mock_response, status_code=200)

    mocker.patch.object(demisto, "getIntegrationContext", return_value={"users_guids": {}})
    mocker.patch.object(demisto, "setIntegrationContext")

    result = get_current_user_guid(client, user_email)

    assert result == expected_guid
    assert requests_mock.call_count == 1


def test_test_module_with_mirroring_missing_user_email(requests_mock):
    """
    Given:
    - Integration parameters with mirroring enabled but missing user email.

    When:
    - Running test_module function.

    Then:
    - Should raise ValueError with USER_EMAIL_REQUIRED message.
    """
    client = bitsight.Client(base_url=BASE_URL)

    params = {"apikey": "test-key", "mirror_direction": "Outgoing", "user_email": "", "isFetch": False}

    # Mock HTTP request for companies
    companies_response = {"companies": [{"guid": "valid-guid-123", "name": "Test Company"}]}
    requests_mock.get(f"{BASE_URL}/v1/companies", json=companies_response, status_code=200)

    with pytest.raises(ValueError) as e:
        bitsight.test_module(client, params)

    assert str(e.value) == bitsight.ERROR_MESSAGES["USER_EMAIL_REQUIRED"]


def test_test_module_with_mirroring_invalid_user_email(mocker, requests_mock):
    """
    Given:
    - Integration parameters with mirroring enabled and invalid user email.

    When:
    - Running test_module function with non-existent email.

    Then:
    - Should raise ValueError with USER_GUID_NOT_FOUND message.
    """
    client = bitsight.Client(base_url=BASE_URL)

    params = {"apikey": "test-key", "mirror_direction": "Outgoing", "user_email": "invalid@example.com", "isFetch": False}

    # Mock HTTP requests using requests_mock
    companies_response = {"companies": [{"guid": "valid-guid-123", "name": "Test Company"}]}
    user_response = {"results": []}  # No user found

    requests_mock.get(f"{BASE_URL}/v1/companies", json=companies_response, status_code=200)
    requests_mock.get(f"{BASE_URL}/ratings/v2/users?email=invalid@example.com", json=user_response, status_code=200)

    mocker.patch.object(demisto, "getIntegrationContext", return_value={"users_guids": {}})
    mocker.patch.object(demisto, "setIntegrationContext")

    with pytest.raises(ValueError) as e:
        bitsight.test_module(client, params)

    assert str(e.value) == bitsight.ERROR_MESSAGES["USER_GUID_NOT_FOUND"]


def test_update_remote_system_command_adds_closing_note_existing_thread(mocker):
    """
    Given:
    - Mirroring arguments that mark the incident as closed with closing details.
    - Existing BitSight comment thread for the finding.

    When:
    - update_remote_system_command is executed.

    Then:
    - A closing note is appended to the existing thread and the remote ID is returned.
    """
    from BitSightForSecurityPerformanceManagement import update_remote_system_command

    client = bitsight.Client(base_url=BASE_URL)
    mock_parsed_args = mocker.MagicMock()
    closing_args = {
        "bitsightrolledupobservationid": "rolledup-123",
        "bitsightriskvector": "web_application_security",
        "bitsightevidencekey": "example.com",
        "id": "xsoar-incident-1",
        "closeNotes": "resolved",
        "closeReason": "Resolved",
        "closingUserId": "admin",
    }

    mock_parsed_args.remote_incident_id = "dummy_id_1-#-2025-09-14"
    mock_parsed_args.data = closing_args
    mock_parsed_args.inc_status = bitsight.IncidentStatus.DONE
    mock_parsed_args.delta = {"closingUserId": "admin"}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-123")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": ["dummy_id_1-#-2025-09-14"]})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(client, "update_external_status")
    mocker.patch.object(client, "get_finding_comments", return_value={"results": [{"thread_guid": "thread-456"}]})
    mock_create_comment = mocker.patch.object(client, "create_finding_comment")

    args = {"guid": "company-guid", "user_email": "user@example.com"}

    result = update_remote_system_command(client, args, "Resolved", "Open")

    closing_note = (
        "[Mirrored From XSOAR] XSOAR Incident ID: xsoar-incident-1\n\n"
        "Close Reason: Resolved\n\n"
        "Closed By: admin\n\n"
        "Close Notes: resolved"
    )
    mock_create_comment.assert_called_once_with(
        company_guid="company-guid",
        rolledup_observation_id="rolledup-123",
        thread_guid="thread-456",
        body={"author_guid": "user-123", "message": closing_note, "public": False},
    )
    assert result == "dummy_id_1-#-2025-09-14"


def test_update_remote_system_command_adds_closing_note_new_thread(mocker):
    """
    Given:
    - Mirroring arguments that mark the incident as closed with closing details.
    - No existing BitSight comment thread for the finding.

    When:
    - update_remote_system_command is executed.

    Then:
    - A closing note is created in a new thread and the remote ID is returned.
    """
    from BitSightForSecurityPerformanceManagement import update_remote_system_command

    client = bitsight.Client(base_url=BASE_URL)
    mock_parsed_args = mocker.MagicMock()
    closing_args = {
        "bitsightrolledupobservationid": "rolledup-456",
        "bitsightriskvector": "malware",
        "bitsightevidencekey": "malware.example.com",
        "id": "xsoar-incident-2",
        "closeNotes": "handled",
        "closeReason": "Mitigated",
        "closingUserId": "analyst",
    }

    mock_parsed_args.remote_incident_id = "dummy_id_2-#-2025-11-25"
    mock_parsed_args.data = closing_args
    mock_parsed_args.inc_status = bitsight.IncidentStatus.DONE
    mock_parsed_args.delta = {"closingUserId": "analyst"}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-456")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": ["dummy_id_2-#-2025-11-25"]})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(client, "update_external_status")
    mocker.patch.object(client, "get_finding_comments", return_value={})
    mock_create_comment = mocker.patch.object(client, "create_finding_comment")

    args = {"guid": "company-guid", "user_email": "user@example.com"}

    result = update_remote_system_command(client, args, "Resolved", "Open")

    closing_note = (
        "[Mirrored From XSOAR] XSOAR Incident ID: xsoar-incident-2\n\n"
        "Close Reason: Mitigated\n\n"
        "Closed By: analyst\n\n"
        "Close Notes: handled"
    )
    mock_create_comment.assert_called_once_with(
        company_guid="company-guid",
        rolledup_observation_id="rolledup-456",
        thread_guid="",
        body={"comments": [{"author_guid": "user-456", "message": closing_note, "public": False}]},
    )
    assert result == "dummy_id_2-#-2025-11-25"


def test_update_remote_system_command_does_not_add_closing_note_when_status_not_done(mocker):
    """
    Given:
    - Mirroring arguments where closing user is provided but the incident status is not DONE.

    When:
    - update_remote_system_command is executed.

    Then:
    - No closing note is mirrored to BitSight.
    """
    from BitSightForSecurityPerformanceManagement import update_remote_system_command

    client = bitsight.Client(base_url=BASE_URL)
    mock_parsed_args = mocker.MagicMock()
    closing_args = {
        "bitsightrolledupobservationid": "rolledup-789",
        "bitsightriskvector": "botnet_infections",
        "bitsightevidencekey": "bot.example.com",
        "id": "xsoar-incident-3",
        "closeNotes": "monitor",
        "closeReason": "Monitoring",
        "closingUserId": "responder",
    }

    mock_parsed_args.remote_incident_id = "Bitsight Finding - rolledup-789"
    mock_parsed_args.data = closing_args
    mock_parsed_args.inc_status = bitsight.IncidentStatus.ACTIVE
    mock_parsed_args.delta = {"closingUserId": "responder"}
    mock_parsed_args.incident_changed = True
    mock_parsed_args.entries = []

    mocker.patch("BitSightForSecurityPerformanceManagement.UpdateRemoteSystemArgs", return_value=mock_parsed_args)
    mocker.patch("BitSightForSecurityPerformanceManagement.get_current_user_guid", return_value="user-789")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"processed_findings": []})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(client, "update_external_status")
    mock_get_comments = mocker.patch.object(client, "get_finding_comments")
    mock_create_comment = mocker.patch.object(client, "create_finding_comment")

    args = {"guid": "company-guid", "user_email": "user@example.com"}

    result = update_remote_system_command(client, args, "Resolved", "Open")

    mock_get_comments.assert_not_called()
    mock_create_comment.assert_not_called()
    assert result == "Bitsight Finding - rolledup-789"
