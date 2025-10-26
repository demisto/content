import pytest
from datetime import datetime
from CommonServerPython import DemistoException
from SearchCases import prepare_start_end_time, main, extract_ids


def test_prepare_start_end_time_normal(monkeypatch):
    """
    GIVEN valid start_time and end_time arguments in ISO format
    WHEN prepare_start_end_time is called
    THEN it sets gte_creation_time and lte_creation_time correctly in the args dict
    """
    args = {"start_time": "2025-09-01T12:00:00", "end_time": "2025-09-02T13:00:00"}
    prepare_start_end_time(args)
    assert args["gte_creation_time"] == "2025-09-01T12:00:00"
    assert args["lte_creation_time"] == "2025-09-02T13:00:00"


def test_prepare_start_end_time_end_without_start():
    """
    GIVEN only end_time is provided in args
    WHEN prepare_start_end_time is called
    THEN it raises DemistoException because start_time is required if end_time is provided
    """
    args = {"end_time": "2025-09-02T13:00:00"}
    with pytest.raises(DemistoException):
        prepare_start_end_time(args)


def test_prepare_start_end_time_only_start(monkeypatch):
    """
    GIVEN only start_time is provided in args
    WHEN prepare_start_end_time is called
    THEN it sets gte_creation_time and lte_creation_time (lte_creation_time defaults to now)
    """
    args = {"start_time": "2025-09-01T12:00:00"}
    monkeypatch.setattr("SearchCases.datetime", datetime)
    prepare_start_end_time(args)
    assert "gte_creation_time" in args
    assert "lte_creation_time" in args


def test_prepare_start_end_time_both_empty():
    """
    GIVEN no start_time or end_time in args
    WHEN prepare_start_end_time is called
    THEN it does not set gte_creation_time or lte_creation_time
    """
    args = {}
    prepare_start_end_time(args)
    assert "gte_creation_time" not in args
    assert "lte_creation_time" not in args


def test_prepare_start_end_time_unparseable():
    """
    GIVEN start_time and end_time are unparseable strings
    WHEN prepare_start_end_time is called
    THEN it does not set gte_creation_time or lte_creation_time
    """
    args = {"start_time": "not-a-date", "end_time": "also-not-a-date"}
    prepare_start_end_time(args)
    assert "gte_creation_time" not in args
    assert "lte_creation_time" not in args


def test_prepare_start_end_time_only_end():
    """
    GIVEN only end_time is provided in args (again)
    WHEN prepare_start_end_time is called
    THEN it raises DemistoException because start_time is required if end_time is provided
    """
    args = {"end_time": "2025-09-02T13:00:00"}
    try:
        prepare_start_end_time(args)
    except DemistoException as e:
        assert "start_time must be provided" in str(e)


def test_prepare_start_end_time_relative(monkeypatch):
    """
    GIVEN start_time and end_time as relative date strings
    WHEN prepare_start_end_time is called
    THEN it sets gte_creation_time and lte_creation_time in the args dict
    """
    args = {"start_time": "1 day ago", "end_time": "now"}
    prepare_start_end_time(args)
    assert "gte_creation_time" in args
    assert "lte_creation_time" in args


def test_main_success(mocker):
    """
    GIVEN valid demisto.args and executeCommand returns a valid result
    WHEN main is called
    THEN return_results is called with the expected output
    """
    mock_args = {"start_time": "2025-09-01T12:00:00", "end_time": "2025-09-02T13:00:00", "page_size": 5}
    mocker.patch("demistomock.args", return_value=mock_args.copy())
    mocker.patch(
        "demistomock.executeCommand",
        return_value=[
            {
                "EntryContext": {"Core.Case": [{"case_id": "1"}]},
                "HumanReadable": "ok",
                "Type": 1,
            }
        ],
    )
    mocker.patch("SearchCases.prepare_start_end_time")
    mocked_return_results = mocker.patch("SearchCases.return_results")
    main()
    mocked_return_results.assert_called()


def test_main_error(mocker):
    """
    GIVEN executeCommand returns an error result
    WHEN main is called
    THEN return_error is called
    """
    mock_args = {"start_time": "2025-09-01T12:00:00", "end_time": "2025-09-02T13:00:00", "page_size": 5}
    mocker.patch("demistomock.args", return_value=mock_args.copy())
    mocker.patch(
        "demistomock.executeCommand",
        return_value=[
            {
                "Type": 4,
                "ContentsFormat": "text",
                "Contents": "error",
                "HumanReadable": "fail",
                "EntryContext": {},
                "ModuleName": "",
                "Brand": "",
                "ID": "",
                "FileID": "",
            }
        ],
    )
    mocker.patch("SearchCases.prepare_start_end_time")
    mocked_return_error = mocker.patch("SearchCases.return_error")
    mocker.patch("SearchCases.is_error", return_value=True)
    mocker.patch("SearchCases.get_error", return_value="fail")
    main()
    mocked_return_error.assert_called()


# add a test for extract id


def test_extract_ids():
    """
    Given:
        - json containing id
    When:
        - extract id from json
    Then:
        - check if id is extracted correctly
    """
    case_extra_data_issue = {
        "case": {
            "aggregated_score": None,
            "assigned_user_mail": None,
            "assigned_user_pretty_name": None,
            "case_domain": "DOMAIN_POSTURE",
            "case_id": "62",
            "case_name": "caseName",
            "case_sources": ["CSPM Scanner"],
            "creation_time": 1761429680000,
            "critical_severity_issue_count": 0,
            "custom_fields": {},
            "description": "caseDescription",
            "detection_time": None,
            "high_severity_issue_count": 2,
            "host_count": 0,
            "hosts": None,
            "is_blocked": False,
            "issue_categories": ["CONFIGURATION"],
            "issue_count": 2,
            "issues_grouping_status": "Enabled",
            "low_severity_issue_count": 0,
            "manual_description": None,
            "manual_score": None,
            "manual_severity": None,
            "med_severity_issue_count": 0,
            "mitre_tactics_ids_and_names": None,
            "mitre_techniques_ids_and_names": None,
            "modification_time": 1761429680000,
            "notes": None,
            "original_tags": ["tag1", "tag2"],
            "predicted_score": None,
            "resolve_comment": None,
            "resolved_timestamp": None,
            "rule_based_score": None,
            "severity": "high",
            "starred": False,
            "starred_manually": False,
            "status": "new",
            "tags": [],
            "user_count": 0,
            "users": [],
            "wildfire_hits": 0,
            "xdr_url": "https://example.com/incident-view?caseId=62",
        },
        "issues": {
            "data": [
                {
                    "action": "SCANNED",
                    "action_country": "UNKNOWN",
                    "action_pretty": "Detected (Scanned)",
                    "action_process_signature_status": "N/A",
                    "actor_process_signature_status": "N/A",
                    "agent_install_type": "NA",
                    "agent_os_type": "NO_HOST",
                    "attempt_counter": 0,
                    "case_id": 62,
                    "category": "CONFIGURATION",
                    "causality_actor_process_signature_status": "N/A",
                    "contains_featured_host": "NO",
                    "contains_featured_ip": "NO",
                    "contains_featured_user": "NO",
                    "description": "description",
                    "detection_timestamp": 1761464615083,
                    "events_length": 1,
                    "external_id": "externalId",
                    "fw_is_phishing": "N/A",
                    "is_pcap": False,
                    "is_whitelisted": False,
                    "issue_domain": "issueDomain",
                    "issue_id": "282",
                    "issue_type": "Unclassified",
                    "last_modified_ts": 1761464616409,
                    "local_insert_ts": 1761249196887,
                    "matching_service_rule_id": "serviceRuleId",
                    "matching_status": "UNMATCHABLE",
                    "name": "Azure Storage Account default network access is set to 'Allow'",
                    "original_tags": "DS:PANW/CSPM Scanner,DOM:Posture",
                    "os_actor_process_signature_status": "N/A",
                    "resolution_comment": "",
                    "resolution_status": "STATUS_010_NEW",
                    "severity": "high",
                    "source": "CSPM Scanner",
                    "starred": False,
                    "tags": "DS:PANW/CSPM Scanner,DOM:Posture",
                },
                {
                    "action": "SCANNED",
                    "action_country": "UNKNOWN",
                    "action_pretty": "Detected (Scanned)",
                    "action_process_signature_status": "N/A",
                    "actor_process_signature_status": "N/A",
                    "agent_install_type": "NA",
                    "agent_os_type": "NO_HOST",
                    "attempt_counter": 0,
                    "case_id": 62,
                    "category": "CONFIGURATION",
                    "causality_actor_process_signature_status": "N/A",
                    "contains_featured_host": "NO",
                    "contains_featured_ip": "NO",
                    "contains_featured_user": "NO",
                    "description": "Azure Storage account Encryption Customer Managed Keys Disabled",
                    "detection_timestamp": 1761464615083,
                    "events_length": 1,
                    "external_id": "P-987654321",
                    "fw_is_phishing": "N/A",
                    "is_pcap": False,
                    "is_whitelisted": False,
                    "issue_domain": "DOMAIN_POSTURE",
                    "issue_id": "283",
                    "issue_type": "Unclassified",
                    "last_modified_ts": 1761464615986,
                    "local_insert_ts": 1761249197825,
                    "matching_status": "UNMATCHABLE",
                    "name": "Azure Storage account Encryption Customer Managed Keys Disabled",
                    "os_actor_process_signature_status": "N/A",
                    "resolution_comment": "",
                    "resolution_status": "STATUS_010_NEW",
                    "severity": "high",
                    "source": "CSPM Scanner",
                    "starred": False,
                },
            ],
            "total_count": 2,
        },
    }
    id = extract_ids(case_extra_data_issue)
    assert id == ["282", "283"]
