import pytest
from datetime import datetime
from CommonServerPython import DemistoException
from SearchCases import prepare_start_end_time, main, extract_ids, add_cases_extra_data, get_case_extra_data


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


def test_get_case_extra_data_command_error(mocker):
    """
    GIVEN execute_command that raises an exception
    WHEN get_case_extra_data is called
    THEN it raises the exception
    """
    mocker.patch("SearchCases.execute_command", side_effect=Exception("Command failed"))

    with pytest.raises(Exception):
        get_case_extra_data({"case_id": "123"})


def test_add_cases_extra_data_single_case(mocker):
    """
    GIVEN a list with one case containing case_id
    WHEN add_cases_extra_data is called
    THEN it adds CaseExtraData to the case by calling get_case_extra_data
    """

    mock_get_case_extra_data = mocker.patch("SearchCases.get_case_extra_data")
    mock_extra_data = {"issues": {"total_count": 5}, "alerts": {"total_count": 3}}
    mock_get_case_extra_data.return_value = mock_extra_data

    case_data = [{"case_id": "123", "case_name": "Test Case"}]

    result = add_cases_extra_data(case_data)

    mock_get_case_extra_data.assert_called_once_with({"case_id": "123", "limit": 1000})
    assert result[0]["CaseExtraData"] == mock_extra_data
    assert result[0]["case_id"] == "123"
    assert result[0]["case_name"] == "Test Case"


def test_add_cases_extra_data_multiple_cases(mocker):
    """
    GIVEN a list with multiple cases containing case_ids
    WHEN add_cases_extra_data is called
    THEN it adds CaseExtraData to each case by calling get_case_extra_data for each
    """

    mock_get_case_extra_data = mocker.patch("SearchCases.get_case_extra_data")
    mock_extra_data_1 = {"issues": {"total_count": 5}}
    mock_extra_data_2 = {"issues": {"total_count": 10}}
    mock_get_case_extra_data.side_effect = [mock_extra_data_1, mock_extra_data_2]

    case_data = [{"case_id": "123", "case_name": "Test Case 1"}, {"case_id": "456", "case_name": "Test Case 2"}]

    result = add_cases_extra_data(case_data)

    assert mock_get_case_extra_data.call_count == 2
    mock_get_case_extra_data.assert_any_call({"case_id": "123", "limit": 1000})
    mock_get_case_extra_data.assert_any_call({"case_id": "456", "limit": 1000})
    assert result[0]["CaseExtraData"] == mock_extra_data_1
    assert result[1]["CaseExtraData"] == mock_extra_data_2


def test_add_cases_extra_data_empty_list(mocker):
    """
    GIVEN an empty list of cases
    WHEN add_cases_extra_data is called
    THEN it returns empty list without calling get_case_extra_data
    """

    mock_get_case_extra_data = mocker.patch("SearchCases.get_case_extra_data")

    case_data = []

    result = add_cases_extra_data(case_data)

    mock_get_case_extra_data.assert_not_called()
    assert result == []


def test_get_case_extra_data_normal(mocker):
    """
    GIVEN valid args for get_case_extra_data
    WHEN get_case_extra_data is called
    THEN it returns properly formatted extra data with issue_ids, network_artifacts, and file_artifacts
    """

    mock_case_extra_data = {
        "issues": {"data": [{"issue_id": "101"}, {"issue_id": "102"}]},
        "network_artifacts": [{"ip": "1.2.3.4"}],
        "file_artifacts": [{"filename": "test.exe"}],
    }

    mocker.patch("SearchCases.execute_command", return_value=mock_case_extra_data)
    mocker.patch("SearchCases.extract_ids", return_value=["101", "102"])
    mock_debug = mocker.patch("demistomock.debug")

    args = {"case_id": "123"}
    result = get_case_extra_data(args)

    assert result["issue_ids"] == ["101", "102"]
    assert result["network_artifacts"] == [{"ip": "1.2.3.4"}]
    assert result["file_artifacts"] == [{"filename": "test.exe"}]
    assert mock_debug.call_count == 2


def test_get_case_extra_data_no_artifacts(mocker):
    """
    GIVEN case extra data with no network or file artifacts
    WHEN get_case_extra_data is called
    THEN it returns None for missing artifact types
    """

    mock_case_extra_data = {"issues": {"data": [{"issue_id": "101"}]}}

    mocker.patch("SearchCases.execute_command", return_value=mock_case_extra_data)
    mocker.patch("SearchCases.extract_ids", return_value=["101"])
    mocker.patch("demistomock.debug")

    args = {"case_id": "123"}
    result = get_case_extra_data(args)

    assert result["issue_ids"] == ["101"]
    assert result["network_artifacts"] is None
    assert result["file_artifacts"] is None


def test_get_case_extra_data_empty_issues(mocker):
    """
    GIVEN case extra data with empty issues
    WHEN get_case_extra_data is called
    THEN it returns empty issue_ids list
    """

    mock_case_extra_data = {"issues": {"data": []}, "network_artifacts": [], "file_artifacts": []}

    mocker.patch("SearchCases.execute_command", return_value=mock_case_extra_data)
    mocker.patch("SearchCases.extract_ids", return_value=[])
    mocker.patch("demistomock.debug")

    args = {"case_id": "123"}
    result = get_case_extra_data(args)

    assert result["issue_ids"] == []
    assert result["network_artifacts"] == []
    assert result["file_artifacts"] == []


def test_extract_ids_mixed_valid_invalid_items():
    """
    GIVEN case_extra_data with mix of valid items, items missing issue_id, and non-dict items
    WHEN extract_ids is called
    THEN it returns only valid issue_ids
    """
    case_extra_data = {
        "issues": {
            "data": [
                {"issue_id": "100", "name": "Issue 1"},
                {"name": "Issue 2"},
                "not_a_dict",
                {"issue_id": "101", "severity": "high"},
                None,
                {"issue_id": "102"},
            ]
        }
    }
    result = extract_ids(case_extra_data)
    assert result == ["100", "101", "102"]


def test_extract_ids_non_list_data(mocker):
    """
    GIVEN case_extra_data where issues.data is not a list
    WHEN extract_ids is called
    THEN it returns empty list
    """
    case_extra_data = {"issues": {"data": {"not_a_list": True}}}

    result = extract_ids(case_extra_data)
    assert result == []


def test_extract_ids_no_issues():
    """
    GIVEN case_extra_data with no issues key
    WHEN extract_ids is called
    THEN it returns empty list
    """
    case_extra_data = {
        "case": {
            "aggregated_score": None,
            "assigned_user_mail": None,
            "assigned_user_pretty_name": None,
            "case_domain": "DOMAIN_POSTURE",
            "case_id": "62",
        }
    }
    result = extract_ids(case_extra_data)
    assert result == []


def test_extract_ids_no_issues_data():
    """
    GIVEN case_extra_data with issues key but no data key
    WHEN extract_ids is called
    THEN it returns empty list
    """
    case_extra_data = {
        "case": {
            "aggregated_score": None,
            "assigned_user_mail": None,
            "assigned_user_pretty_name": None,
            "case_domain": "DOMAIN_POSTURE",
            "case_id": "62",
        },
        "issues": {},
    }
    result = extract_ids(case_extra_data)
    assert result == []


def test_extract_ids_no_valid_issues_data():
    """
    GIVEN case_extra_data with issues.data that is not a list
    WHEN extract_ids is called
    THEN it returns empty list
    """
    case_extra_data = {
        "case": {
            "aggregated_score": None,
            "assigned_user_mail": None,
            "assigned_user_pretty_name": None,
            "case_domain": "DOMAIN_POSTURE",
            "case_id": "62",
        },
        "issues": {"data": {"id": "1"}},
    }
    result = extract_ids(case_extra_data)
    assert result == []


def test_extract_ids_single_valid_item():
    """
    GIVEN case_extra_data with single valid issue
    WHEN extract_ids is called
    THEN it returns list with single issue_id
    """
    case_extra_data = {"issues": {"data": [{"issue_id": "999", "description": "Single issue"}]}}
    result = extract_ids(case_extra_data)
    assert result == ["999"]


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
