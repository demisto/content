import demistomock as demisto
import pytest
from AWS_SecurityHub_V2 import (
    build_fetch_filters,
    disable_security_hub_command,
    enable_security_hub_command,
    fetch_incidents,
    findings_batch_update_command,
    findings_get_command,
    generate_filters_for_get_findings,
    parse_date_filters,
    parse_filters,
    parse_finding_identifiers,
    parse_tags,
)
from CommonServerPython import DemistoException


def test_parse_tags():
    """
    Given: A string of key/value tag pairs separated by ';'.
    When: parse_tags is called.
    Then: It returns a flat {key: value} mapping as required by the Security Hub V2 API.
    """
    result = parse_tags("key=env,value=prod;key=team,value=security")
    assert result == {"env": "prod", "team": "security"}


def test_parse_tags_empty():
    """
    Given: An empty tags string.
    When: parse_tags is called.
    Then: It returns an empty dict.
    """
    assert parse_tags("") == {}


def test_enable_security_hub_command_success(mocker):
    """
    Given: A mocked securityhub client and a tags argument.
    When: enable_security_hub_command is called.
    Then: It calls enable_security_hub_v2 with a flat Tags mapping and returns the V2 ARN.
    """
    mock_client = mocker.Mock()
    mock_client.enable_security_hub_v2.return_value = {
        "HubV2Arn": "dummy_arn",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    args = {"tags": "key=env,value=prod"}

    result = enable_security_hub_command(mock_client, args)

    call_kwargs = mock_client.enable_security_hub_v2.call_args[1]
    assert call_kwargs["Tags"] == {"env": "prod"}
    assert result.outputs_prefix == "AWS.SecurityHub.Hub"
    assert result.outputs == {"HubV2Arn": "dummy_arn"}
    assert "AWS Security Hub V2 Enabled" in result.readable_output


def test_enable_security_hub_command_no_tags(mocker):
    """
    Given: A mocked securityhub client and no tags argument.
    When: enable_security_hub_command is called.
    Then: It calls enable_security_hub_v2 without a Tags parameter (empty kwargs).
    """
    mock_client = mocker.Mock()
    mock_client.enable_security_hub_v2.return_value = {
        "HubV2Arn": "dummy_arn",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    result = enable_security_hub_command(mock_client, {})

    call_kwargs = mock_client.enable_security_hub_v2.call_args[1]
    assert "Tags" not in call_kwargs
    assert result.outputs["HubV2Arn"] == "dummy_arn"


def test_enable_security_hub_command_error(mocker):
    """
    Given: A mocked securityhub client whose enable_security_hub_v2 raises an exception.
    When: enable_security_hub_command is called.
    Then: The exception propagates to be handled in main().
    """
    mock_client = mocker.Mock()
    mock_client.enable_security_hub_v2.side_effect = Exception("AccessDenied")

    with pytest.raises(Exception, match="AccessDenied"):
        enable_security_hub_command(mock_client, {})


def test_disable_security_hub_command_success(mocker):
    """
    Given: A mocked securityhub client.
    When: disable_security_hub_command is called.
    Then: It calls disable_security_hub_v2 and returns a confirmation message.
    """
    mock_client = mocker.Mock()
    mock_client.disable_security_hub_v2.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    result = disable_security_hub_command(mock_client, {})

    mock_client.disable_security_hub_v2.assert_called_once()
    assert "successfully disabled" in result.readable_output


def test_disable_security_hub_command_error(mocker):
    """
    Given: A mocked securityhub client whose disable_security_hub_v2 raises an exception.
    When: disable_security_hub_command is called.
    Then: The exception propagates to be handled in main().
    """
    mock_client = mocker.Mock()
    mock_client.disable_security_hub_v2.side_effect = Exception("AccessDenied")

    with pytest.raises(Exception, match="AccessDenied"):
        disable_security_hub_command(mock_client, {})


def test_parse_filters_string():
    """
    Given: A string_filters argument with two entries and a custom comparison.
    When: parse_filters is called for the "string" category.
    Then: It returns the StringFilters API structure with EQUALS as the default comparison.
    """
    result = parse_filters(
        "fieldname=severity,value=High;fieldname=finding_info.title,value=root,comparison=CONTAINS_WORD", "string"
    )
    assert result == [
        {"FieldName": "severity", "Filter": {"Value": "High", "Comparison": "EQUALS"}},
        {"FieldName": "finding_info.title", "Filter": {"Value": "root", "Comparison": "CONTAINS_WORD"}},
    ]


def test_parse_filters_number():
    """
    Given: A number_filters argument where the operator is the entry key.
    When: parse_filters is called for the "number" category.
    Then: It maps the operator key to the API key and converts the value to a number.
    """
    result = parse_filters("fieldname=severity_id,gte=3", "number")
    assert result == [{"FieldName": "severity_id", "Filter": {"Gte": 3}}]


def test_parse_filters_boolean():
    """
    Given: A boolean_filters argument.
    When: parse_filters is called for the "boolean" category.
    Then: It returns the BooleanFilters API structure with the value coerced to a bool.
    """
    result = parse_filters("fieldname=compliance.assessments.meets_criteria,value=false", "boolean")
    assert result == [{"FieldName": "compliance.assessments.meets_criteria", "Filter": {"Value": False}}]


def test_parse_filters_map():
    """
    Given: A map_filters argument with key/value and no explicit comparison.
    When: parse_filters is called for the "map" category.
    Then: It returns the MapFilters API structure with EQUALS as the default comparison.
    """
    result = parse_filters("fieldname=resources.tags,key=env,value=prod", "map")
    assert result == [{"FieldName": "resources.tags", "Filter": {"Key": "env", "Value": "prod", "Comparison": "EQUALS"}}]


def test_parse_filters_ip():
    """
    Given: An ip_filters argument.
    When: parse_filters is called for the "ip" category.
    Then: It returns the IpFilters API structure.
    """
    result = parse_filters("fieldname=evidences.src_endpoint.ip,cidr=10.0.0.1", "ip")
    assert result == [{"FieldName": "evidences.src_endpoint.ip", "Filter": {"Cidr": "10.0.0.1"}}]


def test_parse_filters_skips_invalid_entries():
    """
    Given: Filter entries missing the fieldname or a required key.
    When: parse_filters is called.
    Then: Invalid entries are skipped while valid ones are kept.
    """
    # Missing fieldname, missing value, and a number entry without any operator are all skipped.
    assert parse_filters("value=High", "string") == []
    assert parse_filters("fieldname=severity", "string") == []
    assert parse_filters("fieldname=severity_id", "number") == []


def test_generate_filters_for_get_findings_empty():
    """
    Given: Args with no filter conditions.
    When: generate_filters_for_get_findings is called.
    Then: It returns None (no filter to apply).
    """
    assert generate_filters_for_get_findings({}) is None


def test_generate_filters_for_get_findings_composite():
    """
    Given: Args with string and date filters and a custom composite operator.
    When: generate_filters_for_get_findings is called.
    Then: It builds the composite Filters structure with the conditions and operators.
    """
    args = {
        "string_filters": "fieldname=severity,value=High",
        "number_filters": "fieldname=severity_id,gte=4",
        "date_filters": "fieldname=finding_info.created_time_dt,start=2024-01-01T00:00:00Z,end=2024-02-01T00:00:00Z",
        "composite_operator": "OR",
    }
    result = generate_filters_for_get_findings(args)
    assert result["CompositeOperator"] == "OR"
    composite = result["CompositeFilters"][0]
    assert composite["Operator"] == "AND"
    assert composite["StringFilters"] == [{"FieldName": "severity", "Filter": {"Value": "High", "Comparison": "EQUALS"}}]
    assert composite["NumberFilters"] == [{"FieldName": "severity_id", "Filter": {"Gte": 4}}]
    assert composite["DateFilters"] == [
        {"FieldName": "finding_info.created_time_dt", "Filter": {"Start": "2024-01-01T00:00:00Z", "End": "2024-02-01T00:00:00Z"}}
    ]


def test_findings_get_command_success(mocker):
    """
    Given: A mocked securityhub client returning findings and filter/sort/limit args.
    When: findings_get_command is called.
    Then: It passes the built Filters, SortCriteria, and MaxResults and returns findings + next token.
    """
    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {
        "Findings": [{"metadata": {"uid": "f-1"}, "severity": "High"}],
        "NextToken": "tok-123",
    }
    args = {"string_filters": "fieldname=severity,value=High", "sort_field": "time", "sort_order": "desc", "limit": "10"}

    result = findings_get_command(mock_client, args)

    call_kwargs = mock_client.get_findings_v2.call_args[1]
    assert call_kwargs["MaxResults"] == 10
    assert call_kwargs["SortCriteria"] == [{"Field": "time", "SortOrder": "desc"}]
    assert call_kwargs["Filters"]["CompositeFilters"][0]["StringFilters"][0]["FieldName"] == "severity"
    findings_output = result.outputs["AWS.SecurityHub.Findings(val.metadata.uid && val.metadata.uid == obj.metadata.uid)"]
    assert findings_output[0]["metadata"]["uid"] == "f-1"
    assert result.outputs["AWS.SecurityHub(true)"] == {"FindingsNextToken": "tok-123"}


def test_findings_get_command_no_results(mocker):
    """
    Given: A mocked securityhub client returning no findings.
    When: findings_get_command is called.
    Then: It returns a 'No findings found.' readable output.
    """
    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {"Findings": []}

    result = findings_get_command(mock_client, {})

    assert result.readable_output == "No findings found."


def test_findings_get_command_error(mocker):
    """
    Given: A mocked securityhub client whose get_findings_v2 raises an exception.
    When: findings_get_command is called.
    Then: The exception propagates to be handled in main().
    """
    mock_client = mocker.Mock()
    mock_client.get_findings_v2.side_effect = Exception("AccessDenied")

    with pytest.raises(Exception, match="AccessDenied"):
        findings_get_command(mock_client, {})


def test_parse_finding_identifiers():
    """
    Given: A finding_identifiers argument with one complete triple.
    When: parse_finding_identifiers is called.
    Then: It returns the FindingIdentifiers API structure.
    """
    result = parse_finding_identifiers("cloud_account_uid=123456789012,finding_info_uid=f-1,metadata_product_uid=p-1")
    assert result == [{"CloudAccountUid": "123456789012", "FindingInfoUid": "f-1", "MetadataProductUid": "p-1"}]


def test_parse_finding_identifiers_incomplete():
    """
    Given: A finding_identifiers entry missing a required key.
    When: parse_finding_identifiers is called.
    Then: The incomplete entry is dropped.
    """
    result = parse_finding_identifiers("cloud_account_uid=123,finding_info_uid=f-1")
    assert result == []


def test_findings_batch_update_command_success(mocker):
    """
    Given: A mocked securityhub client and metadata_uids with update fields.
    When: findings_batch_update_command is called.
    Then: It passes MetadataUids/Comment/SeverityId/StatusId and returns processed/unprocessed.
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {
        "ProcessedFindings": [{"metadata": {"uid": "u-1"}}],
        "UnprocessedFindings": [],
    }
    args = {"metadata_uids": "u-1,u-2", "comment": "triage", "severity_id": "4", "status_id": "2"}

    result = findings_batch_update_command(mock_client, args)

    call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
    assert call_kwargs["MetadataUids"] == ["u-1", "u-2"]
    assert call_kwargs["Comment"] == "triage"
    assert call_kwargs["SeverityId"] == 4
    assert call_kwargs["StatusId"] == 2
    assert result.outputs_prefix == "AWS.SecurityHub.BatchUpdateFindings"
    assert result.outputs["ProcessedFindings"][0]["metadata"]["uid"] == "u-1"


def test_findings_batch_update_command_with_identifiers(mocker):
    """
    Given: A mocked securityhub client and finding_identifiers targeting.
    When: findings_batch_update_command is called.
    Then: It passes the FindingIdentifiers structure to the API.
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {"ProcessedFindings": [], "UnprocessedFindings": []}
    args = {
        "finding_identifiers": "cloud_account_uid=123,finding_info_uid=f-1,metadata_product_uid=p-1",
        "status_id": "4",
    }

    findings_batch_update_command(mock_client, args)

    call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
    assert call_kwargs["FindingIdentifiers"] == [{"CloudAccountUid": "123", "FindingInfoUid": "f-1", "MetadataProductUid": "p-1"}]


def test_findings_batch_update_command_no_target():
    """
    Given: Args with neither metadata_uids nor finding_identifiers.
    When: findings_batch_update_command is called.
    Then: It raises a DemistoException requiring a targeting argument.
    """
    with pytest.raises(DemistoException, match="metadata_uids.*finding_identifiers"):
        findings_batch_update_command(None, {"comment": "x"})


def test_findings_batch_update_command_error(mocker):
    """
    Given: A mocked securityhub client whose batch_update_findings_v2 raises an exception.
    When: findings_batch_update_command is called.
    Then: The exception propagates to be handled in main().
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.side_effect = Exception("AccessDenied")

    with pytest.raises(Exception, match="AccessDenied"):
        findings_batch_update_command(mock_client, {"metadata_uids": "u-1"})


def test_parse_date_filters_absolute():
    """
    Given: A date_filters entry with both start and end.
    When: parse_date_filters is called.
    Then: It builds the absolute {Start, End} Filter.
    """
    result = parse_date_filters("fieldname=finding_info.created_time_dt,start=2024-01-01T00:00:00Z,end=2024-02-01T00:00:00Z")
    assert result == [
        {
            "FieldName": "finding_info.created_time_dt",
            "Filter": {"Start": "2024-01-01T00:00:00Z", "End": "2024-02-01T00:00:00Z"},
        }
    ]


def test_parse_date_filters_relative_days_alias():
    """
    Given: A date_filters entry using the "days" shorthand.
    When: parse_date_filters is called.
    Then: It builds the relative {DateRange: {Value, Unit}} Filter with Unit defaulting to DAYS.
    """
    result = parse_date_filters("fieldname=finding_info.modified_time_dt,days=7")
    assert result == [{"FieldName": "finding_info.modified_time_dt", "Filter": {"DateRange": {"Value": 7, "Unit": "DAYS"}}}]


def test_parse_date_filters_relative_value_unit():
    """
    Given: A date_filters entry using the explicit DateRange value/unit keys.
    When: parse_date_filters is called.
    Then: It builds the relative {DateRange: {Value, Unit}} Filter.
    """
    result = parse_date_filters("fieldname=finding_info.modified_time_dt,value=14,unit=DAYS")
    assert result == [{"FieldName": "finding_info.modified_time_dt", "Filter": {"DateRange": {"Value": 14, "Unit": "DAYS"}}}]


def test_parse_date_filters_relative_with_comparison():
    """
    Given: A date_filters entry providing a DateRange comparison.
    When: parse_date_filters is called.
    Then: The Comparison is included in the DateRange object.
    """
    result = parse_date_filters("fieldname=finding_info.modified_time_dt,value=7,unit=DAYS,comparison=GREATER_THAN")
    assert result == [
        {
            "FieldName": "finding_info.modified_time_dt",
            "Filter": {"DateRange": {"Value": 7, "Unit": "DAYS", "Comparison": "GREATER_THAN"}},
        }
    ]


def test_parse_date_filters_only_start_raises():
    """
    Given: A date_filters entry with start but no end.
    When: parse_date_filters is called.
    Then: It raises a DemistoException (oneOf requires both start and end, or a DateRange).
    """
    with pytest.raises(DemistoException, match="requires either the relative 'DateRange' form"):
        parse_date_filters("fieldname=finding_info.created_time_dt,start=2024-01-01T00:00:00Z")


def test_parse_date_filters_range_with_start_raises():
    """
    Given: A date_filters entry mixing the relative and absolute forms.
    When: parse_date_filters is called.
    Then: It raises a DemistoException (cannot mix the two forms).
    """
    with pytest.raises(DemistoException, match="not both"):
        parse_date_filters("fieldname=finding_info.created_time_dt,days=7,start=2024-01-01T00:00:00Z")


def test_parse_date_filters_skips_entry_without_fieldname():
    """
    Given: A date_filters string whose entry has no fieldname.
    When: parse_date_filters is called.
    Then: The entry is skipped and an empty list is returned (no exception raised).
    """
    assert parse_date_filters("days=7") == []


def test_build_fetch_filters_time_only():
    """
    Given: A fetch start time with no severity or additional filters.
    When: build_fetch_filters is called.
    Then: It builds a composite with only an open-ended created_time_dt DateFilter (Start, no End) and
          AND operators.
    """
    result = build_fetch_filters("2024-01-01T00:00:00.000Z", None, None)
    composite = result["CompositeFilters"][0]
    assert result["CompositeOperator"] == "AND"
    assert composite["Operator"] == "AND"
    assert composite["DateFilters"] == [
        {
            "FieldName": "finding_info.created_time_dt",
            "Filter": {"Start": "2024-01-01T00:00:00.000Z"},
        }
    ]
    assert "End" not in composite["DateFilters"][0]["Filter"]
    assert "NumberFilters" not in composite
    assert "StringFilters" not in composite


def test_build_fetch_filters_with_severity_and_additional():
    """
    Given: A fetch start time with a minimum severity and additional string filters.
    When: build_fetch_filters is called.
    Then: It adds a severity_id Gte NumberFilter and the parsed StringFilters.
    """
    result = build_fetch_filters(
        "2024-01-01T00:00:00.000Z",
        "High",
        "fieldname=cloud.region,value=us-east-1",
    )
    composite = result["CompositeFilters"][0]
    assert composite["NumberFilters"] == [{"FieldName": "severity_id", "Filter": {"Gte": 4}}]
    assert composite["StringFilters"] == [{"FieldName": "cloud.region", "Filter": {"Value": "us-east-1", "Comparison": "EQUALS"}}]


def test_fetch_incidents_first_run(mocker):
    """
    Given: A previous last_fetch window and a client returning two OCSF findings newer than it.
    When: fetch_incidents is called.
    Then: It builds incidents with mapped severity, sets last_fetch to the latest created time (no 1ms
          bump), records the boundary finding id in fetched_ids, and stores the returned next_token.
    """
    import AWS_SecurityHub_V2

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00.000Z"})
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {
        "Findings": [
            {
                "metadata": {"uid": "uid-1"},
                "severity_id": 4,
                "finding_info": {"title": "Finding One", "created_time_dt": "2024-01-01T10:00:00.000Z"},
            },
            {
                "metadata": {"uid": "uid-2"},
                "severity_id": 5,
                "finding_info": {"title": "Finding Two", "created_time_dt": "2024-01-01T12:00:00.000Z"},
            },
        ],
        "NextToken": "tok-next",
    }

    fetch_incidents(mock_client, {"max_fetch": 50, "min_severity": "High"})

    # Two incidents created with correct names and mapped severities.
    incidents = incidents_mock.call_args[0][0]
    assert len(incidents) == 2
    assert incidents[0]["name"] == "Finding One"
    assert incidents[0]["severity"] == AWS_SecurityHub_V2.IncidentSeverity.HIGH
    assert incidents[1]["severity"] == AWS_SecurityHub_V2.IncidentSeverity.CRITICAL
    assert incidents[1]["occurred"] == "2024-01-01T12:00:00.000Z"

    # last_fetch = latest created time (no bump); only the boundary id is stored; next_token persisted.
    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-01T12:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-2"]
    assert last_run["next_token"] == "tok-next"

    # A fresh query uses Filters (not a NextToken).
    call_kwargs = mock_client.get_findings_v2.call_args[1]
    assert "Filters" in call_kwargs
    assert call_kwargs["MaxResults"] == 50


def test_fetch_incidents_first_run_uses_open_ended_window(mocker):
    """
    Given: A previous last_fetch and a client returning a finding.
    When: fetch_incidents builds the fresh query.
    Then: The DateFilter has a Start (from last_fetch) and no End, so the query is stable across cycles.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00.000Z"})
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {
        "Findings": [
            {
                "metadata": {"uid": "uid-1"},
                "severity_id": 3,
                "finding_info": {"title": "Finding One", "created_time_dt": "2024-01-01T10:00:00.000Z"},
            }
        ],
        "NextToken": None,
    }

    fetch_incidents(mock_client, {"max_fetch": 50})

    date_filter = mock_client.get_findings_v2.call_args[1]["Filters"]["CompositeFilters"][0]["DateFilters"][0]["Filter"]
    assert date_filter["Start"] == "2024-01-01T00:00:00.000Z"
    assert "End" not in date_filter


def test_fetch_incidents_continues_with_next_token(mocker):
    """
    Given: A previous run that left a next_token.
    When: fetch_incidents is called.
    Then: It sends the NextToken (not Filters) and advances last_fetch from the token page findings. The
          window is open-ended, so no end_time state is needed to keep the token valid.
    """
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={"last_fetch": "2024-01-01T00:00:00.000Z", "next_token": "tok-prev"},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {
        "Findings": [
            {
                "metadata": {"uid": "uid-3"},
                "severity_id": 2,
                "finding_info": {"title": "Finding Three", "created_time_dt": "2024-01-05T10:00:00.000Z"},
            }
        ],
        "NextToken": None,
    }

    fetch_incidents(mock_client, {"max_fetch": 10})

    call_kwargs = mock_client.get_findings_v2.call_args[1]
    assert call_kwargs["NextToken"] == "tok-prev"
    assert "Filters" not in call_kwargs

    # The token page returns newer findings, so the boundary advances to that finding's created time.
    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-05T10:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-3"]
    assert last_run["next_token"] is None
    # The open-ended design no longer stores an end_time.
    assert "end_time" not in last_run


def test_fetch_incidents_skips_already_fetched_ids(mocker):
    """
    Given: A previous run whose fetched_ids contains a finding at the boundary timestamp, and the API
           returns that same finding again (inclusive Start) plus a new one.
    When: fetch_incidents is called.
    Then: The already-fetched finding is skipped and only the new finding becomes an incident.
    """
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={"last_fetch": "2024-01-01T10:00:00.000Z", "fetched_ids": ["uid-1"]},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {
        "Findings": [
            {
                "metadata": {"uid": "uid-1"},  # already fetched at the boundary - must be skipped
                "severity_id": 4,
                "finding_info": {"title": "Old Finding", "created_time_dt": "2024-01-01T10:00:00.000Z"},
            },
            {
                "metadata": {"uid": "uid-2"},  # new finding
                "severity_id": 3,
                "finding_info": {"title": "New Finding", "created_time_dt": "2024-01-02T09:00:00.000Z"},
            },
        ],
        "NextToken": None,
    }

    fetch_incidents(mock_client, {"max_fetch": 50})

    incidents = incidents_mock.call_args[0][0]
    assert len(incidents) == 1
    assert incidents[0]["name"] == "New Finding"

    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-02T09:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-2"]


def test_fetch_incidents_invalid_next_token_falls_back(mocker):
    """
    Given: A stored next_token that the API rejects with a token-related ClientError.
    When: fetch_incidents is called.
    Then: It falls back to a fresh filtered query and still produces incidents.
    """

    class ClientError(Exception):
        def __init__(self, response):
            super().__init__(response.get("Error", {}).get("Message", ""))
            self.response = response

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00.000Z", "next_token": "stale"})
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.exceptions.ClientError = ClientError
    token_error = ClientError({"Error": {"Code": "ValidationException", "Message": "The provided next token is invalid."}})
    fresh_response = {
        "Findings": [
            {
                "metadata": {"uid": "uid-9"},
                "severity_id": 3,
                "finding_info": {"title": "Recovered Finding", "created_time_dt": "2024-01-03T08:00:00.000Z"},
            }
        ],
        "NextToken": None,
    }
    # First call (with the stale token) raises; the fallback fresh query (with Filters) succeeds.
    mock_client.get_findings_v2.side_effect = [token_error, fresh_response]

    fetch_incidents(mock_client, {"max_fetch": 50})

    # Two calls: the failed token call, then the fresh filtered call.
    assert mock_client.get_findings_v2.call_count == 2
    assert "NextToken" in mock_client.get_findings_v2.call_args_list[0][1]
    assert "Filters" in mock_client.get_findings_v2.call_args_list[1][1]

    # The fresh query advances the boundary to the recovered finding's created time.
    incidents = incidents_mock.call_args[0][0]
    assert len(incidents) == 1
    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-03T08:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-9"]


def test_fetch_incidents_no_results(mocker):
    """
    Given: A client returning no findings.
    When: fetch_incidents is called.
    Then: No incidents are created and last_fetch and fetched_ids are preserved.
    """
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={"last_fetch": "2024-01-01T00:00:00.000Z", "fetched_ids": ["uid-x"]},
    )
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {"Findings": []}

    fetch_incidents(mock_client, {"max_fetch": 50})

    assert incidents_mock.call_args[0][0] == []
    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-01T00:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-x"]
    assert last_run["next_token"] is None
