import demistomock as demisto
import pytest
from AWS_SecurityHub_V2 import (
    build_close_reopen_entries,
    build_fetch_filters,
    disable_security_hub_command,
    enable_security_hub_command,
    fetch_incidents,
    filter_new_findings,
    test_module,
    findings_batch_update_command,
    findings_get_command,
    findings_to_incidents,
    generate_filters_for_get_findings,
    get_mapping_fields_command,
    get_remote_data_command,
    parse_date_filters,
    parse_filter_entries,
    parse_filters,
    parse_finding_identifiers,
    parse_tags,
    update_remote_system_command,
)
from CommonServerPython import DemistoException, IncidentStatus


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
    assert result.outputs_prefix == "AWS.SecurityHubV2.Hub"
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
        "field_name=severity,value=High;field_name=finding_info.title,value=root,comparison=CONTAINS_WORD", "string"
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
    result = parse_filters("field_name=severity_id,gte=3", "number")
    assert result == [{"FieldName": "severity_id", "Filter": {"Gte": 3}}]


def test_parse_filters_number_multiple_operators():
    """
    Given: A single number_filters entry that specifies multiple operators (gte and lt).
    When: parse_filters is called for the "number" category.
    Then: All operators are mapped to their API keys within one Filter, with numeric values.
    """
    result = parse_filters("field_name=severity_id,gte=2,lt=5", "number")
    assert result == [{"FieldName": "severity_id", "Filter": {"Gte": 2, "Lt": 5}}]


def test_parse_filters_boolean():
    """
    Given: A boolean_filters argument.
    When: parse_filters is called for the "boolean" category.
    Then: It returns the BooleanFilters API structure with the value coerced to a bool.
    """
    result = parse_filters("field_name=compliance.assessments.meets_criteria,value=false", "boolean")
    assert result == [{"FieldName": "compliance.assessments.meets_criteria", "Filter": {"Value": False}}]


def test_parse_filters_map():
    """
    Given: A map_filters argument with key/value and no explicit comparison.
    When: parse_filters is called for the "map" category.
    Then: It returns the MapFilters API structure with EQUALS as the default comparison.
    """
    result = parse_filters("field_name=resources.tags,key=env,value=prod", "map")
    assert result == [{"FieldName": "resources.tags", "Filter": {"Key": "env", "Value": "prod", "Comparison": "EQUALS"}}]


def test_parse_filters_ip():
    """
    Given: An ip_filters argument.
    When: parse_filters is called for the "ip" category.
    Then: It returns the IpFilters API structure.
    """
    result = parse_filters("field_name=evidences.src_endpoint.ip,cidr=10.0.0.1", "ip")
    assert result == [{"FieldName": "evidences.src_endpoint.ip", "Filter": {"Cidr": "10.0.0.1"}}]


@pytest.mark.parametrize(
    "filters_str, category, missing_field",
    [
        ("value=High", "string", "field_name"),  # missing field_name
        ("field_name=severity", "string", "value"),  # missing required value
        ("field_name=severity_id", "number", "one of"),  # number entry without any operator
    ],
)
def test_parse_filters_raises_on_missing_fields(filters_str, category, missing_field):
    """
    Given: A filter entry missing field_name, a required key, or all require_any keys.
    When: parse_filters is called.
    Then: A DemistoException is raised naming the missing field(s).
    """
    with pytest.raises(DemistoException, match=missing_field):
        parse_filters(filters_str, category)


def test_parse_filter_entries_multiple():
    """
    Given: A ";"-separated string of two entries, one with an extra comparison key.
    When: parse_filter_entries is called.
    Then: Each entry is parsed into a lower-cased key/value dict.
    """
    result = parse_filter_entries("field_name=severity,value=High;field_name=status,value=New,comparison=NOT_EQUALS")
    assert result == [
        {"field_name": "severity", "value": "High"},
        {"field_name": "status", "value": "New", "comparison": "NOT_EQUALS"},
    ]


def test_parse_filter_entries_empty_and_malformed():
    """
    Given: An empty string, blank entries, and pairs without '='.
    When: parse_filter_entries is called.
    Then: Empty/blank entries yield nothing and pairs without '=' are ignored.
    """
    assert parse_filter_entries("") == []
    assert parse_filter_entries("  ;  ") == []
    # "noequals" has no '=' and is dropped; the valid pair is still parsed.
    assert parse_filter_entries("field_name=severity,noequals") == [{"field_name": "severity"}]


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
        "string_filters": "field_name=severity,value=High",
        "number_filters": "field_name=severity_id,gte=4",
        "date_filters": "field_name=finding_info.created_time_dt,start=2024-01-01T00:00:00Z,end=2024-02-01T00:00:00Z",
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
        "Findings": [
            {
                "metadata": {"uid": "f-1"},
                "severity": "High",
                "status": "New",
                "class_name": "Compliance Finding",
                "resources": [{"uid": "res-1"}, {"uid": "res-2"}, {"name": "no-uid"}],
            }
        ],
        "NextToken": "tok-123",
    }
    args = {"string_filters": "field_name=severity,value=High", "sort_field": "time", "sort_order": "desc", "limit": "1"}

    result = findings_get_command(mock_client, args)

    call_kwargs = mock_client.get_findings_v2.call_args[1]
    assert call_kwargs["MaxResults"] == 10
    assert call_kwargs["SortCriteria"] == [{"Field": "time", "SortOrder": "desc"}]
    assert call_kwargs["Filters"]["CompositeFilters"][0]["StringFilters"][0]["FieldName"] == "severity"
    findings_output = result.outputs["AWS.SecurityHubV2.Findings(val.metadata.uid && val.metadata.uid == obj.metadata.uid)"]
    assert findings_output[0]["metadata"]["uid"] == "f-1"
    assert result.outputs["AWS.SecurityHubV2(true)"] == {"FindingsNextToken": "tok-123"}
    # Readable table surfaces uid/severity/status/class_name and joins only resource entries that have a uid.
    assert "res-1, res-2" in result.readable_output
    assert "f-1" in result.readable_output


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
    Then: A DemistoException is raised naming the missing field.
    """
    with pytest.raises(DemistoException, match="metadata_product_uid"):
        parse_finding_identifiers("cloud_account_uid=123,finding_info_uid=f-1")


def _finding(uid, created_time, severity_id=3, title=None):
    return {
        "metadata": {"uid": uid},
        "finding_info": {"created_time_dt": created_time, "title": title},
        "severity_id": severity_id,
    }


def test_filter_new_findings_drops_stale_and_seen():
    """
    Given: Findings created before the boundary (stale), exactly at it (one already seen), and after it.
    When: filter_new_findings is called with the boundary and the already-seen uid.
    Then: Only the not-yet-ingested findings (the unseen boundary one and the newer one) are returned.
    """
    last_fetch = "2024-01-02T00:00:00Z"
    findings = [
        _finding("stale", "2024-01-01T00:00:00Z"),  # before boundary -> dropped
        _finding("seen", last_fetch),  # at boundary, already seen -> dropped
        _finding("boundary-new", last_fetch),  # at boundary, not seen -> kept
        _finding("newer", "2024-01-03T00:00:00Z"),  # after boundary -> kept
    ]

    result = filter_new_findings(findings, last_fetch, fetched_ids=["seen"])

    assert [f["metadata"]["uid"] for f in result] == ["boundary-new", "newer"]


def test_filter_new_findings_no_boundary_keeps_all():
    """
    Given: An empty last_fetch (first run) and two findings.
    When: filter_new_findings is called.
    Then: All findings are kept (no boundary to dedup against).
    """
    findings = [_finding("a", "2024-01-01T00:00:00Z"), _finding("b", "2024-01-02T00:00:00Z")]

    result = filter_new_findings(findings, last_fetch="", fetched_ids=[])

    assert [f["metadata"]["uid"] for f in result] == ["a", "b"]


def test_findings_to_incidents_builds_and_tags(mocker):
    """
    Given: A finding and a mirror direction.
    When: findings_to_incidents is called.
    Then: An incident is built with the mapped XSOAR severity, and the finding is stamped for mirroring.
    """
    from AWS_SecurityHub_V2 import IncidentSeverity

    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    findings = [_finding("uid-1", "2024-01-01T00:00:00Z", severity_id=3, title="My Finding")]

    incidents = findings_to_incidents(findings, mirror_direction="Both")

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["name"] == "My Finding"
    assert incident["occurred"] == "2024-01-01T00:00:00Z"
    assert incident["severity"] == IncidentSeverity.MEDIUM  # OCSF severity_id 3 -> XSOAR Medium
    # The finding was stamped with mirroring metadata that the rawJSON carries to the mapper.
    assert findings[0]["mirror_direction"] == "Both"
    assert findings[0]["mirror_instance"] == "instance-1"


def test_findings_to_incidents_no_mirror_leaves_finding_untagged():
    """
    Given: A finding and no mirror direction.
    When: findings_to_incidents is called.
    Then: An incident is built but no mirroring metadata is stamped, and the name falls back to the uid.
    """
    findings = [_finding("uid-1", "2024-01-01T00:00:00Z", title=None)]

    incidents = findings_to_incidents(findings, mirror_direction=None)

    assert incidents[0]["name"] == "uid-1"  # no title -> falls back to uid
    assert "mirror_direction" not in findings[0]
    assert "mirror_instance" not in findings[0]


def test_findings_batch_update_command_success(mocker):
    """
    Given: A mocked securityhub client and metadata_uids with update fields.
    When: findings_batch_update_command is called.
    Then: It passes MetadataUids/Comment/SeverityId/StatusId and returns processed/unprocessed.
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {
        "ProcessedFindings": [{"MetadataUid": "u-1", "metadata": {"uid": "u-1"}}],
        "UnprocessedFindings": [{"MetadataUid": "u-9", "ErrorCode": "AccessDenied"}],
    }
    args = {"metadata_uids": "u-1,u-2", "comment": "triage", "severity_id": "4", "status_id": "2"}

    result = findings_batch_update_command(mock_client, args)

    call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
    assert call_kwargs["MetadataUids"] == ["u-1", "u-2"]
    assert call_kwargs["Comment"] == "triage"
    assert call_kwargs["SeverityId"] == 4
    assert call_kwargs["StatusId"] == 2
    assert result.outputs_prefix == "AWS.SecurityHubV2.BatchUpdateFindings"
    assert result.outputs["ProcessedFindings"][0]["metadata"]["uid"] == "u-1"
    # Readable output lists the processed and unprocessed metadata UIDs (not just counts).
    assert "u-1" in result.readable_output
    assert "u-9" in result.readable_output


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


@pytest.mark.parametrize(
    "filters_str,expected_filter",
    [
        # Absolute form: both start and end.
        (
            "field_name=finding_info.created_time_dt,start=2024-01-01T00:00:00Z,end=2024-02-01T00:00:00Z",
            {"Start": "2024-01-01T00:00:00Z", "End": "2024-02-01T00:00:00Z"},
        ),
        # Relative "days" shorthand -> DateRange with Unit defaulting to DAYS.
        ("field_name=finding_info.created_time_dt,days=7", {"DateRange": {"Value": 7, "Unit": "DAYS"}}),
        # Relative explicit value/unit.
        ("field_name=finding_info.created_time_dt,value=14,unit=DAYS", {"DateRange": {"Value": 14, "Unit": "DAYS"}}),
        # Relative with an explicit comparison.
        (
            "field_name=finding_info.created_time_dt,value=7,unit=DAYS,comparison=GREATER_THAN",
            {"DateRange": {"Value": 7, "Unit": "DAYS", "Comparison": "GREATER_THAN"}},
        ),
    ],
)
def test_parse_date_filters_builds_absolute_and_relative(filters_str, expected_filter):
    """
    Given: A date_filters entry in the absolute ({Start,End}) or relative (DateRange) form.
    When: parse_date_filters is called.
    Then: It builds the matching {FieldName, Filter} structure.
    """
    assert parse_date_filters(filters_str) == [{"FieldName": "finding_info.created_time_dt", "Filter": expected_filter}]


@pytest.mark.parametrize(
    "filters_str,match",
    [
        # start without end is invalid (oneOf requires both, or a DateRange).
        ("field_name=finding_info.created_time_dt,start=2024-01-01T00:00:00Z", "requires either the relative 'DateRange' form"),
        # mixing the relative and absolute forms is invalid.
        ("field_name=finding_info.created_time_dt,days=7,start=2024-01-01T00:00:00Z", "not both"),
    ],
)
def test_parse_date_filters_invalid_combinations_raise(filters_str, match):
    """
    Given: A date_filters entry that is incomplete or mixes the two mutually exclusive forms.
    When: parse_date_filters is called.
    Then: It raises a DemistoException explaining the valid forms.
    """
    with pytest.raises(DemistoException, match=match):
        parse_date_filters(filters_str)


def test_parse_date_filters_skips_entry_without_field_name():
    """
    Given: A date_filters string whose entry has no field_name.
    When: parse_date_filters is called.
    Then: The entry is skipped and an empty list is returned (no exception raised).
    """
    assert parse_date_filters("days=7") == []


def test_build_fetch_filters_time_only():
    """
    Given: A bounded fetch window (start and end) with no severity or additional filters.
    When: build_fetch_filters is called.
    Then: It builds a composite with only a bounded created_time_dt DateFilter (Start and End) and
          AND operators.
    """
    result = build_fetch_filters("2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z", None, None)
    composite = result["CompositeFilters"][0]
    assert result["CompositeOperator"] == "AND"
    assert composite["Operator"] == "AND"
    assert composite["DateFilters"] == [
        {
            "FieldName": "finding_info.created_time_dt",
            "Filter": {"Start": "2024-01-01T00:00:00.000Z", "End": "2024-01-02T00:00:00.000Z"},
        }
    ]
    assert "NumberFilters" not in composite
    assert "StringFilters" not in composite


def test_build_fetch_filters_with_severity_and_additional():
    """
    Given: A fetch window with a minimum severity and additional string filters.
    When: build_fetch_filters is called.
    Then: It adds a severity_id Gte NumberFilter and the parsed StringFilters.
    """
    result = build_fetch_filters(
        "2024-01-01T00:00:00.000Z",
        "2024-01-02T00:00:00.000Z",
        "High",
        "field_name=cloud.region,value=us-east-1",
    )
    composite = result["CompositeFilters"][0]
    assert composite["NumberFilters"] == [{"FieldName": "severity_id", "Filter": {"Gte": 4}}]
    assert composite["StringFilters"] == [{"FieldName": "cloud.region", "Filter": {"Value": "us-east-1", "Comparison": "EQUALS"}}]


def test_fetch_incidents_with_existing_last_fetch(mocker):
    """
    Given: A previous last_fetch window and a client returning two OCSF findings newer than it.
    When: fetch_incidents is called.
    Then: It builds incidents with mapped severity, sets last_fetch to the latest created time (no 1ms
          bump), records the boundary finding id in fetched_ids, and stores the returned next_token.
    """
    from AWS_SecurityHub_V2 import IncidentSeverity

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
    assert incidents[0]["severity"] == IncidentSeverity.HIGH
    assert incidents[1]["severity"] == IncidentSeverity.CRITICAL
    assert incidents[1]["occurred"] == "2024-01-01T12:00:00.000Z"

    # last_fetch = latest created time (no bump); only the boundary id is stored; next_token persisted.
    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-01T12:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-2"]
    assert last_run["next_token"] == "tok-next"

    # A fresh query uses Filters (not a NextToken), with a bounded [Start, End] window from last_fetch.
    call_kwargs = mock_client.get_findings_v2.call_args[1]
    assert call_kwargs["MaxResults"] == 50
    assert "NextToken" not in call_kwargs
    composite = call_kwargs["Filters"]["CompositeFilters"][0]
    date_filter = composite["DateFilters"][0]["Filter"]
    assert date_filter["Start"] == "2024-01-01T00:00:00.000Z"
    assert "End" in date_filter
    # min_severity=High is translated to an OCSF severity_id >= 4 NumberFilter in the query.
    assert composite["NumberFilters"] == [{"FieldName": "severity_id", "Filter": {"Gte": 4}}]


def test_fetch_incidents_continues_with_next_token(mocker):
    """
    Given: A previous run that left a next_token and the persisted filters used for that page.
    When: fetch_incidents is called.
    Then: It sends the NextToken together with the persisted Filters and advances last_fetch from the
          token page findings.
    """
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={
            "last_fetch": "2024-01-01T00:00:00.000Z",
            "next_token": "tok-prev",
            "filters": {"CompositeOperator": "AND", "CompositeFilters": []},
        },
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
    # The persisted filters are re-sent alongside the token to keep the page valid.
    assert call_kwargs["Filters"] == {"CompositeOperator": "AND", "CompositeFilters": []}

    # The token page returns newer findings, so the boundary advances to that finding's created time.
    last_run = set_last_run.call_args[0][0]
    assert last_run["last_fetch"] == "2024-01-05T10:00:00.000Z"
    assert last_run["fetched_ids"] == ["uid-3"]
    assert last_run["next_token"] is None


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


def test_fetch_incidents_invalid_next_token_raises(mocker):
    """
    Given: A stored next_token that the API rejects with a token-related ClientError.
    When: fetch_incidents is called.
    Then: It surfaces the error as a DemistoException (a single API call is made, no silent fallback).
    """

    class ClientError(Exception):
        def __init__(self, response):
            super().__init__(response.get("Error", {}).get("Message", ""))
            self.response = response

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00.000Z", "next_token": "stale"})
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")

    mock_client = mocker.Mock()
    mock_client.exceptions.ClientError = ClientError
    token_error = ClientError({"Error": {"Code": "ValidationException", "Message": "The provided next token is invalid."}})
    mock_client.get_findings_v2.side_effect = token_error

    with pytest.raises(DemistoException, match="The provided next token is invalid."):
        fetch_incidents(mock_client, {"max_fetch": 50})

    # Only the token call is made; there is no silent fallback query.
    assert mock_client.get_findings_v2.call_count == 1
    assert "NextToken" in mock_client.get_findings_v2.call_args_list[0][1]


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


@pytest.mark.parametrize(
    "mirror_direction,expected_dbot_direction",
    [
        ("Incoming", "In"),  # enrolled: rawJSON carries mirror metadata
        ("None", None),  # disabled: rawJSON carries no mirror metadata
    ],
)
def test_fetch_incidents_mirror_tagging(mocker, mirror_direction, expected_dbot_direction):
    """
    Given: A client returning one finding and a mirror_direction param (Incoming or None).
    When: fetch_incidents is called.
    Then: The incident rawJSON carries the mirror metadata only when mirroring is enabled.
    """
    import json

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00.000Z"})
    mocker.patch.object(demisto, "integrationInstance", return_value="instance-1")
    mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")

    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {
        "Findings": [
            {
                "metadata": {"uid": "uid-1"},
                "severity_id": 4,
                "finding_info": {"title": "t", "created_time_dt": "2024-01-02T00:00:00.000Z"},
            }
        ]
    }

    fetch_incidents(mock_client, {"max_fetch": 50, "mirror_direction": mirror_direction})

    raw = json.loads(incidents_mock.call_args[0][0][0]["rawJSON"])
    if expected_dbot_direction:
        assert raw["mirror_direction"] == expected_dbot_direction
        assert raw["mirror_instance"] == "instance-1"
    else:
        assert "mirror_direction" not in raw
        assert "mirror_instance" not in raw


def test_get_remote_data_command_returns_finding(mocker):
    """
    Given: A client returning a single finding for the requested uid.
    When: get_remote_data_command is called.
    Then: It fetches by metadata.uid and returns the finding as the mirrored object, enriched with a
          ready-to-use xsoar_severity, and (since status_id=4 Resolved) a close entry.
    """
    from AWS_SecurityHub_V2 import IncidentSeverity

    mock_client = mocker.Mock()
    finding = {"metadata": {"uid": "uid-1"}, "status_id": 4, "severity_id": 3}
    mock_client.get_findings_v2.return_value = {"Findings": [finding]}

    result = get_remote_data_command(mock_client, {"id": "uid-1", "lastUpdate": "2024-01-01T00:00:00Z"})

    # severity_id 3 (OCSF Medium) -> XSOAR Medium, injected as xsoar_severity for the mapper.
    assert result.mirrored_object["xsoar_severity"] == IncidentSeverity.MEDIUM
    assert result.mirrored_object["metadata"]["uid"] == "uid-1"
    # status_id 4 (Resolved) is wired to a close entry for full lifecycle sync.
    assert result.entries[0]["Contents"]["dbotIncidentClose"] is True
    string_filter = mock_client.get_findings_v2.call_args[1]["Filters"]["CompositeFilters"][0]["StringFilters"][0]
    assert string_filter["FieldName"] == "metadata.uid"
    assert string_filter["Filter"]["Value"] == "uid-1"


def test_get_remote_data_command_no_finding(mocker):
    """
    Given: A client returning no finding for the requested uid.
    When: get_remote_data_command is called.
    Then: It returns an empty mirrored object.
    """
    mock_client = mocker.Mock()
    mock_client.get_findings_v2.return_value = {"Findings": []}

    result = get_remote_data_command(mock_client, {"id": "missing", "lastUpdate": "2024-01-01T00:00:00Z"})

    assert result.mirrored_object == {}


def _update_remote_args(delta, remote_id="uid-1", incident_changed=True, status=IncidentStatus.ACTIVE):
    """Build an args dict compatible with UpdateRemoteSystemArgs for outgoing mirroring tests."""
    return {
        "remoteId": remote_id,
        "data": {},
        "entries": [],
        "incidentChanged": incident_changed,
        "delta": delta,
        "status": status,
    }


def test_update_remote_system_mirrors_severity_and_status(mocker):
    """
    Given: An incident whose severityid and statusid changed (delta), with mirroring enabled.
    When: update_remote_system_command is called.
    Then: batch_update_findings_v2 is called targeting the finding uid with SeverityId and StatusId.
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {"ProcessedFindings": [{}], "UnprocessedFindings": []}

    args = _update_remote_args({"severityid": "4", "statusid": "2"})
    result = update_remote_system_command(mock_client, args, resolve_finding=False)

    assert result == "uid-1"
    call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
    assert call_kwargs["MetadataUids"] == ["uid-1"]
    assert call_kwargs["SeverityId"] == 4
    assert call_kwargs["StatusId"] == 2


def test_update_remote_system_mirrors_comment(mocker):
    """
    Given: An incident whose comment changed.
    When: update_remote_system_command is called.
    Then: batch_update_findings_v2 is called with the Comment.
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {"ProcessedFindings": [{}], "UnprocessedFindings": []}

    args = _update_remote_args({"comment": "investigated"})
    update_remote_system_command(mock_client, args, resolve_finding=False)

    call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
    assert call_kwargs["Comment"] == "investigated"


def test_update_remote_system_no_changes_skips_call(mocker):
    """
    Given: An incident with no mirrorable delta.
    When: update_remote_system_command is called.
    Then: batch_update_findings_v2 is NOT called, and the uid is returned.
    """
    mock_client = mocker.Mock()

    args = _update_remote_args({}, incident_changed=False)
    result = update_remote_system_command(mock_client, args, resolve_finding=False)

    assert result == "uid-1"
    mock_client.batch_update_findings_v2.assert_not_called()


def test_update_remote_system_resolves_on_close(mocker):
    """
    Given: A closed incident (status DONE) and resolve_finding enabled.
    When: update_remote_system_command is called.
    Then: batch_update_findings_v2 forces StatusId=4 (Resolved).
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {"ProcessedFindings": [{}], "UnprocessedFindings": []}

    args = _update_remote_args({"comment": "closing"}, status=IncidentStatus.DONE)
    update_remote_system_command(mock_client, args, resolve_finding=True)

    call_kwargs = mock_client.batch_update_findings_v2.call_args[1]
    assert call_kwargs["StatusId"] == 4


@pytest.mark.parametrize(
    "delta,expected_severity_id,expect_call",
    [
        ({"severity": 2}, 3, True),  # built-in XSOAR Medium -> OCSF Medium (3)
        ({"severityid": "5", "severity": 2}, 5, True),  # explicit severityid wins over built-in severity
        ({"severity": 0}, None, False),  # Unknown has no OCSF equivalent -> nothing mirrored
    ],
)
def test_update_remote_system_builtin_severity(mocker, delta, expected_severity_id, expect_call):
    """
    Given: An incident delta carrying the built-in "severity" field (alone, with severityid, or Unknown).
    When: update_remote_system_command is called.
    Then: The built-in severity is translated to OCSF SeverityId, an explicit severityid takes precedence,
          and an unmappable (Unknown) severity mirrors nothing.
    """
    mock_client = mocker.Mock()
    mock_client.batch_update_findings_v2.return_value = {"ProcessedFindings": [{}], "UnprocessedFindings": []}

    update_remote_system_command(mock_client, _update_remote_args(delta), resolve_finding=False)

    if expect_call:
        assert mock_client.batch_update_findings_v2.call_args[1]["SeverityId"] == expected_severity_id
    else:
        mock_client.batch_update_findings_v2.assert_not_called()


def test_get_mapping_fields_command():
    """
    Given: The outgoing mapping schema request.
    When: get_mapping_fields_command is called.
    Then: It returns a scheme for the finding type with every field the outgoing mirror consumes
          (including the built-in "severity" field).
    """
    result = get_mapping_fields_command()

    entry = result.extract_mapping()
    assert "AWS Security Hub v2 Finding" in entry
    finding_fields = entry["AWS Security Hub v2 Finding"]
    assert {"severityid", "statusid", "comment", "severity"} <= set(finding_fields)


@pytest.mark.parametrize(
    "status_id,expected_reason",
    [(4, "Resolved"), (3, "Other")],
)
def test_build_close_reopen_entries_closes_on_resolved_or_suppressed(status_id, expected_reason):
    """
    Given: A finding whose OCSF status_id is Resolved (4) or Suppressed (3).
    When: build_close_reopen_entries is called.
    Then: A single dbotIncidentClose entry with the mapped close reason is returned.
    """
    entries = build_close_reopen_entries({"status_id": status_id, "status": "Resolved"})

    assert len(entries) == 1
    contents = entries[0]["Contents"]
    assert contents["dbotIncidentClose"] is True
    assert contents["closeReason"] == expected_reason


@pytest.mark.parametrize("status_id", [1, 2])
def test_build_close_reopen_entries_reopens_on_open_status(status_id):
    """
    Given: A finding whose OCSF status_id is New (1) or In Progress (2).
    When: build_close_reopen_entries is called.
    Then: A single dbotIncidentReopen entry is returned.
    """
    entries = build_close_reopen_entries({"status_id": status_id})

    assert len(entries) == 1
    assert entries[0]["Contents"] == {"dbotIncidentReopen": True}


@pytest.mark.parametrize("finding", [{}, {"status_id": 0}, {"status_id": 99}])
def test_build_close_reopen_entries_no_action_for_other_status(finding):
    """
    Given: A finding with a missing or non-actionable OCSF status_id.
    When: build_close_reopen_entries is called.
    Then: No entries are returned (the incident is left untouched).
    """
    assert build_close_reopen_entries(finding) == []


def _mock_client_with_exceptions(mocker):
    """Return a mock securityhub client whose ``exceptions.*`` are real Exception subclasses."""
    mock_client = mocker.Mock()
    mock_client.exceptions.ResourceNotFoundException = type("ResourceNotFoundException", (Exception,), {})
    mock_client.exceptions.AccessDeniedException = type("AccessDeniedException", (Exception,), {})
    return mock_client


def test_test_module_success(mocker):
    """
    Given: A client whose describe_security_hub_v2 call succeeds.
    When: test_module is called.
    Then: It returns 'ok'.
    """
    mock_client = _mock_client_with_exceptions(mocker)
    mock_client.describe_security_hub_v2.return_value = {}

    assert test_module(mock_client) == "ok"


def test_test_module_not_enabled_raises(mocker):
    """
    Given: A client whose describe_security_hub_v2 raises ResourceNotFoundException.
    When: test_module is called.
    Then: A DemistoException about Security Hub V2 not being enabled is raised.
    """
    mock_client = _mock_client_with_exceptions(mocker)
    mock_client.describe_security_hub_v2.side_effect = mock_client.exceptions.ResourceNotFoundException()

    with pytest.raises(DemistoException, match="not enabled"):
        test_module(mock_client)


def test_test_module_access_denied_raises(mocker):
    """
    Given: A client whose describe_security_hub_v2 raises AccessDeniedException.
    When: test_module is called.
    Then: A DemistoException about access being denied is raised.
    """
    mock_client = _mock_client_with_exceptions(mocker)
    mock_client.describe_security_hub_v2.side_effect = mock_client.exceptions.AccessDeniedException()

    with pytest.raises(DemistoException, match="Access denied"):
        test_module(mock_client)
