import pytest
from AWS_SecurityHub_V2 import (
    disable_security_hub_command,
    enable_security_hub_command,
    findings_get_command,
    generate_filters_for_get_findings,
    parse_number_filters,
    parse_string_filters,
    parse_tags,
)


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


def test_parse_string_filters():
    """
    Given: A string_filters argument with two entries and a custom comparison.
    When: parse_string_filters is called.
    Then: It returns the StringFilters API structure with EQUALS as the default comparison.
    """
    result = parse_string_filters("fieldname=severity,value=High;fieldname=finding_info.title,value=root,comparison=CONTAINS")
    assert result == [
        {"FieldName": "severity", "Filter": {"Value": "High", "Comparison": "EQUALS"}},
        {"FieldName": "finding_info.title", "Filter": {"Value": "root", "Comparison": "CONTAINS"}},
    ]


def test_parse_number_filters():
    """
    Given: A number_filters argument with an operator.
    When: parse_number_filters is called.
    Then: It maps the operator to the API key and converts the value to a number.
    """
    result = parse_number_filters("fieldname=severity_id,operator=gte,value=3")
    assert result == [{"FieldName": "severity_id", "Filter": {"Gte": 3}}]


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
        "date_filters": "fieldname=finding_info.created_time_dt,start=2024-01-01T00:00:00Z",
        "composite_operator": "OR",
    }
    result = generate_filters_for_get_findings(args)
    assert result["CompositeOperator"] == "OR"
    composite = result["CompositeFilters"][0]
    assert composite["Operator"] == "AND"
    assert composite["StringFilters"] == [{"FieldName": "severity", "Filter": {"Value": "High", "Comparison": "EQUALS"}}]
    assert composite["DateFilters"] == [{"FieldName": "finding_info.created_time_dt", "Filter": {"Start": "2024-01-01T00:00:00Z"}}]


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
