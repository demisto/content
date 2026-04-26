import demistomock as demisto  # noqa: F401
import json

import pytest
from pytest_mock import MockerFixture

from CortexCreateAppSecPolicy import (
    FilterBuilder,
    FilterType,
    POLICY_FINDING_TYPE_MAPPING,
    POLICY_CATEGORY_MAPPING,
    build_conditions,
    build_scope,
    build_triggers,
    main,
    _get_asset_group_ids_from_names,
    _get_appsec_rule_ids_from_names,
)


# ---------------------------------------------------------------------------
# FilterBuilder tests
# ---------------------------------------------------------------------------

def test_filter_builder_empty():
    """Given no fields added, to_dict returns empty dict."""
    fb = FilterBuilder()
    assert fb.to_dict() == {}


def test_filter_builder_single_field():
    """Given one field, to_dict returns a flat condition (no AND wrapper)."""
    fb = FilterBuilder()
    fb.add_field("Severity", FilterType.EQ, ["HIGH"])
    result = fb.to_dict()
    assert result == {"SEARCH_FIELD": "Severity", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": ["HIGH"]}


def test_filter_builder_multiple_fields():
    """Given multiple fields, to_dict wraps them in AND."""
    fb = FilterBuilder()
    fb.add_field("Severity", FilterType.EQ, ["HIGH"])
    fb.add_field("Has A Fix", FilterType.EQ, True)
    result = fb.to_dict()
    assert "AND" in result
    assert len(result["AND"]) == 2


def test_filter_builder_skips_none():
    """Given None value, the field is not added."""
    fb = FilterBuilder()
    fb.add_field("Severity", FilterType.EQ, None)
    assert fb.to_dict() == {}


def test_filter_builder_skips_empty_list():
    """Given empty list value, the field is not added."""
    fb = FilterBuilder()
    fb.add_field("Severity", FilterType.EQ, [])
    assert fb.to_dict() == {}


def test_filter_builder_skips_empty_string():
    """Given empty string value, the field is not added."""
    fb = FilterBuilder()
    fb.add_field("Severity", FilterType.EQ, "")
    assert fb.to_dict() == {}


# ---------------------------------------------------------------------------
# build_conditions tests
# ---------------------------------------------------------------------------

def test_build_conditions_default_finding_types():
    """Given no conditions_finding_type, all types except CI/CD Risk are included."""
    args: dict = {}
    result = build_conditions(args)
    assert "SEARCH_VALUE" in result or "AND" in result
    # Finding Type filter should be present
    if "AND" in result:
        finding_filter = next(f for f in result["AND"] if f.get("SEARCH_FIELD") == "Finding Type")
    else:
        finding_filter = result
    assert "CICD_RISKS" not in finding_filter["SEARCH_VALUE"]
    assert "VULNERABILITY" in finding_filter["SEARCH_VALUE"]


def test_build_conditions_human_readable_finding_type():
    """Given human-readable finding type, it is mapped to the API enum value."""
    args = {"conditions_finding_type": "Vulnerabilities"}
    result = build_conditions(args)
    if "AND" in result:
        finding_filter = next(f for f in result["AND"] if f.get("SEARCH_FIELD") == "Finding Type")
    else:
        finding_filter = result
    assert "VULNERABILITY" in finding_filter["SEARCH_VALUE"]


def test_build_conditions_raw_api_finding_type():
    """Given raw API finding type value, it is passed through unchanged."""
    args = {"conditions_finding_type": "VULNERABILITY"}
    result = build_conditions(args)
    if "AND" in result:
        finding_filter = next(f for f in result["AND"] if f.get("SEARCH_FIELD") == "Finding Type")
    else:
        finding_filter = result
    assert "VULNERABILITY" in finding_filter["SEARCH_VALUE"]


def test_build_conditions_severity():
    """Given conditions_severity, a Severity filter is added."""
    args = {"conditions_finding_type": "Vulnerabilities", "conditions_severity": "HIGH,CRITICAL"}
    result = build_conditions(args)
    assert "AND" in result
    severity_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "Severity"), None)
    assert severity_filter is not None
    assert "HIGH" in severity_filter["SEARCH_VALUE"]
    assert "CRITICAL" in severity_filter["SEARCH_VALUE"]


def test_build_conditions_has_a_fix():
    """Given conditions_has_a_fix=true, a 'Has A Fix' filter is added."""
    args = {"conditions_finding_type": "Vulnerabilities", "conditions_has_a_fix": "true"}
    result = build_conditions(args)
    assert "AND" in result
    fix_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "Has A Fix"), None)
    assert fix_filter is not None
    assert fix_filter["SEARCH_VALUE"] is True


def test_build_conditions_is_kev():
    """Given conditions_is_kev=true, an 'Is Kev' filter is added."""
    args = {"conditions_finding_type": "Vulnerabilities", "conditions_is_kev": "true"}
    result = build_conditions(args)
    assert "AND" in result
    kev_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "Is Kev"), None)
    assert kev_filter is not None


def test_build_conditions_secret_validity():
    """Given conditions_secret_validity, a 'Secret Validity' filter is added."""
    args = {"conditions_finding_type": "Secrets", "conditions_secret_validity": "VALID"}
    result = build_conditions(args)
    assert "AND" in result
    sv_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "Secret Validity"), None)
    assert sv_filter is not None


def test_build_conditions_license_type():
    """Given conditions_license_type, a 'License Type' filter is added."""
    args = {"conditions_finding_type": "Licenses", "conditions_license_type": "GPL"}
    result = build_conditions(args)
    assert "AND" in result
    lt_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "License Type"), None)
    assert lt_filter is not None


def test_build_conditions_cvss_score():
    """Given conditions_cvss, a 'CVSS Score' GTE filter is added."""
    args = {"conditions_finding_type": "Vulnerabilities", "conditions_cvss": "7.5"}
    result = build_conditions(args)
    assert "AND" in result
    cvss_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "CVSS Score"), None)
    assert cvss_filter is not None
    assert cvss_filter["SEARCH_TYPE"] == "GTE"


def test_build_conditions_cvss_severity():
    """Given conditions_cvss_severity, a 'CVSS Severity' filter is added."""
    args = {"conditions_finding_type": "Vulnerabilities", "conditions_cvss_severity": "Critical,High"}
    result = build_conditions(args)
    assert "AND" in result
    cs_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "CVSS Severity"), None)
    assert cs_filter is not None


def test_build_conditions_risk_factors():
    """Given conditions_risk_factors, a 'Risk Factors' filter is added."""
    args = {"conditions_finding_type": "Vulnerabilities", "conditions_risk_factors": "internet_exposure"}
    result = build_conditions(args)
    assert "AND" in result
    rf_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "Risk Factors"), None)
    assert rf_filter is not None


def test_build_conditions_appsec_rule_category():
    """Given conditions_appsec_rule_category, an 'AppSec Rule Category' filter is added."""
    args = {"conditions_finding_type": "Secrets", "conditions_appsec_rule_category": "Credentials"}
    result = build_conditions(args)
    assert "AND" in result
    arc_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "AppSec Rule Category"), None)
    assert arc_filter is not None


def test_build_conditions_license_category():
    """Given conditions_license_category, a 'License Category' filter is added."""
    args = {"conditions_finding_type": "Licenses", "conditions_license_category": "Strong copyleft"}
    result = build_conditions(args)
    assert "AND" in result
    lc_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "License Category"), None)
    assert lc_filter is not None


def test_build_conditions_appsec_rules(mocker: MockerFixture):
    """Given conditions_appsec_rule_names, rule IDs are resolved and added."""
    mocker.patch(
        "CortexCreateAppSecPolicy._get_appsec_rule_ids_from_names",
        return_value=["rule-id-1"],
    )
    args = {"conditions_finding_type": "Secrets", "conditions_appsec_rule_names": "My Rule"}
    result = build_conditions(args)
    assert "AND" in result
    rule_filter = next((f for f in result["AND"] if f.get("SEARCH_FIELD") == "AppSec Rule"), None)
    assert rule_filter is not None
    assert "rule-id-1" in rule_filter["SEARCH_VALUE"]


# ---------------------------------------------------------------------------
# build_scope tests
# ---------------------------------------------------------------------------

def test_build_scope_empty():
    """Given no scope args, an empty dict is returned."""
    assert build_scope({}) == {}


def test_build_scope_category():
    """Given scope_category, a 'category' filter is added with mapped value."""
    args = {"scope_category": "Application"}
    result = build_scope(args)
    assert result.get("SEARCH_FIELD") == "category" or any(
        f.get("SEARCH_FIELD") == "category" for f in result.get("AND", [])
    )


def test_build_scope_business_application_names():
    """Given scope_business_application_names, an ARRAY_CONTAINS filter is added."""
    args = {"scope_business_application_names": "App1,App2"}
    result = build_scope(args)
    if "AND" in result:
        ba_filter = next(f for f in result["AND"] if f.get("SEARCH_FIELD") == "business_application_names")
    else:
        ba_filter = result
    assert ba_filter["SEARCH_TYPE"] == "ARRAY_CONTAINS"


def test_build_scope_repository_name():
    """Given scope_repository_name, a CONTAINS filter is added."""
    args = {"scope_repository_name": "my-repo"}
    result = build_scope(args)
    if "AND" in result:
        repo_filter = next(f for f in result["AND"] if f.get("SEARCH_FIELD") == "repository_name")
    else:
        repo_filter = result
    assert repo_filter["SEARCH_TYPE"] == "CONTAINS"


def test_build_scope_boolean_filters():
    """Given boolean scope filters set to true, they are added."""
    args = {
        "scope_is_public_repository": "true",
        "scope_has_deployed_assets": "true",
    }
    result = build_scope(args)
    assert "AND" in result
    fields = {f["SEARCH_FIELD"] for f in result["AND"]}
    assert "is_public_repository" in fields
    assert "has_deployed_assets" in fields


def test_build_scope_boolean_false_not_added():
    """Given boolean scope filter set to false, it is not added."""
    args = {"scope_is_public_repository": "false"}
    result = build_scope(args)
    assert result == {}


# ---------------------------------------------------------------------------
# build_triggers tests
# ---------------------------------------------------------------------------

def test_build_triggers_periodic_enabled():
    """Given triggers_periodic_report_issue=true, periodic trigger is enabled."""
    args = {"triggers_periodic_report_issue": "true"}
    result = build_triggers(args)
    assert result["periodic"]["isEnabled"] is True
    assert result["periodic"]["actions"]["reportIssue"] is True
    # New required triggers default to disabled
    assert result["ciImage"]["isEnabled"] is False
    assert result["imageRegistry"]["isEnabled"] is False


def test_build_triggers_pr_block():
    """Given triggers_pr_block_pr=true, PR trigger is enabled with blockPr."""
    args = {"triggers_periodic_report_issue": "true", "triggers_pr_block_pr": "true"}
    result = build_triggers(args)
    assert result["pr"]["isEnabled"] is True
    assert result["pr"]["actions"]["blockPr"] is True


def test_build_triggers_cicd():
    """Given CI/CD trigger args, cicd trigger is configured correctly."""
    args = {
        "triggers_periodic_report_issue": "true",
        "triggers_cicd_block_cicd": "true",
        "triggers_cicd_report_cicd": "false",
    }
    result = build_triggers(args)
    assert result["cicd"]["isEnabled"] is True
    assert result["cicd"]["actions"]["blockCicd"] is True
    assert result["cicd"]["actions"]["reportCicd"] is False


def test_build_triggers_ci_image():
    """Given CI image trigger args, ciImage trigger is configured correctly."""
    args = {
        "triggers_periodic_report_issue": "true",
        "triggers_ci_image_block_cicd": "true",
    }
    result = build_triggers(args)
    assert result["ciImage"]["isEnabled"] is True
    assert result["ciImage"]["actions"]["blockCicd"] is True


def test_build_triggers_image_registry():
    """Given image registry trigger args, imageRegistry trigger is configured correctly."""
    args = {
        "triggers_periodic_report_issue": "true",
        "triggers_image_registry_report_issue": "true",
    }
    result = build_triggers(args)
    assert result["imageRegistry"]["isEnabled"] is True
    assert result["imageRegistry"]["actions"]["reportIssue"] is True


def test_build_triggers_override_severity_enables_report_issue():
    """Given override severity, reportIssue is automatically enabled."""
    args = {"triggers_periodic_override_severity": "Critical"}
    result = build_triggers(args)
    assert result["periodic"]["isEnabled"] is True
    assert result["periodic"]["actions"]["reportIssue"] is True
    assert result["periodic"]["overrideIssueSeverity"] == "Critical"


def test_build_triggers_no_triggers_raises():
    """Given no triggers enabled, DemistoException is raised."""
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException, match="At least one trigger"):
        build_triggers({})


def test_build_triggers_all_five_present():
    """All five trigger types are always present in the output."""
    args = {"triggers_periodic_report_issue": "true"}
    result = build_triggers(args)
    assert set(result.keys()) == {"periodic", "pr", "cicd", "ciImage", "imageRegistry"}


def test_build_triggers_override_severity_none_when_not_set():
    """overrideIssueSeverity is None when not provided."""
    args = {"triggers_periodic_report_issue": "true"}
    result = build_triggers(args)
    assert result["periodic"]["overrideIssueSeverity"] is None
    assert result["pr"]["overrideIssueSeverity"] is None
    assert result["cicd"]["overrideIssueSeverity"] is None
    assert result["ciImage"]["overrideIssueSeverity"] is None
    assert result["imageRegistry"]["overrideIssueSeverity"] is None


# ---------------------------------------------------------------------------
# _get_asset_group_ids_from_names tests
# ---------------------------------------------------------------------------

def test_get_asset_group_ids_empty():
    """Given empty group_names, returns empty list without API call."""
    assert _get_asset_group_ids_from_names([]) == []


def test_get_asset_group_ids_success(mocker: MockerFixture):
    """Given valid group names, returns their IDs."""
    mocker.patch(
        "CortexCreateAppSecPolicy._api_call",
        return_value={"reply": {"data": [{"XDM.ASSET_GROUP.NAME": "Group1", "XDM.ASSET_GROUP.ID": "id-1"}]}},
    )
    result = _get_asset_group_ids_from_names(["Group1"])
    assert result == ["id-1"]


def test_get_asset_group_ids_missing_raises(mocker: MockerFixture):
    """Given a group name not found in API response, DemistoException is raised."""
    from CommonServerPython import DemistoException
    mocker.patch(
        "CortexCreateAppSecPolicy._api_call",
        return_value={"reply": {"data": []}},
    )
    with pytest.raises(DemistoException, match="Failed to fetch asset group IDs"):
        _get_asset_group_ids_from_names(["NonExistent"])


# ---------------------------------------------------------------------------
# _get_appsec_rule_ids_from_names tests
# ---------------------------------------------------------------------------

def test_get_appsec_rule_ids_empty():
    """Given empty rule_names, returns empty list without API call."""
    assert _get_appsec_rule_ids_from_names([]) == []


def test_get_appsec_rule_ids_success(mocker: MockerFixture):
    """Given valid rule names, returns their IDs."""
    mocker.patch(
        "CortexCreateAppSecPolicy._api_call",
        return_value={"reply": {"DATA": [{"ruleName": "My Rule", "ruleId": "rule-123"}]}},
    )
    result = _get_appsec_rule_ids_from_names(["My Rule"])
    assert result == ["rule-123"]


def test_get_appsec_rule_ids_missing_raises(mocker: MockerFixture):
    """Given a rule name not found, DemistoException is raised."""
    from CommonServerPython import DemistoException
    mocker.patch(
        "CortexCreateAppSecPolicy._api_call",
        return_value={"reply": {"DATA": []}},
    )
    with pytest.raises(DemistoException, match="Missing AppSec rules"):
        _get_appsec_rule_ids_from_names(["Unknown Rule"])


# ---------------------------------------------------------------------------
# main() tests
# ---------------------------------------------------------------------------

def test_main_success(mocker: MockerFixture):
    """Given valid args, policy is created and success message is returned."""
    mocker.patch.object(demisto, "args", return_value={
        "policy_name": "Test Policy",
        "triggers_periodic_report_issue": "true",
    })
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexCreateAppSecPolicy._get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexCreateAppSecPolicy._api_call", return_value={})
    mock_return = mocker.patch("CortexCreateAppSecPolicy.return_results")

    main()

    result = mock_return.call_args[0][0]
    assert "Test Policy" in result.readable_output
    assert "created successfully" in result.readable_output


def test_main_missing_policy_name(mocker: MockerFixture):
    """Given no policy_name, return_error is called."""
    mocker.patch.object(demisto, "args", return_value={"triggers_periodic_report_issue": "true"})
    mocker.patch.object(demisto, "debug")
    mock_error = mocker.patch("CortexCreateAppSecPolicy.return_error")

    main()

    mock_error.assert_called_once()
    assert "Policy name is required" in mock_error.call_args[0][0]


def test_main_no_triggers_enabled(mocker: MockerFixture):
    """Given no triggers enabled, return_error is called."""
    mocker.patch.object(demisto, "args", return_value={"policy_name": "Test Policy"})
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexCreateAppSecPolicy._get_asset_group_ids_from_names", return_value=[])
    mock_error = mocker.patch("CortexCreateAppSecPolicy.return_error")

    main()

    mock_error.assert_called_once()
    assert "At least one trigger" in mock_error.call_args[0][0]


def test_main_with_suggestion_id(mocker: MockerFixture):
    """Given suggestion_id, it is included in the API payload."""
    mocker.patch.object(demisto, "args", return_value={
        "policy_name": "AI Policy",
        "triggers_periodic_report_issue": "true",
        "suggestion_id": "sugg-abc-123",
    })
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexCreateAppSecPolicy._get_asset_group_ids_from_names", return_value=[])
    mock_api = mocker.patch("CortexCreateAppSecPolicy._api_call", return_value={})
    mocker.patch("CortexCreateAppSecPolicy.return_results")

    main()

    call_kwargs = mock_api.call_args
    payload = call_kwargs[1]["data"] if call_kwargs[1] else call_kwargs[0][2]
    assert payload.get("suggestionId") == "sugg-abc-123"


def test_main_api_error(mocker: MockerFixture):
    """Given API call raises exception, return_error is called."""
    mocker.patch.object(demisto, "args", return_value={
        "policy_name": "Test Policy",
        "triggers_periodic_report_issue": "true",
    })
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexCreateAppSecPolicy._get_asset_group_ids_from_names", return_value=[])
    mocker.patch("CortexCreateAppSecPolicy._api_call", side_effect=Exception("API failure"))
    mock_error = mocker.patch("CortexCreateAppSecPolicy.return_error")

    main()

    mock_error.assert_called_once()
    assert "API failure" in mock_error.call_args[0][0]


def test_main_payload_structure(mocker: MockerFixture):
    """Given valid args, the API payload has the correct top-level structure."""
    mocker.patch.object(demisto, "args", return_value={
        "policy_name": "Structure Test",
        "description": "Test description",
        "triggers_pr_block_pr": "true",
    })
    mocker.patch.object(demisto, "debug")
    mocker.patch("CortexCreateAppSecPolicy._get_asset_group_ids_from_names", return_value=["grp-1"])
    mock_api = mocker.patch("CortexCreateAppSecPolicy._api_call", return_value={})
    mocker.patch("CortexCreateAppSecPolicy.return_results")

    main()

    call_kwargs = mock_api.call_args
    payload = call_kwargs[1]["data"] if call_kwargs[1] else call_kwargs[0][2]

    assert payload["name"] == "Structure Test"
    assert payload["description"] == "Test description"
    assert payload["assetGroupIds"] == ["grp-1"]
    assert "conditions" in payload
    assert "scope" in payload
    assert "triggers" in payload
    assert set(payload["triggers"].keys()) == {"periodic", "pr", "cicd", "ciImage", "imageRegistry"}
