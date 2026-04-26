import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


POLICY_FINDING_TYPE_MAPPING: dict[str, str] = {
    "CI/CD Risk": "CICD_RISKS",
    "Vulnerabilities": "VULNERABILITY",
    "IaC Misconfiguration": "IAC_MISCONFIGURATION",
    "Licenses": "LICENSES",
    "Operational Risk": "OPERATIONAL_RISK",
    "Secrets": "SECRETS",
    "Weaknesses": "CODE_WEAKNESS",
    "Drift": "DRIFT",
    "Malware": "MALWARE",
}

POLICY_CATEGORY_MAPPING: dict[str, str] = {
    "Application": "APPLICATION",
    "Repository": "REPOSITORY",
    "CI/CD Instance": "CICD_INSTANCE",
    "CI/CD Pipeline": "CICD_PIPELINE",
    "VCS Collaborator": "VCS_COLLABORATOR",
    "VCS Organization": "VCS_ORGANIZATION",
}

APPSEC_RULES_TABLE = "CAS_DETECTION_RULES"


# ---------------------------------------------------------------------------
# Minimal filter builder
# ---------------------------------------------------------------------------

class FilterBuilder:
    """AND-based filter builder matching the integration's FilterBuilder (CoreIRApiModule) output.

    Each value in a list becomes a separate filter entry with a scalar SEARCH_VALUE.
    Multiple values for the same field are wrapped in an OR block.
    All field blocks are combined under AND.
    """

    AND = "AND"
    OR = "OR"
    FIELD = "SEARCH_FIELD"
    TYPE = "SEARCH_TYPE"
    VALUE = "SEARCH_VALUE"

    def __init__(self) -> None:
        self._fields: list[tuple[str, str, Any]] = []  # (field, op, values)

    def add_field(self, field: str, op: str, value: Any) -> None:
        if value is None or value == [] or value == "":
            return
        self._fields.append((field, op, value))

    def to_dict(self) -> dict:
        and_blocks: list[dict] = []

        for field, op, value in self._fields:
            values_list = value if isinstance(value, list) else [value]
            values_list = [v for v in values_list if v is not None]
            if not values_list:
                continue

            entries = [
                {self.FIELD: field, self.TYPE: op, self.VALUE: v}
                for v in values_list
            ]
            block = {self.OR: entries} if len(entries) > 1 else entries[0]
            and_blocks.append(block)

        if not and_blocks:
            return {}
        # Always wrap in AND, even for single blocks
        return {self.AND: and_blocks}


class FilterType:
    EQ = "EQ"
    GTE = "GTE"
    CONTAINS = "CONTAINS"
    ARRAY_CONTAINS = "ARRAY_CONTAINS"


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _api_call(method: str, path: str, data: dict | None = None) -> dict:
    res = demisto._apiCall(
        method=method,
        path=path,
        data=json.dumps(data) if data else None,
        headers={"content-type": "application/json"},
    )
    
    raw = res.get("data")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw or {}


def _get_asset_group_ids_from_names(group_names: list[str]) -> list[str]:
    if not group_names:
        return []

    fb = FilterBuilder()
    fb.add_field("XDM.ASSET_GROUP.NAME", FilterType.EQ, group_names)

    reply = _api_call(
        method="POST",
        path="/api/webapp/public_api/v1/asset-groups",
        data={"request_data": {"filters": fb.to_dict()}},
    )
    groups = reply.get("reply", {}).get("data", [])

    group_ids = [g.get("XDM.ASSET_GROUP.ID") for g in groups if g.get("XDM.ASSET_GROUP.ID")]

    if len(group_ids) != len(group_names):
        found = [g.get("XDM.ASSET_GROUP.NAME") for g in groups if g.get("XDM.ASSET_GROUP.ID")]
        missing = [n for n in group_names if n not in found]
        raise DemistoException(f"Failed to fetch asset group IDs for {missing}. Ensure the asset group names are valid.")

    return group_ids


def _get_appsec_rule_ids_from_names(rule_names: list[str]) -> list[str]:
    if not rule_names:
        return []

    fb = FilterBuilder()
    fb.add_field("ruleName", FilterType.EQ, rule_names)

    data = _api_call(
        method="POST",
        path="/api/webapp/get_data",
        data={
            "request_data": {
                "table_id": APPSEC_RULES_TABLE,
                "filters": fb.to_dict(),
                "search_from": 0,
                "search_to": 200,
                "sort": {"field": "ruleName", "keyword": "asc"},
            }
        },
    )
    records = data.get("reply", {}).get("DATA", []) or []

    lookup = {r["ruleName"].lower(): r["ruleId"] for r in records if r.get("ruleId")}
    ids: list[str] = []
    found: set[str] = set()

    for name in rule_names:
        n = name.lower()
        rid = lookup.get(n) or next((v for k, v in lookup.items() if n in k), None)
        if rid:
            ids.append(rid)
            found.add(name)

    missing = set(rule_names) - found
    if missing:
        raise DemistoException(f"Missing AppSec rules: {', '.join(missing)}")

    return ids


# ---------------------------------------------------------------------------
# Build conditions
# ---------------------------------------------------------------------------

def build_conditions(args: dict) -> dict:
    builder = FilterBuilder()

    # 1. Finding Type
    finding_types = argToList(args.get("conditions_finding_type"))
    if not finding_types:
        finding_types = [ft for ft in POLICY_FINDING_TYPE_MAPPING if ft != "CI/CD Risk"]

    api_values = set(POLICY_FINDING_TYPE_MAPPING.values())
    resolved_finding_types = []
    for ft in finding_types:
        if ft in api_values:
            resolved_finding_types.append(ft)
        elif ft in POLICY_FINDING_TYPE_MAPPING:
            resolved_finding_types.append(POLICY_FINDING_TYPE_MAPPING[ft])

    builder.add_field("Finding Type", FilterType.EQ, resolved_finding_types)

    # 2. Severity
    if severities := argToList(args.get("conditions_severity")):
        builder.add_field("Severity", FilterType.EQ, severities)

    # 3. Has A Fix
    if has_a_fix := arg_to_bool_or_none(args.get("conditions_has_a_fix")):
        builder.add_field("Has A Fix", FilterType.EQ, has_a_fix)

    # 4. Backlog Status
    if backlog := args.get("conditions_backlog_status"):
        builder.add_field("Backlog Status", FilterType.EQ, backlog)

    # 5. Is Kev
    if is_kev := arg_to_bool_or_none(args.get("conditions_is_kev")):
        builder.add_field("Is Kev", FilterType.EQ, is_kev)

    # 6. EPSS / CVSS
    for f, n in [("epss", "EPSS"), ("cvss", "CVSS Score")]:
        if val := arg_to_number(args.get(f"conditions_{f}")):
            builder.add_field(n, FilterType.GTE, val)

    # 7. Package Operational Risk
    if package_risk := args.get("conditions_package_operational_risk"):
        builder.add_field("Package Operational Risk", FilterType.EQ, package_risk)

    # Additional fields (order less critical)
    if dev_supp := arg_to_bool_or_none(args.get("conditions_respect_developer_suppression")):
        builder.add_field("Respect Developer Suppression", FilterType.EQ, dev_supp)

    if package_name := args.get("conditions_package_name"):
        builder.add_field("PackageName", FilterType.EQ, package_name)

    if package_version := args.get("conditions_package_version"):
        builder.add_field("PackageVersion", FilterType.EQ, package_version)

    if rule_names := argToList(args.get("conditions_appsec_rule_names")):
        rule_ids = _get_appsec_rule_ids_from_names(rule_names)
        builder.add_field("AppSec Rule", FilterType.EQ, rule_ids)

    if rule_categories := argToList(args.get("conditions_appsec_rule_category", [])):
        builder.add_field("AppSec Rule Category", FilterType.EQ, rule_categories)

    if cvss_severity := argToList(args.get("conditions_cvss_severity", [])):
        builder.add_field("CVSS Severity", FilterType.EQ, cvss_severity)

    if risk_factors := argToList(args.get("conditions_risk_factors", [])):
        builder.add_field("Risk Factors", FilterType.EQ, risk_factors)

    for key, label in {
        "secret_validity": "Secret Validity",
        "license_type": "License Type",
    }.items():
        if vals := argToList(args.get(f"conditions_{key}", [])):
            builder.add_field(label, FilterType.EQ, vals)

    if license_categories := argToList(args.get("conditions_license_category", [])):
        builder.add_field("License Category", FilterType.EQ, license_categories)

    return builder.to_dict()


# ---------------------------------------------------------------------------
# Build scope
# ---------------------------------------------------------------------------

def build_scope(args: dict) -> dict:
    builder = FilterBuilder()

    if categories := argToList(args.get("scope_category", [])):
        resolved = [POLICY_CATEGORY_MAPPING.get(c.title(), POLICY_CATEGORY_MAPPING.get(c, c)) for c in categories]
        builder.add_field("category", FilterType.EQ, resolved)

    if business_app_names := argToList(args.get("scope_business_application_names")):
        builder.add_field("business_application_names", FilterType.ARRAY_CONTAINS, business_app_names)

    if app_criticality := argToList(args.get("scope_application_business_criticality")):
        builder.add_field("application_business_criticality", FilterType.EQ, app_criticality)

    if repo_name := args.get("scope_repository_name"):
        builder.add_field("repository_name", FilterType.CONTAINS, repo_name)

    for key, label in {
        "scope_is_public_repository": "is_public_repository",
        "scope_has_deployed_assets": "has_deployed_assets",
        "scope_has_internet_exposed_deployed_assets": "has_internet_exposed",
        "scope_has_sensitive_data_access": "has_sensitive_data_access",
        "scope_has_privileged_capabilities": "has_leverage_privileged_capabilities",
    }.items():
        if val := arg_to_bool_or_none(args.get(key)):
            builder.add_field(label, FilterType.EQ, val)

    return builder.to_dict()


# ---------------------------------------------------------------------------
# Build triggers
# ---------------------------------------------------------------------------

def build_triggers(args: dict) -> dict:
    # Periodic
    periodic_report_issue = argToBoolean(args.get("triggers_periodic_report_issue", False))
    periodic_override = args.get("triggers_periodic_override_severity")
    if periodic_override:
        periodic_report_issue = True
    periodic_enabled = periodic_report_issue or bool(periodic_override)

    # PR
    pr_report_issue = argToBoolean(args.get("triggers_pr_report_issue", False))
    pr_block_pr = argToBoolean(args.get("triggers_pr_block_pr", False))
    pr_report_comment = argToBoolean(args.get("triggers_pr_report_pr_comment", False))
    pr_override = args.get("triggers_pr_override_severity")
    if pr_override:
        pr_report_issue = True
    pr_enabled = pr_report_issue or pr_block_pr or pr_report_comment or bool(pr_override)

    # CI/CD
    cicd_report_issue = argToBoolean(args.get("triggers_cicd_report_issue", False))
    cicd_block_cicd = argToBoolean(args.get("triggers_cicd_block_cicd", False))
    cicd_report_cicd = argToBoolean(args.get("triggers_cicd_report_cicd", False))
    cicd_override = args.get("triggers_cicd_override_severity")
    if cicd_override:
        cicd_report_issue = True
    cicd_enabled = cicd_report_issue or cicd_block_cicd or cicd_report_cicd or bool(cicd_override)

    # CI Image
    ci_image_report_issue = argToBoolean(args.get("triggers_ci_image_report_issue", False))
    ci_image_block_cicd = argToBoolean(args.get("triggers_ci_image_block_cicd", False))
    ci_image_report_cicd = argToBoolean(args.get("triggers_ci_image_report_cicd", False))
    ci_image_override = args.get("triggers_ci_image_override_severity")
    if ci_image_override:
        ci_image_report_issue = True
    ci_image_enabled = ci_image_report_issue or ci_image_block_cicd or ci_image_report_cicd or bool(ci_image_override)

    # Image Registry
    image_registry_report_issue = argToBoolean(args.get("triggers_image_registry_report_issue", False))
    image_registry_override = args.get("triggers_image_registry_override_severity")
    if image_registry_override:
        image_registry_report_issue = True
    image_registry_enabled = image_registry_report_issue or bool(image_registry_override)

    triggers = {
        "periodic": {
            "isEnabled": periodic_enabled,
            "overrideIssueSeverity": periodic_override if periodic_override else None,
            "actions": {"reportIssue": periodic_report_issue},
        },
        "pr": {
            "isEnabled": pr_enabled,
            "overrideIssueSeverity": pr_override if pr_override else None,
            "actions": {
                "reportIssue": pr_report_issue,
                "blockPr": pr_block_pr,
                "reportPrComment": pr_report_comment,
            },
        },
        "cicd": {
            "isEnabled": cicd_enabled,
            "overrideIssueSeverity": cicd_override if cicd_override else None,
            "actions": {
                "reportIssue": cicd_report_issue,
                "blockCicd": cicd_block_cicd,
                "reportCicd": cicd_report_cicd,
            },
        },
        "ciImage": {
            "isEnabled": ci_image_enabled,
            "overrideIssueSeverity": ci_image_override if ci_image_override else None,
            "actions": {
                "blockCicd": ci_image_block_cicd,
                "reportCicd": ci_image_report_cicd,
                "reportIssue": ci_image_report_issue,
            },
        },
        "imageRegistry": {
            "isEnabled": image_registry_enabled,
            "overrideIssueSeverity": image_registry_override if image_registry_override else None,
            "actions": {"reportIssue": image_registry_report_issue},
        },
    }

    if not any(t["isEnabled"] for t in triggers.values()):
        raise DemistoException("At least one trigger (periodic, PR, CI/CD, CI image, or image registry) must be set.")

    return triggers


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        args = demisto.args()

        policy_name = args.get("policy_name")
        if not policy_name:
            raise DemistoException("Policy name is required.")

        description = args.get("description", "")
        group_names = argToList(args.get("asset_group_names"))
        asset_group_ids = _get_asset_group_ids_from_names(group_names)

        conditions = build_conditions(args)
        scope = build_scope(args)
        triggers = build_triggers(args)

        payload: dict = {
            "name": policy_name,
            "description": description,
            "conditions": conditions,
            "scope": scope,
            "assetGroupIds": asset_group_ids,
            "triggers": triggers,
        }

        if suggestion_id := args.get("suggestion_id"):
            payload["suggestionId"] = suggestion_id

        demisto.debug(f"CortexCreateAppSecPolicy payload: {payload}")

        _api_call(method="POST", path="/api/webapp/public_api/appsec/v1/policies", data=payload)

        return_results(CommandResults(readable_output=f"AppSec policy '{policy_name}' created successfully."))

    except Exception as ex:
        return_error(f"Failed to execute CortexCreateAppSecPolicy. Error:\n{ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
