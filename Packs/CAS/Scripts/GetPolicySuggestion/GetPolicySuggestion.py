import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

VALID_ARGS: set[str] = {
    "business_application_name",
    "application_business_criticality",
    "is_public_repository",
    "has_internet_exposed",
    "has_deployed_assets",
    "has_access_sensitive_data",
    "has_leverage_privileged_capabilities",
    "repository_name",
    "limit",
}

SCOPE_FIELD_MAPPING: dict[str, str] = {
    "business_application_name": "business_application_names",
    "application_business_criticality": "application_business_criticality",
    "is_public_repository": "is_public_repository",
    "has_internet_exposed": "has_internet_exposed",
    "has_deployed_assets": "has_deployed_assets",
    "has_access_sensitive_data": "has_access_sensitive_data",
    "has_leverage_privileged_capabilities": "has_leverage_privileged_capabilities",
    "repository_name": "repository_name",
}


# Fields where the SEARCH_VALUE must match the user-provided value.
# business_application_names uses ARRAY_CONTAINS with a single app name string.
# repository_name uses CONTAINS — the scope value may be a prefix (e.g., "my-org/"), so we use substring matching.
# application_business_criticality uses EQ with uppercase enum (CRITICAL, HIGH, MEDIUM, LOW).
# Boolean fields (has_deployed_assets, is_public_repository, etc.) always have value=true, so only field presence matters.
VALUE_MATCH_FIELDS: set[str] = {"business_application_names", "repository_name", "application_business_criticality"}

# Fields that use substring (CONTAINS) matching instead of exact equality.
CONTAINS_MATCH_FIELDS: set[str] = {"repository_name"}

# Boolean scope fields — only added as filters when the user passes "true".
# The API scope always stores these with value=true, so filtering by "false" is meaningless.
BOOLEAN_SCOPE_FIELDS: set[str] = {
    "is_public_repository",
    "has_internet_exposed",
    "has_deployed_assets",
    "has_access_sensitive_data",
    "has_leverage_privileged_capabilities",
}


def collect_scope_entries(scope: dict) -> list[dict]:
    """
    Recursively collect all SEARCH_FIELD/SEARCH_VALUE pairs from a scope definition.

    Args:
        scope: The scope dictionary from a policy suggestion.

    Returns:
        A list of dicts with 'field' and 'value' keys.
    """
    entries: list[dict] = []

    for condition_type in ("AND", "OR"):
        for condition in scope.get(condition_type, []):
            if "SEARCH_FIELD" in condition:
                entries.append({
                    "field": condition["SEARCH_FIELD"],
                    "value": condition.get("SEARCH_VALUE"),
                })
            if "AND" in condition or "OR" in condition:
                entries.extend(collect_scope_entries(condition))

    return entries


def policy_matches_any_scope_filter(policy: dict, scope_filters: dict[str, str]) -> bool:
    """
    Check if a policy's scope matches ANY of the provided scope filters (OR logic).

    For value-match fields (business_application_names, repository_name, application_business_criticality),
    both the field name and value must match.
    For boolean fields (is_public_repository, has_deployed_assets, etc.), only field presence is checked.

    Args:
        policy: A single policy suggestion dictionary.
        scope_filters: A dictionary mapping scope field names to their expected values.

    Returns:
        True if the policy scope matches at least one of the specified filters.
    """
    policy_name = policy.get("name", "unknown")
    scope = policy.get("scope", {})
    if not scope:
        demisto.debug(f"Policy '{policy_name}': no scope — skipping")
        return False

    scope_entries = collect_scope_entries(scope)
    demisto.debug(f"Policy '{policy_name}' scope entries: {scope_entries}")

    for filter_field, filter_value in scope_filters.items():
        if filter_field in VALUE_MATCH_FIELDS:
            for entry in scope_entries:
                entry_value = entry.get("value")
                if entry_value is None or entry["field"] != filter_field:
                    continue
                if filter_field in CONTAINS_MATCH_FIELDS:
                    # CONTAINS semantics: either side can be a substring of the other
                    if filter_value.lower() in str(entry_value).lower() or str(entry_value).lower() in filter_value.lower():
                        demisto.debug(f"Policy '{policy_name}': contains match on '{filter_field}'='{entry_value}' (filter='{filter_value}')")
                        return True
                elif str(entry_value).lower() == filter_value.lower():
                    demisto.debug(f"Policy '{policy_name}': exact match on '{filter_field}'='{filter_value}'")
                    return True
        else:
            for entry in scope_entries:
                if entry["field"] == filter_field:
                    demisto.debug(f"Policy '{policy_name}': presence match on '{filter_field}'")
                    return True

    demisto.debug(f"Policy '{policy_name}': no filter matched")
    return False


def build_scope_filters(args: dict) -> dict[str, str]:
    """
    Build scope filter criteria from the provided arguments.

    Args:
        args: The script arguments.

    Returns:
        A dictionary mapping scope field names to their expected values.
    """
    scope_filters: dict[str, str] = {}

    for arg_name, scope_field in SCOPE_FIELD_MAPPING.items():
        value = args.get(arg_name)
        if not value:
            continue
        # Boolean scope fields only make sense when "true" — the API scope always stores value=true,
        # so filtering by "false" would never match any policy scope entry.
        if scope_field in BOOLEAN_SCOPE_FIELDS:
            if value.lower() != "true":
                demisto.debug(f"Skipping boolean filter '{arg_name}' with value '{value}' (only 'true' is meaningful)")
                continue
        scope_filters[scope_field] = value

    demisto.debug(f"Built scope filters: {scope_filters}")
    return scope_filters


def main():
    try:
        args = demisto.args()
        demisto.info(f"CASGetPolicySuggestion called with args: {json.dumps(args, indent=2)}")

        extra_args = set(args.keys()) - VALID_ARGS
        if extra_args:
            demisto.error(f"Unexpected args found: {extra_args}")
            raise ValueError(f"Unexpected args found: {extra_args}")

        limit = arg_to_number(args.get("limit")) or 3

        res = demisto.executeCommand(
            "core-generic-api-call",
            {
                "path": "/api/cas/v1/policies/guardrails/suggestions",
                "method": "GET",
            },
        )

        if is_error(res):
            return_error(res)

        else:
            context = res[0]["EntryContext"]
            data = context.get("data")

            if isinstance(data, str):
                data = json.loads(data)

            # Extract policies from response (API returns "policies" key)
            policies = data.get("policies", []) if isinstance(data, dict) else data

            last_updated = data.get("lastUpdated") if isinstance(data, dict) else None

            # Filter by scope criteria if provided (OR logic — match any filter)
            scope_filters = build_scope_filters(args)
            if scope_filters:
                demisto.info(f"Filtering {len(policies)} policies by scope filters: {scope_filters}")
                policies = [p for p in policies if policy_matches_any_scope_filter(p, scope_filters)]
                demisto.info(f"After scope filtering: {len(policies)} policies remain")

            # Limit results (default top 3 per PRD)
            policies = policies[:limit]

            # Build human-readable output
            if policies:
                headers = ["Name", "Type", "Description", "ID"]
                table_data = []
                for policy in policies:
                    table_data.append({
                        "Name": policy.get("name", "N/A"),
                        "Type": policy.get("type", "N/A"),
                        "Description": policy.get("description", "N/A"),
                        "ID": policy.get("id", "N/A"),
                    })
                readable_output = tableToMarkdown(
                    "Policy Suggestions",
                    table_data,
                    headers=headers,
                    removeNull=True
                )
                if last_updated:
                    readable_output += f"\n\n**Last Updated:** {last_updated}"
            else:
                readable_output = "No policy suggestions found."

            return_results(
                CommandResults(
                    outputs_prefix="Core.PolicySuggestion",
                    outputs_key_field="id",
                    outputs=policies,
                    readable_output=readable_output,
                    raw_response=data,
                )
            )
    except Exception as ex:
        return_error(f"Failed to execute CASGetPolicySuggestion. Error:\n{str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
