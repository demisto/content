import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json

# ---------------------------------------------------------------------------
# Hardcoded argument values derived from the real API response.
# These are passed identically to both core-get-issues and core-get-issues-private
# so the outputs can be compared for consistency.
#
# Mapping: ISSUE_ARGS argument → response field → hardcoded value
#   issue_id                              → internal_id                          = "1"
#   severity                              → severity (SEV_040_HIGH)              = "high"
#   Identity_type                         → identity_type                        = null (omitted)
#   agent_id                              → agent_id                             = null (omitted)
#   action_external_hostname              → action_external_hostname             = null (omitted)
#   rule_id                               → matching_service_rule_id             = null (omitted)
#   rule_name                             → fw_rule                              = "test_fw_rule"
#   issue_name                            → alert_name                           = "TestIssue"
#   issue_source                          → alert_source                         = "CREATE_ALERT_PUBLIC_API"
#   user_name                             → actor_effective_username             = "testUserName"
#   actor_process_image_name              → actor_process_image_name             = "test_actor_process_image_name"
#   causality_actor_process_image_command_line → causality_actor_process_command_line = null (omitted)
#   actor_process_image_command_line      → actor_process_command_line           = null (omitted)
#   action_process_image_command_line     → action_process_image_command_line    = "test_action_process_image_command_line"
#   actor_process_image_sha256            → actor_process_image_sha256           = "test_actor_process_image_sha256"
#   causality_actor_process_image_sha256  → causality_actor_process_image_sha256 = "test_causality_actor_process_image_sha256"
#   action_process_image_sha256           → action_process_image_sha256          = "test_action_process_image_sha256"
#   action_file_image_sha256              → action_file_sha256                   = "test_action_file_sha256"
#   action_registry_name                  → action_registry_data                 = "test_action_registry_data"
#   action_registry_key_data              → action_registry_data                 = "test_action_registry_data"
#   host_ip                               → (not in response, using)             = "1.1.1.1"
#   action_local_ip                       → (not in response, using)             = "1.1.1.1"
#   action_remote_ip                      → (not in response, using)             = "1.1.1.1"
#   issue_action_status                   → alert_action_status                  = "NOT_AVAILABLE" → "detected"
#   action_local_port                     → action_local_port                    = null (omitted)
#   action_remote_port                    → (not in response, using)             = "80"
#   dst_action_external_hostname          → dst_agent_hostname                   = null (omitted)
#   starred                               → starred                              = "false"
#   mitre_technique_id_and_name           → mitre_technique_id_and_name          = null (omitted)
#   issue_category                        → alert_category                       = "OTHER"
#   issue_domain                          → alert_domain (DOMAIN_SECURITY)       = "Security"
#   issue_description                     → alert_description                    = "TestIssue"
#   os_actor_process_image_sha256         → os_actor_process_image_sha256        = null (omitted)
#   action_file_macro_sha256              → action_file_macro_sha256             = null (omitted)
#   status                                → status.progress (STATUS_010_NEW)     = "New"
#   asset_ids                             → asset_ids                            = [] (omitted)
#   assignee                              → assigned_to                          = null (omitted)
# ---------------------------------------------------------------------------

HARDCODED_ARGS: dict[str, Any] = {
    "issue_id": "1",
    "severity": "high",
    "rule_name": "test_fw_rule",
    "issue_name": "TestIssue",
    "issue_source": "Custom Alert",  # Must be a valid predefined display value (not internal API enum)
    "user_name": "testUserName",
    "actor_process_image_name": "test_actor_process_image_name",
    "action_process_image_command_line": "test_action_process_image_command_line",
    "actor_process_image_sha256": "test_actor_process_image_sha256",
    "causality_actor_process_image_sha256": "test_causality_actor_process_image_sha256",
    "action_process_image_sha256": "test_action_process_image_sha256",
    "action_file_image_sha256": "test_action_file_sha256",
    "action_registry_name": "test_action_registry_key_name",
    "action_registry_key_data": "test_action_registry_data",
    "host_ip": "1.1.1.1",
    "action_local_ip": "1.1.1.1",
    "action_remote_ip": "1.1.1.1",
    "action_remote_port": "80",
    "starred": "false",
    "issue_category": "OTHER",
    "issue_domain": "Security",
    "issue_description": "TestIssue",
    "status": "New",
    "causality_actor_process_image_command_line": "test_causality_actor_process_image_command_line",
    "actor_process_image_command_line": "test_actor_process_command_line",
    "page": "0",
    "page_size": "50",
    "sort_field": "source_insert_ts",
    "sort_order": "DESC",
    "assignee": "Hezi Yaffe",
    "dst_action_external_hostname": "test_xdm.target.host.fqdn",

    "Identity_type": "test_identity_type",  # Must be a valid predefined value: ANONYMOUS, APPLICATION, COMPUTE, etc.
    "agent_id": "1.1.1.1",
    "action_external_hostname": "test_action_external_hostname",
    "issue_action_status": "detected",  # Must be lowercase to match predefined values
    "action_local_port": "80",
    "mitre_technique_id_and_name": "test_mitre_technique_id_and_name",
    "os_actor_process_image_sha256": "test_os_actor_process_image_sha256",
    "action_file_macro_sha256": "test_action_file_macro_sha256",
    #"asset_ids": ,
    #"rule_id": ,
}

# Base args always sent with every per-argument test (pagination/sorting only, no filters)
BASE_ARGS: dict[str, Any] = {
    "page": "0",
    "page_size": "50",
    "sort_field": "source_insert_ts",
    "sort_order": "DESC",
}

# Arguments that are pagination/sorting controls — tested together as a group, not individually
PAGINATION_ARGS = {"page", "page_size", "sort_field", "sort_order"}

# The specific Core.Issue context fields to verify between the two commands.
# Only these fields are compared — everything else in the context is ignored.
VERIFIED_CONTEXT_FIELDS = [
    "internal_id",
    "Identity_type",
    "source_insert_ts",
    "issue_name",
    "issue_category",
    "issue_description",
    "agent_ids",
    "asset_ids",
    "severity",
    "issue_domain",
    "case_ids",
    "issue_source",
    "starred",
    "status",           # nested: status.progress
    "assigned_to_pretty",
    "assigned_to",
    "agent_ip_addresses",
    "agent_hostname",
    "mitre_tactic_id_and_name",
    "mitre_technique_id_and_name",
    "issue_action_status",
    "issue_action_status_readable",
    "action_file_macro_sha256",
    "action_process_image_sha256",
    "causality_actor_process_image_sha256",
    "os_actor_process_image_sha256",
    "actor_process_image_sha256",
]


def normalize(value: Any) -> Any:
    """Recursively normalize a value for comparison (sort lists, normalize dicts)."""
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        try:
            return sorted([normalize(item) for item in value], key=lambda x: json.dumps(x, sort_keys=True, default=str))
        except TypeError:
            return [normalize(item) for item in value]
    return value


def extract_core_issues(entries: list) -> list[dict]:
    """
    Extract the Core.Issue list from the EntryContext of command result entries.
    Returns a list of issue dicts (may be empty).
    """
    for entry in entries:
        if isinstance(entry, dict):
            ctx = entry.get("EntryContext") or {}
            for key, value in ctx.items():
                if key.startswith("Core.Issue"):
                    if isinstance(value, list):
                        return value
                    if isinstance(value, dict):
                        return [value]
    return []


def compare_context_fields(
    public_issues: list[dict],
    private_issues: list[dict],
) -> list[dict]:
    """
    Compare VERIFIED_CONTEXT_FIELDS field-by-field across the two issue lists.

    Returns a list of per-field result rows — ALL fields, not just mismatches:
        {"Field": str, "Public Value": str, "Private Value": str, "Status": str}
    Rows are sorted: mismatches first, then matches.
    """
    public_issue = public_issues[0] if public_issues else {}
    private_issue = private_issues[0] if private_issues else {}

    rows = []
    for field in VERIFIED_CONTEXT_FIELDS:
        pub_val = public_issue.get(field)
        priv_val = private_issue.get(field)
        match = normalize(pub_val) == normalize(priv_val)
        rows.append({
            "Field": field,
            "Public Value": str(pub_val) if pub_val is not None else "(missing)",
            "Private Value": str(priv_val) if priv_val is not None else "(missing)",
            "Status": "Match" if match else "MISMATCH",
        })

    # Sort: mismatches first so they are immediately visible
    rows.sort(key=lambda r: 0 if r["Status"] == "MISMATCH" else 1)
    return rows


def run_command(command: str, args: dict) -> list:
    """Execute a demisto command and return the result entries."""
    result = demisto.executeCommand(command, args)
    if isError(result):
        error_msg = get_error(result)
        if not error_msg:
            # get_error returned None/empty — extract raw Contents for diagnosis
            raw_contents = []
            if isinstance(result, list):
                for entry in result:
                    if isinstance(entry, dict):
                        contents = entry.get("Contents") or entry.get("HumanReadable") or entry.get("Type")
                        if contents:
                            raw_contents.append(str(contents))
            error_msg = "; ".join(raw_contents) if raw_contents else "unknown error (no error message returned)"
        raise DemistoException(f"Error executing '{command}': {error_msg}")
    return result


def test_single_arg(arg_name: str, arg_value: Any) -> tuple[list[dict], str | None]:
    """
    Run both commands with BASE_ARGS + a single filter argument.
    Returns (field_rows, error_message_or_None).
    Each field_row has: Field, Public Value, Private Value, Status.
    """
    test_args = {**BASE_ARGS, arg_name: arg_value}
    try:
        public_result = run_command("core-get-issues", test_args)
        private_result = run_command("core-get-issues-private", test_args)

        public_issues = extract_core_issues(public_result)
        private_issues = extract_core_issues(private_result)

        field_rows = compare_context_fields(public_issues, private_issues)
        return field_rows, None
    except DemistoException as e:
        return [], str(e)


def main():
    try:
        # Separate filter args from pagination/sorting args
        filter_args = {k: v for k, v in HARDCODED_ARGS.items() if k not in PAGINATION_ARGS}

        # -----------------------------------------------------------------------
        # Per-argument tests: collect summary + full field details
        # -----------------------------------------------------------------------
        arg_summary_rows: list[dict[str, Any]] = []
        failed_args: list[str] = []
        error_args: list[str] = []
        arg_field_details: dict[str, list[dict]] = {}

        for arg_name, arg_value in filter_args.items():
            field_rows, error_msg = test_single_arg(arg_name, arg_value)

            if error_msg:
                status = "ERROR"
                error_args.append(arg_name)
                arg_field_details[arg_name] = []
            else:
                mismatched = [r["Field"] for r in field_rows if r["Status"] == "MISMATCH"]
                status = f"MISMATCH ({len(mismatched)} field(s)): {', '.join(mismatched)}" if mismatched else "Match"
                if mismatched:
                    failed_args.append(arg_name)
                arg_field_details[arg_name] = field_rows

            row: dict[str, Any] = {
                "Argument": arg_name,
                "Value Used": str(arg_value),
                "Status": status,
            }
            if error_msg:
                row["Error"] = error_msg
            arg_summary_rows.append(row)

        # Pagination group test
        try:
            public_result = run_command("core-get-issues", BASE_ARGS)
            private_result = run_command("core-get-issues-private", BASE_ARGS)
            public_issues = extract_core_issues(public_result)
            private_issues = extract_core_issues(private_result)
            pagination_field_rows = compare_context_fields(public_issues, private_issues)
            pagination_error = None
            pagination_mismatches = [r["Field"] for r in pagination_field_rows if r["Status"] == "MISMATCH"]
            pagination_status = (
                f"MISMATCH ({len(pagination_mismatches)} field(s)): {', '.join(pagination_mismatches)}"
                if pagination_mismatches else "Match"
            )
        except DemistoException as e:
            pagination_field_rows = []
            pagination_error = str(e)
            pagination_status = "ERROR"

        for arg_name in PAGINATION_ARGS:
            row = {
                "Argument": arg_name,
                "Value Used": str(HARDCODED_ARGS.get(arg_name, "")),
                "Status": pagination_status,
            }
            if pagination_error:
                row["Error"] = pagination_error
                error_args.append(arg_name)
            elif "MISMATCH" in pagination_status:
                failed_args.append(arg_name)
            arg_summary_rows.append(row)
            arg_field_details[arg_name] = pagination_field_rows

        # Sort summary: errors first, mismatches second, matches last
        def sort_key(row: dict) -> int:
            s = row.get("Status", "")
            if "ERROR" in s:
                return 0
            if "MISMATCH" in s:
                return 1
            return 2

        arg_summary_rows.sort(key=sort_key)

        # -----------------------------------------------------------------------
        # Build readable output
        # -----------------------------------------------------------------------
        total = len(arg_summary_rows)
        num_failed = len(failed_args)
        num_errors = len(error_args)
        num_passed = total - num_failed - num_errors

        if num_failed == 0 and num_errors == 0:
            overall = "FULL MATCH - all arguments passed"
        else:
            parts = []
            if num_failed:
                parts.append(f"MISMATCH on {num_failed} arg(s): {', '.join(failed_args)}")
            if num_errors:
                parts.append(f"ERROR on {num_errors} arg(s): {', '.join(error_args)}")
            overall = " | ".join(parts)

        # Section 1: per-argument summary
        readable = tableToMarkdown(
            "core-get-issues vs core-get-issues-private - Per-Argument Summary",
            arg_summary_rows,
            headers=["Argument", "Value Used", "Status", "Error"],
            removeNull=True,
        )
        readable += f"\n\n**Summary: {num_passed}/{total} passed | {num_failed} failed | {num_errors} errors**"
        readable += f"\n\n**Overall: {overall}**"

        # Section 2: full field-level detail for EVERY argument (all fields + values)
        # Failed arguments shown first, then passing ones
        ordered_args = failed_args + [
            r["Argument"] for r in arg_summary_rows
            if r["Argument"] not in failed_args and r["Argument"] not in error_args
        ]

        for arg_name in ordered_args:
            field_rows = arg_field_details.get(arg_name, [])
            if not field_rows:
                continue
            arg_value = HARDCODED_ARGS.get(arg_name, "")
            has_mismatch = any(r["Status"] == "MISMATCH" for r in field_rows)
            section_title = (
                f"[MISMATCH] Argument: {arg_name} = {arg_value}"
                if has_mismatch
                else f"[Match] Argument: {arg_name} = {arg_value}"
            )
            readable += "\n\n" + tableToMarkdown(
                section_title,
                field_rows,
                headers=["Field", "Public Value", "Private Value", "Status"],
                removeNull=False,
            )

        return_results(
            CommandResults(
                readable_output=readable,
                outputs_prefix="CompareGetIssues",
                outputs_key_field="Argument",
                outputs={
                    "args_tested": list(HARDCODED_ARGS.keys()),
                    "failed_args": failed_args,
                    "error_args": error_args,
                    "overall": overall,
                    "summary": {
                        "total": total,
                        "passed": num_passed,
                        "failed": num_failed,
                        "errors": num_errors,
                    },
                    "field_details": [
                        {
                            "argument": arg_name,
                            "fields": arg_field_details.get(arg_name, []),
                        }
                        for arg_name in ordered_args
                    ],
                },
            )
        )

    except Exception as e:
        return_error(f"Failed to execute CompareGetIssuesCommands.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
