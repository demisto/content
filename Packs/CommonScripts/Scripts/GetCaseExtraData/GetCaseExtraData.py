import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def extract_ids(command_res, field_name):
    ids = []
    if command_res:
        if isinstance(command_res, dict):
            ids = [command_res.get(field_name)] if field_name in command_res else []
        elif isinstance(command_res, list):
            ids = [c.get(field_name) for c in command_res if isinstance(c, dict) and field_name in c]
    return ids


def replace_response_names(obj):
    if isinstance(obj, str):
        return obj.replace("incident", "case").replace("alert", "issue")
    elif isinstance(obj, list):
        return [replace_response_names(item) for item in obj]
    elif isinstance(obj, dict):
        return {replace_response_names(key): replace_response_names(value) for key, value in obj.items()}
    else:
        return obj


def get_case_extra_data(args):
    demisto.debug(f"Calling core-get-case-extra-data, {args=}")
    case_extra_data = execute_command("core-get-case-extra-data", args)
    demisto.debug(f"After calling core-get-case-extra-data, {case_extra_data=}")
    case = case_extra_data.get("case", {})
    issues = case_extra_data.get("issues", {}).get("data")
    issue_ids = extract_ids(issues, "issue_id")
    network_artifacts = case_extra_data.get("network_artifacts")
    file_artifacts = case_extra_data.get("file_artifacts")
    case.update({"issue_ids": issue_ids, "network_artifacts": network_artifacts, "file_artifacts": file_artifacts})
    return case


def main():
    args = demisto.args()
    case_ids = argToList(args.get("case_id", ""))
    issues_limit = str(min(int(args.get("issues_limit", 1000)), 1000))
    try:
        final_results = []
        for case_id in case_ids:
            case_data = get_case_extra_data({"case_id": str(case_id), "issues_limit": issues_limit})
            final_results.append(case_data)
        mapped_cases = replace_response_names(final_results)
        return_results( CommandResults(
            readable_output=tableToMarkdown("Cases Extra Data", mapped_cases, headerTransform=string_to_table_header),
            outputs_prefix="Core.CaseExtraData",
            outputs_key_field="case_id",
            outputs=mapped_cases,
            raw_response=mapped_cases))
    except Exception as e:
        return_error("Error occurred while retrieving cases. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
