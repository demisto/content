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
    
def get_cases_with_extra_data(args):
    demisto.debug(f"Calling core-get-cases, {args=}")
    cases_results = execute_command("core-get-cases", args) or []
    demisto.debug(f"After calling core-get-cases, {cases_results=}")
    issues_limit = int(args.get("issues_limit", 1000))
    issues_limit = min(issues_limit, 1000)
    final_results = []
    for case in cases_results:
        case_id = case.get("case_id")
        demisto.debug(f"Current case id is: {case_id}")
        if not case_id:
            continue
        args.update({"case_id": str(case_id)})
        demisto.debug(f"Calling core-get-case-extra-data, {args=}")
        case_extra_data = execute_command("core-get-case-extra-data", args)
        demisto.debug(f"After calling core-get-case-extra-data, {case_extra_data=}")
        alerts = case_extra_data.get("issues", {}).get("data")
        issue_ids = extract_ids(alerts, "issue_id")
        network_artifacts = case_extra_data.get("network_artifacts")
        file_artifacts = case_extra_data.get("file_artifacts")
        case.update({"issue_ids": issue_ids, "network_artifacts": network_artifacts, "file_artifacts": file_artifacts})
        final_results.append(case)
    
    mapped_raw_cases = replace_response_names(final_results)
    
    return CommandResults(
        readable_output=tableToMarkdown("Cases", mapped_raw_cases, headerTransform=string_to_table_header),
        outputs_prefix="Core.Case",
        outputs_key_field="case_id",
        outputs=mapped_raw_cases,
        raw_response=mapped_raw_cases,
    )
        


def main():
    args = demisto.args()
    try:
        return_results(get_cases_with_extra_data(args))
    except Exception as e:
        return_error("Error occurred while retrieving cases. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
