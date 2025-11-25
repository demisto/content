import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def update_args(args):
    """
    Rename issue-based argument keys to incident-based equivalents,
    keeping all other keys unchanged.
    Args:
        args (dict): dictionary of argument names and values.
    Returns:
        dict: new dictionary with renamed keys.
    """
    name_mapping = {
        "issue_id": "incidentId",
        "min_similarity": "minimunIncidentSimilarity",
        "max_issues_to_display": "maxIncidentsToDisplay",
        "max_issues_in_indicators_for_white_list": "maxIncidentsInIndicatorsForWhiteList",
        "filter_equal_fields": "fieldExactMatch",
        "text_similarity_fields": "similarTextField",
        "json_similarity_fields": "similarJsonField",
        "discrete_match_fields": "similarCategoricalField",
        "fields_to_display": "fieldsToDisplay",
        "use_all_fields": "useAllFields",
        "from_date": "fromDate",
        "to_date": "toDate",
        "aggregate_issues_different_date": "aggreagateIncidentsDifferentDate",
        "include_indicators_similarity": "includeIndicatorsSimilarity",
        "min_number_of_indicators": "minNumberOfIndicators",
        "indicators_types": "indicatorsTypes",
    }

    # Rename keys if found in mapping, otherwise keep them as-is
    new_args = {name_mapping.get(k, k): v for k, v in args.items()}
    demisto.debug(f"Changed args for calling the script to: {new_args}")
    return new_args


def delete_keys_recursively(obj, keys_to_delete):
    if isinstance(obj, dict):
        return {k: delete_keys_recursively(v, keys_to_delete) for k, v in obj.items() if k not in keys_to_delete}
    elif isinstance(obj, list):
        return [delete_keys_recursively(i, keys_to_delete) for i in obj]
    else:
        return obj


def replace_keys_recursively_multi(obj, replacements: dict):
    """
    Recursively replace keys and string values in a dict or list according to replacements dict.

    Args:
        obj (dict | list | str): Input object
        replacements (dict): {old_substring: new_substring, ...}

    Returns:
        dict | list | str: New object with replacements applied
    """
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            new_key = k
            if isinstance(k, str):
                for old, new in replacements.items():
                    new_key = new_key.replace(old, new)
            new_obj[new_key] = replace_keys_recursively_multi(v, replacements)
        return new_obj
    elif isinstance(obj, list):
        return [replace_keys_recursively_multi(item, replacements) for item in obj]
    elif isinstance(obj, str):
        new_str = obj
        for old, new in replacements.items():
            new_str = new_str.replace(old, new)
        return new_str
    else:
        return obj


def replace_fields(args: dict, replacements: dict) -> dict:
    """
    Replaces field names in certain args according to a replacements mapping.
    Handles both comma-separated strings and lists.

    :param args: dictionary of arguments
    :param replacements: dictionary of replacements, e.g. {"status": "status.progress", "domain": "alert_domain"}
    :return: updated args dict
    """
    fields_to_check = ["text_similarity_fields", "filter_equal_fields", "discrete_match_fields"]

    for key in fields_to_check:
        value = args.get(key)
        if not value:
            continue

        # Handle both list and string values
        if isinstance(value, str):
            fields = [f.strip() for f in value.split(",")]
        elif isinstance(value, list):
            fields = [str(f).strip() for f in value]
        else:
            continue

        updated_fields = [replacements.get(f, f) for f in fields]
        args[key] = ",".join(updated_fields)

    return args


def handle_results(results) -> tuple[str, dict]:
    combined_human_readable = ""
    final_outputs = {}
    for d in results:
        if human_readable := d.get("HumanReadable"):
            combined_human_readable += human_readable + "\n"

        if context := d.get("EntryContext"):
            issues_list = context.get("DBotFindSimilarIncidents", {}).get("similarIncident", {})
            replacements = {"incident": "issue", "similarity alert": "similarityIssue"}
            issues_list = replace_keys_recursively_multi(issues_list, replacements)
            issues_list = delete_keys_recursively(issues_list, ["alert ID"])
            final_outputs = {
                "similarIssue": issues_list,
                "isSimilarIssueFound": bool(issues_list),
                "excutionSummary": "Success",
            }
            final_outputs = {"SimilarIssues": final_outputs}

    replacements = {"alerts": "issues", "Alert": "Issue", "alert": "issue", "incidentId": "issueId"}
    combined_human_readable = replace_keys_recursively_multi(combined_human_readable, replacements)
    if not final_outputs:
        final_outputs = {"excutionSummary": combined_human_readable, "similarIssue": {}, "isSimilarIssueFound": False}
        final_outputs = {"SimilarIssues": final_outputs}

    return combined_human_readable, final_outputs


def main():
    try:
        args = demisto.args()
        replacements = {"status": "status.progress", "domain": "alert_domain", "category": "categoryname", "url": "alerturl"}
        new_args = replace_fields(args, replacements)
        new_args = update_args(new_args)
        required_fields = ["text_similarity_fields", "json_similarity_fields", "discrete_match_fields", "use_all_fields"]
        if not any(args.get(field) for field in required_fields):
            return_error(f"At least one of the following arguments muse be provided: {', '.join(required_fields)}.")

        demisto.debug("Calling DBotFindSimilarIncidents.")
        results = execute_command("DBotFindSimilarIncidents", new_args, extract_contents=False)
        demisto.debug(f"Got the following results of DBotFindSimilarIncidents: {results}")
        final_readable, final_outputs = handle_results(results)
        return_results(CommandResults(outputs=final_outputs, readable_output=final_readable))

    except Exception as ex:
        return_error(f"Failed to execute SearchSimilarIssues. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
