from typing import Any, Dict

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
        "issueId": "incidentId",
        "aggreagateIssuesDifferentDate": "aggreagateIncidentsDifferentDate",
        "minimumIssueSimilarity": "minimunIncidentSimilarity",
        "maxIssuesToDisplay": "maxIncidentsToDisplay",
        "maxIssuesInIndicatorsForWhiteList": "maxIncidentsInIndicatorsForWhiteList",
    }

    # Rename keys if found in mapping, otherwise keep them as-is
    new_args = {name_mapping.get(k, k): v for k, v in args.items()}
    demisto.debug(f"Changed args for calling the script to: {new_args}")
    return new_args

def delete_keys_recursively(obj, keys_to_delete):
    if isinstance(obj, dict):
        return {
            k: delete_keys_recursively(v, keys_to_delete)
            for k, v in obj.items() if k not in keys_to_delete
        }
    elif isinstance(obj, list):
        return [delete_keys_recursively(i, keys_to_delete) for i in obj]
    else:
        return obj

def replace_keys_recursively(obj, old: str, new: str):
    """
    Recursively replace all keys containing 'old' with 'new' in a dict or list.
    
    Args:
        obj (dict | list): The input object (dict or list).
        old (str): substring to replace in keys.
        new (str): replacement substring in keys.
    
    Returns:
        dict | list: new object with keys replaced recursively.
    """
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            new_key = k.replace(old, new) if isinstance(k, str) else k
            new_obj[new_key] = replace_keys_recursively(v, old, new)
        return new_obj
    elif isinstance(obj, list):
        return [replace_keys_recursively(item, old, new) for item in obj]
    elif isinstance(obj, str):
        return obj.replace(old, new)
    else:
        return obj

def handle_results(results):
    if isinstance(results, list):
        readable_output = results[0]
        final_readable = replace_keys_recursively(readable_output, "alerts", "issues")
        outputs = results[1]
        if isinstance(outputs, list):
            issues_list = replace_keys_recursively(outputs, "Incident", "Issue")
            issues_list = replace_keys_recursively(issues_list, "Similarity Alert", "SimilarityIssue")
            issues_list = delete_keys_recursively(issues_list, ["Alert Id"])
        else:
            issues_list = outputs.get("DBotFindSimilarIncidents", {}).get("similarIncidentList")
            
        final_outputs = {"similarIssueList": issues_list, "isSimilarIssueFound": True if issues_list else False}
        final_outputs = {"SimilarIssues": final_outputs}
        if issues_list:
            final_readable = final_readable + tableToMarkdown(f"Similar Issues", issues_list)
            
        return final_readable, final_outputs
    
    return "No similar issues were found.", None

def main():
    try:
        args = demisto.args()
        new_args = update_args(args)
        demisto.debug("Calling DBotFindSimilarIncidents.")
        results = execute_command("DBotFindSimilarIncidents", new_args)
        demisto.debug(f"Got the following results of DBotFindSimilarIncidents: {results}")
        final_readable, final_outputs = handle_results(results)
        return_results(CommandResults(outputs=final_outputs, readable_output=final_readable, outputs_key_field="Id"))
        
    except Exception as ex:
        return_error(f"Failed to execute SearchSimilarIssues. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
