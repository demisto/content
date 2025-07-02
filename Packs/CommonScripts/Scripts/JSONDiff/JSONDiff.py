import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any


def compare_jsons(json1: dict[str, Any], json2: dict[str, Any], path: str = "") -> dict[str, list[dict[str, Any]]]:
    """Recursively compare two JSON objects and return structured differences."""
    differences: dict[str, list[dict[str, Any]]] = {
        "changed": [],
        "added": [],
        "removed": []
    }

    # Find keys present in both JSONs
    common_keys = json1.keys() & json2.keys()

    for key in common_keys:
        new_path = f"{path}.{key}" if path else key
        if isinstance(json1[key], dict) and isinstance(json2[key], dict):
            sub_diffs = compare_jsons(json1[key], json2[key], new_path)
            differences["changed"].extend(sub_diffs["changed"])
            differences["added"].extend(sub_diffs["added"])
            differences["removed"].extend(sub_diffs["removed"])
        elif json1[key] != json2[key]:
            differences["changed"].append({"field": new_path, "from": json1[key], "to": json2[key]})

    # Find added keys
    added_keys = json2.keys() - json1.keys()
    for key in added_keys:
        new_path = f"{path}.{key}" if path else key
        differences["added"].append({"field": new_path, "value": json2[key]})

    # Find removed keys
    removed_keys = json1.keys() - json2.keys()
    for key in removed_keys:
        new_path = f"{path}.{key}" if path else key
        differences["removed"].append({"field": new_path, "value": json1[key]})

    return differences


def main():
    try:
        # Get inputs from XSOAR arguments
        json1_str = demisto.args().get("old_json")
        json2_str = demisto.args().get("new_json")

        if not json1_str or not json2_str:
            return_error("Missing required arguments: old_json and new_json")

        # Parse JSON input
        json1 = json.loads(json1_str)
        json2 = json.loads(json2_str)

        # Compare JSONs
        differences = compare_jsons(json1, json2)

        # Format results
        readable_output = f"### JSON Differences\n```json\n{json.dumps(differences, indent=4, ensure_ascii=False)}\n```"

        # Return results to XSOAR
        return_results(CommandResults(
            readable_output=readable_output,
            outputs_prefix="JSONDiff",
            outputs_key_field="field",
            outputs=differences
        ))

    except Exception as e:
        return_error(f"Failed to compare JSONs: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
