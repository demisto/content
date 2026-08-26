import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def build_labels(result: dict) -> list:
    category_names = ",".join(c.get("name", "") for c in (result.get("categories") or []) if c.get("name"))
    list_names = ",".join(url_list.get("name", "") for url_list in (result.get("url_lists") or []) if url_list.get("name"))

    return [
        {"NetskopeURLLookupURL": result.get("url", "")},
        {"NetskopeURLLookupSite": result.get("site", "")},
        {"NetskopeURLLookupApp": result.get("app", "")},
        {"NetskopeURLLookupCategories": category_names},
        {"NetskopeURLLookupResolvedIP": result.get("resolved_ip", "")},
        {"NetskopeURLLookupDynamicClassification": str(result.get("dynamic_classification", ""))},
        {"NetskopeURLLookupCustomLists": list_names},
    ]


def main():
    args = demisto.args()
    lookup_result = args.get("lookup_result")

    if isinstance(lookup_result, dict):
        results = [lookup_result]
    else:
        results = lookup_result or []

    if not results:
        outputs = {"labels_json": "[]", "summary": "No URL Lookup result to record on the incident."}
    else:
        # Netskope.URLLookup is a list even for a single queried URL - this playbook only ever
        # looks up one URL, so the first (only) result is what gets recorded.
        result = results[0]
        labels = build_labels(result)
        outputs = {
            "labels_json": json.dumps(labels),
            "summary": f'Recorded Netskope URL Lookup labels on the incident for "{result.get("url", "")}".',
        }

    return_results(
        CommandResults(
            readable_output=outputs["summary"],
            outputs_prefix="NetskopeURLLookupLabels",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
