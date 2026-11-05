import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def build_labels(result: dict) -> list:
    return [
        {"NetskopeFileScanJobID": str(result.get("jobid", ""))},
        {"NetskopeFileScanStatus": str(result.get("status", ""))},
        {"NetskopeFileScanVerdict": str(result.get("verdict", ""))},
        {"NetskopeFileScanMD5": str(result.get("md5", ""))},
        {"NetskopeFileScanSHA256": str(result.get("sha256", ""))},
    ]


def main():
    args = demisto.args()
    scan_result = args.get("scan_result")

    if isinstance(scan_result, list):
        result = scan_result[0] if scan_result else {}
    else:
        result = scan_result or {}

    if not result:
        outputs = {"LabelsJson": "[]", "Summary": "No scan result to record on the incident."}
    else:
        labels = build_labels(result)
        outputs = {
            "LabelsJson": json.dumps(labels),
            "Summary": (
                f'Recorded Netskope File Scan labels on the incident for job "{result.get("jobid", "")}" '
                f"(verdict: {result.get('verdict', 'n/a')})."
            ),
        }

    return_results(
        CommandResults(
            readable_output=outputs["Summary"],
            outputs_prefix="Netskope.FileScanLabels",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
