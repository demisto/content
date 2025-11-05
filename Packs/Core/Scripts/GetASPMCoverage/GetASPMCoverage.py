from typing import Any, Union

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


scanner_columns = [
    "is_scanned_by_vulnerabilities",
    "is_scanned_by_code_weakness",
    "is_scanned_by_secrets",
    "is_scanned_by_iac",
    "is_scanned_by_malware",
]


def get_command_results(command: str, args: dict[str, Any]) -> Union[dict[str, Any] | list]:
    """Execute a Demisto command and return the result."""
    try:
        command_results = demisto.executeCommand(command, args)
        print(command_results)
        if command_results and isinstance(command_results, list) and command_results[0].get("Contents"):
            return command_results[0]["Contents"].get("reply", {})
        return {}
    except Exception as e:
        demisto.error(f"Error executing command {command}: {str(e)}")
        return {}


def transform_scanner_histograms_outputs(asset_coverage_histograms):
    def get_count(data, value):
        return next((item['count'] for item in data if item['value'] == value), 0)

    output = {}
    total_enabled = 0
    total = 0
    for column in scanner_columns:
        data = asset_coverage_histograms.get(column, [])
        enabled_count = get_count(data, "ENABLED")
        disabled_count = get_count(data, "DISABLED")
        output[column] = {
            "enabled": enabled_count,
            "disabled": disabled_count,
            "coverage_percentage": enabled_count / (enabled_count + disabled_count)
        }
        total_enabled += enabled_count
        total += enabled_count + disabled_count

    return output, total_enabled / total


def transform_status_coverage_histogram_output(data):
    mapping = {
        'PARTIALLY SCANNED': 'partially_scanned',
        'FULLY SCANNED': 'fully_scanned',
        'NOT SCANNED': 'not_scanned'
    }

    output = {}

    for item in data['status_coverage']:
        key = mapping.get(item['value'], item['value'].lower().replace(" ", "_"))
        output[key] = {
            "count": item["count"],
            "percentage": item["percentage"]
        }

    return {"aspm_status_coverage": output}


def main():
    try:
        args = demisto.args()
        asset_coverage = get_command_results("core-get-asset-coverage", args)
        assets = asset_coverage.get("DATA", [])
        args["columns"] = ", ".join(scanner_columns + ["status_coverage"])
        asset_coverage_histograms = get_command_results("core-get-asset-coverage-histogram", args)
        scanner_histograms_outputs , coverage_percentage = transform_scanner_histograms_outputs(asset_coverage_histograms)
        status_coverage_histogram_output = transform_status_coverage_histogram_output(asset_coverage_histograms)
        outputs = {
            "total_filtered_assets": asset_coverage.get("FILTER_COUNT"),
            "number_returned_assets": len(assets),
            "coverage_percentage": coverage_percentage,
            "Histogram": scanner_histograms_outputs | status_coverage_histogram_output,
            "Asset": assets
        }

        return_results(
            CommandResults(
                outputs=outputs,
                outputs_prefix="Core.Coverage",
                readable_output=outputs,
                raw_response=outputs,
            )
        )
    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
