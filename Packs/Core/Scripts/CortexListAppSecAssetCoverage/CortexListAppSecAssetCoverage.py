from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Columns representing different scanner coverage categories
SCANNER_COLUMNS: list[str] = [
    "is_scanned_by_vulnerabilities",
    "is_scanned_by_code_weakness",
    "is_scanned_by_secrets",
    "is_scanned_by_iac",
    "is_scanned_by_malware",
]

# Valid input arguments for this automation
VALID_ARGS: set[str] = {
    "asset_id",
    "asset_name",
    "business_application_names",
    "status_coverage",
    "is_scanned_by_vulnerabilities",
    "is_scanned_by_code_weakness",
    "is_scanned_by_secrets",
    "is_scanned_by_iac",
    "is_scanned_by_malware",
    "is_scanned_by_cicd",
    "asset_type",
    "asset_provider",
    "limit",
}


def get_command_results(command: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a Cortex XSOAR command and return the parsed result."""
    demisto.debug(f"Executing command: {command} with args: {args}")

    results = demisto.executeCommand(command, args)
    demisto.debug(f"Raw results from {command}: {results}")

    if not results or not isinstance(results, list):
        demisto.debug(f"No valid results returned from {command}")
        return {}

    result = results[0]
    if not isinstance(result, dict):
        demisto.debug(f"First result from {command} is not a dict")
        return {}

    if result.get("Type") == EntryType.ERROR:
        error_msg = result.get("Contents", "Unknown error occurred.")
        demisto.error(f"Error returned from {command}: {error_msg}")
        raise Exception(error_msg)

    contents = result.get("Contents")
    demisto.debug(f"Parsed contents from {command}: {contents}")

    if isinstance(contents, dict):
        return contents.get("reply", {})

    return {}


def transform_scanner_histograms_outputs(asset_coverage_histograms: dict[str, Any]) -> tuple[dict[str, dict[str, float]], float]:
    """Transform scanner histogram data into a summarized structure."""
    demisto.debug(f"Transforming scanner histogram data: {asset_coverage_histograms}")

    def get_count(data: list[dict[str, Any]], value: str) -> int:
        count = next((item.get("count", 0) for item in data if item.get("value") == value), 0)
        demisto.debug(f"Count for {value}: {count} in data: {data}")
        return count

    output: dict[str, dict[str, float]] = {}
    total_enabled = total_relevant = 0

    for column in SCANNER_COLUMNS:
        data = asset_coverage_histograms.get(column, [])
        demisto.debug(f"Processing column {column} with data: {data}")

        enabled_count = get_count(data, "ENABLED")
        disabled_count = get_count(data, "DISABLED")
        relevant_count = enabled_count + disabled_count

        coverage_pct = (enabled_count / relevant_count) if relevant_count else 0.0
        output[column] = {
            "enabled": enabled_count,
            "disabled": disabled_count,
            "coverage_percentage": coverage_pct,
        }

        total_enabled += enabled_count
        total_relevant += relevant_count

    overall_coverage = (total_enabled / total_relevant) if total_relevant else 0.0
    demisto.debug(f"Scanner histogram transformation result: {output}, overall: {overall_coverage}")

    return output, overall_coverage


def transform_status_coverage_histogram_output(data: dict[str, Any]) -> dict[str, dict[str, int | float]]:
    """Transform the status coverage histogram into a flattened dictionary."""
    demisto.debug(f"Transforming status coverage histogram: {data}")

    mapping = {
        "PARTIALLY SCANNED": "partially_scanned",
        "FULLY SCANNED": "fully_scanned",
        "NOT SCANNED": "not_scanned",
    }

    output: dict[str, int | float] = {}

    for item in data.get("status_coverage", []):
        label = mapping.get(item.get("value"), str(item.get("value", "")).lower().replace(" ", "_"))
        output[f"{label}_count"] = item.get("count", 0)
        output[f"{label}_percentage"] = item.get("percentage", 0.0)

    demisto.debug(f"Status histogram output: {output}")
    return {"aspm_status_coverage": output}


def main() -> None:
    """Main execution entry point for the Cortex XSOAR script."""
    try:
        args = demisto.args()
        demisto.debug(f"Received script arguments: {args}")

        extra_args = set(args.keys()) - VALID_ARGS
        if extra_args:
            demisto.error(f"Unexpected args found: {extra_args}")
            raise ValueError(f"Unexpected args found: {extra_args}")

        # Fetch asset coverage details
        demisto.debug("Fetching asset coverage via core-get-asset-coverage")
        asset_coverage = get_command_results("core-get-asset-coverage", args)
        demisto.debug(f"Asset coverage received: {asset_coverage}")

        assets = asset_coverage.get("DATA", [])

        # Fetch coverage histogram data
        args["columns"] = ", ".join(SCANNER_COLUMNS + ["status_coverage"])
        demisto.debug(f"Fetching histogram using args: {args}")

        asset_coverage_histograms = get_command_results("core-get-asset-coverage-histogram", args)
        demisto.debug(f"Histogram result: {asset_coverage_histograms}")

        scanner_histograms, coverage_percentage = transform_scanner_histograms_outputs(asset_coverage_histograms)
        status_histogram = transform_status_coverage_histogram_output(asset_coverage_histograms)

        outputs = {
            "total_filtered_assets": asset_coverage.get("FILTER_COUNT"),
            "number_returned_assets": len(assets),
            "coverage_percentage": coverage_percentage,
            "Metrics": {**scanner_histograms, **status_histogram},
            "Asset": assets,
        }

        demisto.debug(f"Final output: {outputs}")

        return_results(
            CommandResults(
                outputs=outputs,
                outputs_prefix="Core.Coverage",
                raw_response=outputs,
            )
        )

    except Exception as e:
        demisto.error(f"Exception occurred: {str(e)}")
        return_error(f"Failed to execute script.\nError:\n{str(e)}")


# Script entry point
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
