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


def get_command_results(command: str, args: dict[str, Any]) -> dict[str, Any] | list[Any]:
    """Execute a Cortex XSOAR (Demisto) command and return the parsed result.
    Args:
        command (str): The name of the Cortex XSOAR command to execute.
        args (Dict[str, Any]): The arguments to pass to the command.
    Returns:
        Union[Dict[str, Any], List[Any]]: The parsed result from the command,
        or an empty dictionary if no valid result is found.
    Raises:
        Exception: If the command execution returns an error entry.
    """
    results = demisto.executeCommand(command, args)

    if not results or not isinstance(results, list):
        return {}

    result = results[0]
    if not isinstance(result, dict):
        return {}

    # Check for execution error
    if result.get("Type") == EntryType.ERROR:
        raise Exception(result.get("Contents", "Unknown error occurred."))

    contents = result.get("Contents")
    if isinstance(contents, dict):
        return contents.get("reply", {})

    return {}


def transform_scanner_histograms_outputs(asset_coverage_histograms: dict[str, Any]) -> tuple[dict[str, dict[str, float]], float]:
    """Transform scanner histogram data into a summarized structure.
    Args:
        asset_coverage_histograms (Dict[str, Any]): The histogram data for each scanner type.
    Returns:
        Tuple[Dict[str, Dict[str, float]], float]: A tuple containing:
            - A dictionary with scanner coverage statistics per scanner type.
            - The overall coverage percentage across all scanners.
    """

    def get_count(data: list[dict[str, Any]], value: str) -> int:
        """Retrieve the count for a given value from histogram data."""
        return next((item.get("count", 0) for item in data if item.get("value") == value), 0)

    output: dict[str, dict[str, float]] = {}
    total_enabled = total_relevant = 0

    for column in SCANNER_COLUMNS:
        data = asset_coverage_histograms.get(column, [])
        enabled_count = get_count(data, "ENABLED")
        disabled_count = get_count(data, "DISABLED")
        relevant_count = enabled_count + disabled_count

        output[column] = {
            "enabled": enabled_count,
            "disabled": disabled_count,
            "coverage_percentage": (enabled_count / relevant_count) if relevant_count else 0.0,
        }

        total_enabled += enabled_count
        total_relevant += relevant_count

    overall_coverage = (total_enabled / total_relevant) if total_relevant else 0.0
    return output, overall_coverage


def transform_status_coverage_histogram_output(data: dict[str, Any]) -> dict[str, dict[str, int | float]]:
    """Transform the status coverage histogram into a flattened dictionary.
    Args:
        data (Dict[str, Any]): The histogram data containing the "status_coverage" field.
    Returns:
        Dict[str, Dict[str, Union[int, float]]]: A dictionary containing
        counts and percentages for each scan status.
    """
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

    return {"aspm_status_coverage": output}


def main() -> None:
    """Main execution entry point for the Cortex XSOAR script."""
    try:
        args = demisto.args()
        demisto.info(f"blabla {args=}")
        #remove_nulls_from_dictionary(args)
        # Validate incoming arguments
        extra_args = set(args.keys()) - VALID_ARGS
        if extra_args:
            raise ValueError(f"Unexpected args found: {extra_args}")

        # Fetch asset coverage details
        asset_coverage = get_command_results("core-get-asset-coverage", args)
        if not isinstance(asset_coverage, dict):
            asset_coverage = {}

        assets = asset_coverage.get("DATA", [])

        # Fetch coverage histogram data
        args["columns"] = ", ".join(SCANNER_COLUMNS + ["status_coverage"])
        asset_coverage_histograms = get_command_results("core-get-asset-coverage-histogram", args)

        # Process histogram outputs
        if type(asset_coverage_histograms) is not dict:
            demisto.debug(f"asset_coverage_histograms are not dict {asset_coverage_histograms}")
            asset_coverage_histograms = {}
        scanner_histograms, coverage_percentage = transform_scanner_histograms_outputs(asset_coverage_histograms)
        status_histogram = transform_status_coverage_histogram_output(asset_coverage_histograms)

        # Prepare final outputs
        outputs = {
            "total_filtered_assets": asset_coverage.get("FILTER_COUNT"),
            "number_returned_assets": len(assets),
            "coverage_percentage": coverage_percentage,
            "Metrics": {**scanner_histograms, **status_histogram},
            "Asset": assets,
        }

        return_results(
            CommandResults(
                outputs=outputs,
                outputs_prefix="Core.Coverage",
                raw_response=outputs,
            )
        )

    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{str(e)}")


# Script entry point
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()