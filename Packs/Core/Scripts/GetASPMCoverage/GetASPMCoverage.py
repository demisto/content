from typing import Any, Union

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_command_results(command: str, args: dict[str, Any]) -> Union[dict[str, Any] | list]:
    """Execute a Demisto command and return the result."""
    try:
        command_results = demisto.executeCommand(command, args)
        if command_results and isinstance(command_results, list) and command_results[0].get("Contents"):
            return command_results[0]["Contents"].get("result", {})
        return {}
    except Exception as e:
        demisto.error(f"Error executing command {command}: {str(e)}")
        return {}


def calculate_coverage_percentage(asset_coverage_histograms):
    return 100


def transform_asset_coverage_histograms_outputs(asset_coverage_histograms):
    return asset_coverage_histograms


def main():
    try:
        args = demisto.args()
        asset_coverage = get_command_results("core-get-asset-coverage", args)
        print(asset_coverage)
        demisto.debug(asset_coverage)

        columns = [
            "is_scanned_by_vulnerabilities",
            "is_scanned_by_code_weakness",
            "is_scanned_by_secrets",
            "is_scanned_by_iac,is_scanned_by_malware",
            "status_coverage"
        ]

        args["columns"] = ", ".join(columns)
        asset_coverage_histograms = get_command_results("core-get-asset-coverage-histogram", args)
        print(asset_coverage_histograms)
        demisto.debug(asset_coverage_histograms)
        outputs = {
            "total_filtered_assets": 0,
            "number_returned_assets": len(asset_coverage),
            "coverage_percentage": calculate_coverage_percentage(asset_coverage_histograms),
            "Histogram": transform_asset_coverage_histograms_outputs(asset_coverage_histograms),
            "Asset": asset_coverage
        }

        human_readable = ""

        return_results(
            CommandResults(
                outputs=outputs,
                outputs_prefix="Core.Coverage",
                readable_output=human_readable,
                raw_response=outputs,
            )
        )
    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
