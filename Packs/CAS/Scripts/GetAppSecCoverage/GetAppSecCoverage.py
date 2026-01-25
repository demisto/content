import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

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

ASSET_COVERAGE_TABLE = "COVERAGE"

def execute_core_api_call(path: str, method: str, data: dict[str, Any]) -> dict[str, Any]:
    """Execute a core-generic-api-call and return the parsed result."""
    res = demisto.executeCommand(
        "core-generic-api-call",
        {
            "path": path,
            "method": method,
            "data": json.dumps(data),
        },
    )

    if is_error(res):
        return_error(f"Error in core-generic-api-call to {path}: {get_error(res)}")

    try:
        context = res[0]["EntryContext"]
        raw_data = context.get("data")
        if isinstance(raw_data, str):
            data_dict = json.loads(raw_data)
        else:
            data_dict = raw_data

        reply = data_dict.get("reply", {})
        return reply
    except Exception as ex:
        raise Exception(f"Failed to parse API response from {path}. Error: {str(ex)}")


def build_asset_coverage_filter(args: dict) -> dict:
    # Mapping from script args to API filter fields
    filter_fields = []

    def add_filter(field, search_type, value):
        if value:
            if not isinstance(value, list):
                value = [value]
            filter_fields.append({
                "SEARCH_FIELD": field,
                "SEARCH_TYPE": search_type,
                "SEARCH_VALUE": value
            })

    add_filter("asset_id", "CONTAINS", args.get("asset_id"))
    add_filter("asset_name", "CONTAINS", args.get("asset_name"))
    add_filter("business_application_names", "ARRAY_CONTAINS", args.get("business_application_names"))
    add_filter("status_coverage", "EQ", args.get("status_coverage"))
    add_filter("is_scanned_by_vulnerabilities", "EQ", args.get("is_scanned_by_vulnerabilities"))
    add_filter("is_scanned_by_code_weakness", "EQ", args.get("is_scanned_by_code_weakness"))
    add_filter("is_scanned_by_secrets", "EQ", args.get("is_scanned_by_secrets"))
    add_filter("is_scanned_by_iac", "EQ", args.get("is_scanned_by_iac"))
    add_filter("is_scanned_by_malware", "EQ", args.get("is_scanned_by_malware"))
    add_filter("is_scanned_by_cicd", "EQ", args.get("is_scanned_by_cicd"))
    add_filter("asset_type", "EQ", args.get("asset_type"))
    add_filter("unified_provider", "EQ", args.get("asset_provider"))

    if not filter_fields:
        return {}

    return {"AND": filter_fields}


def transform_scanner_histograms_outputs(asset_coverage_histograms: dict[str, Any]) -> tuple[dict[str, dict[str, float]], float]:
    def get_count(data: list[dict[str, Any]], value: str) -> int:
        return next((item.get("count", 0) for item in data if item.get("value") == value), 0)

    output: dict[str, dict[str, float]] = {}
    total_enabled = total_relevant = 0

    for column in SCANNER_COLUMNS:
        data = asset_coverage_histograms.get(column, [])
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
    return output, overall_coverage


def transform_status_coverage_histogram_output(data: dict[str, Any]) -> dict[str, dict[str, int | float]]:
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
    try:
        args = demisto.args()

        extra_args = set(args.keys()) - VALID_ARGS
        if extra_args:
            raise ValueError(f"Unexpected args found: {extra_args}")
        # Prepare filters for API calls
        filter_dict = build_asset_coverage_filter(args)
        limit = int(args.get("limit", 100))

        asset_coverage = execute_core_api_call(
            path="/api/webapp/get_data",
            method="POST",
            data={
                "type": "grid",
                "table_name": ASSET_COVERAGE_TABLE,
                "filter_data": {
                    "filter": filter_dict,
                    "paging": {"from": 0, "to": limit},
                    "sort": []
                },
                "jsons": [],
                "onDemandFields": []
            }
        )
        assets = asset_coverage.get("DATA", [])
        histogram_columns = SCANNER_COLUMNS + ["status_coverage", "unified_provider"]
        asset_coverage_histograms = execute_core_api_call(
            path="/api/webapp/get_histograms",
            method="POST",
            data={
                "table_name": ASSET_COVERAGE_TABLE,
                "filter_data": {
                    "filter": filter_dict
                },
                "max_values_per_column": arg_to_number(args.get("limit")) or 100,
                "columns": histogram_columns
            }
        )
        scanner_histograms, coverage_percentage = transform_scanner_histograms_outputs(asset_coverage_histograms)
        status_histogram = transform_status_coverage_histogram_output(asset_coverage_histograms)

        outputs = {
            "total_filtered_assets": asset_coverage.get("FILTER_COUNT"),
            "number_returned_assets": len(assets),
            "coverage_percentage": coverage_percentage,
            "Metrics": {**scanner_histograms, **status_histogram},
            "Asset": assets,
        }
    except Exception as e:
        return_error(f"Failed to execute GetAppSecCoverage. Error:\n{str(e)}")

    return_results(
        CommandResults(
            outputs=outputs,
            outputs_prefix="Cas.Coverage",
            raw_response=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
