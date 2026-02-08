import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Dict, Any, List, Tuple

# Columns representing different scanner coverage categories
SCANNER_COLUMNS: list[str] = [
    "is_scanned_by_vulnerabilities",
    "is_scanned_by_code_weakness",
    "is_scanned_by_secrets",
    "is_scanned_by_iac",
    "is_scanned_by_malware",
]

HISTOGRAM_COLUMNS: list[str] = SCANNER_COLUMNS + ["status_coverage", "unified_provider"]

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

def execute_core_api_call(path: str, method: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a core-generic-api-call and return the parsed result."""
    args = {
        "path": path,
        "method": method,
    }
    if data is not None:
        args["data"] = json.dumps(data)

    res = demisto.executeCommand("core-generic-api-call", args)

    if is_error(res):
        return_error(f"Error in core-generic-api-call to {path}: {get_error(res)}")

    try:
        context = res[0]["EntryContext"]
        raw_data = context.get("data")
        if isinstance(raw_data, str):
            data_dict = json.loads(raw_data)
        else:
            data_dict = raw_data

        if isinstance(data_dict, list):
            return data_dict

        reply = data_dict.get("reply", {})
        return reply
    except Exception as ex:
        raise Exception(f"Failed to parse API response from {path}. Error: {str(ex)}")


def build_asset_coverage_filter(args: dict, extra_filters: list[dict] | None = None) -> dict:
    # Mapping from script args to API filter fields
    filter_fields = []

    def add_filter(field, search_type, value):
        if value:
            if search_type in ("ARRAY_CONTAINS", "CONTAINS") and not isinstance(value, list):
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

    if extra_filters:
        filter_fields.extend(extra_filters)

    if not filter_fields:
        return {}

    return {"AND": filter_fields}


def get_asset_coverage_histograms(args: dict, filter_dict: dict) -> dict[str, Any]:
    return execute_core_api_call(
        path="/api/webapp/get_histograms",
        method="POST",
        data={
            "table_name": ASSET_COVERAGE_TABLE,
            "filter_data": {
                "filter": filter_dict
            },
            "max_values_per_column": arg_to_number(args.get("limit")) or 100,
            "columns": HISTOGRAM_COLUMNS
        }
    )


def transform_scanner_histograms_outputs(
    repo_histograms: Dict[str, Any], 
    non_repo_histograms: Dict[str, Any], 
    total_repos_count: List[Dict[str, Any]]
) -> Tuple[Dict[str, Dict[str, float]], float, float]:
    
    def get_histogram_count(data: List[Dict[str, Any]], value_key: str) -> int:
        """Helper to safely extract count from histogram list."""
        return next((item.get("count", 0) for item in data if item.get("value") == value_key), 0)

    unified_provider_data = repo_histograms.get("unified_provider", [])
    unified_map = {item["value"]: item["count"] for item in unified_provider_data}

    total_external_repos_sum = 0
    use_disabled_override = False

    for repo_entry in total_repos_count:
        provider = repo_entry.get("integrationType")
        total_repos_count = repo_entry.get("totalRepoCount", 0)
        
        # Track the total sum of repos existing in the provider (e.g. Github + Azure)
        total_external_repos_sum += total_repos_count
        
        # Check against what we actually see in the histogram
        internal_count = unified_map.get(provider, 0)
        
        # Logic: If provider API reports more repos than our histogram, trigger override
        if total_repos_count > internal_count:
            use_disabled_override = True

    output: Dict[str, Dict[str, float]] = {}
    
    # Accumulators for "Current" Coverage
    curr_total_enabled = 0
    curr_total_relevant = 0

    # Accumulators for "Potential" Coverage
    potential_total_enabled = 0
    potential_total_relevant = 0

    for column in SCANNER_COLUMNS:
        # 1. Fetch Histogram Data
        repo_data = repo_histograms.get(column, [])
        non_repo_data = non_repo_histograms.get(column, [])

        # 2. Extract Counts (Repo)
        r_enabled = get_histogram_count(repo_data, "ENABLED")
        r_disabled_actual = get_histogram_count(repo_data, "DISABLED")

        # 3. Extract Counts (Non-Repo)
        nr_enabled = get_histogram_count(non_repo_data, "ENABLED")
        nr_disabled = get_histogram_count(non_repo_data, "DISABLED")

        # 4. Calculate "Actual" (Histogram-only) Totals
        # Summing Repo + Non-Repo for the standard calculation
        col_actual_enabled = r_enabled + nr_enabled
        col_actual_disabled = r_disabled_actual + nr_disabled
        
        curr_total_enabled += col_actual_enabled
        curr_total_relevant += (col_actual_enabled + col_actual_disabled)

        # 5. Calculate "Potential" (With Override)
        r_disabled_potential = r_disabled_actual
        # If discrepancy exists, Repo Disabled becomes
        scanner_not_ignored = r_enabled > 0 or r_disabled_actual > 0
        if use_disabled_override and scanner_not_ignored:
            r_disabled_potential = total_external_repos_sum

        # Summing Repo (Potential) + Non-Repo
        col_pot_disabled = r_disabled_potential + nr_disabled
        col_pot_relevant = col_actual_enabled + col_pot_disabled

        potential_total_enabled += col_actual_enabled
        potential_total_relevant += col_pot_relevant

        # 6. Populate Output
        # The output dict usually drives the UI breakdown. 
        # Using Potential data here shows the gap including missing repos.
        scanner_coverage_actual = (col_actual_enabled / (col_actual_enabled + col_actual_disabled)) if (col_actual_enabled + col_actual_disabled) > 0 else 0.0
        scanner_coverage_potential = (col_actual_enabled / col_pot_relevant) if col_pot_relevant > 0 else 0.0
        
        output[column] = {
            "enabled": col_actual_enabled,
            "disabled": col_actual_disabled,
            "coverage_percentage": scanner_coverage_actual,
            "coverage_with_non_onboarded_percentage": scanner_coverage_potential,
        }
    
    # Overall Coverage (As Today): Based purely on histograms
    overall_coverage = (
        (curr_total_enabled / curr_total_relevant) 
        if curr_total_relevant > 0 
        else 0.0
    )

    # Potential Coverage: Includes the calculated "missing" repos
    coverage_with_non_onboarded_percentage = (
        (potential_total_enabled / potential_total_relevant)
        if potential_total_relevant > 0
        else 0.0
    )

    return output, overall_coverage, coverage_with_non_onboarded_percentage


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

        # Call histograms for REPOSITORY
        repo_filter = build_asset_coverage_filter(args, extra_filters=[{
            "SEARCH_FIELD": "asset_type",
            "SEARCH_TYPE": "EQ",
            "SEARCH_VALUE": "REPOSITORY"
        }])
        repo_histograms = get_asset_coverage_histograms(args, repo_filter)

        # Call histograms for non-REPOSITORY
        non_repo_filter = build_asset_coverage_filter(args, extra_filters=[{
            "SEARCH_FIELD": "asset_type",
            "SEARCH_TYPE": "NEQ",
            "SEARCH_VALUE": "REPOSITORY"
        }])
        non_repo_histograms = get_asset_coverage_histograms(args, non_repo_filter)

        total_repos_count = execute_core_api_call(
            path="/api/cas/v1/integrations/coverage/total-repos-count",
            method="GET",
        )

        # Merge histograms
        merged_histograms: dict[str, list] = {}
        for col in HISTOGRAM_COLUMNS:
            repo_data = repo_histograms.get(col, [])
            non_repo_data = non_repo_histograms.get(col, [])

            # Combine counts for same values
            combined_values: dict[str, dict] = {}
            for item in repo_data + non_repo_data:
                val = item.get("value")
                if val not in combined_values:
                    combined_values[val] = {"value": val, "count": 0}
                combined_values[val]["count"] += item.get("count", 0)

            merged_histograms[col] = list(combined_values.values())

        scanner_histograms, coverage_percentage, coverage_with_non_onboarded_percentage = transform_scanner_histograms_outputs(repo_histograms, non_repo_histograms, total_repos_count)
        status_histogram = transform_status_coverage_histogram_output(merged_histograms)

        outputs = {
            "total_filtered_assets": asset_coverage.get("FILTER_COUNT"),
            "number_returned_assets": len(assets),
            "coverage_percentage": coverage_percentage,
            "coverage_with_non_onboarded_percentage": coverage_with_non_onboarded_percentage,
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
