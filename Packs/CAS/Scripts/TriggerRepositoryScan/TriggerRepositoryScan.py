import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

VALID_ARGS: set[str] = {
    "repository_ids",
    "repositories_names",
    "scan_git_history",
}

def execute_core_api_call(args: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a core API call and parse the response.
    Args:
        args (dict[str, Any]): Dictionary containing API call parameters including path, method, data, and headers.
    Returns:
        dict[str, Any]: Parsed API response data.
    Raises:
        Exception: If the API call fails or response parsing fails.
    """
    res = demisto.executeCommand("core-generic-api-call", args)
    path = args.get('path')
    if is_error(res):
        return_error(f"Error in core-generic-api-call to {path}: {get_error(res)}")

    try:
        context = res[0]["EntryContext"]
        raw_data = context.get("data")
        if isinstance(raw_data, str):
            return json.loads(raw_data)
        return raw_data
    except Exception as ex:
        raise Exception(f"Failed to parse API response from {path}. Error: {str(ex)}")


def fetch_repositories_by_name(name: str) -> list[dict[str, Any]]:
    """
    Fetch repositories from the REPOSITORIES_ASSETS table by name using a CONTAINS search.
    Args:
        name (str): The repository name to search for.
    Returns:
        list[dict[str, Any]]: List of matching repository records from the table.
    """
    response = execute_core_api_call({
        "path": "/api/webapp/get_data",
        "method": "POST",
        "data": json.dumps({
            "type": "grid",
            "table_name": "REPOSITORIES_ASSETS",
            "filter_data": {
                "sort": [
                    {
                        "FIELD": "xdm__asset__id",
                        "ORDER": "DESC"
                    }
                ],
                "filter": {
                    "AND": [
                        {
                            "SEARCH_FIELD": "xdm__asset__name",
                            "SEARCH_TYPE": "CONTAINS",
                            "SEARCH_VALUE": name
                        }
                    ]
                },
                "free_text": "",
                "visible_columns": None,
                "locked": {},
                "paging": {
                    "from": 0,
                    "to": 50
                }
            },
            "jsons": [
                "xdm__repository__tags_metadata",
                "xdm__repository__issues_metadata",
                "xdm__repository__releases_metadata",
                "xdm__repository__forks",
                "cas_applications_ids"
            ],
        }),
    })

    reply = response.get("reply", {})
    data = reply.get("DATA", [])
    return data


def resolve_repository_names(names: list[str]) -> list[str]:
    """
    Resolve repository names to their asset IDs by querying the REPOSITORIES_ASSETS table.
    Validates that each name maps to exactly one repository.
    Args:
        names (list[str]): List of repository names to resolve.
    Returns:
        list[str]: List of resolved repository asset IDs (xdm__asset__id).
    Raises:
        ValueError: If any names are not found or if any names match multiple repositories.
    """
    resolved_ids: list[str] = []
    not_found: list[str] = []
    duplicates: dict[str, list[str]] = {}

    for name in names:
        results = fetch_repositories_by_name(name)

        if len(results) == 0:
            not_found.append(name)
        elif len(results) > 1:
            asset_ids = [r.get("xdm__asset__id", "unknown") for r in results]
            duplicates[name] = asset_ids
        else:
            resolved_ids.append(results[0].get("xdm__asset__id"))

    errors: list[str] = []

    if not_found:
        errors.append(f"The following repository names were not found: {', '.join(not_found)}")

    if duplicates:
        duplicate_details = "\n".join(
            f'- "{name}": asset IDs [{", ".join(ids)}]'
            for name, ids in duplicates.items()
        )
        errors.append(
            f"Duplicate repositories found for the following names:\n{duplicate_details}\n"
            f"Please use repository ids to specify the exact repository."
        )

    if errors:
        raise ValueError("\n".join(errors))

    return resolved_ids


def trigger_repository_scan(args: dict):
    """
    Trigger scans for specified repositories.
    Accepts either repository_ids or repositories_names (mutually exclusive).
    When repositories_names is provided, resolves names to IDs via the REPOSITORIES_ASSETS table.
    Args:
        args (dict): Dictionary containing scan configuration including:
                    - repository_ids (list): List of repository IDs to scan.
                    - repositories_names (list): List of repository names to resolve and scan.
                    - scan_git_history (bool): Whether to scan full git history (default: True).
    Returns:
        CommandResults: Command results with readable output and scan IDs.
    Raises:
        ValueError: If both or neither of repository_ids and repositories_names are provided.
    """
    raw_repository_ids = args.get("repository_ids", [])
    raw_repositories_names = args.get("repositories_names", [])

    repository_ids = argToList(raw_repository_ids)
    repositories_names = argToList(raw_repositories_names)

    if repository_ids and repositories_names:
        raise ValueError("Provide either repository_ids or repositories_names, not both.")

    if not repository_ids and not repositories_names:
        raise ValueError("Either repository_ids or repositories_names must be provided.")

    if repositories_names:
        repository_ids = resolve_repository_names(repositories_names)

    scan_git_history = argToBoolean(args.get("scan_git_history", "True"))
    scan_ids = []
    for repository_id in repository_ids:
        response = execute_core_api_call(
            {
                "path": "/api/cas/v1/scan/repository",
                "method": "POST",
                "data": json.dumps(
                    {
                        "repositoryId": repository_id,
                        "scanFullGitHistory": scan_git_history
                    }
                ),
                "headers": json.dumps({
                    "Content-Type": "application/json",
                })
            },
        )
        scan_ids.append(response.get("metadata").get("scan_id"))

    readable_output = f"Successfully triggered scan for repositories: {', '.join(repository_ids)}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Cas.RepositoryScan",
        raw_response={
            "scan_ids": scan_ids
        },
    )


def main() -> None:
    try:
        args = demisto.args()

        extra_args = set(args.keys()) - VALID_ARGS
        if extra_args:
            raise ValueError(f"Unexpected args found: {extra_args}")
        command_results = trigger_repository_scan(args)
        return_results(command_results)
    except Exception as e:
        return_error(f"Failed to execute TriggerRepositoryScan. Error:\n{str(e)}")



if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
