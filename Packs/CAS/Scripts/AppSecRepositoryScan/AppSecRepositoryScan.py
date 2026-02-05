import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

VALID_ARGS: set[str] = {
    "repository_ids",
    "scan_git_history",
}

def execute_core_api_call(args: dict[str, Any]) -> dict[str, Any]:
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


def trigger_repository_scan(args: dict):
    repository_ids = argToList(args.get("repository_ids"))
    scan_git_history = argToBoolean(args.get("scan_git_history", "True"))
    responses = []
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
        responses.append(response.get("metadata").get("scan_id"))

    readable_output = f"Successfully triggered scan for repositories: {', '.join(repository_ids)}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Cas.RepositoryScan",
        raw_response=responses,
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
        return_error(f"Failed to execute AppSecRepositoryScan. Error:\n{str(e)}")



if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
