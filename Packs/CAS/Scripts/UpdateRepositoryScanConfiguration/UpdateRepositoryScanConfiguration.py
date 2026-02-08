import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

ALLOWED_SCANNERS = [
    "SCA",
    "IAC",
    "SECRETS"
]


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


def validate_scanner_name(scanner_name: str):
    """
    Validate that a scanner name is allowed.
    Args:
        scanner_name (str): The name of the scanner to validate.
    Returns:
        bool: True if the scanner name is valid.
    Raises:
        ValueError: If the scanner name is not in the list of allowed scanners.
    """
    if scanner_name.upper() not in ALLOWED_SCANNERS:
        raise ValueError(f"Invalid scanner '{scanner_name}'. Allowed scanners are: {', '.join(sorted(ALLOWED_SCANNERS))}")


def build_scanner_config_payload(args: dict) -> dict:
    """
    Build a scanner configuration payload for repository scanning.

    Args:
        args (dict): Dictionary containing configuration arguments.
                    Expected to include:
                        - enable_scanners (list): List of scanners to enable.
                        - disable_scanners (list): List of scanners to disable.
                        - pr_scanning (bool): Whether to enable PR scanning.
                        - block_on_error (bool): Whether to block on scanning errors.
                        - tag_resource_blocks (bool): Whether to tag resource blocks.
                        - tag_module_blocks (bool): Whether to tag module blocks.
                        - exclude_paths (list): List of paths to exclude from scanning.
    Returns:
        dict: Scanner configuration payload.

    Raises:
        ValueError: If the same scanner is specified in both enable and disabled lists.
    """
    enabled_scanners = argToList(args.get("enable_scanners", []))
    disabled_scanners = argToList(args.get("disable_scanners", []))
    secret_validation = argToBoolean(args.get("secret_validation", "False"))
    enable_git_history = argToBoolean(args.get("enable_git_history", "False"))
    enable_pr_scanning = arg_to_bool_or_none(args.get("pr_scanning"))
    block_on_error = arg_to_bool_or_none(args.get("block_on_error"))
    tag_resource_blocks = arg_to_bool_or_none(args.get("tag_resource_blocks"))
    tag_module_blocks = arg_to_bool_or_none(args.get("tag_module_blocks"))
    exclude_paths = argToList(args.get("exclude_paths", []))

    overlap = set(enabled_scanners) & set(disabled_scanners)
    if overlap:
        raise ValueError(f"Cannot enable and disable the same scanner(s) simultaneously: {', '.join(overlap)}")

    # Build scanners configuration
    scanners = {}
    for scanner in enabled_scanners:
        validate_scanner_name(scanner)
        if scanner.upper() == "SECRETS":
            scanners["SECRETS"] = {
                "isEnabled": True,
                "scanOptions": {"secretValidation": secret_validation, "gitHistory": enable_git_history},
            }
        else:
            scanners[scanner.upper()] = {"isEnabled": True}

    for scanner in disabled_scanners:
        validate_scanner_name(scanner)
        scanners[scanner.upper()] = {"isEnabled": False}

    # Build scan configuration payload with only relevant arguments
    scan_configuration = {}

    if scanners:
        scan_configuration["scanners"] = scanners

    if args.get("pr_scanning") is not None:
        scan_configuration["prScanning"] = {
            "isEnabled": enable_pr_scanning,
            **({"blockOnError": block_on_error} if block_on_error is not None else {}),
        }

    if args.get("tag_resource_blocks") is not None or args.get("tag_module_blocks") is not None:
        scan_configuration["taggingBot"] = {
            **({"tagResourceBlocks": tag_resource_blocks} if tag_resource_blocks is not None else {}),
            **({"tagModuleBlocks": tag_module_blocks} if tag_module_blocks is not None else {}),
        }

    if exclude_paths:
        scan_configuration["excludedPaths"] = exclude_paths

    demisto.debug(f"{scan_configuration=}")

    return scan_configuration


def enable_scanners_command(args: dict):
    """
    Updates repository scan configuration by enabling/disabling scanners and setting scan options.
    Args:
        args (dict): Dictionary containing configuration arguments including repository_ids,
                    enabled_scanners, disabled_scanners, and other scan settings.
    Returns:
        CommandResults: Command results with readable output showing update status and raw response.
    """
    repository_ids = argToList(args.get("repository_ids"))
    payload = build_scanner_config_payload(args)

    # Send request to update repository scan configuration
    for repository_id in repository_ids:
        execute_core_api_call(
            {
                "path": f"/api/webapp/public_api/appsec/v1/repositories/{repository_id}/scan-configuration",
                "method": "PUT",
                "data": json.dumps(payload),
                "headers": json.dumps({
                    "Content-Type": "application/json",
                })
            }
        )

    readable_output = f"Successfully updated repositories: {', '.join(repository_ids)}"

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Cas.RepositoryScanConfiguration",
        raw_response=repository_ids,
    )


def main() -> None:
    try:
        args = demisto.args()
        command_results = enable_scanners_command(args)
        return_results(command_results)
    except Exception as e:
        return_error(f"Failed to execute UpdateRepositoryScanConfiguration. Error:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
