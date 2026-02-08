import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any

VALID_ARGS: set[str] = {
    "application_name",
    "asset_identifiers",
    "filter_type",
    "provider",
    "business_criticality",
    "business_owner",
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


def create_code_asset_selection(asset_identifiers: list[str], provider: str, filter_type: str) -> dict[str, Any]:
    """
    Create a code asset selection configuration for application creation.
    Args:
        asset_identifiers (list[str]): List of asset identifiers (repositories or organizations).
        provider (str): The code provider (e.g., GitHub, GitLab).
        filter_type (str): Type of filter to apply (e.g., REPOSITORY, ORGANIZATION).
    Returns:
        dict[str, Any]: Asset selection configuration dictionary.
    """
    # currently only implemented application for Code and repositories/organizations.
    return {
        "selectionType": "filter",
        "section": "code",
        "filter": {
            "values": asset_identifiers,
            "provider": provider,
            "filterType": filter_type
        }
    }


def create_application(args: dict[str, Any]) -> CommandResults:
    """
    Create a new application in CAS with specified configuration.
    Args:
        args (dict[str, Any]): Dictionary containing application configuration including:
                              - application_name (str): Name of the application.
                              - provider (str): Code provider.
                              - asset_identifiers (list): List of asset identifiers.
                              - filter_type (str): Type of filter (default: REPOSITORY).
                              - business_owner (list): List of business owners.
                              - business_criticality (str): Business criticality level (default: Medium).
    Returns:
        CommandResults: Command results with readable output and application details.
    Raises:
        ValueError: If required fields (application_name or provider) are missing.
    """
    application_name = args.get("application_name")
    provider = args.get("provider")
    asset_identifiers = argToList(args.get("asset_identifiers"))
    filter_type = args.get("filter_type", "REPOSITORY")
    business_owner = argToList(args.get("business_owner", []))
    business_criticality = args.get("business_criticality", "Medium")

    if not application_name:
        raise ValueError("Application Name field must be provided")
    if not provider:
        raise ValueError("Provider field must be provided")

    payload = {
        "name": application_name,
        "description": "",
        "businessCriticality": business_criticality,
        "businessOwner": business_owner,
        "compliance": [],
        "assetSelection": create_code_asset_selection(asset_identifiers, provider, filter_type),
        "category": "Business Application",
        "creationType": "Manual"
    }

    response = execute_core_api_call({
        "path": "/api/cas/v1/application",
        "method": "POST",
        "data": json.dumps(payload),
        "headers": json.dumps({
            "Content-Type": "application/json",
        })
    })
    application_id = response.get('applicationId')
    readable_output = f"Successfully created application '{application_id}' for {filter_type.lower()}s: {', '.join(asset_identifiers)}"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Cas.Application",
        outputs_key_field="applicationId",
        raw_response=response,
    )


def main() -> None:
    try:
        args = demisto.args()
        extra_args = set(args.keys()) - VALID_ARGS
        if extra_args:
            raise ValueError(f"Unexpected args found: {extra_args}")
        command_results = create_application(args)
        return_results(command_results)
    except Exception as e:
        return_error(f"Failed to execute CreateApplication. Error:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
