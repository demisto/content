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
        return_error(f"Failed to execute AppSecCreateApplication. Error:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
