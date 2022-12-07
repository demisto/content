import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, List, Dict
from datetime import datetime

"""
This script is used to simplify the process of creating a new Issue in Jira,
including using custom fields.
"""

INTEGRATION_COMMAND = "jira-create-issue"
DATE_FORMAT = "%Y-%m-%d"


def validate_date_field(date_str: str):
    """
    Private method to validate the date field is in expected format
    YYYY-MM-DD.

    Args:
        - `date_str` (`str`): The date field to validate
    """

    # This raises a ValueError when the parsing fails
    datetime.strptime(date_str, DATE_FORMAT)


def parse_custom_fields(custom_fields: List[str]) -> List[Dict[str, Any]]:
    """
    Private method to parse the custom fields into a list of dictionaries.
    The custom fields arrive as comma-separated values:
        customfield_10101=foo,customfield_10102=bar

    Args:
        - `custom_fields` (`List[str]`): List of custom fields.

    Returns:
        - `List[Dict[str, Any]]` representing the key/values of the custom fields.
    """

    result: List[Dict[str, Any]] = []

    for custom_field in custom_fields:
        if "=" in custom_field:
            field_key, field_value = custom_field.split("=")

            if field_value.isnumeric():
                field_value = int(field_value)

            result.append({field_key: field_value})

    return result


def add_custom_fields(args: Dict[str, Any], custom_fields: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Method to generate the payload representing the Jira issue custom fields and add it to the script arguments.

    Args:

        - `custom_fields` (`List[Dict[str, Any]]`): A list of custom fields
    Returns:
        - A dictionary of custom fields
    """

    args["issueJson"] = {}
    args["issueJson"]["fields"] = {k: v for custom_field in custom_fields for k, v in custom_field.items()}

    return args


def rm_custom_field_from_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Method to remove the `customFields` dict from the command arguments.
    jira-create-issue doesn't include `customFields` arg so we need to remove it and replace it with `issueJson`.
    """

    del args["customFields"]

    return args


def main():  # pragma: no cover
    try:

        args = demisto.args()

        demisto.debug(f"Arguments provided: \n{args}")

        if "dueDate" in args:
            validate_date_field(args.get("dueDate"))

        if "customFields" in args:
            demisto.debug("Found customFields arguments. Attempting to parse them...")
            custom_fields = parse_custom_fields(argToList(args.get("customFields")))
            demisto.debug(f"Custom fields parsed: {custom_fields}. Removing 'customFields' argument...")
            args = rm_custom_field_from_args(args)
            demisto.debug("'customFields' removed. Adding custom field payload to the rest of the command arguments...")
            propagated_args = add_custom_fields(args, custom_fields)
            demisto.debug("Custom fields added to command arguments")

        demisto.debug(f"Executing {INTEGRATION_COMMAND} with arguments: \n{propagated_args}")
        create_issue_result = demisto.executeCommand(
            INTEGRATION_COMMAND,
            propagated_args
        )

        return_results(create_issue_result)
    except Exception as e:
        return_error(f'Failed to JiraCreateIssueExample command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
