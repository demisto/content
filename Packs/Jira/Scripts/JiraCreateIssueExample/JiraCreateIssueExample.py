import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, List, Dict
from datetime import datetime
import re

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


def parse_custom_fields(custom_fields: List[str]) -> Dict[str, Any]:
    """
    Parse the custom fields into a dictionary.
    The custom fields arrive as comma-separated values:
        `customfield_10101=foo,customfield_10102=bar`

    And are returned as a dict:
        `'customfield_10101': 'foo', 'customfield_10101': 'bar'`

    Args:
        - `custom_fields` (`List[str]`): List of custom fields.s

    Returns:
        - `Dict[str, Any]` representing the custom fields.
    """

    result: Dict[str, Any] = {}
    regex = r'(customfield_\d{5,})={1}(\w+)'

    for custom_field in custom_fields:

        field_regex_match = re.search(regex, custom_field)

        if field_regex_match:
            field_key, field_value = re.findall(regex, custom_field)[0]

            if field_value.isnumeric() and not field_value.startswith("0"):
                field_value = int(field_value)  # type: ignore

            result[field_key] = field_value

    return result


def add_custom_fields(args: Dict[str, Any], custom_fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    Method to generate the payload representing the Jira issue custom fields and add it to the script arguments.

    Args:
        - `custom_fields` (`Dict[str, Any]`): A dicto of custom fields
    Returns:
        - A `Dict[str, Any]` with the Jira issue payload
    """

    args["issueJson"] = {}
    args["issueJson"]["fields"] = custom_fields

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

            # supplied custom fields might not parse correctly
            if custom_fields:
                demisto.debug(f"Custom fields parsed: {custom_fields}. Removing 'customFields' argument...")

                # `jira-create-issue`` doesn't include `customFields` arg so we need to remove it and replace it with `issueJson`.
                del args["customFields"]
                demisto.debug("'customFields' removed. Adding custom field payload to the rest of the command arguments...")
                args = add_custom_fields(args, custom_fields)
                demisto.debug("Custom fields added to command arguments")

        demisto.debug(f"Executing {INTEGRATION_COMMAND} with arguments: \n{args}")
        create_issue_result = demisto.executeCommand(
            INTEGRATION_COMMAND,
            args
        )

        return_results(create_issue_result)
    except Exception as e:
        return_error(f'Failed to JiraCreateIssueExample command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
