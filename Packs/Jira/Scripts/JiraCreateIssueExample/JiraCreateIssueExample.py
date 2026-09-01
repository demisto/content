import re
from datetime import datetime
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

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


def parse_custom_fields(custom_fields: list[str]) -> dict[str, Any]:
    """
    Parse the custom fields into a dictionary.
    The custom fields arrive as comma-separated values:
        `customfield_10101=foo,customfield_10102=bar`

    And are returned as a dict:
        `{'customfield_10101': 'foo', 'customfield_10102': 'bar'}`

    Values may contain any characters including non-ASCII text (Korean, Japanese, etc.),
    spaces, hyphens, @, /, and other special characters.

    Args:
        - `custom_fields` (`List[str]`): List of custom fields.

    Returns:
        - `Dict[str, Any]` representing the custom fields.
    """

    result: dict[str, Any] = {}
    regex = r"([^=,]+)=([^,]+)"

    for custom_field in custom_fields:
        for field_key, field_value in re.findall(regex, custom_field):
            field_key = field_key.strip()
            field_value = field_value.strip()

            if field_value.isnumeric() and not field_value.startswith("0"):
                field_value = int(field_value)  # type: ignore

            result[field_key] = field_value

    return result


def add_custom_fields(args: dict[str, Any], custom_fields: dict[str, Any]) -> dict[str, Any]:
    """
    Merge parsed custom fields directly into the args dict.

    JiraV3's `create_issue_fields` natively handles any arg whose key starts with
    `customfield` by mapping it to `fields.<key>` in the Jira API payload. This means
    custom fields can coexist with standard named args (summary, projectKey, etc.)
    without needing `issue_json`.

    Args:
        - `args` (`dict[str, Any]`): The current command arguments dict.
        - `custom_fields` (`Dict[str, Any]`): A dict of custom field keys to values.
    Returns:
        - A `Dict[str, Any]` with custom fields merged in.
    """

    args.update(custom_fields)

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

                # `jira-create-issue` doesn't include `customFields` arg so we need to remove it and merge custom fields directly.
                del args["customFields"]
                demisto.debug("'customFields' removed. Adding custom field payload to the rest of the command arguments...")
                args = add_custom_fields(args, custom_fields)
                demisto.debug("Custom fields added to command arguments")

        demisto.debug(f"Executing {INTEGRATION_COMMAND} with arguments: \n{args}")
        create_issue_result = demisto.executeCommand(INTEGRATION_COMMAND, args)

        return_results(create_issue_result)
    except Exception as e:
        return_error(f"Failed to JiraCreateIssueExample command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
