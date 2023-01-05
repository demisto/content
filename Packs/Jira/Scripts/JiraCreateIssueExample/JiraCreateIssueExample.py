import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from typing import Any, ItemsView

"""
This script is used to simplify the process of creating a new Issue in Jira.
You can add fields that you want in the Issue as script arguments and or in the
code and have a newly created Issue easily.
"""

"""
createIssue default argument, we recommend not changing them.
"""
DEFAULT_ARGS = ['summary',
                'projectKey',
                'issueTypeName',
                'issueTypeId',
                'projectName',
                'description',
                'labels',
                'priority',
                'dueDate',
                'assignee',
                'reporter',
                'parentIssueKey',
                'parentIssueId'
                ]


def add_additional_args(known: Dict[str, Any], additional: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adds the extra arguments to the known arguments.
    The extra arguments need to be serialized to a JSON string.

    Args:
        - `known` (`Dict[str, Any]`): A dict holding the known/expected arguments

    Returns:
        - `Dict[str, Any]` holding the full payload sent to the `jira-create-issue` script
    """

    if additional:
        known["issueJSON"] = json.dumps(additional)

    return known


def get_known_args_from_input(input: ItemsView) -> Dict[str, Any]:
    """
    Creates a dictionary of known arguments passed into script.
    Args:
        - `input` (`dict_items[Tuple[str, Any]]`): A view (dict_items) of the command arguments
    Returns:
        - `Dict[str, Any]` representing the script arguments
    """

    return {key: value for key, value in input if key in DEFAULT_ARGS}


def get_additional_args_from_input(input: ItemsView) -> Dict[str, Any]:
    """
    Creates a dictionary of unknown arguments passed into script.
    Args:
        - `input` (`dict_items[Tuple[str, Any]]`): A view (dict_items) of the command arguments
    Returns:
        - `Dict[str, Any]` representing the script arguments
    """

    return {key: value for key, value in input if key not in DEFAULT_ARGS}


def main():  # pragma: no cover
    try:

        input = demisto.args().items()

        known_args = get_known_args_from_input(input)
        additional_args = get_additional_args_from_input(input)

        # merge known and unknown into one
        args = add_additional_args(known=known_args, additional=additional_args)

        create_issue_result = demisto.executeCommand("jira-create-issue", args)

        return_results(create_issue_result)
    except Exception as e:
        return_error(f'Failed to JiraCreateIssueExample command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
