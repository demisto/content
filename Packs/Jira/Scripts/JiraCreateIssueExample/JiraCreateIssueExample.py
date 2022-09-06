import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

"""
This script is used to simplify the process of creating a new Issue in Jira.
You can add fields that you want in the Issue as script arguments and or in the
code and have a newly created Issue easily.
"""

"""
createIssue default argument, we recommend not changing them.
"""
DEFUALT_ARGS = ['summary',
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


def main():
    try:
        createIssueArgs = {key: value for key, value in demisto.args().items() if key in DEFUALT_ARGS}

        """
        Adding the arguments fields to the issueJson field.
        """
        extraIssueArgs = {key: value for key, value in demisto.args().items() if key not in DEFUALT_ARGS}
        createIssueArgs['issueJson'] = json.dumps(extraIssueArgs)

        """
        Executing the command
        """
        createIssueResult = demisto.executeCommand("jira-create-issue", createIssueArgs)
        return_results(createIssueResult)
    except Exception as e:
        return_error(f'Failed to JiraCreateIssueExample command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
