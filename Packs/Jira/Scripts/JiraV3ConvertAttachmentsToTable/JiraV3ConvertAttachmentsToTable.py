import demistomock as demisto
from CommonServerPython import *
from itertools import chain


def convert_to_table(context_results: List[Dict[str, Any]]) -> CommandResults:
    """
    Args:
        context_results (str): A list of dictionaries representing the attachments of the Jira issue.

    Returns:
        CommandResults: CommandResults object containing only readable_output
    """

    attachments_names = [
        {'Name': context_result.get('name', '')}
        for context_result in context_results
    ]
    md = tableToMarkdown(
        '',
        attachments_names,
        headers=[*dict.fromkeys(chain.from_iterable(attachments_names))],
        removeNull=True,
        sort_headers=False,
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=md
    )


def main():  # pragma: no cover
    try:
        if context := dict_safe_get(
            demisto.callingContext,
            ['context', 'Incidents', 0, 'CustomFields', 'jiraattachments'],
            {},
        ):
            return_results(convert_to_table(context))
        else:
            return CommandResults(readable_output='No data to present')

    except Exception as exc:
        return_error(f'Failed to execute JiraV3ConvertAttachmentsToTable. Error: {exc}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
