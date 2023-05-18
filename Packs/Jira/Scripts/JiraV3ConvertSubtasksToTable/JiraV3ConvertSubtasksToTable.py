import demistomock as demisto
from CommonServerPython import *
from itertools import chain


def convert_to_table(context_results: str) -> CommandResults:
    """
    Args:
        context_results (str): String representing a list of subtasks entries.

    Returns:
        CommandResults: CommandResults object containing only readable_output
    """

    comment_entries = list(json.loads(context_results))

    md = tableToMarkdown(
        '',
        comment_entries,
        headers=[*dict.fromkeys(chain.from_iterable(comment_entries))],
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
            ['context', 'Incidents', 0, 'CustomFields', 'jirasubtask'],
            {},
        ):
            return_results(convert_to_table(context))
        else:
            return CommandResults(readable_output='No data to present')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
