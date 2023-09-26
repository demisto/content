import demistomock as demisto
from CommonServerPython import *


def convert_to_table(context_results: str) -> CommandResults:
    """
    Args:
        context_results (str): String representing the data of the incident field.

    Returns:
        CommandResults: CommandResults object containing only readable_output
    """

    comment_entries = json.loads(context_results)

    md = tableToMarkdown(
        name='',
        t=comment_entries,
        headers=list(comment_entries.keys()),
        removeNull=True,
        sort_headers=False,
        headerTransform=pascalToSpace,
        is_auto_json_transform=True
    )

    return CommandResults(
        readable_output=md
    )


def main():  # pragma: no cover
    try:
        if context := dict_safe_get(
            demisto.callingContext,
            ['context', 'Incidents', 0, 'CustomFields', 'crowdstrikefalconresponseelements'],
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
