import demistomock as demisto
from CommonServerPython import *


def format_comment(comment: dict) -> dict:
    """
    Converts a comment to a dictionary with the relevant fields.
    """
    return {
        'message': comment.get('properties', {}).get('message'),
        'createdTime': datetime.strftime(arg_to_datetime(comment.get('properties', {}).get('createdTimeUtc')), '%d/%m/%Y, %H:%M'), # type: ignore
        'name': comment.get('properties', {}).get('author', {}).get('name'),
    }


def convert_to_table(context_results: str) -> CommandResults:
    """
    Args:
        context_results (str): String representing a list of dicts

    Returns:
        CommandResults: CommandResults object containing only readable_output
    """
    context_results = json.loads(context_results)

    context_formatted = [
        format_comment(comment) for comment in context_results # type: ignore
    ]

    md = tableToMarkdown(
        '',
        context_formatted,
        headers=["message", "createdTime", "name"],
        removeNull=True,
        sort_headers=False,
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=md
    )


def main():  # pragma: no cover
    context = dict_safe_get(
        demisto.callingContext,
        ['context', 'Incidents', 0, 'CustomFields', 'microsoftsentinelcomments'],
        {}
    )

    if not context:
        return_error('No data to present')

    return_results(convert_to_table(context)) # type: ignore


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
