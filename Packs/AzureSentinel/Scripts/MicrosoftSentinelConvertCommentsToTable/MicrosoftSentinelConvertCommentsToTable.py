import demistomock as demisto
from CommonServerPython import *
from dateutil import parser


def format_comment(comment: dict) -> dict:
    """
    Converts a comment to a dictionary with the relevant fields.
    """
    comment_time = comment.get("properties", {}).get("createdTimeUtc")
    try:
        createdTime = datetime.strftime(parser.parse(comment_time), "%d/%m/%Y, %H:%M")
    except Exception:
        createdTime = comment_time
    return {
        "message": comment.get("properties", {}).get("message"),
        "createdTime": createdTime,
        "name": comment.get("properties", {}).get("author", {}).get("name"),
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
        format_comment(comment) for comment in context_results  # type: ignore
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

    return_results(convert_to_table(str(context)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
