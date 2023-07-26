import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_comment(args: Dict[str, Any]) -> CommandResults:
    comment_body = args.get('comment', '')
    tags = argToList(args.get('tags', ''))
    return CommandResults(
        readable_output=comment_body, mark_as_note=True, tags=tags or None
    )


def main():  # pragma: no cover
    try:
        demisto.debug('JiraAddComment is being called')
        res = add_comment(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute JiraAddComment. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
