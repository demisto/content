import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_comment(args: Dict[str, Any]) -> CommandResults:
    demisto.debug("adding comment")
    tags = argToList(args.get('tags', 'FROM XSOAR'))
    comment_body = args.get('comment', '')

    return CommandResults(
        readable_output=comment_body, mark_as_note=True, tags=tags
    )


def main():  # pragma: no cover
    try:
        demisto.debug('SplunkAddComment is being called')
        res = add_comment(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute SplunkAddComment. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
