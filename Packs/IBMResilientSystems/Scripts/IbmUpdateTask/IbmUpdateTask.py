import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def update_task(args: Dict[str, Any]) -> CommandResults:
    demisto.debug(f"update_task {args=}")
    results = demisto.executeCommand('rs-update-task', args=args)
    demisto.debug(f"update_task {results=}")

    readable_output = results[0]["HumanReadable"] \
        if (isinstance(results, list)
            and len(results) > 0
            and results[0]["HumanReadable"]) \
        else "Error updating task ID."
    return CommandResults(
        readable_output=readable_output
    )


def main():  # pragma: no cover
    try:
        res = update_task(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute IbmUpdateTask. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
