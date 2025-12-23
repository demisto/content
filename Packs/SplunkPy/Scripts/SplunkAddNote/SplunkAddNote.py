import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_note(args: Dict[str, Any]) -> CommandResults:
    demisto.debug("adding note")
    tags = argToList(args.get("tags", ["FROM XSOAR"]))
    note_body = args.get("note", "")

    return CommandResults(readable_output=note_body, mark_as_note=True, tags=tags)


def main():  # pragma: no cover
    try:
        demisto.debug("SplunkAddNote is being called")
        res = add_note(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f"Failed to execute SplunkAddNote. Error: {ex!s}")


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
