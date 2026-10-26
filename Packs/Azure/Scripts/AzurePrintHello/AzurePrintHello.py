import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def print_hello() -> CommandResults:
    """Returns a basic hello message."""
    return CommandResults(readable_output="Hello")


def main() -> None:  # pragma: no cover
    try:
        return_results(print_hello())
    except Exception as e:
        return_error(f"Failed to execute AzurePrintHello. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
