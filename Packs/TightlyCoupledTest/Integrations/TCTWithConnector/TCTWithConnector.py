import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():  # pragma: no cover
    command = demisto.command()
    if command == "test-module":
        return_results("ok")
    elif command == "tct-with-connector-ping":
        return_results("pong")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
