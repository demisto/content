from urllib.parse import quote, unquote

import demistomock as demisto
from CommonServerPython import *

""" MAIN FUNCTION """


def main():
    try:
        args = demisto.args()
        value = args.get("value")
        decoded_value = unquote(value)
        if argToBoolean(args.get("ignore_safe_character", "false")):
            return_results(quote(decoded_value, safe=""))
        else:
            return_results(quote(decoded_value, safe=args.get("safe_character", "/")))
    except Exception as exc:
        return_error(f"Failed to execute URLEncode.\nError: {exc!s}", error=exc)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()  # pragma: no cover
