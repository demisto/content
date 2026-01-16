import dateparser
import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *


def check_date(value: str, relative_date: str) -> bool:
    settings = {"TO_TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": False}
    v = dateparser.parse(value, settings=settings)  # type: ignore[arg-type]
    da = dateparser.parse(relative_date, settings=settings)  # type: ignore[arg-type]
    return v < da  # type: ignore


def main():
    try:
        args = demisto.args()
        value = args.get("left", "")
        relative_date = args.get("right", "")
        if value == "" or relative_date == "":
            raise ValueError("A required input is missing or malformed.")
        result = check_date(value, relative_date)
        human_readable = f'# BeforeRelativeDate\nThe date *{value}* {"*IS*" if result else "*IS NOT*"} before *{relative_date}*'

        return_results(CommandResults(outputs_prefix="BeforeRelativeDate", readable_output=human_readable, outputs=result))
    except Exception as e:
        return_error(message="Error Occured", error=str(e))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
