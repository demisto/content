import dateparser
import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *


def check_date(value, relative_date):
    settings = {"TO_TIMEZONE": "UTC", "RETURN_AS_TIMEZONE_AWARE": False}
    v = dateparser.parse(value, settings=settings)  # type: ignore[arg-type]
    da = dateparser.parse(relative_date, settings=settings)  # type: ignore[arg-type]
    return v < da  # type: ignore


def main():    
    args = demisto.args()
    value = args.get("left",None)
    if isinstance(value, list):
        value = value[0]
    relative_date = args.get("right",None)

    result = check_date(value, relative_date)
    human_readable = (
        f'# BetweenDates\nThe date *{value}* {"*IS*" if result else "*IS NOT*"} before *{relative_date}*'
    )

    return_results(CommandResults(outputs_prefix="BeforeRelativeDate", readable_output=human_readable, outputs=result))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
