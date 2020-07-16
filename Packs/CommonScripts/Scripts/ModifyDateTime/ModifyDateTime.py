import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
import dateparser


def apply_variation(original_datetime: datetime = None, variation: str = None) -> datetime:
    new_time = None
    try:
        new_time = dateparser.parse(variation, settings={'RELATIVE_BASE': original_datetime})
    except Exception as err:
        return_error(f"Error adding variation to the date / time - {err}")
    return new_time


def main():
    args = demisto.args()
    value = args.get('value')
    try:
        original_datetime = dateparser.parse(value)
    except Exception as err:
        return_error(f"Error with input date / time - {err}")

    variation = args.get('variation')
    new_time = apply_variation(original_datetime, variation)
    if not new_time:
        return_error('Invalid variation specified')
    demisto.results(new_time.isoformat())


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
