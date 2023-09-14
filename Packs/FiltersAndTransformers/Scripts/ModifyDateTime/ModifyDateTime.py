import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
import dateparser
from typing import Optional


def apply_variation(original_datetime: datetime, variation: str) -> Optional[datetime]:
    try:
        new_time = dateparser.parse(variation, settings={'RELATIVE_BASE': original_datetime})
        assert new_time is not None, f'could not parse {variation}'
        new_time = new_time.replace(tzinfo=original_datetime.tzinfo)
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
    new_time = apply_variation(original_datetime, variation)  # type: ignore
    if isinstance(new_time, datetime):
        return_results(new_time.isoformat())
    else:
        return_error('Invalid variation specified')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
