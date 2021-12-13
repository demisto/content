""" A widget that have 3 stages:

1) invalid time range: return an error message.
2) valid time range:
    2.1) invalid license: return a hint for a new license download link.

"""

import pytz
import random

import demistomock as demisto
from CommonServerPython import *

WRONG_DATE_RANGE_GIFS = (
    '![](https://media.giphy.com/media/3dkPNxMiJWOCWvqGWY/giphy.gif)'
    '![](https://user-images.githubusercontent.com/30797606/103149761-33c18b80-4775-11eb-8cdd-81d3142ea4a7.jpg)'
    '![](https://media.giphy.com/media/fUwOs80ja3sTPpjndh/giphy.gif)'
)

INVALID_LICENSE_GIFS = [
    # 'https://media.giphy.com/media/kDqvtJtxMTFRcqR2r4/giphy.gif',
    'https://media.giphy.com/media/l2Jegpw00OmTdz32w/giphy.gif',  # ok
    'https://media.giphy.com/media/frTCmCyOReJC2AxN7A/giphy.gif',
    'https://media.giphy.com/media/lPQvP5lfjHpapvrssI/giphy.gif',
    'https://media.giphy.com/media/VIQpKu2WDTempgOKHK/giphy.gif',  # ok
    'https://media.giphy.com/media/3ohhwqMZYXMmGNZEgo/giphy.gif',
]

SUCCESS_GIFS = [
    'https://media.giphy.com/media/a0h7sAqON67nO/giphy.gif',
    'https://media.giphy.com/media/XreQmk7ETCak0/giphy.gif',
    'https://media.giphy.com/media/gd0Dqg6rYhttBVCZqd/giphy.gif',
    'https://media.giphy.com/media/Wq3gAYYuERDSU9DAbT/giphy.gif',
    'https://media.giphy.com/media/Q81NcsY6YxK7jxnr4v/giphy.gif',
]


def utc_to_time(naive: datetime, time_zone: str = 'Asia/Tel_Aviv'):
    return naive.replace(tzinfo=pytz.utc).astimezone(pytz.timezone(time_zone))


def is_correct_date_range(from_times: Set[str], to_times: Set[str]):
    validate = [
        '2020-10-31' in from_times,
        '2020-12-25' in to_times,
    ]

    demisto.info(f'WidgetLicenseErrorText - check_time_frame: {validate}')
    return all(validate)


def is_valid_license_temp(from_times: Set[str], to_times: Set[str]):
    validate = [
        '2020-12-01' in from_times,
        '2020-12-25' in to_times,
    ]

    demisto.info(f'WidgetLicenseErrorText - is_correct_date_range: {validate}')
    return all(validate)


def is_valid_license():
    res = demisto.internalHttpRequest('GET', '/license')
    license_info = res.get('body')

    demisto.info(f'license info:\n {license_info}')
    if dict_safe_get(license_info, ['customFields', 'EscapeRoomKey']):
        return True

    return False


# MAIN FUNCTION #


def main():
    try:
        args = demisto.args()
        demisto.info(str(args))
        # Sometimes UTC time and local time doesn't return the same date in XSOAR when choosing specific time frames.
        time_from = dateparser.parse(args.get('from', '0001-01-01T00:00:00Z'))
        local_time_from = utc_to_time(time_from)
        from_times = {
            time_from.date().strftime('%Y-%m-%d'),
            local_time_from.date().strftime('%Y-%m-%d'),
        }
        time_to = dateparser.parse(args.get('to', '0001-01-01T00:00:00Z'))
        local_time_to = utc_to_time(time_to)
        to_times = {
            time_to.date().strftime('%Y-%m-%d'),
            local_time_to.date().strftime('%Y-%m-%d'),
        }

        if not is_correct_date_range(from_times, to_times):
            gifs = WRONG_DATE_RANGE_GIFS
        # elif not is_valid_license():
        elif not is_valid_license_temp(from_times, to_times):
            gifs = (
                f'![]({random.choice(INVALID_LICENSE_GIFS)})'
                f'![]({random.choice(INVALID_LICENSE_GIFS)})'
                f'![]({random.choice(INVALID_LICENSE_GIFS)})'
            )
        else:
            gifs = (
                f'![]({random.choice(SUCCESS_GIFS)})'
                f'![]({random.choice(SUCCESS_GIFS)})'
                f'![]({random.choice(SUCCESS_GIFS)})'
            )

        return_results(TextWidget(gifs))

    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Widget. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
