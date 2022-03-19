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

WRONG_DATE_RANGE_HINT = '''
### You cannot drive a vehicle without a driver's license.
### You cannot practice medicine without a medical license.
### You cannot practice law without a law license.
### You cannot practice security without an XSOAR license.
'''

INVALID_LICENSE_GIFS = [
    # 'https://media.giphy.com/media/kDqvtJtxMTFRcqR2r4/giphy.gif',
    'https://media.giphy.com/media/l2Jegpw00OmTdz32w/giphy.gif',  # ok
    'https://media.giphy.com/media/frTCmCyOReJC2AxN7A/giphy.gif',
    'https://media.giphy.com/media/lPQvP5lfjHpapvrssI/giphy.gif',
    'https://media.giphy.com/media/VIQpKu2WDTempgOKHK/giphy.gif',  # ok
    'https://media.giphy.com/media/3ohhwqMZYXMmGNZEgo/giphy.gif',
]

INVALID_LICENSE_HINT = '''
# Welcome to the twilight zone
#### Looks like we run out of money and lost our XSOAR license.

#### Don't be alarmed, we can handle it together.
#### We've asked sales for a new license.
#### Go get it from the [secret place]({incidents_page})
'''

SUCCESS_GIFS = [
    # 'https://media.giphy.com/media/a0h7sAqON67nO/giphy.gif',
    # 'https://media.giphy.com/media/XreQmk7ETCak0/giphy.gif',
    # 'https://media.giphy.com/media/gd0Dqg6rYhttBVCZqd/giphy.gif',
    # 'https://media.giphy.com/media/Q81NcsY6YxK7jxnr4v/giphy.gif',
    'https://media.giphy.com/media/MCZ39lz83o5lC/giphy.gif',
    'https://media.giphy.com/media/fvlGGxUci1BiJuBET9/giphy.gif',
    'https://media.giphy.com/media/Wq3gAYYuERDSU9DAbT/giphy.gif',
]

SUCCESS_MESSAGE = '''
Now that you have the license issue sorted out.
you have the power of automation!
please help me with my failing task.

> with great power comes great responsibility!
    - B. parker
'''

VICTORY_MESSAGE = '''
'''


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
    license_id = demisto.getLicenseID()
    demisto.info(f'license info: {license_id}')

    return license_id == 'CUID1337deadbeef1337CUID'


def create_starting_incident():
    res = execute_command('getIncidents', args={'name': 'Springdfield', 'raw-reponse': 'true'})
    if res['total']:
        # already created an incident
        return

    res = execute_command('createNewIncident', args={
        'name': 'Springfield Nuclear Power Plant',
        'severity': IncidentSeverity.CRITICAL,
        'type': "D'oh!⚠️",
    })


def get_incident_with_license():
    res = execute_command('getIncidents', args={'name': 'Get Your License Here', 'raw-response': 'true'})
    if res['total'] != 1:
        return '404'

    return res['data'][0]['id']


def v_for_vendetta(time_from: datetime, time_to: datetime):
    validate = [t.day == 5 and t.month == 11 for t in (time_from, time_to)]

    if any(validate):
        return '\n\n> **Remember remember the fifth of November**\n - V for Vendetta'

    return ''


def is_wednesday(time_from: datetime, time_to: datetime):
    validate = [t.weekday == 2 for t in (time_from, time_to)]

    if any(validate):
        return '\n\nP.S.\nAre you wearing Bordeaux? your chosen dates say you should.'

    return ''


# MAIN FUNCTION #


def main():
    try:
        args = demisto.args()
        demisto.info(str(args))
        gif_or_text = args.get('gif_or_text', 'text')

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

        if is_valid_license():
            if gif_or_text == 'text':
                create_starting_incident()
                text = SUCCESS_MESSAGE
            else:
                text = (
                f'![]({random.choice(SUCCESS_GIFS)})'
                f'![]({random.choice(SUCCESS_GIFS)})'
                f'![]({random.choice(SUCCESS_GIFS)})'
            )
        elif is_correct_date_range(from_times, to_times):
            if gif_or_text == 'text':
                demisto_urls = demisto.demistoUrls()
                incidents_page = 'acc_Tier2#/incidents' if 'acc_Tier2' in demisto_urls['server'] else '#/incidents'
                text = INVALID_LICENSE_HINT.format(incidents_page=incidents_page)
            else:
                text = (
                f'![]({random.choice(INVALID_LICENSE_GIFS)})'
                f'![]({random.choice(INVALID_LICENSE_GIFS)})'
                f'![]({random.choice(INVALID_LICENSE_GIFS)})'
            )
        else:
            if gif_or_text == 'text':
                text = WRONG_DATE_RANGE_HINT
            else:
                text = WRONG_DATE_RANGE_GIFS

        return_results(TextWidget(text))

    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Widget. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
