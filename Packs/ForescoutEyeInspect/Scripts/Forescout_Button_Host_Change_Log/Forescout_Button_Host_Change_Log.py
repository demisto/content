import demistomock as demisto
from CommonServerPython import *

HOURS_AGO = 24


def get_past_time(current_time, hours_ago=HOURS_AGO):
    new_time = demisto.executeCommand('GetTime', {
        'date': current_time,
        'dateFormat': 'ISO',
        'hoursAgo': hours_ago
    })[0]['Contents']

    return new_time


def main():
    try:
        start_timestamp = get_past_time(demisto.incident()['occurred'])
        res = demisto.executeCommand('forescout-ei-hosts-changelog-list',
                                     {'start_timestamp': start_timestamp})
        demisto.results(res)
    except Exception as e:
        demisto.error(fix_traceback_line_numbers(traceback.format_exc()))
        return_error(f'Failed to get pcap from Forescout EyeInspect incident.\nError:\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
