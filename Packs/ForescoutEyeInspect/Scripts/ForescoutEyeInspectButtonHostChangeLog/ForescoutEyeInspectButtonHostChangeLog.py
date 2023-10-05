import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Dict


HOURS_AGO = 24


def get_hosts_changelog() -> Dict[str, Any]:
    incident_datetime = datetime.fromisoformat(demisto.incident()['occurred'])
    start_timestamp = (incident_datetime - timedelta(hours=HOURS_AGO)).isoformat()

    return demisto.executeCommand('forescout-ei-hosts-changelog-list',
                                  {'start_timestamp': start_timestamp})


def main():
    try:
        return_results(get_hosts_changelog())
    except Exception as e:
        demisto.error(fix_traceback_line_numbers(traceback.format_exc()))
        return_error(f'Failed to get pcap from Forescout EyeInspect incident.\nError:\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
