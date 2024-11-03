import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any


def get_pcap() -> dict[str, Any]:
    alert_id = demisto.incident()['CustomFields'].get('alertid')
    if not alert_id:
        return_error('Forescout EyeInspect alert ID is missing inside the incident.')

    return demisto.executeCommand('forescout-ei-alert-pcap-get', {'alert_id': alert_id})


def main():
    try:
        return_results(get_pcap())
    except Exception as e:
        demisto.error(fix_traceback_line_numbers(traceback.format_exc()))
        return_error(f'Failed to get pcap from Forescout EyeInspect incident.\nError:\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
