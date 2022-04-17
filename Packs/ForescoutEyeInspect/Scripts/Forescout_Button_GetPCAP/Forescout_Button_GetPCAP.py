import demistomock as demisto
from CommonServerPython import *


def main():
    alert_id = demisto.incident()['CustomFields'].get('alertid')

    if not alert_id:
        return_error('Forescout EyeInspect alert ID is missing inside the incident.')

    try:
        res = demisto.executeCommand('forescout-ei-alert-pcap-get', {'alert_id': alert_id})
        demisto.results(res)
    except Exception as e:
        demisto.error(fix_traceback_line_numbers(traceback.format_exc()))
        return_error(f'Failed to get pcap from Forescout EyeInspect incident.\nError:\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
