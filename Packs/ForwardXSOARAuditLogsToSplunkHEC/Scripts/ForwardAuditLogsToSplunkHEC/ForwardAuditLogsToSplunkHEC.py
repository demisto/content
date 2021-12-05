from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_audit_logs(timeframe: int) -> Dict:
    timefrom = datetime.now() - timedelta(hours=int(timeframe))
    timestring = timefrom.strftime('%Y-%m-%dT%H:%M:%S')
    parameters = {"uri": "/settings/audits",
                  "body": {"size": 1000,
                           "query": f"modified:>{timestring}"}}
    results = demisto.executeCommand('demisto-api-post', parameters)
    return results[0]['Contents']['response']


def submitlogs_to_splunk_hec(auditlogs):
    parameters = {"event": auditlogs}
    results = demisto.executeCommand('splunk-submit-event-hec', parameters)
    return results


def main():
    try:
        auditlogs = get_audit_logs(demisto.args().get('timeframe'))
        response = submitlogs_to_splunk_hec(auditlogs)
        return_results(response[0]['Contents'])
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
