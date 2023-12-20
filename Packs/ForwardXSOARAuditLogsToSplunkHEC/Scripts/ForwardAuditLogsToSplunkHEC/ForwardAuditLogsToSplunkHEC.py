import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime


def get_audit_logs(timeframe: int) -> Dict:
    demisto_version: str = get_demisto_version().get("version")
    demisto.debug(f'{demisto_version=}')
    if not demisto_version:
        raise ValueError('Could not get the version of XSOAR')

    timefrom = datetime.now() - timedelta(hours=int(timeframe))
    timestring = timefrom.strftime('%Y-%m-%dT%H:%M:%S')

    if demisto_version.startswith("6"):  # xsoar 6
        uri = "/settings/audits"
        body = {
            'size': 1000,
            "query": f"modified:>{timestring}"
        }
    else:  # xsoar 8
        uri = "/public_api/v1/audits/management_logs"
        body = {
            "request_data": {
                "search_to": 1000,
                "filters": [
                    {
                        'field': 'modification_time',
                        'operator': 'gte',
                        'value': date_to_timestamp(timestring)
                    },
                ]
            }
        }

    results = demisto.executeCommand('core-api-post', {"uri": uri, "body": body})
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
