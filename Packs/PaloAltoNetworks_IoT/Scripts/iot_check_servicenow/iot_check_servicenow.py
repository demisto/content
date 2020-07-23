import time

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]


def get_opened_iot_incidents():
    resp = demisto.executeCommand('getIncidents', {
        'query': '-status:Closed and (type:"IoT Alert" or type:"IoT Vulnerability")',
        'sort': 'created.desc',
        'size': 1000
    })
    if is_error(resp):
        raise Exception('error in getIncidents command')
    return demisto.get(resp[0], 'Contents.data')


def check_servicenow_and_close():
    incidents = get_opened_iot_incidents()
    if incidents:
        closed_count = 0
        for incident in incidents:
            servicenow_tablename = demisto.get(incident, 'CustomFields.servicenowtablename')
            servicenow_recordid = demisto.get(incident, 'CustomFields.servicenowrecordid')
            if servicenow_tablename:
                # if servicenow_tablename is defined, there's a corresponding ticket created in ServiceNow
                snow_record = demisto.executeCommand('servicenow-get-record', {
                    'id': servicenow_recordid,
                    'table_name': servicenow_tablename
                })
                if is_error(snow_record):
                    raise Exception('error in servicenow-get-record command')

                incident_state = demisto.get(snow_record[0], 'Contents.result.incident_state')
                close_code = demisto.get(snow_record[0], 'Contents.result.close_code')
                if incident_state and int(incident_state) == 7:
                    # 7 is the close state
                    demisto.info(f"closing incident {incident['id']} {incident['status']} {incident['type']}")
                    demisto.executeCommand("closeInvestigation", {
                        "id": incident['id'],
                        "closeReason": "Resolved" if 'Resolved' in close_code else "Other"
                    })
                    closed_count += 1
                else:
                    demisto.debug(f"keep incident {incident['id']} {incident['status']}: {incident_state}")

                # not going to spam the ServiceNow server
                time.sleep(1)
        return f'found {len(incidents)} incidents, closed {closed_count} incidents'
    return 'no incidents found'


def main():
    try:
        demisto.results(check_servicenow_and_close())
    except Exception as ex:
        demisto.error(f'Failed to execute iot-security-check-servicenow. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
