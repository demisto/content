import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time

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


def get_servicenow_record(table, record_id):
    snow_record = demisto.executeCommand('servicenow-get-record', {
        'id': record_id,
        'table_name': table
    })
    if is_error(snow_record):
        raise Exception('error in servicenow-get-record command')
    return snow_record[0]


def close_incident(incident, servicenow_close_code):
    demisto.info(f"closing incident {incident['id']} {incident['status']} {incident['type']}")
    demisto.executeCommand("closeInvestigation", {
        "id": incident['id'],
        "close_reason": "Resolved" if 'Resolved' in servicenow_close_code else "Other"
    })


def check_servicenow_and_close():
    incidents = get_opened_iot_incidents()
    if incidents:
        closed_count = 0
        for incident in incidents:
            servicenow_tablename = demisto.get(incident, 'CustomFields.servicenowtablename')
            servicenow_recordid = demisto.get(incident, 'CustomFields.servicenowrecordid')
            if servicenow_tablename:
                # if servicenow_tablename is defined, there's a corresponding ticket created in ServiceNow
                snow_record = get_servicenow_record(servicenow_tablename, servicenow_recordid)

                incident_state = demisto.get(snow_record, 'Contents.result.incident_state')
                close_code = demisto.get(snow_record, 'Contents.result.close_code')
                if incident_state and int(incident_state) == 7:
                    # 7 is the close state
                    close_incident(incident, close_code)
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
        return_error(f'Failed to execute iot-security-check-servicenow. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
