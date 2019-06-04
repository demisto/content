import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


# XDR_FIELDS
INCIDENT_ID_XDR_FIELD = "incident_id"
MANUAL_SEVERITY_XDR_FIELD = "manual_severity"
MANUAL_DESCRIPTION_XDR_FIELD = "manual_description"
ASSIGNED_USER_MAIL_XDR_FIELD = "assigned_user_mail"
HIGH_SEVERITY_ALERT_COUNT_XDR_FIELD = "high_severity_alert_count"
HOST_COUNT_XDR_FIELD = "host_count"
XDR_URL_XDR_FIELD = "xdr_url"
ASSIGNED_USER_PRETTY_NAME_XDR_FIELD = "assigned_user_pretty_name"
ALERT_COUNT_XDR_FIELD = "alert_count"
MED_SEVERITY_ALERT_COUNT_XDR_FIELD = "med_severity_alert_count"
USER_COUNT_XDR_FIELD = "user_count"
SEVERITY_XDR_FIELD = "severity"
LOW_SEVERITY_ALERT_COUNT_XDR_FIELD = "low_severity_alert_count"
STATUS_XDR_FIELD = "status"
DESCRIPTION_XDR_FIELD = "description"
RESOLVE_COMMENT_XDR_FIELD = "resolve_comment"
NOTES_XDR_FIELD = "notes"
CREATION_TIME_XDR_FIELD = "creation_time"
DETECTION_TIME_XDR_FIELD = "detection_time"
MODIFICATION_TIME_XDR_FIELD = "modification_time"


XDR_INCIDENT_FIELDS = [
    INCIDENT_ID_XDR_FIELD,
    MANUAL_SEVERITY_XDR_FIELD,
    MANUAL_DESCRIPTION_XDR_FIELD,
    ASSIGNED_USER_MAIL_XDR_FIELD,
    HIGH_SEVERITY_ALERT_COUNT_XDR_FIELD,
    HOST_COUNT_XDR_FIELD,
    XDR_URL_XDR_FIELD,
    ASSIGNED_USER_PRETTY_NAME_XDR_FIELD,
    ALERT_COUNT_XDR_FIELD,
    MED_SEVERITY_ALERT_COUNT_XDR_FIELD,
    USER_COUNT_XDR_FIELD,
    SEVERITY_XDR_FIELD,
    LOW_SEVERITY_ALERT_COUNT_XDR_FIELD,
    STATUS_XDR_FIELD,
    DESCRIPTION_XDR_FIELD,
    RESOLVE_COMMENT_XDR_FIELD,
    NOTES_XDR_FIELD,
    CREATION_TIME_XDR_FIELD,
    DETECTION_TIME_XDR_FIELD,
    MODIFICATION_TIME_XDR_FIELD
]


def trigger_xdr_script(incident_id, fields_mapping, interval, playbook_to_rerun, xdr_incident_path_in_context):
    interval = int(interval)

    fields_mapping = json.dumps(fields_mapping)

    res = demisto.executeCommand("ScheduleCommand", {
        'command': '''!XDRIncidentSync incident_id="%s" fields_mapping=`%s` interval="%s" playbook_name_to_run="%s" 
                      xdr_incident_context_path="%s" ''' % (incident_id, fields_mapping, interval, playbook_to_rerun,
                                                            xdr_incident_path_in_context),
        'cron': '*/{} * * * *'.format(interval)
    })

    if is_error(res):
        raise Exception(get_error(res))

    return res[0]["Contents"].get("id")


def main():
    try:
        fields_mapping = {}
        for xdr_field in XDR_INCIDENT_FIELDS:
            if xdr_field in demisto.args() and demisto.args().get(xdr_field) is not None:
                custom_field_in_demisto = demisto.args().get(xdr_field)
                fields_mapping[xdr_field] = custom_field_in_demisto

        interval = demisto.args().get("interval")
        incident_id = demisto.args().get("incident_id")
        playbook_to_rerun = demisto.args().get("playbook_to_rerun")
        xdr_incident_path_in_context = demisto.args().get("xdr_incident_path_in_context")

        scheduled_task_id = trigger_xdr_script(incident_id, fields_mapping, interval, playbook_to_rerun,
                                               xdr_incident_path_in_context)

        demisto.setContext("TriggerXDRIncidentSyncTaskID", scheduled_task_id)
        return_outputs(
            readable_output="Scheduled Task ID: {}".format(scheduled_task_id),
            outputs=None
        )
    except Exception as ex:
        return_error(ex)


if __name__ in ['__main__', 'builtins']:
    main()


