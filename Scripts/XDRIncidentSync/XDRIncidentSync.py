import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from dateutil import parser

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


def compare_incident_in_demisto_vs_xdr_context(incident_in_demisto, xdr_incident_in_context, incident_id, fields_mapping):
    modified_in_demisto = parser.parse(incident_in_demisto.get("modified")).timestamp() * 1000
    modified_in_xdr_in_context = int(xdr_incident_in_context.get("modification_time"))

    incident_in_demisto_was_modified = False

    xdr_update_args = {
        "incident_id": incident_id
    }

    if modified_in_demisto > modified_in_xdr_in_context:
        if ASSIGNED_USER_MAIL_XDR_FIELD in fields_mapping:
            field_name_in_demisto = fields_mapping[ASSIGNED_USER_MAIL_XDR_FIELD]
            assigned_user_mail_current = incident_in_demisto.get("CustomFields").get(field_name_in_demisto)
            assigned_user_mail_previous = xdr_incident_in_context[ASSIGNED_USER_MAIL_XDR_FIELD]

            if assigned_user_mail_current != assigned_user_mail_previous:
                incident_in_demisto_was_modified = True
                xdr_update_args[ASSIGNED_USER_MAIL_XDR_FIELD] = assigned_user_mail_current

        if ASSIGNED_USER_PRETTY_NAME_XDR_FIELD in fields_mapping:
            field_name_in_demisto = fields_mapping[ASSIGNED_USER_PRETTY_NAME_XDR_FIELD]
            assigned_user_pretty_name_current = incident_in_demisto.get("CustomFields").get(field_name_in_demisto)
            assigned_user_pretty_name_previous = xdr_incident_in_context[ASSIGNED_USER_PRETTY_NAME_XDR_FIELD]

            if assigned_user_pretty_name_current != assigned_user_pretty_name_previous:
                incident_in_demisto_was_modified = True
                xdr_update_args[ASSIGNED_USER_PRETTY_NAME_XDR_FIELD] = assigned_user_pretty_name_current

        if STATUS_XDR_FIELD in fields_mapping:
            field_name_in_demisto = fields_mapping[STATUS_XDR_FIELD]
            status_current = incident_in_demisto.get("CustomFields").get(field_name_in_demisto)
            status_previous = xdr_incident_in_context[STATUS_XDR_FIELD]

            if status_current != status_previous:
                incident_in_demisto_was_modified = True
                xdr_update_args[STATUS_XDR_FIELD] = status_current

        if MANUAL_SEVERITY_XDR_FIELD in fields_mapping:
            field_name_in_demisto = fields_mapping[MANUAL_SEVERITY_XDR_FIELD]

            severity_previous = xdr_incident_in_context[MANUAL_SEVERITY_XDR_FIELD]

            if field_name_in_demisto == "severity":
                # if field mapped to original demisto severity field then we should get it directly from incident
                severity_current = incident_in_demisto.get(field_name_in_demisto)

                severity_mapping = {
                    0: None,
                    1: "low",
                    2: "medium",
                    3: "high"
                }
                if severity_mapping[severity_current] != severity_previous:
                    incident_in_demisto_was_modified = True
                    xdr_update_args[MANUAL_SEVERITY_XDR_FIELD] = severity_mapping[severity_current]

            else:
                severity_current = incident_in_demisto.get("CustomFields").get(field_name_in_demisto)

                if severity_current != severity_previous:
                    incident_in_demisto_was_modified = True
                    xdr_update_args[MANUAL_SEVERITY_XDR_FIELD] = severity_current

        if RESOLVE_COMMENT_XDR_FIELD in fields_mapping:
            field_name_in_demisto = fields_mapping[RESOLVE_COMMENT_XDR_FIELD]
            resolve_comment_current = incident_in_demisto.get("CustomFields").get(field_name_in_demisto)
            resolve_comment_previous = xdr_incident_in_context[RESOLVE_COMMENT_XDR_FIELD]

            if resolve_comment_current != resolve_comment_previous:
                incident_in_demisto_was_modified = True
                xdr_update_args[RESOLVE_COMMENT_XDR_FIELD] = resolve_comment_current

    return incident_in_demisto_was_modified, xdr_update_args


def compare_incident_in_xdr_vs_previous_xdr_in_context(incident_in_xdr, xdr_incident_in_context, fields_mapping):
    modified_in_xdr = int(incident_in_xdr.get("modification_time"))
    modified_in_xdr_in_context = int(xdr_incident_in_context.get("modification_time"))

    incident_in_xdr_was_modified = False

    demisto_update_args = {}
    if modified_in_xdr > modified_in_xdr_in_context:

        for field_in_xdr in XDR_INCIDENT_FIELDS:
            if field_in_xdr in fields_mapping:

                current_value = incident_in_xdr.get(field_in_xdr)
                previous_value = xdr_incident_in_context.get(field_in_xdr)

                if current_value != previous_value:
                    incident_in_xdr_was_modified = True
                    field_name_in_demisto = fields_mapping[field_in_xdr]
                    demisto_update_args[field_name_in_demisto] = current_value

    return incident_in_xdr_was_modified, demisto_update_args


def xdr_incident_sync(incident_id, fields_mapping, playbook_name_to_run, xdr_incident_context_path):
    if isinstance(fields_mapping, str):
        try:
            fields_mapping = json.loads(fields_mapping)
        except:
            raise Exception('Failed to parse fields_mapping argument. fields_mapping should be a JSON/dict where '
                            'the keys are the field names in Demisto and values field names in XDR')

    res = demisto.executeCommand("xdr-get-incidents", {"incident_id_list": incident_id, "limit": 1, "page": 0})
    if is_error(res):
        demisto.results(res)
        return

    incident_in_xdr = res[0]["Contents"][0]
    if not incident_in_xdr:
        return_error("Error - for some reason xdr-get-incidents didn't return any incident from xdr with id={}"
                     .format(incident_id))
        return

    incident_in_demisto = demisto.incidents()[0]
    if not incident_in_demisto:
        return_error("Error - demisto.incidents()[0] expected to return current incident "
                     "from context but returned None")
        return

    xdr_incident_in_context = demisto.get(demisto.context(), xdr_incident_context_path)
    if isinstance(xdr_incident_in_context, list):
        # if there a list in the context then we will peak only the incident with the relevant incident id
        for incident in xdr_incident_in_context:
            if incident.get('incident_id') == incident_id:
                xdr_incident_in_context = incident

    if not xdr_incident_in_context:
        # if no incident in the context found then dont do compare
        return_error("No XDR incident found in context")
        return

    incident_in_demisto_was_modified, xdr_update_args = compare_incident_in_demisto_vs_xdr_context(
                                                                                    incident_in_demisto,
                                                                                    xdr_incident_in_context,
                                                                                    incident_id, fields_mapping)

    if incident_in_demisto_was_modified:
        # update xdr and finish the script
        demisto.debug("the incident in demisto was modified, updating the incident in xdr accordingly. ")
        demisto.debug("xdr_update_args: {}".format(json.dumps(xdr_update_args, indent=4)))
        res = demisto.executeCommand("xdr-update-incident", xdr_update_args)
        if is_error(res):
            raise ValueError(get_error(res))

        # res = demisto.executeCommand("xdr-get-incidents", {"incident_id_list": incident_id})
        # if is_error(res):
        #     raise ValueError(get_error(res))
        #
        # # we update the xdr incident in Demisto context
        # return_outputs(None, res[0]["EntryContext"])

    incident_in_xdr_was_modified, demisto_update_args = compare_incident_in_xdr_vs_previous_xdr_in_context(
                                                                                    incident_in_xdr,
                                                                                    xdr_incident_in_context,
                                                                                    fields_mapping)

    if incident_in_xdr_was_modified:
        demisto.debug("the incident in xdr was modified, updating the incident in demisto")
        demisto.debug("demisto_update_args: {}".format(json.dumps(demisto_update_args, indent=4)))
        res = demisto.executeCommand("setIncident", demisto_update_args)
        if is_error(res):
            raise ValueError(get_error(res))

        # stop sync
        scheduled_task_id = demisto.get(demisto.context(), "TriggerXDRIncidentSyncTaskID")
        if not scheduled_task_id or "@" not in scheduled_task_id:
            raise ValueError("TriggerXDRIncidentSyncTaskID is not found in the context")

        res = demisto.executeCommand("StopScheduledTask", {"taskID": scheduled_task_id})
        if is_error(res):
            raise ValueError(get_error(res))

        # rerun the playbook
        demisto.executeCommand("setPlaybook", {"name": playbook_name_to_run})

    if not incident_in_xdr_was_modified and not incident_in_demisto_was_modified:
        return_outputs("Nothing to sync.", None)
    elif incident_in_demisto_was_modified:
        return_outputs("Incident in Demisto was modified, updating incident in XDR accordingly.\n\n{}".format(xdr_update_args), None)
    elif incident_in_xdr_was_modified:
        return_outputs("Incident in XDR was modified, updating incident in Demisto accordingly.\n\n{}".format(demisto_update_args), None)


def main():
    fields_mapping = demisto.args().get('fields_mapping')
    playbook_name_to_run = demisto.args().get('playbook_name_to_run')
    incident_id = demisto.args().get('incident_id')
    xdr_incident_context_path = demisto.args().get('xdr_incident_context_path')

    xdr_incident_sync(incident_id, fields_mapping, playbook_name_to_run, xdr_incident_context_path)


if __name__ == 'builtins':
    main()
