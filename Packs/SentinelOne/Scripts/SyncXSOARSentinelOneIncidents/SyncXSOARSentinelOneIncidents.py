import json
from CommonServerPython import *
# Map determining the S1 Threat Info fields
S1_XSOAR_THREAT_INFO_MAPPING = {
    "analystVerdictDescription": {"name": "closeReason", "type": "str"},
    "confidenceLevel": {"name": "externalconfidence", "type": "list"},
    "threatName": {"name": "threatname", "type": "str"},
    "classification": {"name": "classification", "type": "str"},
    "externalTicketId": {"name": "ticketnumber", "type": "str"},
    "md5": {"name": "filemd5", "type": "list"},
    "sha256": {"name": "filesha256", "type": "list"},
    "sha1": {"name": "filesha1", "type": "list"},
    "filePath": {"name": "filepath", "type": "str"},
    "fileSize": {"name": "filesize", "type": "str"},
    "mitigationStatusDescription": {"name": "externalstatus", "type": "list"},
}

# Map determining the S1 Agent Detections Info fields
S1_XSOAR_AGENT_DETECTION_MAPPING = {
    "agentVersion": {"name": "agentid", "type": "list"},
    "externalIp": {"name": "deviceexternalip", "type": "str"},
    "agentIpV4": {"name": "devicelocalip", "type": "str"},
    "agentLastLoggedInUserName": {"name": "deviceusername", "type": "str"},
    "agentOsName": {"name": "deviceosname", "type": "list"}
}

# Map determining the S1 Agent Info fields
S1_XSOAR_AGENT_INFO_MAPPING = {
    "agentId": {"name": "agentid", "type": "str"},
    "agentComputerName": {"name": "devicename", "type": "str"},
    "agentDomain": {"name": "domainname", "type": "str"},
    "agentOsType": {"name": "ostype", "type": "str"}
}

# Map pointing to Mappings for threat information categories for XSOAR fields
S1_THREAT_INCIDENT_MAP = {
    "threatInfo": S1_XSOAR_THREAT_INFO_MAPPING,
    "agentDetectionInfo": S1_XSOAR_AGENT_DETECTION_MAPPING,
    "agentRealtimeInfo": S1_XSOAR_AGENT_INFO_MAPPING
}

# Mapping of Incident Status from S1 : XSOAR
S1_XSOAR_STATUS_MAPPING = {"resolved": "2", "unresolved": "1", "in_progress": "1"}

# Mapping of Incident Status from XSAOR : S1
XSOAR_S1_STATUS_MAPPING = {"1": "unresolved", "2": "resolved"}


def get_xsoar_s1_incidents(page, size):
    """
        Creating a map of xsoar incidents
        This map will extract S1 incident id from xsoar incident's Label
        Output Map: {"XSOAR-Inc-Id":"{Incident-Info-Dict}"}
    """

    xsoar_s1_incidents: dict = {}

    try:
        xsoar_incidents_resp = demisto.executeCommand("getIncidents", {"page": page, "size": size})
        xsoar_incidents = xsoar_incidents_resp[0].get("Contents").get("data")
        if xsoar_incidents is None or xsoar_incidents == '':
            return None

        for xsoar_incident in xsoar_incidents:
            incident_source = xsoar_incident.get('sourceBrand')
            if xsoar_incident.get('labels') and incident_source == 'SentinelOne V2':
                s1_threat_id = None

                xsoar_incident_info = {}
                for xsoar_s1_incident_attr in xsoar_incident.get("labels"):
                    if xsoar_s1_incident_attr.get("type") == "id":
                        s1_threat_id = xsoar_s1_incident_attr.get("value")

                    if xsoar_s1_incident_attr.get("type") == "threatInfo":
                        xsoar_incident_threatinfo = json.loads(xsoar_s1_incident_attr.get("value"))

                        # If the threatId is not present for S1 inside XSOAR inc, then we skip.
                        if not xsoar_incident_threatinfo.get('threatId'):
                            continue

                        # Using these fields to repopulate the Labels to keep everything in sync
                        xsoar_incident_info.update({'xsoarIncSourceInstance': xsoar_incident.get('sourceInstance')})
                        xsoar_incident_info.update({'xsoarIncSourceBrand': xsoar_incident.get('sourceBrand')})

                        # Using these fields to decide when to update the incident and close the incident in XSOAR
                        xsoar_incident_info.update({'xsoarIncStatus': str(xsoar_incident.get('status'))})
                        xsoar_incident_info.update({'xsoarIncModified': xsoar_incident.get('modified')})
                        xsoar_incident_info.update({'xsoarCloseReason': xsoar_incident.get('closeReason')})

                        # Using these fields to compare the incidents xsoar:s1
                        xsoar_incident_info.update({'threatId': xsoar_incident_threatinfo.get('threatId')})
                        xsoar_incident_info.update({'updatedAt': xsoar_incident_threatinfo.get('updatedAt')})

                    if xsoar_s1_incident_attr.get("type") == "XSOARJobUpdated":
                        xsoar_incident_info.update({'XSOARJobUpdated': "Yes"})

                if s1_threat_id not in xsoar_s1_incidents.keys():
                    xsoar_s1_incidents[xsoar_incident.get('id')] = xsoar_incident_info

    except Exception as ex:
        demisto.error(f'Exception when getting data: {str(ex)}')

    return xsoar_s1_incidents


def extract_s1_threat_ids(xsoar_s1_incidents):
    for s1_info in xsoar_s1_incidents.values():
        s1_threat_ids = [s1_info.get("threatId") for s1_info in xsoar_s1_incidents.values()]
    s1_threat_ids = list(filter(lambda threat_id: threat_id is not None, set(s1_threat_ids)))
    return s1_threat_ids


def close_xsoar_incident(xsoar_incident_id):
    # Close the inc because - S1 has 3 possible statuses and XSOAR 2. When you create incident its Active
    # Check this MAP - S1_XSOAR_STATUS_MAPPING, if S1 incident is closed, we close in XSOAR as well.
    close_inc_response = demisto.executeCommand("closeInvestigation", {"id": xsoar_incident_id})
    return close_inc_response


def prepare_xsoar_inc_update_fields(xsoar_incident_id, s1_threat_info):
    xsoar_inc_update_fields = {"id": xsoar_incident_id}
    # Created the Labels field
    inc_labels = [
        {inc_label_tag: json.dumps(inc_label_tag_value)} for inc_label_tag, inc_label_tag_value in s1_threat_info.items()]
    xsoar_inc_update_fields.update({'labels': inc_labels})

    # Creating the update payload for incident fields
    for s1_threat_info_category, s1_threat_info_category_details in s1_threat_info.items():
        # If the Threat Category is present as per MAP, continue
        category_map = S1_THREAT_INCIDENT_MAP.get(s1_threat_info_category)
        if category_map:
            for threat_field, threat_field_value in s1_threat_info_category_details.items():
                xsoar_field_name = category_map.get(threat_field, {}).get("name")
                xsoar_field_type = category_map.get(threat_field, {}).get("type")
                if xsoar_field_name and threat_field_value:
                    xsoar_field_list = []
                    xsoar_field_list.append(str(threat_field_value))
                    xsoar_inc_update_fields.update(
                        {xsoar_field_name: str(threat_field_value) if xsoar_field_type == "str" else xsoar_field_list})

    return xsoar_inc_update_fields


def sync_s1_xsoar_incidents():
    """
        Running this Automation for 100 incidents at a time.
        Reason : S1 threats info API takes 100 as max list if threat ids
    """
    total_incidents = 0
    updated_incidents = 0
    page = 0
    size = 100
    while True:
        try:
            xsoar_s1_incidents = get_xsoar_s1_incidents(page, size)
            if not xsoar_s1_incidents:
                break
            total_incidents += len(xsoar_s1_incidents)

            xsoar_s1_threat_ids = extract_s1_threat_ids(xsoar_s1_incidents)
            latest_s1_threats_info = get_s1_threat_data(xsoar_s1_threat_ids)

            for xsoar_incident_id, incident_info in xsoar_s1_incidents.items():
                for latest_s1_threat_info in latest_s1_threats_info:
                    latest_s1_threat_contents = latest_s1_threat_info.get("Contents")
                    s1_inc_threat_info = latest_s1_threat_contents.get("threatInfo")

                    # Getting the last modified time for S1 incident and XSOAR Incident's Label
                    s1_inc_modified_time = s1_inc_threat_info.get("updatedAt")
                    xsoar_s1_inc_modified_time = incident_info.get("updatedAt")

                    s1_xsoar_threat_id = incident_info.get("threatId")
                    if latest_s1_threat_contents.get("id") == s1_xsoar_threat_id and \
                       (s1_inc_modified_time > xsoar_s1_inc_modified_time):
                        # The Incident in XSOAR is present in S1, processing further
                        # Updating the labels response for next pull, only if the incident on S1 was modified
                        # Update the incident status if it has changed on S1 and getting XSOAR and S1 incidents status
                        s1_incident_status = s1_inc_threat_info.get("incidentStatus")
                        xsoar_incident_status = incident_info.get("xsoarIncStatus")
                        if S1_XSOAR_STATUS_MAPPING.get(s1_incident_status) != xsoar_incident_status and \
                           xsoar_incident_status != "2":
                            # Not closing already closed incident in XSOAR
                            close_xsoar_incident(xsoar_incident_id)

                        latest_s1_threat_contents.update({"Brand": incident_info.get("xsoarIncSourceBrand")})
                        latest_s1_threat_contents.update({"Instance": incident_info.get("xsoarIncSourceInstance")})
                        latest_s1_threat_contents.update({"XSOARJobUpdated": "Yes"})

                        xsoar_incident_update_fields = prepare_xsoar_inc_update_fields(
                            xsoar_incident_id, latest_s1_threat_contents)
                        update_xsoar_incident(xsoar_incident_update_fields)
                        updated_incidents += 1

                        break
            # Going for the next Iteration / Page
            page += 1
        except Exception as ex:
            demisto.error(f'Exception when getting data: {str(ex)}')

    output_res = {"Total Incidents": total_incidents, "Synced Incidents(from sentinelone to xsoar)": updated_incidents}
    return CommandResults(readable_output=tableToMarkdown(
        "Results- \nSynced Incidents will show how many incidents changed per run of playbook.",
        output_res, headers=("Total Incidents", "Synced Incidents(from sentinelone to xsoar)"),
        headerTransform=string_to_table_header))


def sync_xsoar_s1_incidents():
    """
        Incident sync from XSOAR to S1
    """
    page = 0
    size = 100
    total_incidents = 0
    updated_incidents = 0
    while True:
        try:
            xsoar_s1_incidents = get_xsoar_s1_incidents(page, size)
            if not xsoar_s1_incidents:
                break
            total_incidents += len(xsoar_s1_incidents)
            xsoar_s1_threat_ids = extract_s1_threat_ids(xsoar_s1_incidents)
            latest_s1_threats_info = get_s1_threat_data(xsoar_s1_threat_ids)

            for xsoar_incident_id, incident_info in xsoar_s1_incidents.items():
                for latest_s1_threat_info in latest_s1_threats_info:
                    latest_s1_threat_contents = latest_s1_threat_info.get("Contents")
                    s1_inc_threat_info = latest_s1_threat_contents.get("threatInfo")

                    s1_xsoar_threat_id = incident_info.get("threatId")
                    if latest_s1_threat_contents.get("id") == s1_xsoar_threat_id:
                        # The Incident in XSOAR is present in S1, processing further
                        # Getting XSOAR and S1 incident's status
                        s1_incident_status = s1_inc_threat_info.get("incidentStatus")
                        xsoar_incident_status = incident_info.get("xsoarIncStatus")
                        xsoar_incident_verdict = incident_info.get("xsoarCloseReason")

                        if S1_XSOAR_STATUS_MAPPING.get(s1_incident_status) != xsoar_incident_status:
                            # Update the incident in S1
                            update_s1_threat_incident(s1_xsoar_threat_id, XSOAR_S1_STATUS_MAPPING.get(xsoar_incident_status))

                            # Update the Analyst Verdict by checking the closed Reason.
                            if xsoar_incident_verdict == 'False Positive':
                                verdict_value = 'false_positive'
                                update_s1_threat_verdict(s1_xsoar_threat_id, verdict_value)
                            write_s1_threat_note(s1_xsoar_threat_id)
                            updated_incidents += 1
                        break

            # Going for the next Iteration / Page
            page += 1
        except Exception as ex:
            demisto.error(f'Exception when getting data: {str(ex)}')

    output_res = {"Total Incidents": total_incidents, "Synced Incidents(from xsoar to sentinelone)": updated_incidents}
    return CommandResults(readable_output=tableToMarkdown(
        "Results- \nSynced Incidents will show how many incidents changed per run of playbook.",
        output_res, headers=("Total Incidents", "Synced Incidents(from xsoar to sentinelone)"),
        headerTransform=string_to_table_header))


def update_s1_threat_incident(threatId, status):
    update_response = demisto.executeCommand("sentinelone-update-threats-status", {"threat_ids": threatId, "status": status})
    return update_response


def write_s1_threat_note(threatId):
    note = f"[XSOAR]{os.linesep}Info: Threat synced by XSOAR Job."
    update_response = demisto.executeCommand("sentinelone-write-threat-note", {"threat_ids": threatId, "note": note})
    return update_response


def update_xsoar_incident(xsoar_incident_update_fields):
    update_response = demisto.executeCommand("setIncident", xsoar_incident_update_fields)
    return update_response


def update_s1_threat_verdict(threatId, verdict):
    update_response = demisto.executeCommand("sentinelone-update-threats-verdict", {"threat_ids": threatId, "verdict": verdict})
    return update_response


def get_s1_threat_data(threat_ids_list):
    threat_ids = ",".join(threat_ids_list)
    response = demisto.executeCommand("sentinelone-get-threats-info", {"threat_ids": threat_ids})
    if isError(response[0]):
        err_msg = 'Error, could not get  - ' + str(response[0].get("Contents"))
        raise Exception(err_msg)
    return response


''' MAIN FUNCTION '''


def main():
    selected_option = demisto.args().get('playbook_to_run')
    try:
        if selected_option == 'SyncSentinelOneToXSOAR':
            return_results(sync_s1_xsoar_incidents())  # Using this for S1 to XSOAR
        else:
            return_results(sync_xsoar_s1_incidents())  # Using this for Sync XSOAR to S1
    except Exception as ex:
        return_error(f' Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
