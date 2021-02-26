import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def getQRadarOffenses():
    # Get All Open Incident from QRadar

    filter_qradar = "status=open"
    fields_qradar = "id"

    search_args_for_qradar = {}
    search_args_for_qradar['filter'] = filter_qradar
    search_args_for_qradar['fields'] = fields_qradar

    resp = demisto.executeCommand('qradar-offenses', search_args_for_qradar)

    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], 'Contents')
        if not data:
            error_messages = "Data don't exist for this query"
            return_error(error_messages)

    qradar_offenses = []
    for ids in data:
        qradar_offenses.append(ids['id'])

    return qradar_offenses


def getXSOARIncidents():
    # Get All Incident from Demisto
    search_arg_for_demisto = {}
    size = 2000
    not_status_matched_incident = 2  # 2 is Closed Status

    search_arg_for_demisto['notstatus'] = not_status_matched_incident
    search_arg_for_demisto['size'] = size
    respmatched_incidentsent = demisto.executeCommand('SearchIncidents', search_arg_for_demisto)
    if isError(respmatched_incidentsent[0]):
        return_error(respmatched_incidentsent)
    else:
        incident_from_demisto = demisto.get(respmatched_incidentsent[0], 'Contents')
        if not incident_from_demisto:
            error_messages = "Data don't exist for this query"
            return_error(error_messages)
        else:
            incident_from_demisto = incident_from_demisto if isinstance(incident_from_demisto, list) else [incident_from_demisto]

    matched_incidents = []
    mismatched_incidents = []
    k = 0
    for data in incident_from_demisto:
        i = 0
        for incID in data['labels']:
            if incID['type'] == 'id':
                k = k + 1
                demistoIncValuefromQradar = int(data['labels'][i]['value'])  # type transformation from Unicode to int
                break
            else:
                i = i + 1
        matched_incidents.append(demistoIncValuefromQradar)
        demistoIncValue = int(data['id'])
        mismatched_incidents.append(demistoIncValue)

    return mismatched_incidents, matched_incidents


def controlQRadarXSOAR(qradar_offenses, mismatched_incidents, matched_incidents):
    qradar_id_array = qradar_offenses
    mismatched_incidents = mismatched_incidents
    matched_incidents = matched_incidents
    # Find Different Incident and Close it on QRadar

    difference_incident = []  # Different element between Demisto and QRadar
    match_incidents_list = []
    i = 0
    k = 0
    for demisto_element in matched_incidents:
        is_different = 0  # 0 is no different, 1 is different

        for qradar_element in qradar_id_array:
            if demisto_element == qradar_element:
                is_different = 1
                break

        if is_different != 1:
            difference_incident.append(mismatched_incidents[i])
        else:
            match_incidents_list.append(matched_incidents[k])
        i = i + 1
        k = k + 1

    mach_incident_count = 'Match-up incidents count : ' + str(len(match_incidents_list))
    demisto.results(mach_incident_count)
    mismatched_incident_count = "Mismatched incident count : " + str(len(difference_incident))
    demisto.results(mismatched_incident_count)

    if len(difference_incident) > 0:
        mismatched_incident = "Mismatched Incident : " + str(difference_incident)
        demisto.results(mismatched_incident)
        return difference_incident
    else:
        return_messages = "No inconsistencies"
        return_results(return_messages)
        sys.exit(1)


def synchronizationQRadarXSOAR(difference_incident):
    difference_incident = difference_incident
    # Close the Mismatched incidents from Demisto

    closematched_incidentsents_args = {}
    inc_closed_reason_demisto = 'Investigation is Completed'
    closematched_incidentsents_args['reason'] = inc_closed_reason_demisto
    # i = 0# test
    for will_close_inc in difference_incident:
        inc_id_demisto = will_close_inc
        closematched_incidentsents_args['id'] = inc_id_demisto
        demisto.executeCommand('closeInvestigation', closematched_incidentsents_args)
    result_process = "Synchronization completed."
    demisto.results(result_process)


def main():
    qradar_offenses = getQRadarOffenses()
    mismatched_incidents, matched_incidents = getXSOARIncidents()
    difference_incident = controlQRadarXSOAR(qradar_offenses, mismatched_incidents, matched_incidents)
    synchronizationQRadarXSOAR(difference_incident)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins'):
    main()
