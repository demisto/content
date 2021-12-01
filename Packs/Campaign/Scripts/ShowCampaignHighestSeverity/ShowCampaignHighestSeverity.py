import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


INFORMATIONAL_SEVERITY_COLOR = "rgb(64,65,66)"  # Black
LOW_SEVERITY_COLOR = "rgb(29,184,70)"  # Green
MEDIUM_SEVERITY_COLOR = "rgb(209,125,0)"  # Orange
HIGH_SEVERITY_COLOR = "rgb(209,60,60)"  # Red
CRITICAL_SEVERITY_COLOR = "rgb(143,0,14)"  # Dark Red


COLORS_AND_NAMES = {
    IncidentSeverity.UNKNOWN: {'color': INFORMATIONAL_SEVERITY_COLOR, 'dsc': 'Unknown'},
    IncidentSeverity.INFO: {'color': INFORMATIONAL_SEVERITY_COLOR, 'dsc': 'Informational'},
    IncidentSeverity.LOW: {'color': LOW_SEVERITY_COLOR, 'dsc': 'Low'},
    IncidentSeverity.MEDIUM: {'color': MEDIUM_SEVERITY_COLOR, 'dsc': 'Medium'},
    IncidentSeverity.HIGH: {'color': HIGH_SEVERITY_COLOR, 'dsc': 'High'},
    IncidentSeverity.CRITICAL: {'color': CRITICAL_SEVERITY_COLOR, 'dsc': 'Critical'},
}


def get_incident_severity(incident_id):
    data = execute_command("getIncidents", {'id': incident_id})
    return dict_safe_get(data, ['data', 0, 'severity'], IncidentSeverity.UNKNOWN)


def incidents_id():
    incidents = dict_safe_get(demisto.context(), ['EmailCampaign', 'incidents'], [])
    for incident in incidents:
        yield incident['id']


def main():  # pragma: no cover
    try:
        # Getting incident context:
        highest_severity = max(IncidentSeverity.UNKNOWN, demisto.incident().get('severity', IncidentSeverity.UNKNOWN))
        for incident_id in incidents_id():
            highest_severity = max(highest_severity, get_incident_severity(incident_id))
        # Determine color:
        color = COLORS_AND_NAMES[highest_severity]['color']
        description = COLORS_AND_NAMES[highest_severity]['dsc']
        html = "<div style='text-align:center; font-size:17px; padding: 15px;'> Highest Severity</br> " \
            f"<div style='font-size:32px; color:{color};'> {description} </div></div>"
    except Exception:
        demisto.error(traceback.format_exc())
        html = "<div style='text-align:center; padding: 20px;'> <div> No severity </div>"

    # Return the data to the layout:
    return_results({
        'ContentsFormat': EntryFormat.HTML,
        'Type': EntryType.NOTE,
        'Contents': html,
    })


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
