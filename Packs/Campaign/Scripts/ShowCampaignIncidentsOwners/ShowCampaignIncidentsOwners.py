import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def get_incident_ids() -> list:
    """
    Gets all the campaign incident ids.

    Returns:
        List of all the ids.
    """
    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident["id"] for incident in incidents]


def get_incident_owners(incident_ids) -> list:
    """
    Gets the campaign incident owners by their ids.

    Args:
        incident_ids: All the campaign incident ids.

    Returns:
        List of the incident owners.
    """

    incident_owners = set([demisto.executeCommand("getIncidents", {'id': incident_id})
                           [0]['Contents']['data'][0]['owner'] for incident_id in incident_ids])
    incident_owners.add(demisto.incident()["owner"])  # Add the campaign incident
    incident_owners_res = list(filter(lambda x: x, incident_owners))

    return incident_owners_res


def main():
    try:
        incident_ids = get_incident_ids()
        incident_owners = get_incident_owners(incident_ids)

        if incident_owners:
            html_readable_output = f"<div style='text-align:center; font-size:17px; padding: 5px;'> Incident Owners" \
                                   f"</br> <div style='font-size:32px;'> {len(incident_owners)} </div>" \
                                   f" <div style='font-size:16px;'> {', '.join(incident_owners)} </div></div>"

        else:
            html_readable_output = "<div style='text-align:center; font-size:17px; padding: 15px;'> Incident Owners" \
                                   "</br> <div style='font-size:32px;'> Owners Not Found </div></div>"

        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html_readable_output
        })
    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
