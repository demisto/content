import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


def get_incident_ids():

    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident['id'] for incident in incidents]


def get_incident_owners(incident_ids):

    incident_owners = set([demisto.executeCommand("getIncidents", {'id': incident_id})
                           [0]['Contents']['data'][0]['owner'] for incident_id in incident_ids])
    incident_owners.add(demisto.incident()["owner"])  # Add the campaign incident
    incident_owners_res = list(filter(lambda x: x, incident_owners))

    return incident_owners_res


def main():

    incident_ids = get_incident_ids()
    incident_owners = get_incident_owners(incident_ids)

    if incident_owners:
        html_readable_output = f"<div style='text-align:center; font-size:17px; padding: 5px;'> Incident Owners</br>" \
                               f" <div style='font-size:32px;'> {len(incident_owners)} </div>" \
                               f" <div style='font-size:16px;'> {', '.join(incident_owners)} </div></div>"

    else:
        html_readable_output = "<div style='text-align:center; font-size:17px; padding: 15px;'> Incident Owners</br>" \
                               " <div style='font-size:32px;'> Owners Not Found </div></div>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html_readable_output
    })


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
