import traceback
from typing import Iterable, Set

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def get_incidents_ids_by_type(incident_type: str) -> Iterable[str]:
    """
    Get list of incidents ids with the given type.
    Args:
        Incident_type(str): the incident type name.

    Returns:
        List of ids as strings.
    """
    search_args = {
        'type': incident_type,
        'page': 0,
        'sort': {
            'field': 'occurred',
            'asc': False,
        },
    }

    incidents = execute_command("getIncidents", search_args)['data']
    while incidents:
        demisto.debug(f'Searching for incidents: {search_args}')
        for incident in incidents:
            # for type name with more than one word getIncidents returns also incidents with the type name of that
            # is part of the original type name (Ex. Phishing Campaign will also return incidents of Phishing).
            if incident.get('type') == incident_type:
                yield incident.get('id')

        search_args['page'] += 1  # type: ignore

        incidents = execute_command("getIncidents", search_args)['data']


''' COMMAND FUNCTION '''


def check_incidents_ids_in_campaign(campaign_id: str, incidents_ids_set: Set[str]) -> bool:
    """
    Check for each incident in the campaigns_ids_list if any of the ids in incidents_ids_set is linked.
    Args:
        campaigns_ids_list(str): campaign incident id to search in.
        incidents_ids_set(Set[str]): Set of incident ids to search for.

    Returns:
        True if at least one id from the incidents_ids_set is linked to the campaign incident, otherwise False.
    """
    campaign_context = execute_command("getContext", {'id': campaign_id})['context']

    connected_incidents_list = demisto.get(campaign_context, 'EmailCampaign.incidents')
    if connected_incidents_list:
        connected_campaign_incidents_ids = {incident.get('id') for incident in connected_incidents_list}
        is_incidents_in_campaign = bool(incidents_ids_set & connected_campaign_incidents_ids)
        if is_incidents_in_campaign:
            return True

    return False


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        campaign_type = args.get('CampaignIncidentType', 'Phishing Campaign')
        incidents_ids_set = set(argToList(args.get('IncidentIDs', '')))
        campaign_id = None

        for campaign_id in get_incidents_ids_by_type(campaign_type):
            if check_incidents_ids_in_campaign(campaign_id, incidents_ids_set):
                readable = f"Found campaign with ID - {campaign_id}"
                break
        else:
            # did not find a relevant campaign
            campaign_id = None
            readable = "No campaign has found"

        return CommandResults(readable_output=readable, outputs={"ExistingCampaignID": campaign_id})

    except Exception as ex:  # pylint: disable=broad-except  pragma: no cover
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute. Error: {str(ex)}', error=ex)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main())
