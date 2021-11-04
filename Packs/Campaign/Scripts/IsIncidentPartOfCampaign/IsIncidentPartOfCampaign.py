import traceback
from typing import List, Set

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def get_incidents_ids_by_type(incident_type: str) -> List[str]:
    """
    Get list of incidents ids with the given type.
    Args:
        Incident_type(str): the incident type name.

    Returns:
        List of ids as strings.
    """
    incidents_list = demisto.executeCommand("getIncidents", {'type': incident_type})[0]['Contents']['data']
    if not incidents_list:
        return []
    # for type name with more than one word getIncidents returns also incidents with the type name of that is part of
    # the original type name (Ex. Phishing Campaign will also return incidents of Phishing)
    return [demisto.get(incident, 'id') for incident in incidents_list if
            demisto.get(incident, 'type') == incident_type]


def arg_to_set(arg: str) -> Set[str]:
    """
    Convert given comma separated string to set.
    Args:
        arg (str): list as comma separated string.

    Returns: Set

    """
    if not isinstance(arg, str):
        return set()
    arg_list = arg.split(',')
    return set(arg_list)


''' COMMAND FUNCTION '''


def check_incidents_ids_in_campaigns_list(campaigns_ids_list: List[str], incidents_ids_set: Set[str]) -> Optional[str]:
    """
    Check for each incident in the campaigns_ids_list if any of the ids in incidents_ids_set is linked.
    Args:
        campaigns_ids_list(List[str]): List of campaign incident ids to search in.
        incidents_ids_set(Set[str]): Set of incident ids to search for.

    Returns:
        Campaign incident's id where at least one id from the incidents_ids_set is linked to that campaign incident.
    """
    for campaign_id in campaigns_ids_list:
        campaign_context = demisto.executeCommand("getContext", {'id': campaign_id})

        try:
            campaign_context = campaign_context[0]['Contents']['context']
        except (TypeError, KeyError, IndexError):  # ensure that the received context is from the type we expect
            continue

        connected_incidents_list = demisto.get(campaign_context, 'EmailCampaign.incidents')
        if connected_incidents_list:
            connected_campaign_incidents_ids = {incident.get('id') for incident in connected_incidents_list}
            is_incidents_in_campaign = bool(incidents_ids_set & connected_campaign_incidents_ids)
            if is_incidents_in_campaign:
                return campaign_id

    return None


''' MAIN FUNCTION '''


def main():
    try:
        campaign_type = demisto.args().get('CampaignIncidentType', 'Phishing Campaign')
        incidents_ids = demisto.args().get('IncidentIDs', '')

        incidents_ids_set = arg_to_set(incidents_ids)
        campaigns_ids_list = get_incidents_ids_by_type(campaign_type)

        campaign_id = check_incidents_ids_in_campaigns_list(campaigns_ids_list, incidents_ids_set)

        readable = f"Found campaign with ID - {campaign_id}" if campaign_id else "No campaign has found"
        return CommandResults(readable_output=readable, outputs={"ExistingCampaignID": campaign_id})

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
