import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Iterable


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
        'query': f'type:"{incident_type}"',
        'sort': {
            'field': 'occurred',
            'asc': False,
        },
    }
    incidents = execute_command("GetIncidentsByQuery", search_args)
    demisto.debug(f"Incidents getting from response: {incidents}")

    try:
        incidents = json.loads(incidents)
    except Exception as e:
        raise DemistoException(f'Failed loads for incidents: {incidents=}, error message: {str(e)}') from e

    campaign_ids = [incident.get('id') for incident in incidents]
    demisto.debug(f"Found campaing incident ids: {campaign_ids}")

    return campaign_ids


''' COMMAND FUNCTION '''


def check_incidents_ids_in_campaign(campaign_id: str, incidents_ids_set: set[str]) -> bool:
    """
    Check for each incident in the campaigns_ids_list if any of the ids in incidents_ids_set is linked.
    Args:
        campaigns_ids_list(str): campaign incident id to search in.
        incidents_ids_set(Set[str]): Set of incident ids to search for.

    Returns:
        True if at least one id from the incidents_ids_set is linked to the campaign incident, otherwise False.
    """
    try:
        campaign_context = execute_command("getContext", {'id': campaign_id})['context']

        if (connected_incidents_list := demisto.get(campaign_context, 'EmailCampaign.incidents')):
            connected_campaign_incidents_ids = {incident.get('id') for incident in connected_incidents_list}
            is_incidents_in_campaign = bool(incidents_ids_set & connected_campaign_incidents_ids)
            if is_incidents_in_campaign:
                return True
    except Exception as e:
        demisto.info(f"skipping for incident {campaign_id}, reason: {e}")
    return False


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        campaign_type = args.get('CampaignIncidentType', 'Phishing Campaign')
        incidents_ids_set = set(argToList(args.get('IncidentIDs', '')))
        campaign_id = None

        campaigns_ids_list = get_incidents_ids_by_type(campaign_type)

        for campaign_id in campaigns_ids_list:
            if check_incidents_ids_in_campaign(campaign_id, incidents_ids_set):
                readable = f"Found campaign with ID - {campaign_id}"
                break
        else:
            # did not find a relevant campaign
            campaign_id = None
            readable = "No campaign has found"

        return CommandResults(readable_output=readable, outputs={"ExistingCampaignID": campaign_id},
                              raw_response=readable)

    except Exception as ex:  # pylint: disable=broad-except  pragma: no cover
        return_error(f'Failed to execute. Error: {str(ex)}', error=ex)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main())
