import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from GetIncidentsApiModule import *  # noqa: E402


def get_campaign_ids_by_incidents(incidents_ids_set: set) -> list:
    """
    Gets a list of campaign incidents ids for the given type and linked incident IDs.
    Args:
        incidents_ids_set (set): A set of incident IDs.

    Returns:
        List of ids as strings.
    """
    search_args = {
        'query': f'partofcampaign:* incident.id:({" ".join(incidents_ids_set)})',
        'sort': {
            'field': 'occurred',
            'asc': False,
        },
    }
    incidents = get_incidents_by_query(search_args)
    campaign_ids = [
        i.get("partofcampaign") for i in incidents
        if i.get("partofcampaign") != "None"
    ]
    demisto.debug(f"Found campaign incident ids: {campaign_ids}")

    return campaign_ids


def main():
    try:
        args = demisto.args()
        incidents_ids_set = set(argToList(args.get('IncidentIDs', '')))
        campaign_id = None

        if campaigns_ids_list := get_campaign_ids_by_incidents(incidents_ids_set):
            campaign_id = campaigns_ids_list[0]
            readable = f"Found campaign with ID - {campaign_id}"
        else:
            # did not find a relevant campaign
            campaign_id = None
            readable = "No campaign was found"

        return CommandResults(readable_output=readable, outputs={"ExistingCampaignID": campaign_id},
                              raw_response=readable)

    except Exception as ex:  # pylint: disable=broad-except  pragma: no cover
        return_error(f'Failed to execute. Error: {str(ex)}', error=ex)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    return_results(main())
