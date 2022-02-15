import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


"""
This Script is a duplicate of Packs/Campaign/Scripts/GetCampaignIncidentsIdsAsOptions with the only change of the context field
the data is taken from. The reason is that these two scripts are used for two different fields
(higher similarity and lower similarity incidents fields).
"""


ALL_OPTION = 'All'
NO_CAMPAIGN_INCIDENTS_MSG = 'There is no Campaign Incidents in the Context'
NO_ID_IN_CONTEXT = 'There is no \"id\" key in the incidents'


def get_campaign_incidents():
    """
        Get the campaign incidents form the incident's context

        :rtype: ``list``
        :return: list of campaign incidents
    """

    incident_id = demisto.incidents()[0]['id']
    res = demisto.executeCommand('getContext', {'id': incident_id})
    if isError(res):
        return_error(f'Error occurred while trying to get the incident context: {get_error(res)}')

    return demisto.get(res[0], 'Contents.context.EmailCampaign.LowerSimilarityIncidents')


def get_incident_ids_as_options(incidents):
    """
        Collect the campaign incidents ids form the context and return them as options for MultiSelect field

        :type incidents: ``list``
        :param incidents: the campaign incidents to collect ids from

        :rtype: ``dict``
        :return: dict with the ids as options for MultiSelect field e.g {"hidden": False, "options": ids}
    """
    try:
        ids = [str(incident['id']) for incident in incidents]
        ids.sort(key=lambda incident_id: int(incident_id))
        ids.insert(0, ALL_OPTION)
        return {"hidden": False, "options": ids}
    except KeyError as e:
        raise DemistoException(NO_ID_IN_CONTEXT) from e


def main():

    try:
        incidents = get_campaign_incidents()
        if incidents:
            result = get_incident_ids_as_options(incidents)
        else:
            result = NO_CAMPAIGN_INCIDENTS_MSG

        return_results(result)

    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
