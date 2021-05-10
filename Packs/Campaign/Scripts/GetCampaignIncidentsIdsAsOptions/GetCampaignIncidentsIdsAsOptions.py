import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ALL_OPTION = 'All'
NO_CAMPAIGN_INCIDENTS_MSG = 'There is no Campaign Incidents in the Context'
NO_ID_IN_CONTEXT = 'There is no \"id\" key in the incidents'


def get_campaign_incidents():
    incident_id = demisto.incidents()[0]['id']
    res = demisto.executeCommand('getContext', {'id': incident_id})
    if isError(res):
        return_error(f'Error occurred while trying to get the incident context: {get_error(res)}')

    return demisto.get(res[0], 'Contents.context.EmailCampaign.incidents')


def get_incident_ids_as_options(incidents):
    try:
        ids = [str(incident['id']) for incident in incidents]
        ids.sort(key=lambda incident_id: int(incident_id))
        ids.insert(0, ALL_OPTION)
        return {"hidden": False, "options": ids}
    except KeyError:
        raise Exception(NO_ID_IN_CONTEXT)


def main():

    try:
        incidents = get_campaign_incidents()
        if incidents:
            result = get_incident_ids_as_options(incidents)
        else:
            result = NO_CAMPAIGN_INCIDENTS_MSG
            demisto.debug(result)

        demisto.results(result)

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
