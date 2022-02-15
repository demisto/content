from collections import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

FROM_FIELD = 'emailfrom'


def get_incident_ids() -> list:
    """
    Gets all the campaign incident ids.

    Returns:
        List of all the ids.
    """
    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident["id"] for incident in incidents]


def get_campaign_senders() -> str:
    """
    Gets the campaign senders in a readable table.

    Returns:
        MD table of the senders and their amount.
    """
    incident_ids = get_incident_ids()

    res = demisto.executeCommand('GetIncidentsByQuery', {
        'query': "id:({})".format(' '.join(incident_ids))
    })

    if isError(res):
        return_error(f'Error occurred while trying to get incidents by query: {get_error(res)}')

    incidents_from_query = json.loads(res[0]['Contents'])

    if not incidents_from_query:
        return 'No incidents found.'

    senders = [incident[FROM_FIELD] for incident in incidents_from_query if FROM_FIELD in incident]

    if not senders:
        return 'No incident senders found.'

    senders_counter = Counter(senders).most_common()  # type: ignore

    senders_table_content = [{"Email": email, "Number Of Appearances": count} for email, count in senders_counter]
    headers = ['Email', 'Number Of Appearances']

    return tableToMarkdown('', senders_table_content, headers=headers)


def main():
    try:

        campaign_senders = get_campaign_senders()
        return_results(CommandResults(readable_output=campaign_senders))

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
