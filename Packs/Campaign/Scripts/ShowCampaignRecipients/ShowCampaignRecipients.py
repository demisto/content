from collections import Counter

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_TO_FIELD = 'emailto'
EMAIL_CC_FIELD = 'emailcc'
EMAIL_BCC_FIELD = 'emailbcc'
RECIPIENTS_FIELDS = [EMAIL_TO_FIELD, EMAIL_CC_FIELD, EMAIL_BCC_FIELD]


def get_incident_ids() -> list:
    """
    Gets all the campaign incident ids.

    Returns:
        List of all the ids.
    """
    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident["id"] for incident in incidents]


def get_campaign_recipients() -> str:
    """
    Gets the campaign recipients in a readable table.

    Returns:
        MD table of the recipients and their amount.
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

    recipients = []
    for recipient_field in RECIPIENTS_FIELDS:
        recipients.extend([incident[recipient_field] for incident in incidents_from_query if recipient_field in incident])

    if not recipients:
        return 'No incident recipients found.'

    recipients_counter = Counter(recipients).most_common()  # type: ignore

    recipients_table_content = [{"Email": item[0], "Number Of Appearances": item[1]} for item in recipients_counter]
    headers = ['Email', 'Number Of Appearances']

    return tableToMarkdown('', recipients_table_content, headers=headers)


def main():
    try:

        campaign_recipients = get_campaign_recipients()
        return_results(CommandResults(readable_output=campaign_recipients))

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
