

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


ALL_INCIDENTS = 'All'
CAMPAIGN_EMAIL_TO_FIELD = 'campaignemailto'


def get_campaign_incidents():
    incident = demisto.incidents()[0]
    incident_id = incident.get('id') or incident.get('investigationId')
    res = demisto.executeCommand('getContext', {'id': incident_id})
    if isError(res):
        return_error(f'Error occurred while trying to get the incident context: {get_error(res)}')

    return demisto.get(res[0], 'Contents.context.EmailCampaign.incidents')


def collect_campaign_recipients():
    try:
        selected_ids = demisto.args()['new']
        if not selected_ids:
            return ''

        incidents = get_campaign_incidents()
        if ALL_INCIDENTS not in selected_ids:
            incidents = filter(lambda incident: incident['id'] in selected_ids, incidents)

        recipient_set = {recipient for incident in incidents for recipient in incident['recipients']}
        return ','.join(recipient_set)
    except KeyError as e:
        raise Exception(f'Missing required arg: {str(e)}')


def update_campaign_email_to_field(recipients):
    incident_id = demisto.incidents()[0]['id']
    demisto.executeCommand('setIncident', {'id': incident_id, 'customFields': {CAMPAIGN_EMAIL_TO_FIELD: recipients}})


def main():
    try:
        recipients = collect_campaign_recipients()
        update_campaign_email_to_field(recipients)
    except Exception as e:
        return_error(f'Failed to execute CollectCampaignRecipients. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
