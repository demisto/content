import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


ALL_INCIDENTS = 'All'
CAMPAIGN_EMAIL_TO_FIELD = 'campaignemailto'


def get_campaign_incidents():
    """
        Get the campaign incidents form the incident's context

        :rtype: ``list``
        :return: list of campaign incidents
    """
    incident = demisto.incidents()[0]
    incident_id = incident.get('id') or incident.get('investigationId')
    res = demisto.executeCommand('getContext', {'id': incident_id})
    if isError(res):
        return_error(f'Error occurred while trying to get the incident context: {get_error(res)}')

    return demisto.get(res[0], 'Contents.context.EmailCampaign.incidents')


def collect_campaign_recipients(args):
    """
        Collect the campaign unique recipients from all the campaign incidents

        :type args: ``dict``
        :param args: args from demisto

        :rtype: ``str``
        :return: unique recipients in CSV
    """
    try:
        selected_ids = args['new']
        if not selected_ids:
            return ''

        incidents = get_campaign_incidents()
        if ALL_INCIDENTS not in selected_ids:
            incidents = filter(lambda incident: incident['id'] in selected_ids, incidents)

        recipient_set = {recipient for incident in incidents for recipient in incident['recipients']}
        return ','.join(recipient_set)
    except KeyError as e:
        raise DemistoException(f'Missing required arg: {str(e)}') from e


def update_campaign_email_to_field(recipients):
    """
        Update the campaignemailto field with the collected recipients
    """
    incident_id = demisto.incidents()[0]['id']
    demisto.executeCommand('setIncident', {'id': incident_id, 'customFields': {CAMPAIGN_EMAIL_TO_FIELD: recipients}})


def main():
    try:
        args = demisto.args()
        recipients = collect_campaign_recipients(args)
        update_campaign_email_to_field(recipients)
    except Exception as e:
        return_error(f'Failed to execute CollectCampaignRecipients. Error: {str(e)}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
