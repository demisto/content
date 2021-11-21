import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_CAMPAIGN_KEY = 'EmailCampaign'


def get_campaign_context():
    current_incident_context = demisto.context()
    current_incident_campaing_data = current_incident_context.get(EMAIL_CAMPAIGN_KEY)
    return current_incident_campaing_data

def copy_campaign_data_to_incident(incident_id: int, campaign_data: dict, append: bool):
    args = {'key': EMAIL_CAMPAIGN_KEY, 'value': campaign_data, 'append': append}

    res = demisto.executeCommand(
        'executeCommandAt',
        {
            'incidents': incident_id,
            'command': 'Set',
            'arguments': args,
        }
    )
    if is_error(res):
        return_error(res)
    return res

def main():
    args = demisto.args()
    incident_id = args['id']
    append = argToBoolean(args['append'])

    campaign_data = get_campaign_context()
    res = copy_campaign_data_to_incident(incident_id, campaign_data, append)

    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
