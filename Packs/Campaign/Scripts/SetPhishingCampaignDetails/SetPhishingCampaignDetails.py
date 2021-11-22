import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_CAMPAIGN_KEY = 'EmailCampaign'


def get_campaign_context():
    current_incident_context = demisto.context()
    current_incident_campaing_data = current_incident_context.get(EMAIL_CAMPAIGN_KEY)
    return current_incident_campaing_data


def copy_campaign_data_to_incident(incident_id: int, campaign_data: dict, append: bool):
    if not campaign_data:
        demisto.debug(f"Error - {EMAIL_CAMPAIGN_KEY} was not found. Ignoring incident id: {incident_id}")
        return

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
        return_error(f"error in setting context to incident id {incident_id}. Error: {res}")

    return res


def main():
    try:
        args = demisto.args()
        incident_id = args.get('id')
        if not incident_id:
            raise Exception("Please provide incident id.")
        append = argToBoolean(args['append'])

        campaign_data = get_campaign_context()
        res = copy_campaign_data_to_incident(incident_id, campaign_data, append)
        if res:
            demisto.results(res)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to set campaign details.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
