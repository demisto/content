import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_CAMPAIGN_KEY = 'EmailCampaign'


def get_campaign_context():
    current_incident_context = demisto.context()
    current_incident_campaing_data = current_incident_context.get(EMAIL_CAMPAIGN_KEY)
    return current_incident_campaing_data


def main():
    incident_id = demisto.args()['id'] if 'id' in demisto.args() else demisto.incidents()[0]['id']
    append = demisto.args()['append']
    error_unfinished = argToBoolean(demisto.args().get('errorUnfinished', "false"))

    campaign_data = get_campaign_context()
    args = {'key': EMAIL_CAMPAIGN_KEY, 'value': campaign_data, 'append': append}

    res = demisto.executeCommand(
        'executeCommandAt',
        {
            'incidents': incident_id,
            'command': 'Set',
            'arguments': args,
        }
    )
    if error_unfinished:
        result_string = res[-1].get('Contents', "")
        result_string = result_string.strip('.')
        numbers = [int(s) for s in result_string.split() if s.isdigit()]
        if len(set(numbers)) > 1:  # check if all the numbers are the same. Supposed to be 2 numbers.
            # if the numbers are the same, Set succeed on all of the incidents.
            return_error("Not all incidents were set.\n" + result_string)

    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
