from CommonServerPython import *


def search_and_quarantine(farm: str, customer: str, date_range: str, sender: str, subject: str):
    result = demisto.executeCommand(
        "checkpointhec-search-emails",
        {
            'date_range': date_range,
            'sender': sender,
            'subject': subject
        }
    )
    if ids := result[0].get('Contents', {}).get('ids'):
        result = demisto.executeCommand(
            "checkpointhec-send-action",
            {
                'farm': farm,
                'customer': customer,
                'entity': ids,
                'action': 'quarantine'
            }
        )
        task = result[0]['Contents']['task']
        demisto.executeCommand(
            "setIncident",
            {
                'customFields': json.dumps({
                    'checkpointheccampaigntask': task
                })
            }
        )
    return result


def main():  # pragma: no cover
    try:
        args = demisto.args()
        date_range = args.get('date_range')
        by_sender = args.get('by_sender') == 'true'
        by_subject = args.get('by_subject') == 'true'

        if not by_sender and not by_subject:
            raise Exception('Need to select at least one option to search for')

        custom_fields = demisto.incident()['CustomFields']
        sender = subject = ''
        if by_sender:
            sender = custom_fields.get('checkpointhecemailsender')
        if by_subject:
            subject = custom_fields.get('checkpointhecemailsubject')

        farm = custom_fields.get('checkpointhecfarm')
        customer = custom_fields.get('checkpointheccustomer')
        return_results(
            search_and_quarantine(farm, customer, date_range, sender, subject)
        )
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
