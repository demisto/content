
from CommonServerPython import *


def get_sender_and_subject(entity: str) -> tuple[str, str]:
    email_info = demisto.executeCommand(
        "checkpointhec-get-entity",
        {'entity': entity}
    )[0]['Contents']

    return email_info.get('fromEmail'), email_info.get('subject')


def search_and_quarantine(date_range: str, sender: str, subject: str):
    result = demisto.executeCommand(
        "checkpointhec-search-emails",
        {
            'date_last': date_range,
            'sender_match': sender,
            'subject_contains': subject
        }
    )

    entity_ids = [x.get('entityId') for x in result[0].get('Contents')]
    if entity_ids:
        result = demisto.executeCommand(
            "checkpointhec-send-action",
            {
                'entity': entity_ids,
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
        entity = custom_fields.get('checkpointhecentity')
        sender, subject = get_sender_and_subject(entity)
        if not by_sender:
            sender = ''
        if not by_subject:
            subject = ''

        return_results(search_and_quarantine(date_range, sender, subject))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
