import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback




def security_and_compliance_delete_mail(search_name, args):
    if not search_name:
        # first time, creating the search
        search_name = f'search_for_delete_{time()}'
        execute_command('o365-sc-new-search', {'kql': query, 'search_name': search_name, 'using-brand': delete_from_brand})
        execute_command('o365-sc-start-search', {'search_name': search_name, 'using-brand': delete_from_brand})
        polling_args = {
                'interval_in_seconds': 60,
                'polling': True,
                **args,
            }
        scheduled_command = ScheduledCommand(
            command='!DeleteEmail',
            next_run_in_seconds=60,
            args=polling_args,
            timeout_in_seconds=600)
        return CommandResults(scheduled_command=scheduled_command)
    # the search already exists, but not finished
    results = execute_command('o365-sc-get-search', {'search_name': search_name, 'using-brand': delete_from_brand})
    if results.get('Status') != 'Complete':
        # schedule next poll
        polling_args = {
            'interval_in_seconds': 60,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command='!DeleteEmail',
            next_run_in_seconds=60,
            args=polling_args,
            timeout_in_seconds=600)
        return CommandResults(scheduled_command=scheduled_command)
    # the search is finished
    if results.get('SuccessResults'):
        # the email was found
        execute_command('o365-sc-new-search-action', {'search_name': search_name, 'purge_type': delete_type, 'using-brand': delete_from_brand})
        need here to do another generic polling - need to make it nicer

def main():
    try:
        args = demisto.args()
        delete_type = args.get('delete_type')
        incident_info = demisto.incident()
        custom_fields = incident_info.get('CustomFields')
        delete_from_brand = args.get('delete_from_brand', incident_info.get('sourceBrand'))
        user_id = custom_fields.get('reportedemailto')
        email_subject = custom_fields.get('reportedemailsubject')
        message_id = custom_fields.get("reportedemailmessageid")
        deletion_status = 'failure'
        deletion_failure_reason = ''

        # Gmail
        if delete_from_brand == 'Gmail':
            is_permanent = True if delete_type == 'Hard' else False
            query = f'Rfc822msgid:{message_id}'
            result = execute_command('gmail-search', {'user-id': user_id, 'query': query, 'using-brand': delete_from_brand})
            print(result)
            gmail_message_id = result[0].get('id')
            resp = execute_command('gmail-delete-mail', {'user-id': user_id, 'message-id': gmail_message_id, 'permanent': is_permanent, 'using-brand': delete_from_brand})
            if 'successfully' in result:
                deletion_status = 'Success'
            else:
                deletion_failure_reason = 'Unknown'

        # Security & Compliance - implement by playbook
        elif delete_from_brand == 'SecurityAndCompliance':
            search_name = args.get('search_name')
            delete_type = f'{delete_type}Delete'


        # EWS
        elif delete_from_brand in ['EWSO365', 'EWS v2']:
            delete_type = f'{delete_type.lower()}'
            result = execute_command('ews-search-mailbox', {'target-mailbox': user_id, 'message-id': message_id, 'using-brand': delete_from_brand})
            print(result)
            if not result:
                raise Exception('Email was not found, is it possible that the email was already deleted.')
            item_id = result[0].get('itemId')
            resp = execute_command('ews-delete-items', {'item-ids': item_id, 'delete-type': delete_type, 'using-brand': delete_from_brand})

        # Agari Phishing Defense - no instance, search API for response
        elif delete_from_brand == 'Agari Phishing Defense':
            agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
            resp = execute_command('apd-remediate-message', {'operation': 'delete', 'id': agari_message_id, 'using-brand': delete_from_brand})

        # O365 Outlook Mail
        elif delete_from_brand == 'MicrosoftGraphMail':
            # no soft or hard here
            odata = f'"$filter=internetMessageId eq \'{message_id}\'"'
            result = execute_command('msgraph-mail-list-emails',
                                     {'user_id': user_id, 'odata': odata, 'using-brand': delete_from_brand})
            results = result[0].get('value', [])
            results = [res for res in results if res.get('internetMessageId') == message_id]
            internal_id = results[0].get('id')
            resp = execute_command('msgraph-mail-delete-email', {'user_id': user_id, 'message_id': internal_id, 'using-brand': delete_from_brand})

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute DeleteEmail. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
