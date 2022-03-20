import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback


class ReDeleteException(Exception):
    def __init__(self):
        super().__init__('Email was not found in mailbox, is it possible that the email was already deleted.')


class DeletionFailed(Exception):
    pass


def schedule_next_command(args):
    """
    Handle the creation of the ScheduleCommand object
    Returns:
        ScheduleCommand object that will cal this script again.
    """
    polling_args = {
        'interval_in_seconds': 60,
        'polling': True,
        **args,
    }
    return ScheduledCommand(
        command='!DeleteEmail',
        next_run_in_seconds=60,
        args=polling_args,
        timeout_in_seconds=600)


def security_and_compliance_delete_mail(user_id, email_subject, delete_from_brand, delete_type, args):
    if not is_demisto_version_ge('6.2.0'):
        raise DemistoException('Deleting an email using this script for Security And Compliance integration is not '
                               'supported by this XSOAR server version. Please update your server version to 6.2.0 '
                               'or later, or delete the email using the playbook: '
                               'O365 - Security And Compliance - Search And Delete ')
    query = f'from:{user_id} AND subject:{email_subject}'
    search_name = args.get('search_name')
    is_finished_searching = args.get('is_finished_searching')

    if not is_finished_searching:
        if not search_name:
            # first time, creating the search
            search_name = f'search_for_delete_{time()}'
            execute_command('o365-sc-new-search', {'kql': query, 'search_name': search_name,
                                                   'using-brand': delete_from_brand})
            execute_command('o365-sc-start-search', {'search_name': search_name, 'using-brand': delete_from_brand})
            args['search_name'] = search_name

        # the search already exists, but not finished
        results = execute_command('o365-sc-get-search', {'search_name': search_name, 'using-brand': delete_from_brand})

        if results.get('Status') != 'Complete':
            return CommandResults(scheduled_command=schedule_next_command(args))

        # the search is finished
        if results.get('SuccessResults'):
            # the email was found
            execute_command('o365-sc-new-search-action', {'search_name': search_name, 'purge_type': delete_type,
                                                          'using-brand': delete_from_brand})
            args['is_finished_searching'] = True
            return CommandResults(scheduled_command=schedule_next_command(args))
    else:
        results = execute_command('o365-sc-get-search-action', {'search_action_name': search_name,
                                                                'using-brand': delete_from_brand})
        if results.get('Status') != 'Complete':
            return CommandResults(scheduled_command=schedule_next_command(args))
        execute_command('o365-sc-remove-search-action', {'search_action_name': search_name,
                                                         'using-brand': delete_from_brand})
        execute_command('o365-sc-remove-search', {'search_name': search_name,
                                                  'using-brand': delete_from_brand})
        return 'Success'


def gmail_delete_args_function(search_result, delete_type, user_id, delete_from_brand, **kwargs):
    is_permanent = True if delete_type == 'Hard' else False
    gmail_message_id = search_result[0].get('id')
    return {'user-id': user_id, 'message-id': gmail_message_id, 'permanent': is_permanent,
            'using-brand': delete_from_brand}

def gmail_delete_email(delete_type, message_id, user_id, delete_from_brand):
    is_permanent = True if delete_type == 'Hard' else False
    query = f'Rfc822msgid:{message_id}'
    result = execute_command('gmail-search', {'user-id': user_id, 'query': query, 'using-brand': delete_from_brand})
    if not result:
        raise ReDeleteException()
    gmail_message_id = result[0].get('id')
    resp = execute_command('gmail-delete-mail',
                           {'user-id': user_id, 'message-id': gmail_message_id, 'permanent': is_permanent,
                            'using-brand': delete_from_brand})
    if 'successfully' not in resp:
        raise DeletionFailed(resp)


def ews_delete_args_function(search_result, delete_type, delete_from_brand, **kwargs):
    delete_type = f'{delete_type.lower()}'
    item_id = search_result[0].get('itemId')
    return {'item-ids': item_id, 'delete-type': delete_type, 'using-brand': delete_from_brand}


def ews_delete_email(delete_type, user_id, delete_from_brand, message_id):
    delete_type = f'{delete_type.lower()}'
    result = execute_command('ews-search-mailbox', {'target-mailbox': user_id, 'message-id': message_id,
                                                    'using-brand': delete_from_brand})
    if not result:
        raise ReDeleteException()
    item_id = result[0].get('itemId')
    resp = execute_command('ews-delete-items', {'item-ids': item_id, 'delete-type': delete_type,
                                                'using-brand': delete_from_brand})
    if not isinstance(resp, dict):
        raise DeletionFailed(resp)


def msgraph_delete_args_function(search_result, user_id, delete_from_brand, message_id, **kwargs):
    results = search_result[0].get('value', [])
    results = [res for res in results if res.get('internetMessageId') == message_id]
    internal_id = results[0].get('id')
    return {'user_id': user_id, 'message_id': internal_id, 'using-brand': delete_from_brand}


def msgraph_delete_email(user_id, delete_from_brand, message_id):
    # no soft or hard here
    odata = f'"$filter=internetMessageId eq \'{message_id}\'"'
    result = execute_command('msgraph-mail-list-emails',
                             {'user_id': user_id, 'odata': odata, 'using-brand': delete_from_brand})
    if not result:
        raise ReDeleteException()
    results = result[0].get('value', [])
    results = [res for res in results if res.get('internetMessageId') == message_id]
    internal_id = results[0].get('id')
    resp = execute_command('msgraph-mail-delete-email', {'user_id': user_id, 'message_id': internal_id,
                                                         'using-brand': delete_from_brand})
    if 'successfully' not in resp:
        raise DeletionFailed(resp)

def msgraph_delete_args_function(delete_from_brand, **kwargs):
    agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
    return {'operation': 'delete', 'id': agari_message_id, 'using-brand': delete_from_brand}


def agari_delete_args_function(delete_from_brand, **kwargs):
    agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
    return {'operation': 'delete', 'id': agari_message_id,
     'using-brand': delete_from_brand}

def agari_delete_email(delete_from_brand):
    agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
    resp = execute_command('apd-remediate-message', {'operation': 'delete', 'id': agari_message_id,
                                                     'using-brand': delete_from_brand})
    if 'successfully' not in resp:
        raise DeletionFailed(resp)


def delete_email(search_args, search_function, delete_args_function, delete_function, deletion_error_condition=
    lambda x: 'successfully' not in x):
    result = None
    if search_function:
        result = execute_command(search_function, search_args)
        if not result:
            raise ReDeleteException()
    delete_args = delete_args_function(result)
    resp = execute_command(delete_function, delete_args)
    if deletion_error_condition(resp):
        raise DeletionFailed(resp)

def new_main():
    # test all functions
    # create get_search_arguments_func
    # test Sec&Comp

    args = demisto.args()
    search_argumnets = {'delete_type': args.get('delete_type')}
    incident_info = demisto.incident()
    custom_fields = incident_info.get('CustomFields')
    message_id = custom_fields.get("reportedemailmessageid")
    delete_from_brand = args.get('delete_from_brand', incident_info.get('sourceBrand'))
    search_argumnets['delete_from_brand'] = delete_from_brand
    search_argumnets['user_id'] = custom_fields.get('reportedemailto')
    search_argumnets['email_subject'] = custom_fields.get('reportedemailsubject')
    search_argumnets['message_id'] = message_id
    search_argumnets['query'] = f'Rfc822msgid:{message_id}'
    search_argumnets['odata'] = f'"$filter=internetMessageId eq \'{message_id}\'"'
    result = ''
    deletion_failure_reason = ''

    try:
        if delete_from_brand == 'SecurityAndCompliance':
            pass # TODO: fix
        else:
            integrations_dict = {'Gmail': ('gmail-search', gmail_delete_args_function, 'gmail-delete-mail'),
                                 'EWS': ('ews-search-mailbox', ews_delete_args_function, 'ews-delete-items',
                                         lambda x: not isinstance(x, dict)),
                                 'Agari Phishing Defense': (None, agari_delete_args_function, 'apd-remediate-message'),
                                 'MicrosoftGraphMail': ('msgraph-mail-list-emails', msgraph_delete_args_function,
                                                        'msgraph-mail-delete-email')}
            delete_email(*integrations_dict[delete_from_brand])

    except ReDeleteException as e:
        result = 'Skipped'
        deletion_failure_reason = f'Skipped deleting email: {e}'
    except DeletionFailed as e:
        result = 'Failed'
        deletion_failure_reason = f'Failed deleting email: {e}'
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute DeleteEmail. Error: {str(e)}')
    finally:
        return result, deletion_failure_reason



def main():
    try:
        # need to have: a dict with brand name and function name
        # create function for each integration
        # raise errors that can be related to failed deletion
        # add skipped
        # check security and compliance - will wait
        # add agari - done
        args = demisto.args()
        delete_type = args.get('delete_type')
        incident_info = demisto.incident()
        custom_fields = incident_info.get('CustomFields')
        delete_from_brand = args.get('delete_from_brand', incident_info.get('sourceBrand'))
        user_id = custom_fields.get('reportedemailto')
        email_subject = custom_fields.get('reportedemailsubject')
        message_id = custom_fields.get("reportedemailmessageid")
        result = ''
        deletion_failure_reason = ''





        # Gmail
        if delete_from_brand == 'Gmail':
            is_permanent = True if delete_type == 'Hard' else False
            query = f'Rfc822msgid:{message_id}'
            result = execute_command('gmail-search', {'user-id': user_id, 'query': query, 'using-brand': delete_from_brand})
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
            try:
                result = security_and_compliance_delete_mail(user_id, email_subject, delete_from_brand, delete_type, args)
                if not isinstance(result, str):
                    return result

            except Exception as e:
                result = 'Failed'
                deletion_failure_reason = f'Failed trying to delete email: {e}'
            finally:
                return result, deletion_failure_reason

        # EWS
        elif delete_from_brand in ['EWSO365', 'EWS v2']:
            delete_type = f'{delete_type.lower()}'
            result = execute_command('ews-search-mailbox', {'target-mailbox': user_id, 'message-id': message_id,
                                                            'using-brand': delete_from_brand})
            print(result)
            if not result:
                raise Exception('Email was not found, is it possible that the email was already deleted.')
            item_id = result[0].get('itemId')
            resp = execute_command('ews-delete-items', {'item-ids': item_id, 'delete-type': delete_type,
                                                        'using-brand': delete_from_brand})

        # Agari Phishing Defense - no instance, search API for response
        elif delete_from_brand == 'Agari Phishing Defense':
            agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
            resp = execute_command('apd-remediate-message', {'operation': 'delete', 'id': agari_message_id,
                                                             'using-brand': delete_from_brand})
            if 'successfully' not in resp:
                result = 'Failed'
                deletion_failure_reason = f'Failed trying to delete email: {e}'

        # O365 Outlook Mail
        elif delete_from_brand == 'MicrosoftGraphMail':
            # no soft or hard here
            odata = f'"$filter=internetMessageId eq \'{message_id}\'"'
            result = execute_command('msgraph-mail-list-emails',
                                     {'user_id': user_id, 'odata': odata, 'using-brand': delete_from_brand})
            results = result[0].get('value', [])
            results = [res for res in results if res.get('internetMessageId') == message_id]
            internal_id = results[0].get('id')
            resp = execute_command('msgraph-mail-delete-email', {'user_id': user_id, 'message_id': internal_id,
                                                                 'using-brand': delete_from_brand})

    except DeletionFailed as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute DeleteEmail. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
