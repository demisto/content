import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import time
seconds = time.time()
from typing import Dict, Any
import traceback

EMAIL_INTEGRATIONS = ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                      'SecurityAndCompliance']


class MissingEmailException(Exception):
    def __init__(self):
        super().__init__('Email was not found in mailbox.It is possible that the email was already deleted manually.')


class DeletionFailed(Exception):
    pass


def was_email_already_deleted(search_args, e):
    delete_email_from_context = demisto.get(demisto.context(), 'DeleteReportedEmail')
    if not isinstance(delete_email_from_context, list):
        delete_email_from_context = [delete_email_from_context]
    for item in delete_email_from_context:
        message_id = item.get('messge_id')
        if message_id == search_args.get('message_id') and search_args.get('Status') == 'Success':
            return 'Success', ''
    return 'Skipped', str(e)


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
    print(f'polling args:{polling_args}')
    return ScheduledCommand(
        command='DeleteReportedEmail',
        next_run_in_seconds=60,
        args=polling_args,
        timeout_in_seconds=600)


def security_and_compliance_delete_mail(args, user_id, email_subject, using_brand, delete_type, message_id):
    if not is_demisto_version_ge('6.2.0'):
        raise DemistoException('Deleting an email using this script for Security And Compliance integration is not '
                               'supported by this XSOAR server version. Please update your server version to 6.2.0 '
                               'or later, or delete the email using the playbook: '
                               'O365 - Security And Compliance - Search And Delete ')
    query = f'from:{user_id} AND subject:{email_subject}'
    search_name = args.get('search_name')
    is_finished_searching = args.get('is_finished_searching')
    print("entering func")
    if not is_finished_searching:
        if not search_name:
            # first time, creating the search
            print("first search")
            search_name = f'search_for_delete_{seconds}'
            execute_command('o365-sc-new-search', {'kql': query, 'search_name': search_name,
                                                   'using-brand': using_brand})
            execute_command('o365-sc-start-search', {'search_name': search_name, 'using-brand': using_brand})
            args['search_name'] = search_name

        # the search already exists, but not finished
        print("calling get search")
        results = execute_command('o365-sc-get-search', {'search_name': search_name, 'using-brand': using_brand})
        if results[0].get('Status') != 'Completed':
            print("returning ScheduledCommand")
            return 'In progress', schedule_next_command(args) # consider removing the commsndResults

        # the search is finished
        print("search is finished")
        # the email was found
        execute_command('o365-sc-new-search-action',
                        {'search_name': search_name, 'action': 'Purge', 'purge_type': delete_type,
                         'using-brand': using_brand})
        args['is_finished_searching'] = 'true'
        print(f'args after adding:{args}')
        return 'In progress', schedule_next_command(args)
    else:
        print("search is finished - starting to delete")
        results = execute_command('o365-sc-get-search-action', {'search_action_name': search_name,
                                                                'using-brand': using_brand})
        if results.get('Status') != 'Completed':
            print("not finished deleting yet")
            return schedule_next_command(args)
        execute_command('o365-sc-remove-search-action', {'search_action_name': search_name,
                                                         'using-brand': using_brand})
        execute_command('o365-sc-remove-search', {'search_name': search_name,
                                                  'using-brand': using_brand})
        return 'Success', None


def gmail_delete_args_function(search_result, search_args):
    is_permanent = True if search_args['delete-type'] == 'Hard' else False
    gmail_message_id = search_result[0].get('id')
    return {'user-id': search_args['user-id'], 'message-id': gmail_message_id, 'permanent': is_permanent,
            'using-brand': search_args['using-brand']}


def msgraph_delete_args_function(search_result, search_args):
    results = search_result[0].get('value', [])
    results = [res for res in results if res.get('internetMessageId') == search_args['message-id']]
    internal_id = results[0].get('id')
    return {'user_id': search_args['user_id'], 'message_id': internal_id, 'using-brand': search_args['using-brand']}


def agari_delete_args_function(search_result=None, search_args=None):
    agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
    return {'operation': 'delete', 'id': agari_message_id,
            'using-brand': search_args['using-brand']}  # TODO: fix


def ews_delete_args_function(search_result, search_args):
    delete_type = f'{search_args["delete-type"].lower()}'
    item_id = search_result[0].get('itemId')
    return {'item-ids': item_id, 'delete-type': delete_type, 'using-brand': search_args['using-brand']}


def delete_email(search_args, search_function, delete_args_function, delete_function, deletion_error_condition=
lambda x: 'successfully' not in x):
    search_result = None
    if search_function:
        search_result = execute_command(search_function, search_args)
        if not search_result or isinstance(search_result, str):
            raise MissingEmailException()
    delete_args = delete_args_function(search_result, search_args)
    resp = execute_command(delete_function, delete_args)
    if deletion_error_condition(resp):
        raise DeletionFailed(resp)


def get_search_args(args):
    incident_info = demisto.incident()
    custom_fields = incident_info.get('CustomFields')
    message_id = custom_fields.get("reportedemailmessageid")
    user_id = custom_fields.get('reportedemailto')
    delete_from_brand = args.get('delete_from_brand', incident_info.get('sourceBrand'))

    search_args = {
        'delete-type': args.get('delete_type'),
        'using-brand': delete_from_brand,
        'email_subject': custom_fields.get('reportedemailsubject'),
        'message-id': message_id, # TODO: not in sec & comp
    }
    additional_args = {
        'Gmail': {'query': f'Rfc822msgid:{message_id}', 'user-id': user_id},
        'EWSO365': {'target-mailbox': user_id},
        'EWS v2': {'target-mailbox': user_id},
        'MicrosoftGraphMail': {'user_id': user_id, 'odata': f'"$filter=internetMessageId eq \'{message_id}\'"'},
        'SecurityAndCompliance': {'user_id': user_id}
    }

    search_args.update(additional_args.get(delete_from_brand, {}))
    return search_args


def main():
    args = demisto.args()
    print(args)
    search_args = get_search_args(args)
    result = None
    deletion_failure_reason = None
    delete_from_brand = search_args['using-brand']
    scheduled_command = None
    try:
        if delete_from_brand not in EMAIL_INTEGRATIONS:
            raise DemistoException(
                f'Can not delete email using the chosen brand. The possible brands are: {EMAIL_INTEGRATIONS}')

        if delete_from_brand == 'SecurityAndCompliance':
            search_args = replace_in_keys(search_args, '-', '_')
            result, scheduled_command = security_and_compliance_delete_mail(args, **search_args)
        else:
            integrations_dict = {'Gmail': ('gmail-search', gmail_delete_args_function, 'gmail-delete-mail'),
                                 'EWSO365': ('ews-search-mailbox', ews_delete_args_function, 'ews-delete-items',
                                             lambda x: not isinstance(x, list)),
                                 'EWS v2': ('ews-search-mailbox', ews_delete_args_function, 'ews-delete-items',
                                            lambda x: not isinstance(x, list)),
                                 'Agari Phishing Defense': (None, agari_delete_args_function, 'apd-remediate-message'),
                                 'MicrosoftGraphMail': ('msgraph-mail-list-emails', msgraph_delete_args_function,
                                                        'msgraph-mail-delete-email')}
            delete_email(search_args, *integrations_dict[delete_from_brand])
            result = 'Success'
        # else:
        #     search_args = replace_in_keys(search_args, '-', '_')

    except MissingEmailException as e:
        result, deletion_failure_reason = was_email_already_deleted(search_args, e)
    except DeletionFailed as e:
        result = 'Failed'
        deletion_failure_reason = f'Failed deleting email: {str(e)}'
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute DeleteEmail. Error: {str(e)}')
    # TODO: add fields population

    finally:
        search_args.update({'result': result, 'deletion_failure_reason': deletion_failure_reason})
        search_args = remove_empty_elements(replace_in_keys(search_args, '-', '_'))
        return_results(
            CommandResults(
            readable_output=tableToMarkdown(
                'Deletion Results',
                search_args,
                headerTransform=string_to_table_header,
            ),
            outputs_prefix='DeleteReportedEmail',
            outputs_key_field='message_id',
            raw_response='',
            outputs=search_args,
            scheduled_command = scheduled_command
            ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
