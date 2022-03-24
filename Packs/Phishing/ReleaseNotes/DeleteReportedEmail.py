from CommonServerPython import *
from typing import Callable, Union
import traceback
import time
seconds = time.time()

EMAIL_INTEGRATIONS = ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                      'SecurityAndCompliance']


class MissingEmailException(Exception):
    def __init__(self):
        super().__init__('Email was not found in mailbox. It is possible that the email was already deleted manually.')


class DeletionFailed(Exception):
    pass


class DeletionArgs:

    @staticmethod
    def gmail(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for Gmail integration.
        Args:
            search_result: Results from the priorly preformed search operation
            search_args: The args used for the search operation

        Returns:
            The args needed for the deletion operation

        """
        is_permanent = True if search_args['delete-type'] == 'hard' else False
        gmail_message_id = search_result[0].get('id')
        return {
            'user-id': search_args['user-id'],
            'message-id': gmail_message_id,
            'permanent': is_permanent,
            'using-brand': search_args['using-brand'],
        }

    @staticmethod
    def msgraph(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for O365 - MSGraph integration.
        Args:
            search_result: Results from the priorly preformed search operation
            search_args: The args used for the search operation

        Returns:
            The args needed for the deletion operation

        """
        results = search_result[0].get('value', [])
        results = [res for res in results if res.get('internetMessageId') == search_args['message-id']]
        if not results:
            raise MissingEmailException()
        internal_id = results[0].get('id')
        return {
            'user_id': search_args['user_id'],
            'message_id': internal_id,
            'using-brand': search_args['using-brand'],
        }

    @staticmethod
    def agari(search_args: dict):
        """
        Parse the arguments needed for the delete operation for Agari Phishing Defence integration.
        Args:
            search_args: The args used for the search operation

        Returns:
            The args needed for the deletion operation

        """
        agari_message_id = demisto.get(demisto.context(), 'incident.apdglobalmessageid')
        return {
            'operation': 'delete',
            'id': agari_message_id,
            'using-brand': search_args['using-brand'],
        }

    @staticmethod
    def ews(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for EWS integrations (EWS365, EWSv2).
        Args:
            search_result: Results from the priorly preformed search operation
            search_args: The args used for the search operation

        Returns:
            The args needed for the deletion operation

        """
        delete_type = f'{search_args["delete-type"]}'
        item_id = search_result[0].get('itemId')
        return {
            'item-ids': item_id,
            'delete-type': delete_type,
            'using-brand': search_args['using-brand'],
        }


def check_demisto_version():
    """
    Check if the demisto version is suitable for preforming the polling flow (6.2 and above)
    """
    if not is_demisto_version_ge('6.2.0'):
        raise DemistoException('Deleting an email using this script for Security And Compliance integration is not '
                               'supported by this XSOAR server version. Please update your server version to 6.2.0 '
                               'or later, or delete the email using the playbook: '
                               'O365 - Security And Compliance - Search And Delete ')


def schedule_next_command(args: dict):
    """
    Handle the creation of the ScheduleCommand object
    Returns:
        ScheduleCommand object that will cal this script again.
    """
    polling_args = {
        'interval_in_seconds': 120,
        'polling': True,
        **args,
    }
    return ScheduledCommand(
        command='DeleteReportedEmail',
        next_run_in_seconds=120,
        args=polling_args,
        timeout_in_seconds=600,
    )


def was_email_already_deleted(search_args: dict, e: Exception):
    """
    Checks if the email was already deleted by this script, using the context data info.
    Args:
        search_args: the command arguments
        e: error msg indicating the email was not found

    Returns:
        'Success', '' if the email was already previously deleted by this script
        'Skipped', e if the email was not found in the mailbox and was not priorly deleted by this script

    """
    delete_email_from_context = demisto.get(demisto.context(), 'DeleteReportedEmail')
    if not isinstance(delete_email_from_context, list):
        delete_email_from_context = [delete_email_from_context]
    for item in delete_email_from_context:
        message_id = item.get('messge_id')
        if message_id == search_args.get('message_id') and item.get('result') == 'Success':
            return 'Success', ''
    return 'Skipped', str(e)


def was_email_found_security_and_compliance(search_results: dict):
    """
    Checks if the search command using the Security & Compliance integration has found the email of interest.
    Args:
        search_results: The results retrived from the search preformed priorly.
    Returns:
        True if the email was found, False otherwise

    """
    success_results = search_results[0].get('SuccessResults').split(', ')
    for item in success_results:
        if item.startswith(('Item count', 'Total size')):
            if int(item.split(': ')) > 0:
                return True
    return False


def security_and_compliance_delete_mail(args: dict, user_id: str, email_subject: str, using_brand: str,
                                        delete_type: str):
    """
    Search and delete the email using the Security & Compliance integration, preformed by the genric polling flow.
    Args:
        args: script args
        user_id: user id of email of interest
        email_subject: subject of email of interest
        using_brand: the brand used for this operation
        delete_type: the delete type, soft or hard.
    Returns:
        The command status (In Progress or Success) and the scheduledCommand object for the next command, if needed.

    """
    check_demisto_version()
    query = f'from:{user_id} AND subject:{email_subject}'
    search_name = args.get('search_name', '')

    if not search_name:
        # first time entering this function, creating the search
        search_name = f'search_for_delete_{seconds}'
        execute_command('o365-sc-new-search', {'kql': query, 'search_name': search_name, 'using-brand': using_brand})
        execute_command('o365-sc-start-search', {'search_name': search_name, 'using-brand': using_brand})
        args['search_name'] = search_name

    # check the search status
    results = execute_command('o365-sc-get-search', {'search_name': search_name, 'using-brand': using_brand})

    if not was_email_found_security_and_compliance(results):
        raise MissingEmailException()

    # check if the search is complete
    if results[0].get('Status') != 'Completed':
        return 'In Progress', schedule_next_command(args)

    # the email was found, start deletion
    search_action_name = f'{search_name}_Purge'
    search_actions_list = [item.get('Name') for item in execute_command('o365-sc-list-search-action', {})]

    # create the deletion action if it does not already exists
    if search_action_name not in search_actions_list:
        execute_command('o365-sc-new-search-action',
                        {'search_name': search_name, 'action': 'Purge', 'purge_type': delete_type.capitalize(),
                         'using-brand': using_brand})

    results = execute_command('o365-sc-get-search-action', {'search_action_name': search_action_name,
                                                            'using-brand': using_brand})
    # check if the deletion is complete
    if results.get('Status') != 'Completed':
        return 'In Progress', schedule_next_command(args)

    # the email was deleted, clean searches
    execute_command('o365-sc-remove-search-action', {'search_action_name': search_name, 'using-brand': using_brand})
    execute_command('o365-sc-remove-search', {'search_name': search_name, 'using-brand': using_brand})

    return 'Success', None


def delete_email(search_args: dict, search_function: str,
                 delete_args_function: Union[Callable[[dict, dict], dict],
                                             Callable[[dict], dict]], delete_function: str,
                 deletion_error_condition: Callable[[str], bool] = lambda x: 'successfully' not in x):
    """
    Generic function to preform the search and delete operations.
    Args:
        search_args: arguments needed to preform the search command.
        search_function: a string representing the search command.
        delete_args_function: a function that parses the arguments needed to preform the search command.
        delete_function: a string representing the delete command.
        deletion_error_condition: a condition to validate if the deletion was successful or not.
    Returns:
        Success if the deletion succeeded, fails otherwise
    """
    if search_function:
        search_result = execute_command(search_function, search_args)
        if not search_result or isinstance(search_result, str):
            raise MissingEmailException()
        delete_args = delete_args_function(search_result, search_args)
    else:
        delete_args = delete_args_function(search_args)
    resp = execute_command(delete_function, delete_args)
    if deletion_error_condition(resp):
        raise DeletionFailed(resp)
    return 'Success'


def get_search_args(args: dict):
    """
    Get the parsed arguments needed for the search operation
    Args:
        args: this script's arguments.

    Returns: parsed arguments needed for the search operation

    """
    incident_info = demisto.incident()
    custom_fields = incident_info.get('CustomFields')
    message_id = custom_fields.get("reportedemailmessageid")
    user_id = custom_fields.get('reportedemailto')
    delete_from_brand = args.get('delete_from_brand', incident_info.get('sourceBrand'))

    search_args = {
        'delete-type': args.get('delete_type'),
        'using-brand': delete_from_brand,
        'email_subject': custom_fields.get('reportedemailsubject'),
        'message-id': message_id,
    }
    additional_args = {
        'Gmail': {'query': f'Rfc822msgid:{message_id}', 'user-id': user_id},
        'EWSO365': {'target-mailbox': user_id},
        'EWS v2': {'target-mailbox': user_id},
        'MicrosoftGraphMail': {'user_id': user_id, 'odata': f'"$filter=internetMessageId eq \'{message_id}\'"'},
        'SecurityAndCompliance': {'user_id': user_id},
    }

    search_args.update(additional_args.get(delete_from_brand, {}))
    return search_args


def main():
    args = demisto.args()
    search_args = get_search_args(args)
    result, deletion_failure_reason, scheduled_command = None, None, None
    delete_from_brand = search_args['using-brand']
    try:
        if delete_from_brand not in EMAIL_INTEGRATIONS:
            raise DemistoException(
                f'Can not delete email using the chosen brand. The possible brands are: {EMAIL_INTEGRATIONS}')

        if delete_from_brand == 'SecurityAndCompliance':
            security_and_compliance_args = {k.replace('-', '_'): v for k, v in search_args.items() if k != 'message-id'}
            result, scheduled_command = security_and_compliance_delete_mail(args, **security_and_compliance_args)

        else:
            integrations_dict = {
                'Gmail': ('gmail-search', DeletionArgs.gmail, 'gmail-delete-mail'),
                'EWSO365': ('ews-search-mailbox', DeletionArgs.ews, 'ews-delete-items',
                             lambda x: not isinstance(x, list)),
                'EWS v2': ('ews-search-mailbox', DeletionArgs.ews, 'ews-delete-items',
                            lambda x: not isinstance(x, list)),
                'Agari Phishing Defense': (None, DeletionArgs.agari, 'apd-remediate-message'),
                'MicrosoftGraphMail': ('msgraph-mail-list-emails', DeletionArgs.msgraph, 'msgraph-mail-delete-email'),
                                 }
            result = delete_email(search_args, *integrations_dict[delete_from_brand])

    except MissingEmailException as e:
        result, deletion_failure_reason = was_email_already_deleted(search_args, e)
    except DeletionFailed as e:
        result, deletion_failure_reason = 'Failed', f'Failed deleting email: {str(e)}'
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute DeleteEmail. Error: {str(e)}')

    finally:
        search_args.update({'result': result, 'deletion_failure_reason': deletion_failure_reason})
        search_args = remove_empty_elements(replace_in_keys(search_args, '-', '_'))
        demisto.executeCommand('setIncident',
                               {'emaildeleteresult': result,
                                "emaildeletereason": deletion_failure_reason})
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
                scheduled_command=scheduled_command,
                ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
