import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Callable, Union
import time
from urllib.parse import quote, unquote

DOCS_TROUBLESHOOTING_URL = 'https://xsoar.pan.dev/docs/reference/scripts/delete-reported-email#troubleshooting'
EMAIL_INTEGRATIONS = ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                      'SecurityAndCompliance', 'SecurityAndComplianceV2']
seconds = time.time()


class MissingEmailException(Exception):
    def __init__(self):
        super().__init__('Email not found in mailbox. It may have been manually deleted.')


class DeletionFailed(Exception):
    pass


class DeletionArgs:

    @staticmethod
    def gmail(search_result: dict, search_args: dict):
        """
        Parse the arguments needed for the delete operation for Gmail integration.
        Args:
            search_result: Results from the previously performed search operation
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        is_permanent = search_args['delete-type'] == 'hard'
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
            search_result: Results from the previously performed search operation
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

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
        Parse the arguments needed for the delete operation for the Agari Phishing Defense integration.
        Args:
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        incident_info = demisto.incident()
        agari_message_id = incident_info.get('CustomFields', {}).get('apdglobalmessageid')
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
            search_result: Results from the previously performed search operation
            search_args: The arguments used for the search operation

        Returns:
            The arguments needed for the deletion operation

        """
        item_id = search_result[0].get('itemId')
        return {
            'item-ids': item_id,
            'delete-type': search_args['delete-type'],
            'target-mailbox': search_args['target-mailbox'],
            'using-brand': search_args['using-brand'],
        }


def check_demisto_version():
    """
    Check if the Cortex XSOAR version is suitable for performing the polling flow (6.2 and above)
    """
    if not is_demisto_version_ge('6.2.0'):
        raise DemistoException('Deleting an email using this script for Security And Compliance integration is not '
                               'supported by this Cortex XSOAR server version. Please update your server version to 6.2.0 '
                               'or later, or delete the email using the '
                               'O365 - Security And Compliance - Search And Delete playbook')


def schedule_next_command(args: dict):
    """
    Handle the creation of the ScheduleCommand object
    Returns:
        ScheduleCommand object that will call this script again.
    """
    polling_args = {
        'interval_in_seconds': 60,
        'polling': True,
        **args,
    }
    return ScheduledCommand(
        command='DeleteReportedEmail',
        next_run_in_seconds=60,
        args=polling_args,
        timeout_in_seconds=60,
    )


def was_email_already_deleted(search_args: dict, e: str):
    """
    Checks if the email was already deleted by this script, using the context data information.
    Args:
        search_args: the command arguments
        e: error message indicating the email was not found

    Returns:
        'Success', if the email was previously deleted by this script
        'Skipped', if the email was not found in the mailbox and was not previously deleted by this script

    """
    delete_email_from_context = demisto.get(demisto.context(), 'DeleteReportedEmail')
    if delete_email_from_context:
        if not isinstance(delete_email_from_context, list):
            delete_email_from_context = [delete_email_from_context]
        for item in delete_email_from_context:
            message_id = item.get('message_id')
            if message_id == search_args.get('message_id') and item.get('result') == 'Success':
                return 'Success', ''
    return 'Skipped', e


def was_email_found_security_and_compliance(search_results: list):
    """
    Checks if the search command using the Security & Compliance integration found the email of interest.
    Args:
        search_results: The results retrieved from the search previously performed.
    Returns:
        True if the email was found, False otherwise

    """
    success_results = search_results[0].get('SuccessResults').split(', ')
    for item in success_results:
        if item.startswith('Item count'):
            if int(item.split(': ')[1]) > 0:
                return True
    return False


def security_and_compliance_delete_mail(args: dict, to_user_id: str, from_user_id: str, email_subject: str,
                                        using_brand: str, delete_type: str, message_id: str):
    """
    Search and delete the email using the Security & Compliance integration, performed by the generic polling flow.
    Args:
        args: script args
        from_user_id: source user ID of the email of interest
        to_user_id: destination user ID of the email
        email_subject: subject of the email of interest
        using_brand: the brand used for this operation
        delete_type: the delete type, soft or hard.
        message_id: the message id of the email.
    Returns:
        The command status (In Progress or Success) and the scheduledCommand object for the next command, if needed.

    """
    check_demisto_version()
    query = f'from:{from_user_id} AND subject:\"{email_subject}\"'
    search_name = args.get('search_name', '')

    if was_email_already_deleted({'message_id': message_id}, '')[0] == 'Success':
        # Since Security & Compliance will change the context due to the polling flow, we conduct this check first,
        # instead of only if the email is not found.
        return 'Success', None

    if not search_name:
        # first time entering this function, creating the search
        search_name = f'search_for_delete_{seconds}'
        execute_command('o365-sc-new-search', {'kql': query, 'search_name': search_name, 'using-brand': using_brand,
                                               'exchange_location': to_user_id})
        execute_command('o365-sc-start-search', {'search_name': search_name, 'using-brand': using_brand})
        args['search_name'] = search_name

    # check the search status
    results = execute_command('o365-sc-get-search', {'search_name': search_name, 'using-brand': using_brand})

    # check if the search is complete
    if results[0].get('Status') != 'Completed':
        return 'In Progress', schedule_next_command(args)

    if not was_email_found_security_and_compliance(results):
        raise MissingEmailException()

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
    Generic function to perform the search and delete operations.
    Args:
        search_args: arguments needed to perform the search command.
        search_function: a string representing the search command.
        delete_args_function: a function that parses the arguments needed to perform the search command.
        delete_function: a string representing the delete command.
        deletion_error_condition: a condition to validate if the deletion was successful or not.
    Returns:
        Success if the deletion succeeded, fails otherwise
    """
    if search_function:
        search_result = execute_command(search_function, search_args)
        if not search_result or isinstance(search_result, str):
            raise MissingEmailException()
        delete_args = delete_args_function(search_result, search_args)  # type: ignore
    else:
        delete_args = delete_args_function(search_args)  # type: ignore
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
    custom_fields = incident_info.get('CustomFields', {})
    message_id = custom_fields.get('reportedemailmessageid')
    user_id = custom_fields.get('reportedemailto')
    email_subject = custom_fields.get('reportedemailsubject')
    from_user_id = custom_fields.get('reportedemailfrom')
    email_origin = custom_fields.get('reportedemailorigin')
    delete_type = args.get('delete_type', custom_fields.get('emaildeletetype', 'soft'))
    delete_from_brand = delete_from_brand_handler(incident_info, args)

    missing_field_error_message = "'{field_name}' field could not be found.\n" \
                                  f"See {DOCS_TROUBLESHOOTING_URL} for possible solutions."

    if not email_origin or email_origin.lower() == 'none':
        raise ValueError(missing_field_error_message.format(field_name='Reported Email Origin'))

    if not message_id:
        raise ValueError(missing_field_error_message.format(field_name='Reported Email Message ID'))

    if not user_id:
        raise ValueError(missing_field_error_message.format(field_name='Reported Email To'))

    search_args = {
        'delete-type': delete_type,
        'using-brand': delete_from_brand,
        'email_subject': email_subject,
        'message-id': message_id,
    }
    additional_args = {
        'Gmail': {'query': f'Rfc822msgid:{message_id}', 'user-id': user_id},
        'EWSO365': {'target-mailbox': user_id},
        'EWS v2': {'target-mailbox': user_id},
        'MicrosoftGraphMail': {'user_id': user_id, 'odata': f'"$filter=internetMessageId eq '
                                                            f'\'{quote(unquote(message_id))}\'"'},
        'SecurityAndCompliance': {'to_user_id': user_id, 'from_user_id': from_user_id},
        'SecurityAndComplianceV2': {'to_user_id': user_id, 'from_user_id': from_user_id}
    }

    search_args.update(additional_args.get(delete_from_brand, {}))
    return search_args


def delete_from_brand_handler(incident_info: dict, args: dict):
    """
    Handle the delete_from_brand argument in the following logic:
    1. If the source brand exists in the 'emaildeletefrombrand' field, use it.
    2. If the field is empty, use the script's argument.
    3. If there is no argument given, use the incident's source brand.
    2. If the value is given (in any of the above ways) but it is not of a suitable integration, raise an error.
    Otherwise, use it.

    Args:
        incident_info: Incident info from the context data.
        args: the arguments of this script

    Returns:
        The suitable delete brand

    """
    delete_from_brand = incident_info.get('CustomFields', {}).get('emaildeletefrombrand')
    if not delete_from_brand or delete_from_brand == 'Unspecified':
        delete_from_brand = args.get('delete_from_brand', incident_info.get('sourceBrand'))

    elif delete_from_brand not in EMAIL_INTEGRATIONS:
        raise DemistoException(
            f'Cannot delete the email using the chosen brand. The possible brands are: {EMAIL_INTEGRATIONS}')
    return delete_from_brand


def main():
    args = demisto.args()
    search_args = get_search_args(args)
    result, deletion_failure_reason, scheduled_command = '', '', None
    delete_from_brand = search_args['using-brand']

    try:
        if delete_from_brand in ['SecurityAndCompliance', 'SecurityAndComplianceV2']:
            security_and_compliance_args = {k.replace('-', '_'): v for k, v in search_args.items()}
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
            result = delete_email(search_args, *integrations_dict[delete_from_brand])  # type: ignore

    except MissingEmailException as e:
        result, deletion_failure_reason = was_email_already_deleted(search_args, str(e))
    except DeletionFailed as e:
        result, deletion_failure_reason = 'Failed', f'Failed deleting email: {str(e)}'
    except Exception as e:
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
                scheduled_command=scheduled_command
            ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
