from CommonServerPython import *

''' IMPORTS '''

import urllib.parse
import urllib3
from typing import List, Dict, Any, Tuple, Union, Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MESSAGES: Dict[str, str] = {
    'TEST_FAILED_ERROR': 'Test connectivity failed. Check the configuration parameters provided.',
    'BOOLEAN_ERROR': 'The argument {} must be either true or false.',
}

HR_MESSAGES: Dict[str, str] = {
    'ACL_ADD_SUCCESS': 'Giving an access control rule for calendar id "{}".',
    'LIST_COMMAND_SUCCESS': 'Total Retrieved {}: {}',
}

URL_SUFFIX: Dict[str, str] = {
    'TEST_MODULE': 'calendar/v3/users/me/calendarList',
    'CALENDAR_ACL': 'calendar/v3/calendars/{}/acl'
}

SCOPES: Dict[str, List[str]] = {
    'TEST_MODULE': ['https://www.googleapis.com/auth/userinfo.email'],
    'CALENDAR': ['https://www.googleapis.com/auth/calendar'],
}

OUTPUT_PREFIX: Dict[str, str] = {
    'ADD_ACL': 'GoogleCalendar.Acl',
    'LIST_ACL': 'GoogleCalendar.Acl(val.id == obj.id && val.calendarId == obj.calendarId && val.userId == obj.userId)',
    'LIST_ACL_PAGE_TOKEN': 'GoogleCalendar.PageToken.Acl(val.calendarId == obj.calendarId && val.userId == obj.userId)',
}

NEXT_PAGE_TOKEN: str = '### Next Page Token: {}\n'


def prepare_acl_list_output(acl_records: Dict[str, Any], calendar_id: str, user_id: str) -> \
        Tuple[Dict[str, Union[List[Dict[str, Union[str, Any]]], Dict[str, Union[str, Any]]]], List[dict]]:
    """
    Prepares context output and human readable for gsuite-acl-list command.

    :param acl_records: Dict containing acl records.
    :param calendar_id: Calendar id.
    :param user_id: User  id.
    :return: Tuple of prepared context output list and human readable.
    """
    acl_context = [{'calendarId': calendar_id,
                    'userId': user_id,
                    'kind': record.get('kind', ''),
                    'etag': record.get('etag', ''),
                    'id': record.get('id', ''),
                    'scopeType': record.get('scope', {}).get('type', ''),
                    'scopeValue': record.get('scope', {}).get('value', ''),
                    'role': record.get('role', '')
                    } for record in acl_records.get('items', [])]

    page_context = {
        'calendarId': calendar_id,
        'userId': user_id,
        'nextPageToken': acl_records.get('nextPageToken', ''),
        'nextSyncToken': acl_records.get('nextSyncToken', '')
    }

    outputs = {
        OUTPUT_PREFIX['LIST_ACL']: acl_context,
        OUTPUT_PREFIX['LIST_ACL_PAGE_TOKEN']: page_context
    }
    outputs = GSuiteClient.remove_empty_entities(outputs)
    acl_hr = acl_context
    acl_hr_list = [
        {acl_key: acl_value for acl_key, acl_value in acl.items() if
         acl_key not in ['kind', 'etag', 'calendarId', 'userId']} for acl in acl_hr]
    acl_hr_list = GSuiteClient.remove_empty_entities(acl_hr_list)
    return outputs, acl_hr_list


def prepare_output_acl_add(acl_records: Dict[str, Any], calendar_id: str, user_id: str) -> Tuple[Dict[str, Any],
                                                                                                 List[Dict[str, Any]]]:
    """
    Prepares context output and human readable for gsuite-user-to-acl-add command.

    :param acl_records: List containing dictionaries of ACL records.
    :param calendar_id: Calendar id.
    :param user_id: User id.
    :return: prepared context output list.
    """
    acl_id = acl_records.get('id', '')
    acl_scope_type = acl_records.get('scope', {}).get('type', '')
    acl_scope_value = acl_records.get('scope', {}).get('value', '')
    acl_role = acl_records.get('role', '')
    acl_add_output = {
        'calendarId': calendar_id,
        'userId': user_id,
        'kind': acl_records.get('kind', ''),
        'etag': acl_records.get('etag', ''),
        'id': acl_id,
        'scopeType': acl_scope_type,
        'scopeValue': acl_scope_value,
        'role': acl_role}
    acl_add_output = GSuiteClient.remove_empty_entities(acl_add_output)
    acl_add_hr = {
        'id': acl_id,
        'scopeType': acl_scope_type,
        'scopeValue': acl_scope_value,
        'role': acl_role
    }
    acl_add_hr = GSuiteClient.remove_empty_entities(acl_add_hr)
    return acl_add_hr, acl_add_output


def prepare_body_gsuite_acl_add(args: Dict[str, str]) -> Dict[str, Any]:
    """
    To prepare params for acl_add_command.

    :param args: Command arguments.
    :return: Dict of body.
    """
    return GSuiteClient.remove_empty_entities({
        'role': args.get('role'),
        'scope': {
            'type': args.get('scope_type'),
            'value': args.get('scope_value')
        }
    })


def prepare_params_for_acl_list(args: Dict[str, str]) -> Dict[str, Union[str, int]]:
    """
    To prepare params for gsuite_acl_list.

    :param args: Command arguments.
    :return: Dict of arguments.
    """
    max_result = args.get('max_results', 100)
    GSuiteClient.validate_set_boolean_arg(args, 'show_deleted', )

    return GSuiteClient.remove_empty_entities({
        'maxResults': max_result,
        'pageToken': args.get('page_token', ''),
        'showDeleted': args.get('show_deleted', 'false'),
        'syncToken': args.get('sync_token', '')
    })


''' COMMAND FUNCTIONS '''


@logger
def test_module(gsuite_client) -> str:
    """
    Performs test connectivity by valid http response

    :param gsuite_client: client object which is used to get response from api.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """

    with GSuiteClient.http_exception_handler():
        gsuite_client.set_authorized_http(scopes=SCOPES['CALENDAR'])
        gsuite_client.http_request(url_suffix=URL_SUFFIX['TEST_MODULE'], method='GET')
    return 'ok'


@logger
def acl_add_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an access control rule.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    calendar_id = args.get('calendar_id', '')
    calendar_id = urllib.parse.quote(calendar_id)  # type: ignore

    user_id = args.get('user_id', '')
    body = prepare_body_gsuite_acl_add(args)

    send_notifications = args.get('send_notifications', 'true').lower()
    if send_notifications not in ['true', 'false']:
        raise ValueError(MESSAGES['BOOLEAN_ERROR'].format('send_notifications'))

    client.set_authorized_http(scopes=SCOPES['CALENDAR'], subject=user_id)
    response = client.http_request(url_suffix=URL_SUFFIX['CALENDAR_ACL'].format(calendar_id),
                                   body=body, method='POST', params={'sendNotifications': send_notifications})

    acl_add_hr, acl_add_output = prepare_output_acl_add(response, args.get('calendar_id', ''), user_id)
    readable_output = tableToMarkdown(
        HR_MESSAGES['ACL_ADD_SUCCESS'].format(args.get('calendar_id'), acl_add_hr.get('scopeValue', '')),
        acl_add_hr, headerTransform=pascalToSpace, removeNull=True)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['ADD_ACL'],
        outputs_key_field=['calendarId', 'id', 'userId'],
        outputs=acl_add_output,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def acl_list_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Shows the access control lists for the given calendar id. The ACL list will show who has access to the calendar
    and what level of access they have.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    user_id = args.get('user_id', '')
    calendar_id = urllib.parse.quote(args.get('calendar_id', ''))  # type: ignore

    params = prepare_params_for_acl_list(args)

    client.set_authorized_http(scopes=SCOPES['CALENDAR'], subject=user_id)
    response = client.http_request(url_suffix=URL_SUFFIX['CALENDAR_ACL'].format(calendar_id), method='GET',
                                   params=params)

    outputs, acl_hr_list = prepare_acl_list_output(response, args.get('calendar_id', ''), user_id)
    readable_hr = ''
    if response.get('nextPageToken'):
        readable_hr += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
    if response.get('nextSyncToken'):
        readable_hr += '### Next Sync Token: {}\n'.format(response.get('nextSyncToken'))

    readable_hr += tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('ACL', len(acl_hr_list)), acl_hr_list,
                                   headerTransform=pascalToSpace,
                                   removeNull=True)
    return CommandResults(
        outputs=outputs,
        readable_output=readable_hr,
        raw_response=response
    )


def main() -> None:
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dictionary
    commands: Dict[str, Callable] = {
        'google-calendar-acl-add': acl_add_command,
        'google-calendar-acl-list': acl_list_command,
    }
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        params = demisto.params()
        service_account_dict = GSuiteClient.safe_load_non_strict_json(params.get('user_service_account_json'))
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        headers = {
            'Content-Type': 'application/json'
        }

        # prepare client class object
        gsuite_client = GSuiteClient(service_account_dict,
                                     base_url='https://www.googleapis.com/', verify=verify_certificate, proxy=proxy,
                                     headers=headers)

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':

            result = test_module(gsuite_client)
            demisto.results(result)

        elif command in commands:
            return_results(commands[command](gsuite_client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


from GSuiteApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
