# import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from GSuiteApiModule import *  # noqa: E402

''' IMPORTS '''

import urllib3
from typing import List, Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

ADMIN_EMAIL = None

''' CONSTANTS '''

MESSAGES: Dict[str, str] = {
    'TEST_FAILED_ERROR': 'Test connectivity failed. Check the configuration parameters provided.',
    'BOOLEAN_ERROR': 'The argument {} must be either true or false.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'REQUIRED_ARGS_CUSTOM_SCHEMA': 'Argument field_raw_json or field_json_entry_id is required.',
    'CUSTOM_SCHEMA_UPDATE_REQUIRED_ARGS': 'Argument schema_id or schema_name is required.',
    'UNEXPECTED_ERROR': 'An unexpected error occurred.',
    'DATATRANSFER_MISSING_ARGUMENT': 'The argument application_id or applications_raw_json'
                                     ' or application_raw_json_entry_id is required.',
    'DATATRANSFER_TRANSFER_PARAM_FORMAT_ERROR': 'application_transfer_params argument not in expected format. Please '
                                                'provide a comma separated string of format "key1:val;key2:val1,val2"',
    'INVALID_ADMIN_EMAIL': 'Invalid value of argument/parameter Admin Email.'
}

OUTPUT_PREFIX: Dict[str, str] = {
    'ACTIVITY_LIST': 'GSuite.ActivitySearch',
    'ACTIVITY_LIST_PAGE_TOKEN': 'GSuite.PageToken.ActivitySearch',
}

URL_SUFFIX = 'admin/reports/v1/activity/users/{}/applications/{}'
SCOPE = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']

HR_MESSAGES: Dict[str, str] = {
    'MOBILE_UPDATE_SUCCESS': 'Mobile device with resource id - {} updated.',
    'MOBILE_DELETE_SUCCESS': 'Mobile device with resource id - {} deleted.',
    'USER_CREATE': 'User Details',
    'LIST_COMMAND_SUCCESS': 'Total Retrieved {}: {}',
    'ALIAS_ADD_SUCCESS': 'Added alias "{}" to user key "{}".',
    'GROUP_CREATE_SUCCESS': 'A new group named "{}" created.',
    'ROLE_ASSIGNMENT_CREATE': 'Role Assignment Details',
    'ROLE_CREATE_PRIVILEGES_INCORRECT_FORMAT': 'role_privileges argument missing or not in expected format. Please '
                                               'provide a comma separated string of form "PrivilegeName1:ServiceId1,'
                                               'PrivilegeName2:ServiceId2".',
    'ROLE_CREATE_SUCCESS': 'A new role created.',
    'TOKEN_REVOKE_SUCCESS': 'All access tokens deleted for {}.',
    'NO_RECORDS': 'No {} found for the given argument(s).',
    'CUSTOM_USER_SCHEMA_CREATE': 'Custom User Schema Details',
    'CUSTOM_USER_SCHEMA_FIELD_DETAILS': 'Field Details',
    'CUSTOM_USER_SCHEMA_UPDATE': 'Updated Custom User Schema Details',
    'DATATRANSFER_REQUEST_CREATE_SUCCESS': 'Data Transfer Details',
    'NOT_FOUND': 'No {} found.',
    'USER_DELETE': 'User with user key {} deleted successfully.',
    'USER_UPDATE': 'Updated User Details'
}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' HELPER FUNCTIONS '''


def is_email_valid(email: str) -> bool:
    """
    Validates provided email is valid or not.

    :param email: email string.
    :return:  True if email is in valid format.
    """

    return True if re.match(emailRegex, email) else False


def prepare_args_for_activities_list(args: Dict[str, str]) -> Dict[str, str]:
    """
    Prepares arguments for gsuite-activity-search command.

    :param args: Command arguments.

    :return: Prepared arguments.
    """

    return GSuiteClient.remove_empty_entities({
        'eventName': args.get('event_name'),
        'filters': args.get('filters'),
        'orgUnitId': args.get('org_unit_id'),
        'groupIdFilter': args.get('group_id'),
        'actorIpAddress': args.get('actor_ip_address'),
        'startTime': args.get('start_time'),
        'endTime': args.get('end_time'),
        'maxResults': GSuiteClient.validate_get_int(args.get('max_results'),
                                                    MESSAGES['INTEGER_ERROR'].format('max_results')),
        'pageToken': args.get('page_token')
    })


def prepare_readable_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    readable_items = [
        {
            'time': item.get('id', {}).get('time'),
            'applicationName': item.get('id', {}).get('applicationName'),
            'email': item.get('actor', {}).get('email'),
            'profileId': item.get('actor', {}).get('profileId'),
            'ipAddress': item.get('ipAddress', ''),
            'events': item['events']
        } for item in items
    ]

    return GSuiteClient.remove_empty_entities(readable_items)


def prepare_output_for_activities_list(response: Dict[str, Any]) -> Dict[str, Any]:
    """
        prepares context output for gsuite-activity-search.

        :param response: API response.

        :return: output dictionary.
        """
    output_items = [{'id': item['id'],
                     'actor': item['actor'],
                     'ipAddress': item.get('ipAddress', []),
                     'events': item['events']} for item in response.get('items', [])]

    return {
        'GSuite.ActivitySearch': GSuiteClient.remove_empty_entities(output_items),
        'GSuite.PageToken.ActivitySearch': {
            'nextPageToken': response['nextPageToken']
        } if response.get('nextPageToken', '') else {}
    }


def create_end_time(start_time: str, added_time: str) -> str:
    time_list = added_time.split(' ')

    if len(time_list) < 2:
        raise DemistoException("Invalid time parameter")

    timedelta_param = timedelta()
    time_param = int(time_list[0])
    if time_list[1] == 'minutes':
        timedelta_param = timedelta(minutes=time_param)
    elif time_list[1] == 'hours':
        timedelta_param = timedelta(hours=time_param)
    elif time_list[1] == 'days':
        timedelta_param = timedelta(days=time_param)

    end_time = dateparser.parse(start_time) + timedelta_param

    return end_time.strftime(DATE_FORMAT)


@logger
def test_module(client: GSuiteClient) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """
    with GSuiteClient.http_exception_handler():
        if ADMIN_EMAIL:
            suffix = URL_SUFFIX.format('all', 'admin')
            client.http_request(url_suffix=suffix, method='GET', params={'max_results': '1'})
        else:
            return_results("Please insert Admin Email parameter for the test to run")
    return 'ok'


''' COMMAND FUNCTIONS '''


def activities_list_command(client: GSuiteClient, args: Dict[str, Any]) -> CommandResults:
    """
    Prints all activities in the G Suite instance.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    arguments = prepare_args_for_activities_list(args)
    response = client.http_request(
        url_suffix=URL_SUFFIX.format(args.get('user_key', 'all'), args.get('application_name')),
        params=arguments)

    # Readable Output
    readable_items = prepare_readable_items(response.get('items', []))

    readable_output = f'### Next Page Token: {response["nextPageToken"]}\n' if response.get("nextPageToken") else ''
    readable_output += tableToMarkdown(
        'Total Retrieved {}: {}'.format('Activities', len(response.get('items', []))),
        readable_items,
        ['time', 'applicationName', 'email', 'profileId', 'ipAddress', 'events']) if response.get(
        'items') else 'No activities found for the given ' \
                      'argument(s). '
    # Context
    context_outputs = prepare_output_for_activities_list(response)

    return CommandResults(
        outputs=context_outputs,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def fetch_incidents(client: GSuiteClient, first_fetch_time: str, fetch_limit: int, application: str) -> List[Dict]:
    incidents = []
    last_run_dict = demisto.getLastRun()
    last_run = last_run_dict.get('last_run')
    last_ids = last_run_dict.get('last_ids', [])

    if not last_run:  # this is the first run
        last_run = dateparser.parse(first_fetch_time).strftime(DATE_FORMAT)

    end_time = create_end_time(last_run, '1 hour')

    response = client.http_request(
        url_suffix=URL_SUFFIX.format('all', application),
        params={'startTime': last_run,
                'endTime': end_time})

    items = response.get('items', [])
    sorted_items = sorted(items, key=lambda k: k['id']['time'])  # sort the data from earlist to last.
    counter = 0

    for item in sorted_items:
        if counter == fetch_limit:
            break

        if item['id']['uniqueQualifier'] in last_ids:
            continue

        counter += 1
        incident = {
            'name': f"GSuite Auditor event {item['id']['applicationName']} {item['id']['uniqueQualifier']}",
            'occurred': item['id']['time'],
            'rawJSON': json.dumps(item)
        }
        incidents.append(incident)

    if len(incidents) > 0:
        new_last_run = incidents[-1]['occurred']
    elif end_time < time.ctime():
        new_last_run = end_time
    else:
        new_last_run = last_run

    new_last_ids = []
    for incident in incidents:
        if incident['occurred'] == new_last_run:
            item = json.loads(incident["rawJSON"])
            new_last_ids.append(item['id']['uniqueQualifier'])

    demisto.setLastRun({'last_run': new_last_run, 'last_ids': new_last_ids})
    return incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        global ADMIN_EMAIL
        params = demisto.params()
        service_account_dict = GSuiteClient.safe_load_non_strict_json(params.get('user_service_account_json'))
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        headers = {
            'Content-Type': 'application/json'
        }

        # prepare client class object
        gsuite_client = GSuiteClient(service_account_dict,
                                     base_url='https://admin.googleapis.com/', verify=verify_certificate, proxy=proxy,
                                     headers=headers)

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())
        first_fetch_time = demisto.params().get('first_fetch', '12 hours').strip()
        fetch_limit = demisto.params().get('max_fetch', '10')
        fetch_app = params.get('application', 'admin')

        ADMIN_EMAIL = args.get('admin_email') if args.get('admin_email') else params.get('admin_email')
        # Validation of ADMIN_EMAIL
        if ADMIN_EMAIL and not is_email_valid(ADMIN_EMAIL):
            raise ValueError(MESSAGES['INVALID_ADMIN_EMAIL'])

        gsuite_client.set_authorized_http(scopes=SCOPE, subject=ADMIN_EMAIL)
        # This is the call made when pressing the integration Test button.
        if command == 'test-module':
            result = test_module(gsuite_client)
            return_results(result)

        elif command == 'gsuite-activity-search':
            return_results(activities_list_command(gsuite_client, args))

        elif command == 'fetch-incidents':
            fetch_limit = arg_to_number(fetch_limit)
            incidents = fetch_incidents(gsuite_client, first_fetch_time, fetch_limit, fetch_app)
            demisto.incidents(incidents)

        # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
