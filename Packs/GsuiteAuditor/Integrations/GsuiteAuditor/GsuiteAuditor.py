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

OUTPUT_PREFIX: Dict[str, str] = {
    'ACTIVITY_LIST': 'GSuite.ActivitySearch',
    'ACTIVITY_LIST_PAGE_TOKEN': 'GSuite.PageToken.ActivitySearch',
}

REQ_URL = 'https://admin.googleapis.com/'
URL_SUFFIX = 'admin/reports/v1/activity/users/{}/applications/{}'
SCOPE = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
DATE_MILISEC_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

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
                                                    'The argument max_results must be a positive integer.'),
        'pageToken': args.get('page_token')
    })


def prepare_readable_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    readable_items = [
        {
            'Time': item.get('id', {}).get('time'),
            'Application Name': item.get('id', {}).get('applicationName'),
            'Email': item.get('actor', {}).get('email'),
            'ProfileId': item.get('actor', {}).get('profileId'),
            'IpAddress': item.get('ipAddress', ''),
            'Events': item['events']
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


def prepare_gsuite_client(params: Dict) -> GSuiteClient:
    user_service_account = params.get('credentials', {}).get('password')
    service_account_dict = GSuiteClient.safe_load_non_strict_json(user_service_account)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {
        'Content-Type': 'application/json'
    }

    # prepare client class object
    gsuite_client = GSuiteClient(service_account_dict,
                                 base_url=REQ_URL, verify=verify_certificate, proxy=proxy,
                                 headers=headers)
    return gsuite_client


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
        ['Time', 'Application Name', 'Email', 'ProfileId', 'IpAddress', 'Events']) if response.get(
        'items') else 'No activities found for the given ' \
                      'argument(s). '
    # Context
    context_outputs = prepare_output_for_activities_list(response)

    return CommandResults(
        outputs=context_outputs,
        readable_output=readable_output,
        raw_response=response
    )


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
        gsuite_client = prepare_gsuite_client(params)

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())

        ADMIN_EMAIL = args.get('admin_email') if args.get('admin_email') else params.get('credentials', {}).get('identifier')
        # Validation of ADMIN_EMAIL
        if ADMIN_EMAIL and not is_email_valid(ADMIN_EMAIL):
            raise ValueError('Invalid value of argument/parameter Admin Email.')

        gsuite_client.set_authorized_http(scopes=SCOPE, subject=ADMIN_EMAIL)
        # This is the call made when pressing the integration Test button.
        if command == 'test-module':
            result = test_module(gsuite_client)
            return_results(result)

        elif command == 'gsuite-activity-search':
            return_results(activities_list_command(gsuite_client, args))

        # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
