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
            'Profile Id': item.get('actor', {}).get('profileId'),
            'Ip Address': item.get('ipAddress', ''),
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


def create_end_time(start_time: str, added_time: str) -> str:
    time_list = added_time.split(' ')

    if len(time_list) < 2:
        raise DemistoException("Invalid time parameter")

    timedelta_param = timedelta()
    time_param = int(time_list[0])
    if time_list[1] == 'milliseconds':
        timedelta_param = timedelta(milliseconds=time_param)
    elif time_list[1] == 'minutes':
        timedelta_param = timedelta(minutes=time_param)
    elif time_list[1] == 'hours':
        timedelta_param = timedelta(hours=time_param)
    elif time_list[1] == 'days':
        timedelta_param = timedelta(days=time_param)

    end_time = dateparser.parse(start_time) + timedelta_param

    return end_time.strftime(DATE_MILISEC_FORMAT)


def fetch_request(client: GSuiteClient, app: str, start_time: str, end_time: str) -> List[Dict]:
    """
    for an app and start time, send an API request and return the items
    """

    response = client.http_request(
        url_suffix=URL_SUFFIX.format('all', app),
        params={'startTime': start_time, 'endTime': end_time})

    items = response.get('items', [])
    next_page = response.get('nextPageToken')

    # the response might be divided to several pages
    while next_page:
        response = client.http_request(
            url_suffix=URL_SUFFIX.format('all', app),
            params={'nextPageToken': next_page})
        items.append(response.get('items', []))
        next_page = response.get('nextPageToken')

    # debug
    demisto.debug("\nFETCH_DEBUGGING_1\n")
    demisto.debug(f"number fetched - {len(items)} from {start_time} to {end_time}\n")
    return items


def prepare_gsuite_client(params: Dict) -> GSuiteClient:
    service_account_dict = GSuiteClient.safe_load_non_strict_json(params.get('user_service_account_json', ''))
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


def create_incidents_from_items(sorted_items: List, fetch_limit: int, new_leftover_items: List, last_run: str) -> List:
    """
    Create an incidents list from the sorted_items we received, add the leftover items to the new leftover list.
    return the new incidents list
    """
    counter = 0
    incidents = []
    for i in range(0, len(sorted_items)):
        # if we reached our limit add to our leftover list and exit
        if counter == fetch_limit:
            new_leftover_items.extend(sorted_items[i:])
            break

        item = sorted_items[i]

        counter += 1
        incident = {
            'name': f"GSuite Auditor event {item['id']['applicationName']} {item['id']['uniqueQualifier']}",
            'occurred': dateparser.parse(item['id']['time']).strftime(DATE_FORMAT),
            'rawJSON': json.dumps(item)
        }
        incidents.append(incident)

    return incidents


def get_new_last_run(last_leftover_item: Dict, last_sorted_item: Dict, end_time: str, last_run: str) -> str:
    """
    return the new 'last run' time
    """

    # check if there's last item
    if last_leftover_item:
        return create_end_time(last_leftover_item['id']['time'], '1 milliseconds')
    elif last_sorted_item:
        return create_end_time(last_sorted_item['id']['time'], '1 milliseconds')
    # no items - if we are still retrieving old results advance the time
    elif end_time < time.ctime():
        return end_time
    else:
        return last_run


def get_list_last_item(given_list) -> Any:
    if len(given_list) != 0:
        return given_list[-1]
    else:
        return None


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
def fetch_incidents(client: GSuiteClient, first_fetch_time: str, fetch_limit: int, applications: Any) -> List[Dict]:
    last_run_dict = demisto.getLastRun()
    last_run = last_run_dict.get('last_run')
    last_leftover_items = last_run_dict.get('last_leftover_items', [])

    if not last_run:  # this is the first run
        last_run = dateparser.parse(first_fetch_time).strftime(DATE_MILISEC_FORMAT)

    # get leftover items from last run
    new_items = []
    new_leftover_items = []
    if len(last_leftover_items) != 0:
        new_items = last_leftover_items[:fetch_limit]
        new_leftover_items = last_leftover_items[fetch_limit:]

    end_time = create_end_time(last_run, "1 hour")
    # get new items
    if len(new_items) < fetch_limit:
        for app in applications:
            new_items.extend(fetch_request(client, app, last_run, end_time))

    sorted_items = sorted(new_items,
                          key=lambda k: dateparser.parse(k['id']['time']))  # sort the data from earliest to last.
    incidents = create_incidents_from_items(sorted_items, fetch_limit, new_leftover_items, last_run)
    new_last_run = get_new_last_run(get_list_last_item(new_leftover_items), get_list_last_item(sorted_items), end_time,
                                    last_run)

    # debug
    demisto.debug("\nFETCH_DEBUGGING_2\n")
    demisto.debug(f"new_last_run : {new_last_run}\n")
    demisto.debug(f"number of new leftover : {len(new_leftover_items)}\n")
    demisto.debug(f"number of new incidents : {len(incidents)}\n")
    demisto.debug(f"incidents : {incidents}\n")

    demisto.setLastRun(
        {'last_run': new_last_run, 'last_leftover_items': new_leftover_items})

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
        gsuite_client = prepare_gsuite_client(params)

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())
        first_fetch_time = demisto.params().get('first_fetch', '12 hours').strip()
        fetch_limit = demisto.params().get('max_fetch', '10')
        fetch_app = params.get('applications', ['admin'])

        ADMIN_EMAIL = args.get('admin_email') if args.get('admin_email') else params.get('admin_email')
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
