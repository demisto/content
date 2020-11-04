import shutil
from typing import Dict, Tuple
from dateparser import parse
import urllib3
from CommonServerPython import *


# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client to use in the Zimperium integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, api_key: str, verify: bool):
        super().__init__(base_url=base_url, verify=verify)
        self._headers = {'api_key': api_key, 'Accept': 'application/json'}
        self._proxies = handle_proxy()

    def users_search_request(self, query: str, size: str, page: str) -> dict:
        """Search users by sending a GET request.

        Args:
            query: users search query.
            size: response size.
            page: response page.
        Returns:
            Response from API.
        """
        params = {
            'rsql': query,
            'size': size,
            'page': page,
        }
        return self._http_request(method='GET', url_suffix='/users/public/search', headers=self._headers, params=params)

    def user_get_by_id_request(self, object_id: str) -> dict:
        """Retrieve user details by sending a GET request.

        Args:
            object_id: object ID.
        Returns:
            Response from API.
        """
        return self._http_request(method='GET', url_suffix=f'/users/public/{object_id}', headers=self._headers)

    def devices_search_request(self, query: str, size: str, page: str) -> dict:
        """Search devices by sending a GET request.

        Args:
            query: devices search query.
            size: response size.
            page: response page.
        Returns:
            Response from API.
        """
        params = {
            'rsql': query,
            'size': size,
            'page': page,
        }
        return self._http_request(method='GET', url_suffix='/devices/public/search', headers=self._headers,
                                  params=params)

    def device_get_by_id_request(self, zdid: str, device_id: str) -> dict:
        """Retrieve device details by sending a GET request.

        Args:
            zdid: zimperium ID.
            device_id: device ID.
        Returns:
            Response from API.
        """
        if (zdid and device_id) or (not zdid and not device_id):
            raise Exception("To get device by ID, use the zdid or the device_id argument.")

        if zdid:
            url_suffix = f'/devices/public/{zdid}'
        else:
            url_suffix = f'/devices/public/deviceId/{device_id}'

        return self._http_request(method='GET', url_suffix=url_suffix, headers=self._headers)

    def devices_get_last_updated_request(self, last_updated: str, exclude_deleted: bool, size: str, page: str)\
            -> dict:
        """Search last updated devices by sending a GET request.

        Args:
            last_updated: Last updated devices time frame.
            exclude_deleted: whether to exclude deleted devices.
            size: response size.
            page: response page.
        Returns:
            Response from API.
        """
        params = {
            'fromLastUpdate': last_updated,
            'excludeDeleted': exclude_deleted,
            'size': size,
            'page': page,
        }
        return self._http_request(method='GET', url_suffix='/devices/public/device_updates', headers=self._headers,
                                  params=params)

    def app_classification_get_request(self, app_hash: str, app_name: str) -> dict:
        """Retrieve device details by sending a GET request.

        Args:
            app_hash: application hash.
            app_name: application name.
        Returns:
            Response from API.
        """
        if (app_hash and app_name) or (not app_hash and not app_name):
            raise Exception("To get application classification, use the app_hash or the app_name argument.")

        if app_hash:
            url_suffix = f'/malware/public/classify/hash/{app_hash}'
        else:
            url_suffix = f'/malware/public/classify/name/{app_name}'

        return self._http_request(method='GET', url_suffix=url_suffix, headers=self._headers)

    def report_get_request(self, bundle_id: str, itunes_id: str, app_hash: str, platform: str) -> dict:
        """Retrieve device details by sending a GET request.

        Args:
            bundle_id: bundle ID.
            itunes_id: itunes ID.
            app_hash: application hash.
            platform: app platform
        Returns:
            Response from API.
        """
        if not bundle_id and not itunes_id and not app_hash:
            raise Exception("To get a report, use the bundle_id or the itunes_id or the app_hash argument.")
        if (bundle_id and itunes_id) or (bundle_id and app_hash) or (itunes_id and app_hash):
            raise Exception("To get a report, use exactly one of the arguments: bundle_id, itunes_id, app_hash.")

        params = {}
        if bundle_id:
            url_suffix = f'/malware/public/reports/bundle/{bundle_id}'
            params['platform'] = platform
        elif itunes_id:
            url_suffix = f'/malware/public/reports/itunes/{itunes_id}'
        else:
            url_suffix = f'/malware/public/reports/hash/{app_hash}'
            params['platform'] = platform

        return self._http_request(method='GET', url_suffix=url_suffix, headers=self._headers,
                                  params=params)

    def app_upload_for_analysis_request(self, entry_id: str) -> dict:
        """Upload an application for analysis by sending a POST request.

        Args:
            entry_id: entry ID.
        Returns:
            Response from API.
        """

        file_path = demisto.getFilePath(entry_id).get('path')
        file_name = demisto.getFilePath(entry_id).get('name')
        if not file_path or not file_name:
            raise Exception('Failed to find the file to upload for analysis.')
        try:
            shutil.copy(file_path, file_name)
        except Exception:
            raise Exception('Failed to prepare application for upload.')

        try:
            with open(file_path, 'rb') as file:
                self._headers.update({'Content-Type': 'multipart/form-data'})
                result = self._http_request(method='POST', url_suffix='/malware/public/upload/app',
                                            headers=self._headers, files={'file1': file.read()}, timeout=240)
        except Exception as err:
            raise Exception(str(err))
        finally:
            shutil.rmtree(file_name, ignore_errors=True)

        return result

    def events_search_request(self, query: str, size: str, page: str, verbose: bool):
        """Search events by sending a GET request.

        Args:
            query: devices search query.
            size: response size.
            page: response page.
            verbose: whether to include full event details.
        Returns:
            Response from API.
        """
        params = {
            'rsql': query,
            'size': size,
            'page': page,
            'sort': 'deviceTime,asc',
            'includeFullEventDetail': verbose,
        }

        return self._http_request(method='GET', url_suffix='/events/public/search', headers=self._headers,
                                  params=params)


def test_module(client: Client, *_) -> str:
    """
    Performs basic get request to get incident samples
    """
    client.users_search_request(query='objectId==*', size='10', page='0')
    if demisto.params().get('isFetch'):
        client.events_search_request(query='eventId==*', size='10', page='0', verbose=False)

    return 'ok'


def users_search(client: Client, args: Dict) -> CommandResults:
    """Search users

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    email = str(args.get('email', ''))
    query = str(args.get('query', ''))
    size = str(args.get('size', '10'))
    page = str(args.get('page', '0'))

    if email and query:
        raise Exception('Provide either the email or the query arguments.')
    elif email:
        search_query = f'email=={email}'
    elif query:
        search_query = query
    else:
        search_query = 'objectId==*'

    users = client.users_search_request(search_query, size, page)

    users_data = users.get('content')
    total_elements = users.get('totalElements', '0')
    table_name = ''
    if not users.get('last'):
        table_name = ' More users are available in the next page.'
    headers = ['objectId', 'alias', 'firstName', 'middleName', 'lastName', 'email']
    readable_output = tableToMarkdown(name=f"Number of users found: {total_elements}. {table_name}",
                                      t=users_data, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Users',
        outputs_key_field='objectId',
        outputs=users_data,
        readable_output=readable_output,
        raw_response=users
    )

    return command_results


def user_get_by_id(client: Client, args: Dict) -> CommandResults:
    """Retrieve details for a single user.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    object_id = str(args.get('object_id', ''))

    user = client.user_get_by_id_request(object_id)

    headers = ['objectId', 'alias', 'firstName', 'middleName', 'lastName', 'email']
    readable_output = tableToMarkdown(name="User:", t=user, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Users',
        outputs_key_field='objectId',
        outputs=user,
        readable_output=readable_output,
        raw_response=user
    )

    return command_results


def devices_search(client: Client, args: Dict) -> CommandResults:
    """Search devices

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    query = str(args.get('query', 'deviceId==*'))
    size = str(args.get('size', '10'))
    page = str(args.get('page', '0'))

    devices = client.devices_search_request(query, size, page)

    devices_data = devices.get('content')
    total_elements = devices.get('totalElements', '0')
    table_name = ''
    if not devices.get('last'):
        table_name = ' More Devices are available in the next page.'
    headers = ['deviceId', 'zdid', 'deviceHash', 'model', 'osType', 'osVersion', 'updatedDate']
    readable_output = tableToMarkdown(name=f"Number of devices found: {total_elements}. {table_name}",
                                      t=devices_data, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Devices',
        outputs_key_field='deviceId',
        outputs=devices_data,
        readable_output=readable_output,
        raw_response=devices
    )

    return command_results


def device_get_by_id(client: Client, args: Dict) -> CommandResults:
    """Retrieve details for a single device.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    zdid = str(args.get('zdid', ''))
    device_id = str(args.get('device_id', ''))

    device = client.device_get_by_id_request(zdid, device_id)

    headers = ['deviceId', 'zdid', 'model', 'osType', 'osVersion', 'updatedDate', 'deviceHash']
    readable_output = tableToMarkdown(name=f"Device {device_id}:", t=device, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Devices',
        outputs_key_field='deviceId',
        outputs=device,
        readable_output=readable_output,
        raw_response=device
    )

    return command_results


def devices_get_last_updated(client: Client, args: Dict) -> CommandResults:
    """Retrieve last updated devices

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    timestamp_format = '%Y-%m-%d'
    from_last_update = str(args.get('from_last_update', '1 day'))
    last_updated = parse_date_range(from_last_update, date_format=timestamp_format)[0]
    exclude_deleted = args.get('exclude_deleted') == 'false'
    size = str(args.get('size', '10'))
    page = str(args.get('page', '0'))

    devices = client.devices_get_last_updated_request(last_updated, exclude_deleted, size, page)

    devices_data = devices.get('content')
    total_elements = devices.get('totalElements', '0')
    table_name = ''
    if not devices.get('last'):
        table_name = ' More Devices are available in the next page.'
    headers = ['deviceId', 'zdid', 'model', 'osType', 'osVersion', 'updatedDate', 'deviceHash']
    readable_output = tableToMarkdown(name=f"Number of devices found: {total_elements}. {table_name}",
                                      t=devices_data, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Devices',
        outputs_key_field='deviceId',
        outputs=devices_data,
        readable_output=readable_output,
        raw_response=devices
    )

    return command_results


def app_classification_get(client: Client, args: Dict) -> CommandResults:
    """Retrieve application classification.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    app_hash = str(args.get('app_hash', ''))
    app_name = str(args.get('app_name', ''))

    application = client.app_classification_get_request(app_hash, app_name)

    if isinstance(application, dict):  # an app name can have multiple results due to different versions.
        application_data = application.get('content')
    else:  # or it can have only one result, if queried using a hash or if it has only one version.
        application_data = application[0]
    headers = ['objectId', 'hash', 'name', 'version', 'classification', 'score', 'privacyEnum', 'securityEnum']
    readable_output = tableToMarkdown(name="Application:", t=application_data, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Application',
        outputs_key_field='objectId',
        outputs=application_data,
        readable_output=readable_output,
        raw_response=application
    )

    return command_results


def calculate_dbot_score(application_data: dict) -> int:
    """Determines app dbot score

    Args:
        application_data: app data

    Returns:
        a number representing the dbot score
    """
    if not application_data:  # no response from Zimperium
        return 0

    classification = application_data.get('classification')
    if not classification:
        return 0
    if classification == 'Legitimate':
        return 1
    return 3  # classification == Malicious


def file_reputation(client: Client, args: Dict) -> List[CommandResults]:
    """Get the reputation of a hash representing an App

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        list of CommandResults.
    """
    hash_list = argToList(args.get('file'))

    command_results_list: List[CommandResults] = []
    headers = ['objectId', 'hash', 'name', 'version', 'classification', 'score', 'privacyEnum', 'securityEnum']

    for app_hash in hash_list:
        try:
            application = client.app_classification_get_request(app_hash, '')
            application_data = application[0]
        except Exception as err:
            if 'Error in API call [404]' in str(err):
                application_data = {'hash': app_hash}
            else:
                raise Exception(err)

        score = calculate_dbot_score(application_data)

        dbot_score = Common.DBotScore(
            indicator=app_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name='Zimperium',
            score=score
        )
        hash_type = get_hash_type(app_hash)
        if hash_type == 'md5':
            file = Common.File(
                md5=app_hash,
                dbot_score=dbot_score
            )
        elif hash_type == 'sha1':
            file = Common.File(
                sha1=app_hash,
                dbot_score=dbot_score
            )
        else:
            file = Common.File(
                sha256=app_hash,
                dbot_score=dbot_score
            )

        if not score:
            readable_output = tableToMarkdown(name=f"Hash {app_hash} reputation is unknown to Zimperium.",
                                              t=application_data, headers=headers, removeNull=True)
        else:
            readable_output = tableToMarkdown(name=f"Hash {app_hash} reputation:", t=application_data, headers=headers,
                                              removeNull=True)

        command_results = CommandResults(
            outputs_prefix='Zimperium.Application',
            outputs_key_field='objectId',
            outputs=application_data,
            readable_output=readable_output,
            raw_response=application_data,
            indicator=file
        )
        command_results_list.append(command_results)

    return command_results_list


def report_get(client: Client, args: Dict) -> CommandResults:
    """Retrieve a report.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    bundle_id = str(args.get('bundle_id', ''))
    itunes_id = str(args.get('itunes_id', ''))
    app_hash = str(args.get('app_hash', ''))
    platform = str(args.get('platform', 'ios'))

    report = client.report_get_request(bundle_id, itunes_id, app_hash, platform).get('report', {})
    report_data = report.get('report')
    if not report_data:
        command_results = CommandResults(
            readable_output='A report was not found.',
            raw_response=report
        )
    else:
        # deleting analysis metadata to not load the context
        app_analysis = report_data.get('app_analysis')
        if app_analysis and app_analysis.get('application_type') == 'Android':
            analysis = app_analysis.get('analysis')
            if analysis:
                report_data['app_analysis']['analysis'] = list(analysis.keys())

        app_md5 = report.get('md5') if 'md5' in report else report_data.get('app_analysis', {}).get('md5_hash')
        if app_md5:
            report_data.update({'md5': app_md5})
        headers = ['behavior', 'md5', 'threats']
        readable_output = tableToMarkdown(name="Report:", t=report_data, headers=headers, removeNull=True)

        command_results = CommandResults(
            outputs_prefix='Zimperium.Reports',
            outputs_key_field='app_md5',
            outputs=report_data,
            readable_output=readable_output,
            raw_response=report
        )

    return command_results


def events_search(client: Client, args: Dict) -> CommandResults:
    """Search events.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    query = str(args.get('query', 'eventId==*'))
    size = str(args.get('size', '10'))
    page = str(args.get('page', '0'))
    verbose = str(args.get('verbose')) == 'true'

    events = client.events_search_request(query, size, page, verbose)
    events_data = events.get('content')
    total_elements = events.get('totalElements')

    if not verbose:
        for event_data in events_data:
            event_data.pop('eventDetail', None)

    table_name = ''
    if not events.get('last'):
        table_name = ' More events are available in the next page.'
    headers = ['eventId', 'eventName', 'eventState', 'incidentSummary', 'severity', 'persistedTime']
    readable_output = tableToMarkdown(name=f"Number of events found: {total_elements}. {table_name}",
                                      t=events_data, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Events',
        outputs_key_field='eventId',
        outputs=events_data,
        readable_output=readable_output,
        raw_response=events
    )

    return command_results


def fetch_incidents(client: Client, last_run: dict, fetch_query: str, first_fetch_time: str, max_fetch: str = '50')\
        -> Tuple[dict, list]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): Zimperium client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        fetch_query: fetch query to append to the persistedtime
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time
        max_fetch: max events to fetch

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    if not last_run:  # if first time fetching
        next_run = {
            'time': parse_date_range(first_fetch_time, date_format=timestamp_format)[0],
            'last_event_ids': []
        }
    else:
        next_run = last_run

    query = f"persistedTime=gt={next_run.get('time')}"
    if fetch_query:
        query += f";{fetch_query}"

    events = client.events_search_request(query=query, size=max_fetch, page='0', verbose=False)
    events_data = events.get('content')
    incidents = []

    if events_data:
        last_event_ids = last_run.get('last_event_ids', [])
        new_event_ids = []
        last_event_created_time = None
        for event_data in events_data:
            event_data.pop('eventDetail', None)  # deleting eventDetail to not load the context
            event_id = event_data.get('eventId')

            if event_id not in last_event_ids:  # check that event was not fetched in the last fetch
                last_event_created_time = parse(event_data.get('persistedTime'))
                incident = {
                    'name': event_data.get('incidentSummary'),
                    'occurred': last_event_created_time.strftime(timestamp_format),
                    'severity': event_severity_to_dbot_score(event_data.get('severity')),
                    'rawJSON': json.dumps(event_data)
                }
                incidents.extend([incident])
                new_event_ids.extend([event_id])

        if new_event_ids and last_event_created_time:
            next_run = {
                'time': last_event_created_time.strftime(timestamp_format),
                'last_event_ids': json.dumps(new_event_ids)  # save the event IDs from the last fetch
            }

    demisto.debug(f'Zimperium last fetch data: {str(next_run)}')
    return next_run, incidents


def event_severity_to_dbot_score(severity_str: str):
    """Converts an severity string to DBot score representation
        alert severity. Can be one of:
        Low    ->  1
        Medium ->  2
        High   ->  3

    Args:
        severity_str: String representation of severity.

    Returns:
        Dbot representation of severity
    """
    severity = severity_str.lower()
    if severity == 'low':
        return 1
    if severity == 'important':
        return 2
    if severity == 'critical':
        return 3
    demisto.info(f'Zimperium incident severity: {severity} is not known. Setting as unknown(DBotScore of 0).')
    return 0


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = params.get('api_key')
    base_url = urljoin(params.get('url'), '/api/v1/')
    verify = not params.get('insecure', False)

    # fetch params
    fetch_query = params.get('fetch_query')
    max_fetch = min('50', params.get('max_fetch', '50'))
    first_fetch_time = params.get('fetch_time', '3 days').strip()

    command = demisto.command()
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify)
        commands = {
            'zimperium-events-search': events_search,
            'zimperium-users-search': users_search,
            'zimperium-user-get-by-id': user_get_by_id,
            'zimperium-devices-search': devices_search,
            'zimperium-device-get-by-id': device_get_by_id,
            'zimperium-devices-get-last-updated': devices_get_last_updated,
            'zimperium-app-classification-get': app_classification_get,
            'file': file_reputation,
            'zimperium-report-get': report_get,
        }
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                fetch_query=fetch_query,
                first_fetch_time=first_fetch_time,
                max_fetch=max_fetch
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        if 'Resource not found' in str(err):
            return_results('Object was not found in Zimperium, please make sure your arguments are correct.')
        else:
            return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
