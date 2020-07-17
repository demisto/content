from typing import Optional, Dict, Any
import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import json
import requests
from py42.sdk import SDK
import py42.settings
from py42.sdk.file_event_query import (
    MD5,
    SHA256,
    Actor,
    EventTimestamp,
    OSHostname,
    DeviceUsername,
    ExposureType,
    EventType,
    FileEventQuery
)
from py42.sdk.alert_query import (
    DateObserved,
    Severity,
    AlertState,
    AlertQuery
)
import time
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
CODE42_EVENT_CONTEXT_FIELD_MAPPER = {
    'eventTimestamp': 'EventTimestamp',
    'createTimestamp': 'FileCreated',
    'deviceUid': 'EndpointID',
    'deviceUserName': 'DeviceUsername',
    'emailFrom': 'EmailFrom',
    'emailRecipients': 'EmailTo',
    'emailSubject': 'EmailSubject',
    'eventId': 'EventID',
    'eventType': 'EventType',
    'fileCategory': 'FileCategory',
    'fileOwner': 'FileOwner',
    'fileName': 'FileName',
    'filePath': 'FilePath',
    'fileSize': 'FileSize',
    'modifyTimestamp': 'FileModified',
    'md5Checksum': 'FileMD5',
    'osHostName': 'FileHostname',
    'privateIpAddresses': 'DevicePrivateIPAddress',
    'publicIpAddresses': 'DevicePublicIPAddress',
    'removableMediaBusType': 'RemovableMediaType',
    'removableMediaCapacity': 'RemovableMediaCapacity',
    'removableMediaMediaName': 'RemovableMediaMediaName',
    'removableMediaName': 'RemovableMediaName',
    'removableMediaSerialNumber': 'RemovableMediaSerialNumber',
    'removableMediaVendor': 'RemovableMediaVendor',
    'sha256Checksum': 'FileSHA256',
    'shared': 'FileShared',
    'sharedWith': 'FileSharedWith',
    'source': 'Source',
    'tabUrl': 'ApplicationTabURL',
    'url': 'FileURL',
    'processName': 'ProcessName',
    'processOwner': 'ProcessOwner',
    'windowTitle': 'WindowTitle',
    'exposure': 'Exposure',
    'sharingTypeAdded': 'SharingTypeAdded'
}

CODE42_ALERT_CONTEXT_FIELD_MAPPER = {
    'actor': 'Username',
    'createdAt': 'Occurred',
    'description': 'Description',
    'id': 'ID',
    'name': 'Name',
    'state': 'State',
    'type': 'Type',
    'severity': 'Severity'
}

FILE_CONTEXT_FIELD_MAPPER = {
    'fileName': 'Name',
    'filePath': 'Path',
    'fileSize': 'Size',
    'md5Checksum': 'MD5',
    'sha256Checksum': 'SHA256',
    'osHostName': 'Hostname'
}

CODE42_FILE_TYPE_MAPPER = {
    'SourceCode': 'SOURCE_CODE',
    'Audio': 'AUDIO',
    'Executable': 'EXECUTABLE',
    'Document': 'DOCUMENT',
    'Image': 'IMAGE',
    'PDF': 'PDF',
    'Presentation': 'PRESENTATION',
    'Script': 'SCRIPT',
    'Spreadsheet': 'SPREADSHEET',
    'Video': 'VIDEO',
    'VirtualDiskImage': 'VIRTUAL_DISK_IMAGE',
    'Archive': 'ARCHIVE'
}

SECURITY_EVENT_HEADERS = ['EventType', 'FileName', 'FileSize', 'FileHostname', 'FileOwner', 'FileCategory', 'DeviceUsername']
SECURITY_ALERT_HEADERS = ['Type', 'Occurred', 'Username', 'Name', 'Description', 'State', 'ID']


class Code42Client(BaseClient):
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    """

    def __init__(self, sdk, base_url, auth, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy)
        # Create the Code42 SDK instnace
        self._sdk = sdk.create_using_local_account(base_url, auth[0], auth[1])
        py42.settings.set_user_agent_suffix("Demisto")

    def add_user_to_departing_employee(self, username, departure_epoch=None, note=None):
        de = self._sdk.employee_case_management.departing_employee
        try:
            res = de.create_departing_employee(username, departure_epoch=departure_epoch, notes=note)
        except Exception:
            return None
        return res.json().get('caseId')

    def fetch_alerts(self, start_time, event_severity_filter=None):
        alert_filter = []
        # Create alert filter
        if event_severity_filter:
            alert_filter.append(Severity.is_in(list(map(lambda x: x.upper(), event_severity_filter))))
        alert_filter.append(AlertState.eq(AlertState.OPEN))
        alert_filter.append(DateObserved.on_or_after(start_time))
        alert_query = AlertQuery(self._sdk.user_context.get_current_tenant_id(), *alert_filter)
        alert_query.sort_direction = "asc"
        alerts = self._sdk.security.alerts
        try:
            res = alerts.search_alerts(alert_query)
        except Exception:
            return None
        return res.json().get('alerts')

    def get_alert_details(self, alert_id):
        alerts = self._sdk.security.alerts
        try:
            res = alerts.get_query_details([alert_id])
        except Exception:
            return None
        else:
            # There will only ever be one alert since we search on just one ID
            return res.json().get('alerts')[0]

    def get_current_user(self):
        try:
            res = self._sdk.users.get_current_user()
        except Exception:
            return None
        return res.json()

    def remove_user_from_departing_employee(self, username):
        try:
            de = self._sdk.employee_case_management.departing_employee
            res = de.get_case_by_username(username)
        except Exception:
            return None
        case_id = res.json().get('caseId')
        try:
            de.resolve_departing_employee(case_id)
        except Exception:
            return None
        return case_id

    def resolve_alert(self, id):
        alerts = self._sdk.security.alerts
        try:
            alerts.resolve_alert(id)
        except Exception:
            return None
        return id

    def search_json(self, payload):
        try:
            res = self._sdk.security.search_file_events(payload)
        except Exception:
            return None
        return res.json().get('fileEvents')


@logger
def build_query_payload(args):
    """
    Build a query payload combining passed args
    """
    search_args = []
    if args.get('hash'):
        if len(args['hash']) == 32:
            search_args.append(MD5.eq(args['hash']))
        elif len(args['hash']) == 64:
            search_args.append(SHA256.eq(args['hash']))
    if args.get('hostname'):
        search_args.append(OSHostname.eq(args['hostname']))
    if args.get('username'):
        search_args.append(DeviceUsername.eq(args['username']))
    if args.get('exposure'):
        # Because the CLI can't accept lists, convert the args to a list if the type is string.
        if isinstance(args['exposure'], str):
            args['exposure'] = args['exposure'].split(',')
        search_args.append(ExposureType.is_in(args['exposure']))
    # Convert list of search criteria to *args
    query = FileEventQuery.all(*search_args)
    query.page_size = args.get('results')
    LOG('File Event Query: {}'.format(query))
    return str(query)


@logger
def map_observation_to_security_query(observation, actor):
    file_categories: Dict[str, Any]
    observation_data = json.loads(observation['data'])
    search_args = []
    exp_types = []
    exposure_types = observation_data['exposureTypes']
    begin_time = observation_data['firstActivityAt']
    end_time = observation_data['lastActivityAt']
    if observation['type'] == 'FedEndpointExfiltration':
        search_args.append(DeviceUsername.eq(actor))
    else:
        search_args.append(Actor.eq(actor))
    search_args.append(EventTimestamp.on_or_after(
        int(time.mktime(time.strptime(begin_time.replace('0000000', '000'), "%Y-%m-%dT%H:%M:%S.000Z")))))
    search_args.append(EventTimestamp.on_or_before(
        int(time.mktime(time.strptime(end_time.replace('0000000', '000'), "%Y-%m-%dT%H:%M:%S.000Z")))))
    # Determine exposure types based on alert type
    if observation['type'] == 'FedCloudSharePermissions':
        if 'PublicSearchableShare' in exposure_types:
            exp_types.append(ExposureType.IS_PUBLIC)
        if 'PublicLinkShare' in exposure_types:
            exp_types.append(ExposureType.SHARED_VIA_LINK)
    elif observation['type'] == 'FedEndpointExfiltration':
        exp_types = exposure_types
        search_args.append(EventType.is_in(['CREATED', 'MODIFIED', 'READ_BY_APP']))
    search_args.append(ExposureType.is_in(exp_types))
    # Determine if file categorization is significant
    file_categories = {
        "filterClause": "OR"
    }
    filters = []
    for filetype in observation_data['fileCategories']:
        if filetype['isSignificant']:
            file_category = {
                "operator": "IS",
                "term": "fileCategory",
                "value": CODE42_FILE_TYPE_MAPPER.get(filetype['category'], 'UNCATEGORIZED')
            }
            filters.append(file_category)
    if len(filters):
        file_categories['filters'] = filters
        search_args.append(json.dumps(file_categories))
    # Convert list of search criteria to *args
    query = FileEventQuery.all(*search_args)
    LOG('Alert Observation Query: {}'.format(query))
    return str(query)


@logger
def map_to_code42_event_context(obj):
    code42_context = {}
    for (k, v) in CODE42_EVENT_CONTEXT_FIELD_MAPPER.items():
        if obj.get(k):
            code42_context[v] = obj.get(k)
    # FileSharedWith is a special case and needs to be converted to a list
    if code42_context.get('FileSharedWith'):
        shared_list = []
        for shared_with in code42_context['FileSharedWith']:
            shared_list.append(shared_with['cloudUsername'])
            code42_context['FileSharedWith'] = str(shared_list)
    return code42_context


@logger
def map_to_code42_alert_context(obj):
    code42_context = {}
    for (k, v) in CODE42_ALERT_CONTEXT_FIELD_MAPPER.items():
        if obj.get(k):
            code42_context[v] = obj.get(k)
    return code42_context


@logger
def map_to_file_context(obj):
    file_context = {}
    for (k, v) in FILE_CONTEXT_FIELD_MAPPER.items():
        if obj.get(k):
            file_context[v] = obj.get(k)
    return file_context


@logger
def alert_get_command(client, args):
    code42_securityalert_context = []
    alert = client.get_alert_details(args['id'])
    if alert:
        code42_context = map_to_code42_alert_context(alert)
        code42_securityalert_context.append(code42_context)
        readable_outputs = tableToMarkdown(
            'Code42 Security Alert Results',
            code42_securityalert_context,
            headers=SECURITY_ALERT_HEADERS
        )
        return readable_outputs, {'Code42.SecurityAlert': code42_securityalert_context}, alert
    else:
        return 'No results found', {}, {}


@logger
def alert_resolve_command(client, args):
    code42_securityalert_context = []
    alert = client.resolve_alert(args['id'])
    if alert:
        # Retrieve new alert details
        updated_alert = client.get_alert_details(args['id'])
        if updated_alert:
            code42_context = map_to_code42_alert_context(updated_alert)
            code42_securityalert_context.append(code42_context)
            readable_outputs = tableToMarkdown(
                'Code42 Security Alert Resolved',
                code42_securityalert_context,
                headers=SECURITY_ALERT_HEADERS
            )
            return readable_outputs, {'Code42.SecurityAlert': code42_securityalert_context}, updated_alert
        else:
            return 'Error retrieving updated alert', {}, {}
    else:
        return 'No results found', {}, {}


@logger
def departingemployee_add_command(client, args):
    departure_epoch: Optional[int]
    # Convert date to epoch
    if args.get('departuredate'):
        try:
            departure_epoch = int(time.mktime(time.strptime(args['departuredate'], '%Y-%m-%d')))
        except Exception:
            return_error(message='Could not add user to Departing Employee Lens: '
                         'unable to parse departure date. Is it in YYYY-MM-DD format?')
    else:
        departure_epoch = None
    case = client.add_user_to_departing_employee(args['username'], departure_epoch, args.get('note'))
    if case:
        de_context = {
            'CaseID': case,
            'Username': args['username'],
            'DepartureDate': args.get('departuredate'),
            'Note': args.get('note')
        }
        readable_outputs = tableToMarkdown(
            'Code42 Departing Employee Lens User Added',
            de_context
        )
        return readable_outputs, {'Code42.DepartingEmployee': de_context}, case
    else:
        return_error(message='Could not add user to Departing Employee Lens')


@logger
def departingemployee_remove_command(client, args):
    case = client.remove_user_from_departing_employee(args['username'])
    if case:
        de_context = {
            'CaseID': case,
            'Username': args['username'],
        }
        readable_outputs = tableToMarkdown(
            'Code42 Departing Employee Lens User Removed',
            de_context
        )
        return readable_outputs, {'Code42.DepartingEmployee': de_context}, case
    else:
        return_error(message='Could not remove user from Departing Employee Lens')


@logger
def fetch_incidents(client, last_run, first_fetch_time, event_severity_filter,
                    fetch_limit, include_files, integration_context=None):
    incidents = []
    # Determine if there are remaining incidents from last fetch run
    if integration_context:
        remaining_incidents = integration_context.get("remaining_incidents")
        # return incidents if exists in context.
        if remaining_incidents:
            return last_run, remaining_incidents[:fetch_limit], remaining_incidents[fetch_limit:]
    # Get the last fetch time, if exists
    start_query_time = last_run.get('last_fetch')
    # Handle first time fetch, fetch incidents retroactively
    if not start_query_time:
        start_query_time, _ = parse_date_range(first_fetch_time, to_timestamp=True, utc=True)
        start_query_time /= 1000
    alerts = client.fetch_alerts(start_query_time, demisto.params().get('alert_severity'))
    for alert in alerts:
        details = client.get_alert_details(alert['id'])
        incident = {
            'name': 'Code42 - {}'.format(details['name']),
            'occurred': details['createdAt'],
        }
        if include_files:
            details['fileevents'] = []
            for obs in details['observations']:
                security_data_query = map_observation_to_security_query(obs, details['actor'])
                file_events = client.search_json(security_data_query)
                for event in file_events:
                    # We need to convert certain fields to a stringified list or React.JS will throw an error
                    if event.get('sharedWith'):
                        shared_list = []
                        for shared_with in event['sharedWith']:
                            shared_list.append(shared_with['cloudUsername'])
                        event['sharedWith'] = str(shared_list)
                    if event.get('privateIpAddresses'):
                        event['privateIpAddresses'] = str(event['privateIpAddresses'])
                    details['fileevents'].append(event)
        incident['rawJSON'] = json.dumps(details)
        incidents.append(incident)
    save_time = datetime.utcnow().timestamp()
    next_run = {'last_fetch': save_time}
    return next_run, incidents[:fetch_limit], incidents[fetch_limit:]


@logger
def securitydata_search_command(client, args):
    code42_securitydata_context = []
    file_context = []
    # If JSON payload is passed as an argument, ignore all other args and search by JSON payload
    if args.get('json') is not None:
        file_events = client.search_json(args.get('json'))
    else:
        # Build payload
        payload = build_query_payload(args)
        file_events = client.search_json(payload)
    if file_events:
        for file_event in file_events:
            code42_context_event = map_to_code42_event_context(file_event)
            code42_securitydata_context.append(code42_context_event)
            file_context_event = map_to_file_context(file_event)
            file_context.append(file_context_event)
        readable_outputs = tableToMarkdown(
            'Code42 Security Data Results',
            code42_securitydata_context,
            headers=SECURITY_EVENT_HEADERS
        )
        return readable_outputs, {'Code42.SecurityData(val.EventID && val.EventID == obj.EventID)': code42_securitydata_context,
                                  'File': file_context}, file_events
    else:
        return 'No results found', {}, {}


def test_module(client):
    user = client.get_current_user()
    if user:
        return 'ok'
    else:
        return 'Invalid credentials or host address. Check that the username and password are correct, \
               that the host is available and reachable, and that you have supplied the full scheme, \
               domain, and port (e.g. https://myhost.code42.com:4285)'


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    base_url = demisto.params().get('console_url')
    # Remove trailing slash to prevent wrong URL path to service
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Code42Client(
            sdk=SDK,
            base_url=base_url,
            auth=(username, password),
            verify=verify_certificate,
            proxy=proxy)
        commands = {
            'code42-alert-get': alert_get_command,
            'code42-alert-resolve': alert_resolve_command,
            'code42-securitydata-search': securitydata_search_command,
            'code42-departingemployee-add': departingemployee_add_command,
            'code42-departingemployee-remove': departingemployee_remove_command
        }
        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif command == 'fetch-incidents':
            integration_context = demisto.getIntegrationContext()
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents, remaining_incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=demisto.params().get('fetch_time'),
                event_severity_filter=demisto.params().get('alert_severity'),
                fetch_limit=int(demisto.params().get('fetch_limit')),
                include_files=demisto.params().get('include_files'),
                integration_context=integration_context
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            # Store remaining incidents in integration context
            integration_context['remaining_incidents'] = remaining_incidents
            demisto.setIntegrationContext(integration_context)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
