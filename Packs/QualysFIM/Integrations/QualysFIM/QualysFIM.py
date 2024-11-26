import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CommonServerUserPython import *

''' IMPORTS '''

import json
import dateparser

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f+0000'
TABLE_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
SORT_DICTIONARY = {'most_recent': 'desc',
                   'least_recent': 'asc'}


class Client(BaseClient):
    """
    API Client to communicate with QualysFIM.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, auth: tuple):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._headers = self.get_token_and_set_headers(auth)

    def get_token_and_set_headers(self, auth: tuple) -> dict:
        """
        Get JWT token by authentication and set headers.

        Args:
            auth (tuple): credentials for authentication.

        Returns:
            headers with token.

        Raises:
            DemistoException if authentication request was not successful.
        """
        try:
            data = {'username': auth[0], 'password': auth[1], 'token': True}
            headers = {'ContentType': 'application/x-www-form-urlencoded'}

            token = self._http_request(
                method='POST',
                url_suffix='/auth',
                headers=headers,
                data=data,
                resp_type='text',
                raise_on_status=True,
            )
            return {'Authorization': f'Bearer {token}', 'content-type': 'application/json'}

        except Exception as e:
            raise DemistoException('Authentication failed. Verify the Qualys API Platform URL, '
                                   'access credentials, and other connection parameters.') from e

    def incidents_list_test(self):
        """
        List 1 Incident for "test_module".

        return:
            response (Response): API response from Qualys FIM.
        """
        return self.incidents_list(data={'pageSize': '1'})

    def events_list(self, data: dict):
        """
        List all logged events.

        Args:
            data (dict): dictionary of parameters for API call.

        return:
            response (Dict): API response from Qualys FIM.
        """
        return self._http_request(method='POST', url_suffix='fim/v2/events/search', json_data=data)

    def get_event(self, event_id: str):
        """
        Get a single event based on ID.

        Args:
            event_id (str): ID of the event to get.

        return:
            response (Dict): API response from Qualys FIM.
        """
        return self._http_request(method='GET', url_suffix=f'fim/v2/events/{event_id}')

    def incidents_list(self, data: dict):
        """
        List all Incidents.

        Args:
            data (dict): dictionary of parameters for API call.

        return:
            response (Dict): API response from Qualys FIM.
        """
        return self._http_request(method='POST', url_suffix='fim/v3/incidents/search', json_data=data)

    def get_incident_events(self, incident_id: str, data: dict):
        """
        Get all events from single incident based on incident ID.

        Args:
            incident_id (str): ID of the incident's events to get.
            data (dict): dictionary of parameters for API call.
        return:
            response (Dict): API response from Qualys FIM.
        """
        return self._http_request(method='POST',
                                  url_suffix=f'fim/v2/incidents/{incident_id}/events/search',
                                  json_data=data)

    def assets_list(self, params: dict):
        """
        list all assets.

        Args:
            params (dict): dictionary of parameters for API call.

        return:
            response (Dict): API response from Qualys FIM.
        """
        return self._http_request(method='POST', url_suffix='fim/v3/assets/search',
                                  json_data=params)

    def create_incident(self, data: dict):
        """
        Create new incident.

        Args:
            data (dict): dictionary with incident creation data.

        return:
            response (Dict): API response from Qualys FIM.
        """

        return self._http_request(method='POST', url_suffix='fim/v3/incidents/create',
                                  json_data=data)

    def approve_incident(self, incident_id: str, data: dict):
        """
        Approve incident based on ID.

        Args:
            incident_id (str):  ID of the incident to approve.
            data (dict): dictionary with approval data for the approval request.

        return:
            response (Dict): API response from Qualys FIM.
        """
        return self._http_request(method='POST',
                                  url_suffix=f'fim/v3/incidents/{incident_id}/approve',
                                  json_data=data)


def create_event_or_incident_output(item: Dict,
                                    table_headers: List[str]) -> Dict[str, str]:
    """
    Create the complete output dictionary for events or incidents.

    Args:
        item (dict): A source dictionary from the API response.
        table_headers (list(str)): The table headers to be used when creating initial data.

    Returns:
        object_data (dict[str,str]): The output dictionary.
    """
    alert_data = {field: item.get(field) for field in table_headers}
    if 'agentId' in table_headers:
        alert_data['agentId'] = dict_safe_get(item, ['asset', 'agentId'])

    if 'username' in table_headers:
        alert_data['occurred'] = dict_safe_get(item, ['createdBy', 'date'])
        alert_data['username'] = dict_safe_get(item, ['createdBy', 'user', 'name'])

    if 'profiles' in table_headers:
        profiles = item.get('profiles', [])
        profiles_list = []
        for profile in profiles:
            name = profile.get('name')
            if name is not None:
                profiles_list.append(name)
        alert_data['profiles'] = profiles_list

    return remove_empty_elements(alert_data)


def list_events_command(client: Client, args: dict):
    """
    List all relevant events.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    sort = json.dumps([{'dateTime': SORT_DICTIONARY.get(str(args['sort']))}])
    params = remove_empty_elements({'filter': args.get('filter'),
                                    'pageNumber': args.get('page_number', '0'),
                                    'pageSize': args.get('limit', '10'),
                                    'incidentIds': argToList(args.get('incident_ids')),
                                    'sort': sort})

    raw_response = client.events_list(params)
    table_headers = ['id', 'severity', 'dateTime', 'agentId', 'fullPath']

    outputs = []
    raw_outputs = []

    if raw_response:
        for item in raw_response:
            data = item.get('data')
            raw_outputs.append(data)

            item_dictionary = create_event_or_incident_output(data, table_headers)
            date_time = item_dictionary.get('dateTime')
            if date_time:
                item_dictionary['dateTime'] = datetime.strptime(date_time, DATETIME_FORMAT)\
                    .strftime(TABLE_DATETIME_FORMAT)

            outputs.append(item_dictionary)

    readable_output = tableToMarkdown(name=f'Listed {len(outputs)} Events:',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Event',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_outputs,
                          readable_output=readable_output)


def get_event_command(client: Client, args: dict):
    """
    Get a specific event by ID.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    raw_response = client.get_event(str(args['event_id']))
    table_headers = ['name', 'action', 'id', 'severity', 'action', 'incidentId',
                     'profiles', 'type', 'dateTime', 'fullPath']

    object_data = create_event_or_incident_output(raw_response, table_headers)
    object_data['dateTime'] = datetime.strptime(str(object_data.get('dateTime')),
                                                DATETIME_FORMAT).strftime(TABLE_DATETIME_FORMAT)

    readable_output = tableToMarkdown(name='Found Event:',
                                      t=object_data,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Event',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_response,
                          readable_output=readable_output)


def list_incidents_command(client: Client, args: dict):
    """
    List all relevant incidents.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    sort = json.dumps([{'dateTime': SORT_DICTIONARY.get(str(args['sort']))}])
    params = remove_empty_elements({'filter': args.get('filter'),
                                    'pageNumber': args.get('page_number', '0'),
                                    'pageSize': args.get('limit', '10'),
                                    'attributes': args.get('attributes'),
                                    'sort': sort})

    raw_response = client.incidents_list(params)
    table_headers = ['id', 'name', 'type', 'username', 'status', 'occurred', 'approvalStatus',
                     'approvalType', 'comment', 'dispositionCategory']

    outputs = []
    raw_outputs = []

    if raw_response:
        for item in raw_response:
            data = item.get('data')
            raw_outputs.append(data)

            item_dictionary = create_event_or_incident_output(data, table_headers)
            occurred = item_dictionary.get('occurred')

            if occurred:
                item_dictionary['occurred'] = epochToTimestamp(occurred)
            outputs.append(item_dictionary)

    readable_output = tableToMarkdown(name=f'Listed {len(outputs)} Incidents:',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Incident',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_outputs,
                          readable_output=readable_output)


def list_incident_events_command(client: Client, args: dict):
    """
    Get a specific incident's events by incident ID.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    params = remove_empty_elements({'filter': args.get('filter'),
                                    'pageNumber': args.get('page_number', '0'),
                                    'pageSize': args['limit'],
                                    'attributes': args.get('attributes')})

    raw_response = client.get_incident_events(str(args.get('incident_id')), params)
    table_headers = ['id', 'name', 'severity', 'action', 'type', 'dateTime']

    outputs = []
    raw_outputs = []

    if raw_response:
        for item in raw_response:
            data = item.get('data')
            if data:
                raw_outputs.append(data)
                item_dictionary = create_event_or_incident_output(data, table_headers)

                date_time = item_dictionary.get('dateTime')
                if date_time:
                    date_time = datetime.strptime(date_time,
                                                  DATETIME_FORMAT).strftime(TABLE_DATETIME_FORMAT)
                    item_dictionary['dateTime'] = date_time

                outputs.append(item_dictionary)

    readable_output = tableToMarkdown(name=f'Listed {len(outputs)} Events From Incident:',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Event',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_outputs,
                          readable_output=readable_output)


def create_incident_command(client: Client, args: dict):
    """
    Create a new incident.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    if len(str(args.get('name'))) > 128:
        raise ValueError('Name is limited to 128 characters, please shorten name.')

    if args.get('filters'):
        filters = args.get('filters')
    else:
        if args.get('from_date') and args.get('to_date'):
            filters = f"dateTime: ['{args.get('from_date')}'..'{args.get('to_date')}']"
        else:
            yesterday = (datetime.today() - timedelta(days=1)).strftime(DATETIME_FORMAT)
            today = datetime.today().strftime(DATETIME_FORMAT)
            filters = f"dateTime: ['{yesterday}'..'{today}']"

    data = remove_empty_elements({'name': args['name'],
                                  'type': 'DEFAULT',
                                  'filters': [filters],
                                  'comment': args.get('comment'),
                                  'reviewers': argToList(args.get('reviewers'))})

    created = client.create_incident(data)
    raw_response = client.incidents_list({'filter': f'id:{created.get("id")}'})

    raw_response = raw_response[0].get('data')
    table_headers = ['id', 'name', 'reviewers', 'username', 'occurred', 'filters', 'approvalType']

    output = create_event_or_incident_output(raw_response, table_headers)

    username = dict_safe_get(raw_response, ['userInfo', 'user', 'name'])
    if username:
        output.update({'username': username})
    occurred = dict_safe_get(raw_response, ['userInfo', 'date'])
    if occurred:
        output.update({'occurred': epochToTimestamp(occurred)})

    readable_output = tableToMarkdown(name=f'Created New Incident: {raw_response.get("name")}',
                                      t=output,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Incident',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_response,
                          readable_output=readable_output)


def approve_incident_command(client: Client, args: dict):
    """
    Approve incident based on ID.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    data = {'approvalStatus': args['approval_status'],
            'changeType': args['change_type'],
            'comment': args['comment'],
            'dispositionCategory': args['disposition_category']}

    raw_response = client.approve_incident(str(args.get('incident_id')),
                                           remove_empty_elements(data))

    table_headers = ['id', 'name', 'type', 'filterFromDate', 'filterToDate', 'filters',
                     'approvalDate', 'approvalStatus', 'approvalType', 'comment', 'createdByName',
                     'status', 'reviewers', 'dispositionCategory', 'changeType']

    if raw_response:
        output = create_event_or_incident_output(raw_response, table_headers)
        output['approvalDate'] = datetime.strptime(str(output.get('approvalDate')),
                                                   DATETIME_FORMAT).strftime(TABLE_DATETIME_FORMAT)

        output['filterFromDate'] = datetime.strptime(str(output.get('filterFromDate')),
                                                     DATETIME_FORMAT).\
            strftime(TABLE_DATETIME_FORMAT)

        output['filterToDate'] = datetime.strptime(str(output.get('filterToDate')),
                                                   DATETIME_FORMAT).strftime(TABLE_DATETIME_FORMAT)
    else:
        raise ValueError(f"Incident {args.get('incident_id')} wasn't found")

    readable_output = tableToMarkdown(name=f'Approved Incident: '
                                           f'{raw_response.get("name", "unknown")}',
                                      t=output,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Incident',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_response,
                          readable_output=readable_output)


def list_assets_command(client: Client, args: dict):
    """
    List all relevant assets.

    Args:
        client (Client): Qualys FIM API client.
        args (dict): All command arguments.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    params = remove_empty_elements({'filter': args.get('filter'),
                                    'pageNumber': args.get('page_number', '0'),
                                    'pageSize': args.get('limit'),
                                    'attributes': args.get('attributes')})
    raw_response = client.assets_list(params)
    table_headers = ['Hostname', 'Last Activity', 'Creation Time', 'Agent Version',
                     'Driver Version', 'Last Agent Update', 'Asset ID']
    outputs = []
    raw_outputs = []

    if raw_response:
        for item in raw_response:
            asset_data = item.get('data')
            raw_outputs.append(asset_data)

            last_checked_in = asset_data.get('lastCheckedIn')
            if last_checked_in:
                last_checked_in = epochToTimestamp(last_checked_in)
            else:
                last_checked_in = None

            created = asset_data.get('created')
            if created:
                created = epochToTimestamp(created)
            else:
                created = None

            agent_version = asset_data.get('agentVersion')
            driver_version = dict_safe_get(asset_data, ['agentService', 'driverVersion'])
            asset_id = asset_data.get('id')

            agent_last_updated = (dict_safe_get(asset_data, ['agentService', 'updatedDate']))
            if agent_last_updated:
                agent_last_updated = epochToTimestamp(agent_last_updated)

            hostname = None
            interfaces = asset_data.get('interfaces', [])
            for interface in interfaces:
                if interface.get('hostname') != 'None':
                    hostname = interface.get('hostname')
                    break

            item_dictionary = remove_empty_elements({'Hostname': hostname,
                                                     'Last Activity': last_checked_in,
                                                     'Creation Time': created,
                                                     'Agent Version': agent_version,
                                                     'Driver Version': driver_version,
                                                     'Last Agent Update': agent_last_updated,
                                                     'Asset ID': asset_id})

            outputs.append(item_dictionary)

    readable_output = tableToMarkdown(name=f'Listed {len(outputs)} Assets:',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True)

    return CommandResults(outputs_prefix='QualysFIM.Asset',
                          outputs_key_field='id',
                          raw_response=raw_response,
                          outputs=raw_outputs,
                          readable_output=readable_output)


def fetch_incidents(client: Client, last_run: Dict[str, int],
                    max_fetch: str, fetch_filter: str,
                    first_fetch_time: str) -> tuple[Dict, List[dict]]:
    """
    Fetch incidents (alerts) each minute (by default).
    Args:
        client (Client): QualysFIM Client.
        last_run (dict): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp).
        max_fetch (str): Max number of alerts to fetch.
        fetch_filter (str): filter incidents with Qualys syntax.
        first_fetch_time (str): Dict with first fetch time in str (ex: 3 days ago).

    Returns:
        Tuple of next_run (millisecond timestamp) and the incidents list.
    """
    last_fetch_timestamp = last_run.get('last_fetch', None)
    if last_fetch_timestamp:
        next_run = datetime.fromtimestamp(last_fetch_timestamp)
    else:
        next_run = dateparser.parse(first_fetch_time)  # type: ignore

    last_fetch_timestamp_new = int(datetime.timestamp(next_run) * 1000)
    time_now = int(datetime.timestamp(datetime.now()) * 1000)

    if int(max_fetch) > 200:
        raise ValueError('Max Fetch is limited to 200 incidents per fetch, '
                         'please choose lower number than 200.')

    if fetch_filter != '':
        fetch_filter = f"and {fetch_filter}"

    params = {'pageSize': max_fetch,
              'filter': f"createdBy.date: ['{last_fetch_timestamp_new}'..'{time_now}']"
                        f" {fetch_filter}",
              'sort': '[{"createdBy.date":"asc"}]'}
    raw_response = client.incidents_list(params)
    incidents = []
    last_incident_id = last_run.get('last_fetched_id')

    for incident in raw_response:
        incident = incident.get('data', None)
        incident_id = incident.get('id', None)
        if incident_id == last_incident_id:
            continue
        incident_name = incident.get('name', None)

        created_date = dict_safe_get(incident, ['createdBy', 'date'])
        if not created_date:
            continue
        incident_created_time = datetime.fromtimestamp(created_date / 1000)

        incident = {
            'name': incident_name,
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'rawJSON': json.dumps(incident),
            'incident_id': incident_id
        }
        incidents.append(incident)
        if incident_created_time > next_run:
            next_run = incident_created_time

    if len(incidents) > 0:
        last_incident_id = incidents[-1].get('incident_id')
    next_run_timestamp = int(datetime.timestamp(next_run))
    return {'last_fetch': next_run_timestamp, 'last_fetched_id': last_incident_id}, incidents


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to.
     Connection to the service is successful.

    Args:
        client: Qualys FIM client.

    Returns:
        'ok' if test passed.

    Raises:
        DemistoException: If test failed (e.g. due to failed authentication).
    """
    try:
        client.incidents_list_test()  # raises exception if non-okay response
        return 'ok'
    except Exception as e:
        if 'Authorization' in str(e):
            DemistoException("Authentication wasn't successful,\n"
                             " Please check credentials,\n"
                             " or specify correct Platform URL.")

        raise


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    base_url = params.get('platform')

    verify_certificate = not params.get('insecure', False)

    first_fetch_time = params.get('first_fetch', '7 days').strip()

    proxy = params.get('proxy', False)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        commands = {
            'qualys-fim-events-list': list_events_command,
            'qualys-fim-event-get': get_event_command,
            'qualys-fim-incidents-list': list_incidents_command,
            'qualys-fim-incidents-get-events': list_incident_events_command,
            'qualys-fim-incident-create': create_incident_command,
            'qualys-fim-incident-approve': approve_incident_command,
            'qualys-fim-assets-list': list_assets_command,
        }

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                fetch_filter=params.get('fetch_filter'),
                max_fetch=params.get('max_fetch', 50))

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
