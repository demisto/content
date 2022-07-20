import base64
import re
import traceback
from typing import Dict, List, Optional, Tuple

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

register_module_line('Microsoft 365 Defender', 'start', __line__())


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MAX_ENTRIES = 100
TIMEOUT = '30'
BASE_URL = "https://api.security.microsoft.com"

''' CLIENT CLASS '''


class Client:
    @logger
    def __init__(self, app_id: str, verify: bool, proxy: bool, base_url: str = BASE_URL, tenant_id: str = None,
                 enc_key: str = None, client_credentials: bool = False, certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        self.client_credentials = client_credentials
        client_args = assign_params(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=(200, 201, 202, 204),
            scope='offline_access https://security.microsoft.com/mtp/.default',
            self_deployed=True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.

            auth_id=app_id,
            grant_type=CLIENT_CREDENTIALS if client_credentials else DEVICE_CODE,

            # used for device code flow
            resource='https://api.security.microsoft.com' if not client_credentials else None,
            token_retrieval_url='https://login.windows.net/organizations/oauth2/v2.0/token' if not client_credentials else None,
            # used for client credentials flow
            tenant_id=tenant_id,
            enc_key=enc_key,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
        )
        self.ms_client = MicrosoftClient(**client_args)  # type: ignore

    @logger
    def incidents_list(self, timeout: int, limit: int = MAX_ENTRIES, status: Optional[str] = None,
                       assigned_to: Optional[str] = None, from_date: Optional[datetime] = None,
                       skip: Optional[int] = None) -> Dict:
        """
        GET request from the client using OData operators:
            - $top: how many incidents to receive, maximum value is 100
            - $filter: OData query to filter the the list on the properties:
                                                                lastUpdateTime, createdTime, status, and assignedTo
        Args:
            limit (int): how many incidents to receive, the maximum value is 100
            status (str): filter list to contain only incidents with the given status (Active, Resolved, or Redirected)
            assigned_to (str): Owner of the incident, or None if no owner is assigned
            timeout (int): The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
            from_date (datetime): get incident with creation date more recent than from_date
            skip (int): how many entries to skip

        Returns (Dict): request results as dict:
                    { '@odata.context',
                      'value': list of incidents,
                      '@odata.nextLink'
                    }

        """
        params = {'$top': limit}
        filter_query = ''
        if status:
            filter_query += 'status eq ' + "'" + status + "'"

        if assigned_to:
            filter_query += ' and ' if filter_query else ''
            filter_query += f"assignedTo eq '{assigned_to}'"

        # fetch incidents
        if from_date:
            filter_query += ' and ' if filter_query else ''
            filter_query += f"createdTime gt {from_date}"

        if filter_query:
            params['$filter'] = filter_query  # type: ignore

        if skip:
            params['$skip'] = skip

        return self.ms_client.http_request(method='GET', url_suffix='api/incidents', timeout=timeout,
                                           params=params)

    @logger
    def update_incident(self, incident_id: int, status: Optional[str], assigned_to: Optional[str],
                        classification: Optional[str],
                        determination: Optional[str], tags: Optional[List[str]], timeout: int, comment: str) -> Dict:
        """
        PATCH request to update single incident.
        Args:
            incident_id (int): incident's id
            status (str): Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
            assigned_to (str): Owner of the incident.
            classification (str): Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
            determination (str):  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
            tags (list): Custom tags associated with an incident. Separated by commas without spaces (CSV)
                 for example: tag1,tag2,tag3.
            timeout (int): The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
            comment (str): Comment to be added to the incident
       Returns( Dict): request results as dict:
                    { '@odata.context',
                      'value': updated incident,
                    }

        """
        body = assign_params(status=status, assignedTo=assigned_to, classification=classification,
                             determination=determination, tags=tags, comment=comment)
        updated_incident = self.ms_client.http_request(method='PATCH', url_suffix=f'api/incidents/{incident_id}',
                                                       json_data=body, timeout=timeout)
        return updated_incident

    @logger
    def get_incident(self, incident_id: int, timeout: int) -> Dict:
        """
        GET request to get single incident.
        Args:
            incident_id (int): incident's id
            timeout (int): waiting time for command execution


       Returns( Dict): request results as dict:
                    { '@odata.context',
                      'value': updated incident,
                    }

        """
        incident = self.ms_client.http_request(
            method='GET', url_suffix=f'api/incidents/{incident_id}', timeout=timeout)
        return incident

    @logger
    def advanced_hunting(self, query: str, timeout: int):
        """
        POST request to the advanced hunting API:
        Args:
            query (str): query advanced hunting query language
            timeout (int): The amount of time (in seconds) that a request will wait for a client to
                     establish a connection to a remote machine before a timeout occurs.

        Returns:
            The response object contains three top-level properties:

                Stats - A dictionary of query performance statistics.
                Schema - The schema of the response, a list of Name-Type pairs for each column.
                Results - A list of advanced hunting events.
        """
        return self.ms_client.http_request(method='POST', url_suffix='api/advancedhunting/run',
                                           json_data={"Query": query}, timeout=timeout)


@logger
def start_auth(client: Client) -> CommandResults:
    result = client.ms_client.start_auth('!microsoft-365-defender-auth-complete')
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: Client) -> CommandResults:
    client.ms_client.get_access_token()
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. You can now run '
                                          '**!microsoft-365-defender-auth-start** and **!microsoft-365-defender-auth-complete**.')


@logger
def test_connection(client: Client) -> CommandResults:
    test_context_for_token(client)
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


''' HELPER FUNCTIONS '''


def test_context_for_token(client: Client) -> None:
    """test_context_for_token
    Checks if the user acquired token via the authentication process.
    Args:
    Returns:

    """
    if client.client_credentials:
        return
    if not (get_integration_context().get('access_token') or get_integration_context().get('current_refresh_token')):
        raise DemistoException(
            "This integration does not have a test module. Please run !microsoft-365-defender-auth-start and "
            "!microsoft-365-defender-auth-complete and check the connection using !microsoft-365-defender-auth-test")


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if client.client_credentials:
        raise DemistoException("When using a self-deployed configuration, run the !microsoft-365-defender-auth-test"
                               "command in order to test the connection")

    test_connection(client)

    return "ok"


def _get_meta_data_for_incident(raw_incident: Dict) -> Dict:
    """
    Calculated metadata for the gicen incident
    Args:
        raw_incident (Dict): The incident as received from microsoft 365 defender

    Returns: Dictionary with the calculated data

    """
    if not raw_incident:
        raw_incident = {}

    alerts_list = raw_incident.get('alerts', [])

    alerts_status = [alert.get('status') for alert in alerts_list if alert.get('status')]
    first_activity_list = [alert.get('firstActivity') for alert in alerts_list]
    last_activity_list = [alert.get('lastActivity') for alert in alerts_list]

    return {
        'Categories': [alert.get('category', '') for alert in alerts_list],
        'Impacted entities': list({(entity.get('domainName', ''))
                                   for alert in alerts_list
                                   for entity in alert.get('entities') if entity.get('entityType') == 'User'}),
        'Active alerts': f'{alerts_status.count("Active") + alerts_status.count("New")} / {len(alerts_status)}',
        'Service sources': list({alert.get('serviceSource', '') for alert in alerts_list}),
        'Detection sources': list({alert.get('detectionSource', '') for alert in alerts_list}),
        'First activity': str(min(first_activity_list,
                                  key=lambda x: dateparser.parse(x))) if alerts_list else '',  # type: ignore
        'Last activity': str(max(last_activity_list,
                                 key=lambda x: dateparser.parse(x))) if alerts_list else '',  # type: ignore
        'Devices': [{'device name': device.get('deviceDnsName', ''),
                     'risk level': device.get('riskScore', ''),
                     'tags': ','.join(device.get('tags', []))
                     } for alert in alerts_list
                    for device in alert.get('devices', [])]
    }


def convert_incident_to_readable(raw_incident: Dict) -> Dict:
    """
    Converts incident received from microsoft 365 defender to readable format
    Args:
        raw_incident (Dict): The incident as received from microsoft 365 defender

    Returns: new dictionary with keys mapping.

    """
    if not raw_incident:
        raw_incident = {}

    incident_meta_data = _get_meta_data_for_incident(raw_incident)
    device_groups = {device.get('device name') for device in incident_meta_data.get('Devices', [])
                     if device.get('device name')}
    return {
        'Incident name': raw_incident.get('incidentName'),
        'Tags': ', '.join(raw_incident.get('tags', [])),
        'Severity': raw_incident.get('severity'),
        'Incident ID': raw_incident.get('incidentId'),
        # investigation state - relevant only for alerts.
        'Categories': ', '.join(set(incident_meta_data.get('Categories', []))),
        'Impacted entities': ', '.join(incident_meta_data.get('Impacted entities', [])),
        'Active alerts': incident_meta_data.get('Active alerts', []),
        'Service sources': ', '.join(incident_meta_data.get('Service sources', [])),
        'Detection sources': ', '.join(incident_meta_data.get('Detection sources', [])),
        # Data sensitivity - is not relevant
        'First activity': incident_meta_data.get('First activity', ''),
        'Last activity': incident_meta_data.get('Last activity', ''),
        'Status': raw_incident.get('status'),
        'Assigned to': raw_incident.get('assignedTo', 'Unassigned'),
        'Classification': raw_incident.get('classification', 'Not set'),
        'Device groups': ', '.join(device_groups),
    }


''' COMMAND FUNCTIONS '''


@logger
def microsoft_365_defender_incidents_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Returns list of the latest incidents in microsoft 365 defender in readable table.
    The list can be filtered using the following arguments:
        - limit (int) - number of incidents in the list, integer between 0 to 100.
        - status (str) - fetch only incidents with the given status.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - limit (int) - integer between 0 to 100
              - status (str) - get incidents with the given status (Active, Resolved or Redirected)
              - assigned_to (str) - get incidents assigned to the given user
              - offset (int) - skip the first N entries of the list
    Returns: CommandResults

    """
    limit = arg_to_number(args.get('limit', MAX_ENTRIES), arg_name='limit', required=True)
    status = args.get('status')
    assigned_to = args.get('assigned_to')
    offset = arg_to_number(args.get('offset'))
    timeout = arg_to_number(args.get('timeout', TIMEOUT))

    response = client.incidents_list(limit=limit, status=status, assigned_to=assigned_to, skip=offset, timeout=timeout)

    raw_incidents = response.get('value')
    readable_incidents = [convert_incident_to_readable(incident) for incident in raw_incidents]
    if readable_incidents:
        headers = list(readable_incidents[0].keys())  # the table headers are the incident keys.
        human_readable = tableToMarkdown(name="Incidents:", t=readable_incidents, headers=headers)

    else:
        human_readable = "No incidents found"

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=raw_incidents, readable_output=human_readable)


@logger
def microsoft_365_defender_incident_update_command(client: Client, args: Dict) -> CommandResults:
    """
    Update an incident.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - id (int) - incident's id (required)
              - status (str) - Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
              - assigned_to (str) - Owner of the incident.
              - classification (str) - Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
              - determination (str) -  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
              - tags - Custom tags associated with an incident. Separated by commas without spaces (CSV)
                       for example: tag1,tag2,tag3.

    Returns: CommandResults
    """
    raw_tags = args.get('tags')
    tags = raw_tags.split(',') if raw_tags else None
    status = args.get('status')
    assigned_to = args.get('assigned_to')
    classification = args.get('classification')
    determination = args.get('determination')
    incident_id = arg_to_number(args.get('id'))
    timeout = arg_to_number(args.get('timeout', TIMEOUT))
    comment = args.get('comment')

    updated_incident = client.update_incident(incident_id=incident_id, status=status, assigned_to=assigned_to,
                                              classification=classification, determination=determination, tags=tags,
                                              timeout=timeout, comment=comment)
    if updated_incident.get('@odata.context'):
        del updated_incident['@odata.context']

    readable_incident = convert_incident_to_readable(updated_incident)
    human_readable_table = tableToMarkdown(name=f"Updated incident No. {incident_id}:", t=readable_incident,
                                           headers=list(readable_incident.keys()))

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=updated_incident, readable_output=human_readable_table)


@logger
def microsoft_365_defender_incident_get_command(client: Client, args: Dict) -> CommandResults:
    """
    Get an incident.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - id (int)        - incident's id (required)
              - timeout (int)   - waiting time for command execution

    Returns: CommandResults
    """
    incident_id = arg_to_number(args.get('id'))
    timeout = arg_to_number(args.get('timeout', TIMEOUT))

    incident = client.get_incident(incident_id=incident_id, timeout=timeout)
    if incident.get('@odata.context'):
        del incident['@odata.context']

    readable_incident = convert_incident_to_readable(incident)
    human_readable_table = tableToMarkdown(name=f"Incident No. {incident_id}:", t=readable_incident,
                                           headers=list(readable_incident.keys()))

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=incident, readable_output=human_readable_table)


@logger
def fetch_incidents(client: Client, first_fetch_time: str, fetch_limit: int, timeout: int = None) -> List[Dict]:
    """
    Uses to fetch incidents into Demisto
    Documentation: https://xsoar.pan.dev/docs/integrations/fetching-incidents#the-fetch-incidents-command

    Due to API limitations (The incidents are not ordered and there is a limit of 100 incident for each request),
    We get all the incidents newer than last_run/first_fetch_time and saves them in a queue. The queue is sorted by
    creation date of each incident.

    As long as the queue has more incidents than fetch_limit the function will return the oldest incidents in the queue.
    If the queue is smaller than fetch_limit we fetch more incidents with the same logic described above.


    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        first_fetch_time(str): From when to fetch if first time, e.g. `3 days`.
        fetch_limit(int): The number of incidents in each fetch.
        timeout(int): The time limit in seconds for this function to run.
            Note: exceeding the time doesnt kill the function just prevents the next api call.
    Returns:
        incidents, new last_run
    """
    start_time = time.time()
    test_context_for_token(client)

    last_run_dict = demisto.getLastRun()

    last_run = last_run_dict.get('last_run')
    if not last_run:  # this is the first run
        first_fetch_date_time = dateparser.parse(first_fetch_time)
        assert first_fetch_date_time is not None, f'could not parse {first_fetch_time}'
        last_run = first_fetch_date_time.strftime(DATE_FORMAT)

    # creates incidents queue
    incidents_queue = last_run_dict.get('incidents_queue', [])

    if len(incidents_queue) < fetch_limit:

        incidents = list()

        # The API is limited to MAX_ENTRIES incidents for each requests, if we are trying to get more than MAX_ENTRIES
        # incident we skip (offset) the number of incidents we already fetched.
        offset = 0

        # This loop fetches all the incidents that had been created after last_run, due to API limitations the fetching
        # occurs in batches. If timeout was given, exceeding the time will result an error.
        # Note: Because the list is cannot be ordered by creation date, reaching timeout will force to re-run this
        #       function from the start.

        while True:
            time_delta = time.time() - start_time
            if timeout and time_delta > timeout:
                raise DemistoException(
                    "Fetch incidents - Time out. Please change first_fetch parameter to be more recent one")

            # HTTP request
            response = client.incidents_list(from_date=last_run, skip=offset, timeout=timeout)
            raw_incidents = response.get('value')
            for incident in raw_incidents:
                incident.update(_get_meta_data_for_incident(incident))

            incidents += [{
                "name": f"Microsoft 365 Defender {incident.get('incidentId')}",
                "occurred": incident.get('createdTime'),
                "rawJSON": json.dumps(incident)
            } for incident in raw_incidents]

            # raw_incidents length is less than MAX_ENTRIES than we fetch all the relevant incidents
            if len(raw_incidents) < int(MAX_ENTRIES):
                break
            offset += int(MAX_ENTRIES)

        # sort the incidents by the creation time
        incidents.sort(key=lambda x: dateparser.parse(x['occurred']))  # type: ignore
        incidents_queue += incidents

    oldest_incidents = incidents_queue[:fetch_limit]
    new_last_run = incidents_queue[-1]["occurred"] if oldest_incidents else last_run  # newest incident creation time
    demisto.setLastRun({'last_run': new_last_run,
                        'incidents_queue': incidents_queue[fetch_limit:]})
    return oldest_incidents


def _query_set_limit(query: str, limit: int) -> str:
    """
    Add limit to given query. If the query has limit, changes it.
    Args:
        query: the original query
        limit: new limit value, if the value is negative return the original query.
    Returns: query with limit parameters
    """
    if limit < 0:
        return query

    # the query has the structure of "section | section | section ..."
    query_list = query.split('|')

    # split the query to sections and find limit sections
    changed = False
    for i, section in enumerate(query_list):
        section_list = section.split()
        # 'take' and 'limit' are synonyms.
        if section_list and section_list[0] == 'limit' or section_list[0] == 'take':
            query_list[i] = f" limit {limit} "
            changed = True

    # if the query have not been changed than limit is added to the query
    if not changed:
        query_list.append(f" limit {limit} ")

    fixed_query = '|'.join(query_list)
    return fixed_query


@logger
def microsoft_365_defender_advanced_hunting_command(client: Client, args: Dict) -> CommandResults:
    """
    Sends a query for the advanced hunting tool.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments:
              - query (str) - The query to run (required)
              - limit (int) - number of entries in the result, -1 for no limit.
    Returns:

    """
    query = args.get('query', '')
    limit = arg_to_number(args.get('limit', '-1'))
    timeout = arg_to_number(args.get('timeout', TIMEOUT))

    query = _query_set_limit(query, limit)  # type: ignore

    response = client.advanced_hunting(query=query, timeout=timeout)
    results = response.get('Results')
    schema = response.get('Schema', {})
    headers = [item.get('Name') for item in schema]
    context_result = {'query': query, 'results': results}
    human_readable_table = tableToMarkdown(name=f" Result of query: {query}:", t=results,
                                           headers=headers)
    return CommandResults(outputs_prefix='Microsoft365Defender.Hunt', outputs_key_field='query', outputs=context_result,
                          readable_output=human_readable_table)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)
    app_id = params.get('app_id') or params.get('_app_id')
    base_url = params.get('base_url')

    tenant_id = params.get('tenant_id') or params.get('_tenant_id')
    client_credentials = params.get('client_credentials', False)
    enc_key = params.get('enc_key') or (params.get('credentials') or {}).get('password')
    certificate_thumbprint = params.get('certificate_thumbprint')
    private_key = params.get('private_key')

    first_fetch_time = params.get('first_fetch', '3 days').strip()
    fetch_limit = arg_to_number(params.get('max_fetch', 10))
    fetch_timeout = arg_to_number(params.get('fetch_timeout', TIMEOUT))
    demisto.debug(f'Command being called is {demisto.command()}')

    command = demisto.command()
    args = demisto.args()

    try:
        if not app_id:
            raise Exception('Application ID must be provided.')

        client = Client(
            app_id=app_id,
            verify=verify_certificate,
            base_url=base_url,
            proxy=proxy,
            tenant_id=tenant_id,
            enc_key=enc_key,
            client_credentials=client_credentials,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
        )
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'microsoft-365-defender-auth-start':
            return_results(start_auth(client))

        elif command == 'microsoft-365-defender-auth-complete':
            return_results(complete_auth(client))

        elif command == 'microsoft-365-defender-auth-reset':
            return_results(reset_auth())

        elif command == 'microsoft-365-defender-auth-test':
            return_results(test_connection(client))

        elif command == 'microsoft-365-defender-incidents-list':
            test_context_for_token(client)
            return_results(microsoft_365_defender_incidents_list_command(client, args))

        elif command == 'microsoft-365-defender-incident-update':
            test_context_for_token(client)
            return_results(microsoft_365_defender_incident_update_command(client, args))

        elif command == 'microsoft-365-defender-advanced-hunting':
            test_context_for_token(client)
            return_results(microsoft_365_defender_advanced_hunting_command(client, args))

        elif command == 'microsoft-365-defender-incident-get':
            test_context_for_token(client)
            return_results(microsoft_365_defender_incident_get_command(client, args))

        elif command == 'fetch-incidents':
            fetch_limit = arg_to_number(fetch_limit)
            fetch_timeout = arg_to_number(fetch_timeout) if fetch_timeout else None
            incidents = fetch_incidents(client, first_fetch_time, fetch_limit, fetch_timeout)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


### GENERATED CODE ###: from MicrosoftApiModule import *  # noqa: E402
# This code was inserted in place of an API module.
register_module_line('MicrosoftApiModule', 'start', __line__(), wrapper=-3)


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'
    security_center_apt_service = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
    management_azure = 'https://management.azure.com/.default'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
SESSION_STATE = 'session_state'
TOKEN_RETRIEVAL_ENDPOINTS = {
    'com': 'https://login.microsoftonline.com',
    'gcc-high': 'https://login.microsoftonline.us',
    'dod': 'https://login.microsoftonline.us',
    'de': 'https://login.microsoftonline.de',
    'cn': 'https://login.chinacloudapi.cn',
}
GRAPH_ENDPOINTS = {
    'com': 'https://graph.microsoft.com',
    'gcc-high': 'https://graph.microsoft.us',
    'dod': 'https://dod-graph.microsoft.us',
    'de': 'https://graph.microsoft.de',
    'cn': 'https://microsoftgraph.chinacloudapi.cn'
}
GRAPH_BASE_ENDPOINTS = {
    'https://graph.microsoft.com': 'com',
    'https://graph.microsoft.us': 'gcc-high',
    'https://dod-graph.microsoft.us': 'dod',
    'https://graph.microsoft.de': 'de',
    'https://microsoftgraph.chinacloudapi.cn': 'cn'
}


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: Optional[str] = '',
                 token_retrieval_url: str = '{endpoint}/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = '{graph_endpoint}/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: Optional[str] = '',
                 multi_resource: bool = False,
                 resources: List[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 timeout: Optional[int] = None,
                 azure_ad_endpoint: str = '{endpoint}',
                 endpoint: str = 'com',
                 certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None,
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
            certificate_thumbprint: Certificate's thumbprint that's associated to the app
            private_key: Private key of the certificate
        """
        super().__init__(verify=verify, *args, **kwargs)  # type: ignore[misc]
        self.endpoint = endpoint
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.tenant_id = tenant_id
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id,
                                                                  endpoint=TOKEN_RETRIEVAL_ENDPOINTS[self.endpoint])
            self.client_id = auth_id
            self.client_secret = enc_key
            self.tenant_id = tenant_id
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope.format(graph_endpoint=GRAPH_ENDPOINTS[self.endpoint])
            self.redirect_uri = redirect_uri
            if certificate_thumbprint and private_key:
                try:
                    import msal  # pylint: disable=E0401
                    self.jwt = msal.oauth2cli.assertion.JwtAssertionCreator(
                        private_key,
                        'RS256',
                        certificate_thumbprint
                    ).create_normal_assertion(audience=self.token_retrieval_url, issuer=self.client_id)
                except ModuleNotFoundError:
                    raise DemistoException('Unable to use certificate authentication because `msal` is missing.')
            else:
                self.jwt = None

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint.format(endpoint=TOKEN_RETRIEVAL_ENDPOINTS[self.endpoint])
        self.timeout = timeout  # type: ignore

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: Dict[str, str] = {}

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: Optional[str] = None,
            resource: str = '', **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs and not self._ok_codes:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers.update(headers)

        if self.timeout:
            kwargs['timeout'] = self.timeout

        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def get_access_token(self, resource: str = '', scope: Optional[str] = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource (str): The resource identifier for which the generated token will have access to.
            scope (str): A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        if self.multi_resource:
            access_token = integration_context.get(resource)
        else:
            access_token = integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        if self.auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                for resource_str in self.resources:
                    access_token, expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _oproxy_authorize(self, resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope,
                'resource': resource
            },
            verify=self.verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: Optional[str] = None,
                                 integration_context: Optional[dict] = None
                                 ) -> Tuple[str, int, str]:
        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            else:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                      resource)
                    self.resource_to_access_token[resource] = access_token

                return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            if self.multi_resource:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_client_credentials(
                        resource=resource)
                    self.resource_to_access_token[resource] = access_token
                return '', expires_in, refresh_token
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: Optional[str] = None,
                                                    resource: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope: A scope to add to the headers. Else will get self.scope.
            resource: A resource to add to the headers. Else will get self.resource.
        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope if scope else self.scope

        if self.resource or resource:
            data['resource'] = resource or self.resource  # type: ignore

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: Optional[str] = None) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=self.resource if not resource else resource,
            redirect_uri=self.redirect_uri
        )

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_token_device_code(
            self, refresh_token: str = '', scope: Optional[str] = None, integration_context: Optional[dict] = None
    ) -> Tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: Optional[str]) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search.group('url') if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


register_module_line('MicrosoftApiModule', 'end', __line__(), wrapper=1)
### END GENERATED CODE ###

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('Microsoft 365 Defender', 'end', __line__())
