import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401 #todo: revert
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MAX_ENTRIES = 100
TIMEOUT = '30'
BASE_URL = "https://api.security.microsoft.com"

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}

OUTGOING_MIRRORED_FIELDS = {
    'status': 'Specifies the current status of the incident.',
    'assignedTo': 'Owner of the incident.',
    'classification': 'Specification of the incident.',
    'determination': 'Specifies the determination of the incident.',
    'tags': 'List of Incident tags.',
    'comment': 'Comment to be added to the incident.'
}

CLASSIFICATION_DETERMINATION_MAPPING = {
    'TruePositive': ['MultiStagedAttack', 'MaliciousUserActivity', 'Malware', 'Phishing', 'CompromisedAccount',
                     'UnwantedSoftware', 'Other'],
    'InformationalExpectedActivity': ['SecurityTesting', 'LineOfBusinessApplication', 'ConfirmedActivity', 'Other'],
    'FalsePositive': ['Clean', 'NoEnoughDataToValidate', 'Other'],
    'Unknown': ['NotAvailable']}

''' CLIENT CLASS '''


class Client:
    @logger
    def __init__(self, app_id: str, verify: bool, proxy: bool, base_url: str = BASE_URL, tenant_id: str = None,
                 enc_key: str = None, client_credentials: bool = False, certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None,
                 managed_identities_client_id: Optional[str] = None):
        if app_id and '@' in app_id:
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
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.security,
            command_prefix="microsoft-365-defender",
        )
        self.ms_client = MicrosoftClient(**client_args)  # type: ignore

    @logger
    def incidents_list(self, timeout: int, limit: int = MAX_ENTRIES, status: Optional[str] = None,
                       assigned_to: Optional[str] = None, from_date: Optional[datetime] = None,
                       skip: Optional[int] = None, odata: Optional[dict] = None, last_update_time: Optional[str] = None) -> dict:
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
            odata (dict): alternative method for listing incidents, accepts dictionary of URI parameters

        Returns (Dict): request results as dict:
                    { '@odata.context',
                      'value': list of incidents,
                      '@odata.nextLink'
                    }

        """
        params = {}

        if odata:
            params = odata
        else:
            filter_query = ''
            params = {'$top': limit}
            if status:
                filter_query += 'status eq ' + "'" + status + "'"

            if assigned_to:
                filter_query += ' and ' if filter_query else ''
                filter_query += f"assignedTo eq '{assigned_to}'"

            # fetch incidents
            if from_date:
                filter_query += ' and ' if filter_query else ''
                filter_query += f"createdTime gt {from_date}"

            # mirroring get-modified-remote-data
            if last_update_time:
                filter_query += ' and ' if filter_query else ''
                filter_query += f"lastUpdateTime gt {last_update_time}"

            if filter_query:
                params['$filter'] = filter_query  # type: ignore

            if skip:
                params['$skip'] = skip

        return self.ms_client.http_request(method='GET', url_suffix='api/incidents', timeout=timeout,
                                           params=params)

    @logger
    def update_incident(self, incident_id: int, status: Optional[str], assigned_to: Optional[str],
                        classification: Optional[str],
                        determination: Optional[str], tags: Optional[List[str]], timeout: int, comment: str) -> dict:
        """
        PATCH request to update single incident.
        Args:
            incident_id (int): incident's id
            status (str): Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
            assigned_to (str): Owner of the incident.
            classification (str): Specification of the alert. Possible values are: InformationalExpectedActivity, FalsePositive, TruePositive.
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
        if assigned_to == "":
            body['assignedTo'] = ""
        updated_incident = self.ms_client.http_request(method='PATCH', url_suffix=f'api/incidents/{incident_id}',
                                                       json_data=body, timeout=timeout)
        return updated_incident

    @logger
    def get_incident(self, incident_id: int, timeout: int) -> dict:
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
    if client.client_credentials or client.ms_client.managed_identities_client_id:
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
        raise DemistoException("When using a self-deployed configuration, run the !microsoft-365-defender-auth-test "
                               "command in order to test the connection")

    test_connection(client)

    return "ok"


def _get_meta_data_for_incident(raw_incident: dict) -> dict:
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

    mailboxes_set = set()
    mailboxes = []
    for alert in alerts_list:
        for entity in alert.get('entities', []):
            if entity.get('entityType') == 'Mailbox':
                if entity.get('mailboxAddress', '') not in mailboxes_set:
                    mailboxes.append({'Mailbox': entity.get('mailboxAddress', ''),
                                      'Display Name': entity.get('mailboxDisplayName', '')})
                    mailboxes_set.add((entity.get('mailboxAddress', '')))
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
                    for device in alert.get('devices', [])],
        'Mailboxes': mailboxes}


def convert_incident_to_readable(raw_incident: dict) -> dict:
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
        'Impacted users': ', '.join(incident_meta_data.get('Impacted entities', [])),
        'Impacted mailboxes': ', '.join(mailbox.get('Mailbox') for mailbox in incident_meta_data.get('Mailboxes', [])),
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
def microsoft_365_defender_incidents_list_command(client: Client, args: dict) -> CommandResults:
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
              - odata (str) - json dictionary containing odata uri parameters
    Returns: CommandResults

    """
    limit = arg_to_number(args.get('limit', MAX_ENTRIES), arg_name='limit', required=True)
    status = args.get('status')
    assigned_to = args.get('assigned_to')
    offset = arg_to_number(args.get('offset'))
    timeout = arg_to_number(args.get('timeout', TIMEOUT))
    odata = args.get('odata')

    if odata:
        try:
            odata = json.loads(odata)
        except json.JSONDecodeError:
            return_error(f"Can't parse odata argument as JSON array.\nvalue: {odata}")

    response = client.incidents_list(limit=limit, status=status, assigned_to=assigned_to,
                                     skip=offset, timeout=timeout, odata=odata)

    raw_incidents = response.get('value')
    readable_incidents = [convert_incident_to_readable(incident) for incident in raw_incidents]
    if readable_incidents:
        headers = list(readable_incidents[0].keys())  # the table headers are the incident keys.
        human_readable = tableToMarkdown(name="Incidents:", t=readable_incidents, headers=headers)

    else:
        human_readable = "No incidents found"

    return CommandResults(outputs_prefix='Microsoft365Defender.Incident', outputs_key_field='incidentId',
                          outputs=raw_incidents, readable_output=human_readable)


def get_determination_value(classification: Optional[str], determination: Optional[str]) -> Optional[str]:
    if classification is None and determination is None:
        return None

    if not classification or classification not in CLASSIFICATION_DETERMINATION_MAPPING:
        raise DemistoException("Please provide a valid classification")

    if not determination:
        return 'NotAvailable' if classification == 'Unknown' else 'Other'

    if determination not in CLASSIFICATION_DETERMINATION_MAPPING[classification]:
        raise DemistoException(
            f"Invalid determination. "
            f"Please provide one of the following: {CLASSIFICATION_DETERMINATION_MAPPING[classification]}"
        )

    return determination


@logger
def microsoft_365_defender_incident_update_command(client: Client, args: dict) -> CommandResults:
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
    determination = get_determination_value(classification, args.get('determination'))
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
def microsoft_365_defender_incident_get_command(client: Client, args: dict) -> CommandResults:
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


def store_ids_for_first_mirroring(incidents: list):
    """
    Stores the fetched incident IDs in the integration context to trigger mirroring.
    We're triggering mirroring for new incidents to mirror existing comments.

    Args:
        incidents (list): List of fetched incidents.
    """
    int_context = get_integration_context()
    fetched_incidents_ids = [json.loads(incident.get('rawJSON')).get("incidentId", "") for incident in incidents]
    int_context.setdefault("last_fetched_incident_ids", []).extend(fetched_incidents_ids)
    demisto.debug(f"Microsoft 365 Defender  - Saving the following incident ids in the integration context: {int_context=}")
    set_integration_context(int_context)


@logger
def fetch_incidents(client: Client, mirroring_fields: dict, first_fetch_time: str, fetch_limit: int,
                    timeout: int = None) -> List[
    dict]:
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

        incidents = []

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
                incident.update(mirroring_fields)
                demisto.debug(f"MIRRORING FIELDS: {str(incident)=}")

            incidents += [{
                "name": f"Microsoft 365 Defender {incident.get('incidentId')}",
                "occurred": incident.get('createdTime'),
                "rawJSON": json.dumps(incident),
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
    store_ids_for_first_mirroring(oldest_incidents)
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
    query_list = re.split(r'(?<!\|)\|(?!\|)', query)

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
def microsoft_365_defender_advanced_hunting_command(client: Client, args: dict) -> CommandResults:
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


''' MIRRORING COMMANDS '''


def fetch_modified_incident_ids(client: Client, last_update_time) -> List[str]:
    demisto.debug("microsoft365::Starting fetch_modified_incidents")
    incidents = []

    # The API is limited to MAX_ENTRIES incidents for each requests, if we are trying to get more than MAX_ENTRIES
    # incident we skip (offset) the number of incidents we already fetched.
    offset = 0

    # This loop fetches all the incidents that had been created after last_run, due to API limitations the fetching
    # occurs in batches. If timeout was given, exceeding the time will result an error.

    while True:
        # HTTP request
        demisto.debug(f"microsoft365::fetch_modified_incidents - fetching incidents with offset {offset}")
        response = client.incidents_list(timeout=50, last_update_time=last_update_time,
                                         skip=offset)  # todo: should include timeout?
        raw_incidents = response.get('value')
        demisto.debug(f"microsoft365::fetch_modified_incidents - fetched {len(raw_incidents)} incidents")
        demisto.debug(f"microsoft365::{str(raw_incidents)}")
        for incident in raw_incidents:
            incidents.append(str(incident.get('incidentId')))
        # raw_incidents length is less than MAX_ENTRIES than we fetch all the relevant incidents
        if len(raw_incidents) < int(
            MAX_ENTRIES):  # todo: how to handle - Maximum rate of requests is 50 calls per minute and 1500 calls per hour
            break
        offset += int(MAX_ENTRIES)
    return incidents


def fetch_modified_incidents(client: Client, last_update_time) -> List[dict]:
    demisto.debug("microsoft365::Starting fetch_modified_incidents")
    incidents = []

    # The API is limited to MAX_ENTRIES incidents for each requests, if we are trying to get more than MAX_ENTRIES
    # incident we skip (offset) the number of incidents we already fetched.
    offset = 0

    # This loop fetches all the incidents that had been created after last_run, due to API limitations the fetching
    # occurs in batches. If timeout was given, exceeding the time will result an error.

    while True:
        # HTTP request
        demisto.debug(f"microsoft365::fetch_modified_incidents - fetching incidents with offset {offset}")
        response = client.incidents_list(timeout=50, last_update_time=last_update_time,
                                         skip=offset)  # todo: should include timeout?
        raw_incidents = response.get('value')
        demisto.debug(f"microsoft365::fetch_modified_incidents - fetched {len(raw_incidents)} incidents")
        demisto.debug(f"microsoft365::{str(raw_incidents)}")
        for incident in raw_incidents:
            incident.update(_get_meta_data_for_incident(incident))
            incident['mirrorRemoteId'] = incident.get('incidentId')
            incidents.append(incident)
        # raw_incidents length is less than MAX_ENTRIES than we fetch all the relevant incidents
        if len(raw_incidents) < int(
            MAX_ENTRIES):  # todo: how to handle - Maximum rate of requests is 50 calls per minute and 1500 calls per hour
            break
        offset += int(MAX_ENTRIES)
    return incidents


MICROSOFT_RESOLVED_CLASSIFICATION_TO_XSOAR_CLOSE_REASON = {
    'Unknown': 'Other',
    'TruePositive': 'Resolved',
    'FalsePositive': 'False Positive',
    'InformationalExpectedActivity': 'Resolved',
}


def is_new_incident(incident_id: str) -> bool:
    """
    Returns whether the ticket id is a new fetched incident in XSOAR which should mirror existing comments.

    Args:
        incident_id (str): The incident ID.

    Returns:
        bool: Whether its a new incident in XSOAR.
    """
    int_context = get_integration_context()
    last_fetched_ids = int_context.get("last_fetched_incident_ids") or []
    demisto.debug(f"Microsoft Defender 365 - Last fetched incident ids are: {last_fetched_ids}")
    if id_in_last_fetch := incident_id in last_fetched_ids:
        demisto.debug(f"Microsoft Defender 365 - Incident {incident_id} is already in the last fetched incidents")
        last_fetched_ids.remove(incident_id)
        int_context["last_fetched_incident_ids"] = last_fetched_ids
        demisto.debug(f"Microsoft Defender 365 - Removed incident {incident_id} from last fetched incidents")
        set_integration_context(int_context)
    else:
        demisto.debug(f"Microsoft Defender 365 - Incident {incident_id} is not in the last fetched incidents")
    return id_in_last_fetch


def extend_with_new_incidents(modified_records_ids: list) -> list:
    """
    Extend list of modified incidents with new fetched incidents to trigger mirroring.
    We're triggering mirroring for new incidents to mirror existing comments.

    Args:
        modified_records_ids (list): List of modified incidents.

    Returns:
        list: Extended list of incidents to trigger mirroring.
    """
    int_context = get_integration_context()
    last_fetched_incident_ids = int_context.get("last_fetched_incident_ids" , [])
    demisto.debug(f"Microsoft Defender 365 - Extending with last fetched incident ids: {last_fetched_incident_ids}")
    modified_records_ids.extend(last_fetched_incident_ids)
    modified_records_ids = list(set(modified_records_ids))  # remove duplicates
    return modified_records_ids


def get_modified_incidents_close_or_repopen_entries_content(modified_incidents: List[dict], close_incident: bool) -> List[dict]:
    demisto.debug("microsoft365::Starting get_modified_incidents_close_or_repopen_entries_content")
    entries_content = []
    if close_incident:
        for incident in modified_incidents:
            if incident.get('status') == 'Resolved':
                demisto.debug(
                    f"handle_incoming_closing_incidents for incident {incident.get('incidentId')}"
                )
                classification = incident.get('classification', 'Unknown')
                entries_content.append({
                    'dbotIncidentClose': True,
                    'closeReason': MICROSOFT_RESOLVED_CLASSIFICATION_TO_XSOAR_CLOSE_REASON.get(classification, 'Other'),
                })
            else:
                demisto.debug(
                    f"handle_incoming_reopen_incidents for incident {incident.get('incidentId')}"
                )
                entries_content.append({
                    'dbotIncidentReopen': True
                })
    return entries_content


def get_modified_remote_data_command(client: Client, args,
                                     return_entire_data=False) -> GetModifiedRemoteDataResponse:
    # todo - do we want to sync assignedto like in xdr?
    demisto.debug("microsoft365::Starting get_modified_remote_data_command")
    close_incident = argToBoolean(demisto.params().get('close_incident', False))
    remote_args = GetModifiedRemoteDataArgs(args)
    parsed_date = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
    assert parsed_date is not None, f'could not parse {remote_args.last_update}'
    last_update = parsed_date.strftime(DATE_FORMAT)
    demisto.debug(f"microsoft365::Last update: {last_update}")
    try:
        # if return_entire_data:
        #     modified_incidents = fetch_modified_incidents(client, last_update)
        #     demisto.debug(f"microsoft365::Found {len(modified_incidents)} modified incidents")
        #     demisto.debug(f"microsoft365::{str(modified_incidents)}")
        #     modified_incidents_entries_content = get_modified_incidents_entries_content(modified_incidents, close_incident)
        #
        #     # todo - handle incident reopen and closing
        #     # skip update: In case of a failure. In order to notify the server that the command failed and prevent execution of the get-remote-data commands, returns an error that contains the string "skip update".?
        #     return GetModifiedRemoteDataResponse(modified_incidents_data=modified_incidents + modified_incidents_entries_content)
        # else:
        modified_incident_ids = fetch_modified_incident_ids(client, last_update)
        demisto.debug(f"microsoft365::Found {len(modified_incident_ids)} modified incidents: {str(modified_incident_ids)}")
        # modified_incident_ids = extend_with_new_incidents(modified_incident_ids)



        # skip update: In case of a failure. In order to notify the server that the command failed and prevent execution of the get-remote-data commands, returns an error that contains the string "skip update".?
        return GetModifiedRemoteDataResponse(modified_incident_ids=modified_incident_ids)
    except Exception as e:
        demisto.debug(f"Error in Microsoft 365 defender incoming mirror \n"
                      f"Error message: {str(e)}")
        if "Rate limit exceeded" in str(
            e):  # todo - check if this is the correct error message + on the server side what does is expect to ger
            return_error("API rate limit")


def fetch_modified_incident(client: Client, incident_id: str) -> dict:
    demisto.debug(f"microsoft365::Fetching incident {incident_id}")
    incident = client.get_incident(incident_id=arg_to_number(incident_id), timeout=50)
    demisto.debug(f"microsoft365::raw incident {str(incident)}")
    if incident.get('@odata.context'):
        del incident['@odata.context']
    incident.update(_get_meta_data_for_incident(incident))
    return incident


def get_entries_for_comments(incident_id: str, comments: List[dict], last_update: datetime, comment_tag: str, new_incident : bool) -> List[dict]:
    """
    Get the entries for the comments of the incident.
    Args:
        incident_id (str): The incident ID.
        comments (List[dict]): The comments of the incident.
        last_update (datetime): The last update time.

    Returns:
        List[dict]: The entries for the comments.
    """
    entries = []
    for comment in comments:
        if 'Mirrored from Cortex XSOAR' not in comment.get('comment', ''):
            demisto.debug(f"microsoft365::comment {str(comment)}")
            comment_time = dateparser.parse(comment.get('createdTime'))
            if new_incident or comment_time > last_update:
                entries.append({
                    'Type': EntryType.NOTE,
                    'Contents': f"Created By: {comment.get('createdBy')}\n"
                                f"Created On: {comment.get('createdTime')}\n"
                                f"{comment.get('comment')}",
                    'ContentsFormat': EntryFormat.TEXT,
                    'Tags': [comment_tag],
                    'Note': True,
                    'EntryContext': {
                        'comments': comment
                    },
                })
    return entries


def get_incident_entries(remote_incident_id: str, mirrored_object: dict, last_update: datetime, comment_tag: str, new_incident : bool,
                         close_incident: bool = False) -> \
    List[dict]:
    close_or_repopen_entry_contents = get_modified_incidents_close_or_repopen_entries_content([mirrored_object],
                                                                                              close_incident=close_incident)
    entries = [{
        'Type': EntryType.NOTE,
        'Contents': entry_content,
        'ContentsFormat': EntryFormat.JSON,

    } for entry_content in close_or_repopen_entry_contents]

    entries.extend(get_entries_for_comments(remote_incident_id, mirrored_object.get('comments', []), last_update, comment_tag, new_incident))
    return entries


def get_remote_data_command(client: Client, args: dict[str, Any]) -> GetRemoteDataResponse:
    remote_args = GetRemoteDataArgs(args)
    comment_tag = demisto.params().get('comment_tag_from_microsoft365defender', 'CommentFromMicrosoft365Defender')
    last_update = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
    assert last_update is not None, f'could not parse {remote_args.last_update}'
    close_incident = argToBoolean(demisto.params().get('close_incident', False))
    mirrored_object = {}
    demisto.debug(
        f'Performing get-remote-data command with incident id: {remote_args.remote_incident_id} and last_update: {remote_args.last_update}')
    try:
        mirrored_object: Dict = fetch_modified_incident(client, remote_args.remote_incident_id)
        demisto.debug(f"microsoft365::Fetched incident {str(mirrored_object)}")
        new_incident = is_new_incident(remote_args.remote_incident_id)
        entries = get_incident_entries(remote_args.remote_incident_id, mirrored_object, last_update, comment_tag, new_incident,
                                       close_incident=close_incident) #todo: if new, get the object from the context rather than making api call
        demisto.debug(f"microsoft365::Fetched entries {str(entries)}")
        return GetRemoteDataResponse(mirrored_object, entries)
    except Exception as e:
        demisto.debug(f"Error in Microsoft incoming mirror for incident: {remote_args.remote_incident_id}\n"
                      f"Error message: {str(e)} \n {traceback.format_exc()}")

        if not mirrored_object:
            mirrored_object = {'id': remote_args.remote_incident_id}
        mirrored_object['in_mirror_error'] = str(e)
        return GetRemoteDataResponse(mirrored_object, entries=[])


def get_mapping_fields_command():
    incident_type_scheme = SchemeTypeMapping(type_name='Microsoft 365 Defender Incident')
    for field in OUTGOING_MIRRORED_FIELDS:
        incident_type_scheme.add_field(name=field, description=OUTGOING_MIRRORED_FIELDS.get(field))
    return GetMappingFieldsResponse(incident_type_scheme)


def update_remote_incident(client: Client, updated_args: dict, remote_incident_id: int):
    demisto.debug(f"microsoft365::Starting update_remote_incident")
    updated_incident = client.update_incident(incident_id=remote_incident_id,
                                              status=updated_args.get('status'),
                                              assigned_to=updated_args.get('assignedTo'),
                                              classification=updated_args.get('classification'),
                                              determination=updated_args.get('determination'),
                                              tags=argToList(updated_args.get('tags')),
                                              timeout=50,
                                              comment=updated_args.get('comment'))
    demisto.debug(f"microsoft365::Updated incident {str(updated_incident)}")


def handle_incident_close_out(delta):
    demisto.debug("microsoft365::Starting handle_incident_close_out")
    if not argToBoolean(demisto.params().get('close_out', False)):
        demisto.debug("microsoft365::Close out is not enabled")
        return
    demisto.debug("microsoft365::Close out is enabled")
    if any(delta.get(key) for key in ['closeReason', 'closeNotes', 'closingUserId']):
        delta['status'] = 'Resolved'
        if delta.get('closeReason') == 'FalsePositive' and delta.get('classification') != 'FalsePositive':
            delta.update({'classification': 'FalsePositive', 'determination': 'Other'})
        elif delta.get('closeReason') == 'Other' or delta.get('closeReason') == 'Duplicate':
            delta.update({'classification': 'Unknown', 'determination': 'NotAvailable'})


def handle_mirror_out_entries(client, entries, comment_tag, remote_incident_id):
    for entry in entries:
        demisto.debug(f'handling entry {entry.get("id")}, type: {entry.get("type")}')
        tags = entry.get('tags', [])
        user = entry.get('user', 'dbot') or 'dbot'
        if comment_tag in tags:
            if str(entry.get('format')) == 'html':
                contents = str(entry.get('contents', ''))
                text = f"({user}): <br/><br/>[code]{contents} <br/><br/>[/code] Mirrored from Cortex XSOAR"
            else:
                text = f"({user}): {str(entry.get('contents', ''))}\n\n Mirrored from Cortex XSOAR"

            update_remote_incident(client, {'comment': text}, remote_incident_id)
        else:
            demisto.debug(f"Skipping entry {entry.get('id')} as it does not contain the comment tag")


def handle_incident_reopening(delta):
    if any(delta.get(key) == '' for key in ['closeReason', 'closeNotes', 'closingUserId']):
        delta['status'] = 'Active'


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    update_remote_system_args = UpdateRemoteSystemArgs(args)
    remote_incident_id = update_remote_system_args.remote_incident_id
    data = update_remote_system_args.data
    delta = update_remote_system_args.delta
    comment_tag = demisto.params().get('comment_tag', 'CommentToMicrosoft365Defender')

    demisto.debug(
        f"update_remote_system_command {remote_incident_id=} \n {delta=} \n {data=} \n "
        f"{update_remote_system_args.incident_changed=} \n {update_remote_system_args.inc_status=}"
        f" \n {update_remote_system_args.entries=}")

    try:
        if update_remote_system_args.incident_changed and delta:
            demisto.debug(f'Got the following delta keys {str(list(update_remote_system_args.delta.keys()))} to update'
                          f'incident {remote_incident_id}')
            if update_remote_system_args.inc_status == IncidentStatus.DONE:
                handle_incident_close_out(delta)
            else:
                handle_incident_reopening(delta)

            update_remote_incident(client, delta, remote_incident_id)
        else:
            demisto.debug(f'Skipping updating remote incident fields [{remote_incident_id}] '
                          f'as it is not new nor changed')

        if update_remote_system_args.entries:
            demisto.debug(f"Adding entries {str(update_remote_system_args.entries)}")
            handle_mirror_out_entries(client, update_remote_system_args.entries, comment_tag, remote_incident_id)

        return remote_incident_id

    except Exception as e:
        demisto.error(f"Error in outgoing mirror for incident {remote_incident_id} \n"
                      f"Error message: {str(e)}")
        return remote_incident_id


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
    app_id = params.get('creds_client_id', {}).get('password', '') or params.get('app_id') or params.get('_app_id')
    base_url = params.get('base_url')

    tenant_id = params.get('creds_tenant_id', {}).get('password', '') or params.get('tenant_id') or params.get('_tenant_id')
    client_credentials = params.get('client_credentials', False)
    enc_key = params.get('enc_key') or (params.get('credentials') or {}).get('password')
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier', '') or \
                             params.get('certificate_thumbprint', '')

    private_key = (replace_spaces_in_credential(params.get('creds_certificate', {}).get('password', ''))
                   or params.get('private_key', ''))
    managed_identities_client_id = get_azure_managed_identities_client_id(params)

    first_fetch_time = params.get('first_fetch', '3 days').strip()
    fetch_limit = arg_to_number(params.get('max_fetch', 10))
    fetch_timeout = arg_to_number(params.get('fetch_timeout', TIMEOUT))

    demisto.info(str(params))

    mirroring_fields = {
        'mirror_direction': MIRROR_DIRECTION.get(params.get('mirror_direction', 'None')),
        'mirror_instance': demisto.integrationInstance()
    }

    demisto.debug(f'Command being called is {demisto.command()}')

    command = demisto.command()
    args = demisto.args()
    demisto.debug(str(args))

    try:
        if not managed_identities_client_id and not app_id:
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
            managed_identities_client_id=managed_identities_client_id
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
            incidents = fetch_incidents(client, mirroring_fields, first_fetch_time, fetch_limit, fetch_timeout)
            demisto.incidents(incidents)

        elif command == 'get-remote-data':
            test_context_for_token(client)
            return_results(get_remote_data_command(client, args))

        elif command == 'get-modified-remote-data':
            test_context_for_token(client)
            modified_incidents = get_modified_remote_data_command(client, args)
            demisto.debug(
                f"microsoft365::returning {len(modified_incidents.modified_incident_ids)} incidents to the server. {str(modified_incidents.modified_incident_ids)}")
            return_results(modified_incidents)

        elif command == 'update-remote-system':
            test_context_for_token(client)
            return_results(update_remote_system_command(client, args))

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        else:
            raise NotImplementedError
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
