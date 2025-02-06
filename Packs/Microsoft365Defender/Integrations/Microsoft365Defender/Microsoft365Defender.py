import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

MAX_ENTRIES = 100
TIMEOUT = '30'
TIMEOUT_INT = 30
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
    'FalsePositive': ['NotMalicious', 'NoEnoughDataToValidate', 'Other'],
    'Unknown': ['NotAvailable']}

MICROSOFT_RESOLVED_CLASSIFICATION_TO_XSOAR_CLOSE_REASON = {
    'Unknown': 'Other',
    'TruePositive': 'Resolved',
    'FalsePositive': 'False Positive',
    'InformationalExpectedActivity': 'Resolved',
}

MICROSOFT_INCIDENT_ID_KEY = 'incidentId'
MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR = "Mirrored from Cortex XSOAR"
COMMENT_TO_MICROSOFT_DEFAULT_TAG = 'CommentToMicrosoft365Defender'

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
            last_update_time (str): get incident with last update time more recent than last_update_time.

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
    def update_incident(self, incident_id: int, status: Optional[str] = None, assigned_to: Optional[str] = None,
                        classification: Optional[str] = None,
                        determination: Optional[str] = None,
                        tags: Optional[List[str]] = None,
                        timeout: int = None,
                        comment: Optional[str] = None) -> dict:
        """
        PATCH request to update single incident.
        Args:
            incident_id (int): incident's id
            status (str): Specifies the current status of the alert. Possible values are: (Active, Resolved, InProgress or
            Redirected)
            assigned_to (str): Owner of the incident.
            classification (str): Specification of the alert. Possible values are: InformationalExpectedActivity, FalsePositive,
             TruePositive.
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
            if entity.get('entityType') == 'Mailbox' and entity.get('mailboxAddress', '') not in mailboxes_set:
                mailboxes.append({'Mailbox': entity.get('mailboxAddress', ''),
                                  'Display Name': entity.get('mailboxDisplayName', '')})
                mailboxes_set.add(entity.get('mailboxAddress', ''))

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
        'Mailboxes': mailboxes,
        'comments': raw_incident.get('comments', [])}


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
        'Impacted entities': ', '.join(incident_meta_data.get('Impacted entities', [])),
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
    """
    Determines the appropriate determination value based on the provided classification and determination inputs.

    Args:
        classification (Optional[str]): The classification of the incident. Must be a valid key in
            the CLASSIFICATION_DETERMINATION_MAPPING dictionary.
        determination (Optional[str]): The determination value associated with the classification. Must be
            a valid value in the corresponding list of determination values for the given classification.

    Returns:
        Optional[str]:
            - If both classification and determination are `None`, returns `None`.
            - If classification is valid but determination is not provided:
                - Returns "NotAvailable" if the classification is "Unknown".
                - Returns "Other" for all other classifications.
            - If both classification and determination are valid, returns the provided determination.

    Raises:
        DemistoException:
            - If classification is not provided or not valid (not in CLASSIFICATION_DETERMINATION_MAPPING).
            - If determination is provided but is not valid for the given classification.

    """
    if classification is None and determination is None:
        return None

    if not classification or classification not in CLASSIFICATION_DETERMINATION_MAPPING:
        raise DemistoException("get_determination_value - Please provide a valid classification")

    if not determination:
        return 'NotAvailable' if classification == 'Unknown' else 'Other'

    if determination not in CLASSIFICATION_DETERMINATION_MAPPING[classification]:
        raise DemistoException(
            f"get_determination_value - Invalid determination. "
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
              - status (str) - Specifies the current status of the alert. Possible values are: (Active, Resolved, InProgress or
              Redirected)
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
        mirroring_fields(dict): The required fields to add to an incident to enable mirroring.
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
        if not first_fetch_date_time:
            raise DemistoException(f"Fetch incidents - Could not parse the first_fetch_time: {first_fetch_time=}")
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


def fetch_modified_incident_ids(client: Client, last_update_time: str) -> List[str]:
    """
    Fetches the incident ids that had been created after last_run and filters their ids.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        last_update_time(str): last update time of the mirroring to fetch incidents that were modified after this time.
    Returns: List of incident ids.
    """

    demisto.debug("Microsoft Defender 365 - Starting fetch_modified_incident_ids")
    incidents = []

    # The API is limited to MAX_ENTRIES incidents for each requests, if we are trying to get more than MAX_ENTRIES
    # incident we skip (offset) the number of incidents we already fetched.
    offset = 0

    # This loop fetches all the incidents that had been created after last_run, due to API limitations the fetching
    # occurs in batches. If timeout was given, exceeding the time will result an error.

    while True:
        # HTTP request
        demisto.debug(f"Microsoft Defender 365 - fetch_modified_incident_ids - fetching incidents with offset {offset}")
        response = client.incidents_list(timeout=TIMEOUT_INT, last_update_time=last_update_time,
                                         skip=offset)
        raw_incidents = response.get('value')
        demisto.debug(
            f"Microsoft Defender 365 - fetch_modified_incident_ids - fetched {len(raw_incidents)}")
        for incident in raw_incidents:
            incidents.append(str(incident.get(MICROSOFT_INCIDENT_ID_KEY)))
        # raw_incidents length is less than MAX_ENTRIES than we fetch all the relevant incidents
        if len(raw_incidents) < int(MAX_ENTRIES):
            break
        offset += int(MAX_ENTRIES)
    demisto.debug(f"Microsoft Defender 365 - fetch_modified_incident_ids - returning incident ids {incidents}")
    return incidents


def get_modified_incidents_close_or_repopen_entries(modified_incidents: List[dict], close_incident: bool) -> List[dict]:
    """
    Get the entries for closing or reopening incidents.
    Args:
        modified_incidents (List[dict]): The modified incidents.
        close_incident (bool): Whether resolved incidents from Microsoft should be closed in XSOAR in the mirroring in process.
    Returns:
        List[dict]: The entries for closing or reopening incidents.
    """
    demisto.debug("Microsoft Defender 365 - Starting get_modified_incidents_close_or_repopen_entries")
    entries = []
    if close_incident:
        for incident in modified_incidents:
            if incident.get('status') == 'Resolved':
                demisto.debug(
                    f"Microsoft Defender 365 - incident {incident.get(MICROSOFT_INCIDENT_ID_KEY)} is resolved in Microsoft, "
                    f"adding close entry to XSOAR."
                )
                entry = {
                    'Type': EntryType.NOTE,
                    'Contents': {
                        'dbotIncidentClose': True,
                        'closeReason': MICROSOFT_RESOLVED_CLASSIFICATION_TO_XSOAR_CLOSE_REASON.get(
                            incident.get('classification', 'Unknown'), 'Other'),
                    },
                    'ContentsFormat': EntryFormat.JSON,

                }
            else:
                demisto.debug(
                    f"Microsoft Defender 365 - incident {incident.get(MICROSOFT_INCIDENT_ID_KEY)} "
                    f"is not Resolved in Microsoft, adding reopen entry to XSOAR."
                )
                entry = {
                    'dbotIncidentReopen': True
                }
            entries.append(entry)
    return entries


def get_modified_remote_data_command(client: Client, args: dict) -> GetModifiedRemoteDataResponse:
    """
    Get the modified remote data.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments.

    Returns:
        GetModifiedRemoteDataResponse: The modified remote data.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    parsed_date = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
    if not parsed_date:
        demisto.error(f"Microsoft Defender 365 get_modified_remote_data_command - Could not parse {remote_args.last_update=}")
        return GetModifiedRemoteDataResponse(modified_incident_ids=[])

    last_update = parsed_date.strftime(DATE_FORMAT)
    demisto.debug(f"Microsoft Defender 365 - Last update: {last_update}")
    modified_incident_ids = fetch_modified_incident_ids(client, last_update)
    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_incident_ids)


def fetch_modified_incident(client: Client, incident_id: int) -> dict:
    """
    Fetches the modified incident from Microsoft 365 Defender.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        incident_id(int): The incident ID.
    Returns:
        dict: The modified incident.
    """
    demisto.debug(f"Microsoft Defender 365 - Starting fetch_modified_incident {incident_id=}")
    incident = client.get_incident(incident_id=incident_id, timeout=TIMEOUT_INT)
    demisto.debug(f"Microsoft Defender 365 - Fetched incident {incident_id=}")
    if incident.get('@odata.context'):
        del incident['@odata.context']
    incident.update(_get_meta_data_for_incident(incident))
    demisto.debug(f"Microsoft Defender 365 - Updated incident {incident_id=} with metadata")
    return incident


def get_entries_for_comments(comments: List[dict[str, str]], last_update: datetime, comment_tag: str) -> List[
        dict]:
    """
    Get the entries for the comments of the incident.
    Args:
        comments (List[dict]): The comments of the incident from Microsoft 365 Defender.
        last_update (datetime): The last run time of the mirroring - should bring in comments that were added afterward to
         avoid entries duplicates.
        comment_tag (str): The tag to add for the comments entries when mirroring in.

    Returns:
        List[dict]: The entries for the comments.
    """
    entries = []
    for comment in comments:
        # check if the comment is a mirrored out entry to ms fto avoid duplicates
        if MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR not in comment.get('comment', ''):
            comment_time = dateparser.parse(comment.get('createdTime', ''))
            if not comment_time:
                demisto.error(f"Could not parse {comment.get('createdTime')} for {comment=}")
                continue
            if comment_time > last_update:
                entries.append(entry := {
                    'Type': EntryType.NOTE,
                    'Contents': f"Created By: {comment.get('createdBy', '')}\n"
                                f"Created On: {comment.get('createdTime', '')}\n"
                                f"{comment.get('comment', '')}",
                    'ContentsFormat': EntryFormat.HTML,
                    'Tags': [comment_tag],
                    'Note': True,
                    'EntryContext': {
                        'comments': comment
                    },
                })
    return entries


def get_incident_entries(mirrored_object: dict, last_update: datetime, comment_tag: str, close_incident: bool = False) -> List[
        dict]:
    """
    Creates the entries for the mirrored in incident.
    Args:
        mirrored_object (dict): The incident object from Microsoft 365 Defender.
        last_update (datetime): The last run time of the mirroring - should bring in comments that were added afterward to avoid
         entries duplicates.
        comment_tag (str): The tag to add for the comments entries when mirroring in.
        new_incident (bool): Whether the incident is new a- was just fetched therefore should bring in all the comments.
        close_incident (bool): Whether resolved incidents from Microsoft should be closed in XSOAR in the mirroring in process.

    Returns:
        List[dict]: The entries for the incident.
    """
    entries = get_modified_incidents_close_or_repopen_entries([mirrored_object], close_incident=close_incident)
    entries.extend(get_entries_for_comments(mirrored_object.get('comments', []), last_update, comment_tag))
    return entries


def get_remote_data_command(client: Client, args: dict[str, Any]) -> GetRemoteDataResponse:
    """
    Get the remote incident data from Microsoft 365 Defender to mirror in XSOAR and create the entries for the incident.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments.
    Returns:
        GetRemoteDataResponse: The remote data.

    """
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = arg_to_number(remote_args.remote_incident_id)
    if remote_incident_id is None:
        raise DemistoException("get_remote_data_command - remote_incident_id is None")
    comment_tag = demisto.params().get('comment_tag_from_microsoft365defender', 'CommentFromMicrosoft365Defender')
    last_update = dateparser.parse(remote_args.last_update, settings={'TIMEZONE': 'UTC'})
    if not last_update:
        demisto.error(f"get_remote_data_command - Could not parse {remote_args.last_update=}")
        return GetRemoteDataResponse({MICROSOFT_INCIDENT_ID_KEY: remote_incident_id}, entries=[])
    close_incident = argToBoolean(demisto.params().get('close_incident', False))

    mirrored_object: Dict = {}
    demisto.debug(
        f'Microsoft Defender 365 - Performing get-remote-data command with incident id: {remote_incident_id} and '
        f'last_update: {remote_args.last_update}')
    try:
        mirrored_object = fetch_modified_incident(client, remote_incident_id)
        entries = get_incident_entries(mirrored_object, last_update, comment_tag, close_incident=close_incident)
        return GetRemoteDataResponse(mirrored_object, entries)
    except Exception as e:
        demisto.debug(f"Error in Microsoft incoming mirror for incident: {remote_incident_id}\n"
                      f"Error message: {str(e)} \n {traceback.format_exc()}")

        if not mirrored_object:
            mirrored_object = {MICROSOFT_INCIDENT_ID_KEY: remote_incident_id}
        mirrored_object['in_mirror_error'] = str(e)
        return GetRemoteDataResponse(mirrored_object, entries=[])


def get_mapping_fields_command():
    """
    Get the mapping fields for the incident type.
    Returns:
        GetMappingFieldsResponse: The mapping fields.
    """
    incident_type_scheme = SchemeTypeMapping(type_name='Microsoft 365 Defender Incident')
    demisto.debug("Microsoft Defender 365 - collecting incident mapping for Microsoft 365 Defender Incident type.")
    for name, description in OUTGOING_MIRRORED_FIELDS.items():
        incident_type_scheme.add_field(name=name, description=description)
    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(incident_type_scheme)
    return mapping_response


def handle_incident_close_out_or_reactivation(delta: dict, incident_status: IncidentStatus):
    """
    Handle the incident close out. If the close out is enabled, the incident will be resolved and the classification and
    determination will be updated according to the close reason.

    Args:
        delta (dict): The delta of the incident to update.
        incident_status (IncidentStatus): The incident status in XSOAR.

    """
    demisto.debug("Microsoft Defender 365 - Starting handle_incident_close_out_or_reactivation")
    # Only close or reopen microsoft incidents based on xsoar if close_out is enabled.
    if not argToBoolean(demisto.params().get('close_out', False)):
        demisto.debug("Microsoft Defender 365 - Close out is not enabled")
        return
    demisto.debug("Microsoft Defender 365 - Close out is enabled")
    if incident_status == IncidentStatus.DONE:
        if any(delta.get(key) for key in ['closeReason', 'closeNotes', 'closingUserId']):
            delta['status'] = 'Resolved'
            demisto.debug("Microsoft Defender 365 - Updating incident status to Resolved")
            # this functionality awaits https://jira-dc.paloaltonetworks.com/browse/CRTX-151123?filter=-2
            # once resolved the microsoft365classification field needs to be returned to the close form in order to get
            # the classification and determination fields in delta.
            if delta.get('closeReason') == 'FalsePositive' and delta.get('classification') != 'FalsePositive':
                delta.update({'classification': 'FalsePositive', 'determination': 'Other'})
                demisto.debug("Microsoft Defender 365 - Updating classification and determination to FalsePositive and Other")
            elif delta.get('closeReason') == 'Other' or delta.get('closeReason') == 'Duplicate':
                delta.update({'classification': 'Unknown', 'determination': 'NotAvailable'})
                demisto.debug("Microsoft Defender 365 - Updating classification and determination to Unknown and NotAvailable")
    else:
        if any(delta.get(key) == '' for key in ['closeReason', 'closeNotes', 'closingUserId']):
            delta['status'] = 'Active'
            demisto.debug("Microsoft Defender 365 - Updating incident status to Active")


def mirror_out_entries(client: Client, entries: list[Dict], comment_tag: str, remote_incident_id: int):
    """
    Mirror out the entries to Microsoft 365 Defender.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        entries (list[Dict]): The entries added to the incident.
        comment_tag (str): The comment tag to identify the entries that should be mirrored out as comments.
        remote_incident_id (int): The remote incident ID.


    """
    demisto.debug("Microsoft Defender 365 - Starting mirror_out_entries")
    for entry in entries:
        demisto.debug(f'handling entry {entry.get("id")}, type: {entry.get("type")}, tags: {entry.get("tags", [])}')
        tags = entry.get('tags', [])
        user = entry.get('user', 'dbot') or 'dbot'
        if comment_tag in tags:
            if str(entry.get('format')) == 'html':
                contents = str(entry.get('contents', ''))
                text = (f"({user}): <br/><br/>[code]{contents} <br/><br/>[/code]"
                        f" {MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR}")
            else:
                text = f"({user}): {str(entry.get('contents', ''))}\n\n {MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR}"

            client.update_incident(incident_id=remote_incident_id,
                                   timeout=TIMEOUT_INT,
                                   comment=text)
            demisto.debug(f"Microsoft Defender 365 - mirror out entries updated incident {remote_incident_id=}")

        else:
            demisto.debug(f"Microsoft Defender 365 - Skipping entry {entry.get('id')} as it does not contain the comment tag")


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """
    Update the remote system in Microsoft 365 Defender - Mirror out the entries and update the incident.
    Args:
        client(Client): Microsoft 365 Defender's client to preform the API calls.
        args(Dict): Demisto arguments.
    Returns:
        str: The remote incident ID.
    """
    update_remote_system_args = UpdateRemoteSystemArgs(args)
    remote_incident_id = update_remote_system_args.remote_incident_id
    data = update_remote_system_args.data
    delta = update_remote_system_args.delta

    demisto.debug(
        f"Microsoft Defender 365 -  update_remote_system_command {remote_incident_id=} \n {delta=} \n {data=} \n "
        f"{update_remote_system_args.incident_changed=} \n {update_remote_system_args.inc_status=}"
        f" \n {update_remote_system_args.entries=}")

    try:
        if update_remote_system_args.incident_changed and delta:
            handle_incident_close_out_or_reactivation(delta, update_remote_system_args.inc_status)

            client.update_incident(incident_id=remote_incident_id,
                                   status=delta.get('status'),
                                   assigned_to=delta.get('assignedTo'),
                                   classification=delta.get('classification'),
                                   determination=delta.get('determination'),
                                   tags=argToList(delta.get('tags')),
                                   timeout=TIMEOUT_INT,
                                   comment=delta.get('comment'))

            demisto.debug(f"Microsoft Defender 365 - Updated incident {remote_incident_id=}")
        else:
            demisto.debug(
                f'Microsoft Defender 365 -  Skipping updating remote incident fields [{remote_incident_id}] as it is not new '
                f'nor changed')

        if update_remote_system_args.entries:
            comment_tag = demisto.params().get('comment_tag', COMMENT_TO_MICROSOFT_DEFAULT_TAG)
            demisto.debug(
                "Microsoft Defender 365 - new entries were found in the xsoar incident.")
            mirror_out_entries(client, update_remote_system_args.entries, comment_tag, remote_incident_id)

        return remote_incident_id

    except Exception as e:
        demisto.error(f"Microsoft Defender 365 - Error in outgoing mirror for incident {remote_incident_id} \n"
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

    mirroring_fields = {
        'mirror_direction': MIRROR_DIRECTION.get(params.get('mirror_direction', 'None')),
        'mirror_instance': demisto.integrationInstance(),
        'mirror_tags': [params.get('comment_tag', COMMENT_TO_MICROSOFT_DEFAULT_TAG)],
    }

    demisto.debug(f'Command being called is {demisto.command()}')

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'{params=}, \n {args=}, \n{mirroring_fields}')

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
