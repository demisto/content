import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" ADVANCED GLOBAL PARAMETERS """
EVENTS_INTERVAL_SECS = 15  # interval between events polling
EVENTS_FAILURE_LIMIT = 3  # amount of consecutive failures events fetch will tolerate
FAILURE_SLEEP = 15  # sleep between consecutive failures events fetch
FETCH_SLEEP = 60  # sleep between fetches
BATCH_SIZE = 100  # batch size used for offense ip enrichment
OFF_ENRCH_LIMIT = BATCH_SIZE * 10  # max amount of IPs to enrich per offense
LOCK_WAIT_TIME = 0.5  # time to wait for lock.acquire
MAX_WORKERS = 8  # max concurrent workers used for events enriching
DOMAIN_ENRCH_FLG = "True"  # when set to true, will try to enrich offense and assets with domain names
RULES_ENRCH_FLG = "True"  # when set to true, will try to enrich offense with rule names
MAX_FETCH_EVENT_RETIRES = 3  # max iteration to try search the events of an offense
SLEEP_FETCH_EVENT_RETIRES = 10  # sleep between iteration to try search the events of an offense

''' CONSTANTS '''
MINIMUM_API_VERSION = 10.1
DEFAULT_RANGE_VALUE = '0-49'

USECS_ENTRIES_MAPPING = {'last_persisted_time': 'last_persisted_time_usecs',
                         'start_time': 'start_time_usecs',
                         'close_time': 'close_time_usecs',
                         'create_time': 'create_time_usecs',
                         'last_updated_time': 'last_updated_time_usecs',
                         'first_persisted_time': 'first_persisted_time_usecs'}
''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, server: str, verify: bool, proxy: bool, api_version: str, credentials: Dict):
        username = credentials.get("identifier", "")
        password = credentials.get("password", "")
        super().__init__(base_url=server, verify=verify, proxy=proxy, auth=(username, password))
        self.password = password
        self.server = server
        self.base_headers = {
            'Version': api_version,
        }

    def http_request(self, method: str, url_suffix: str, params: Optional[Dict] = None, data: Optional[Dict] = None,
                     additional_headers: Optional[Dict] = None):
        headers = {**additional_headers, **self.base_headers} if additional_headers else self.base_headers
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            data=data,
            headers=headers,
            error_handler=qradar_error_handler
        )

    def qradar_offenses_list(self, offense_id: Optional[int], range_: str, filter_: Optional[str],
                             fields: Optional[str]):
        id_suffix = f'/{offense_id}' if offense_id else ''
        response = self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses{id_suffix}',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if not offense_id else None
        )
        return [response] if id_suffix else response

    def qradar_offense_update(self, offense_id: Optional[int], protected: Optional[bool], follow_up: Optional[bool],
                              status: Optional[str], closing_reason_id: Optional[int], assigned_to: Optional[str],
                              fields: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix=f'/siem/offenses/{offense_id}',
            params=assign_params(
                protected=protected,
                follow_up=follow_up,
                status=status,
                closing_reason_id=closing_reason_id,
                assigned_to=assigned_to,
                fields=fields
            )
        )

    def qradar_closing_reasons_list(self, closing_reason_id: Optional[int], range_: Optional[str],
                                    filter_: Optional[str], fields: Optional[str]):
        id_suffix = f'/{closing_reason_id}' if closing_reason_id else ''
        response = self.http_request(
            method='GET',
            url_suffix=f'/siem/offense_closing_reasons{id_suffix}',
            additional_headers={'Range': range_} if not closing_reason_id and range_ else None,
            params=assign_params(filter=filter_, fields=fields)
        )
        return [response] if id_suffix else response

    def qradar_offense_notes_list(self, offense_id: Optional[int], note_id: Optional[int], range_: str,
                                  filter_: Optional[str], fields: Optional[str]):
        note_id_suffix = f'/{note_id}' if note_id else ''
        response = self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses/{offense_id}/notes{note_id_suffix}',
            additional_headers={'Range': range_} if not note_id else None,
            params=assign_params(filter=filter_, fields=fields)
        )
        return [response] if note_id_suffix else response

    def qradar_offense_notes_create(self, offense_id: Optional[int], note_text: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix=f'/siem/offenses/{offense_id}/notes',
            params=assign_params(note_text=note_text, fields=fields)
        )

    # figure how to use rule type
    def qradar_rules_list(self, rule_id: Optional[int], range_: Optional[str], filter_: Optional[str],
                          fields: Optional[str]):
        id_suffix = f'/{rule_id}' if rule_id else ''
        response = self.http_request(
            method='GET',
            url_suffix=f'/analytics/rules{id_suffix}',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if range_ else None
        )
        return [response] if id_suffix else response

    def qradar_rule_groups_list(self, rule_group_id: Optional[int], range_: str, filter_: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        response = self.http_request(
            method='GET',
            url_suffix=f'/analytics/rule_groups{id_suffix}',
            additional_headers={'Range': range_} if not rule_group_id else None,
            params=assign_params(filter=filter_)
        )
        return [response] if id_suffix else response

    def qradar_assets_list(self, range_: str, filter_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/asset_model/assets',
            additional_headers={'Range': range_},
            params=assign_params(filter=filter_)
        )

    def qradar_saved_searches_list(self, rule_group_id: Optional[int], range_: str, filter_: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        response = self.http_request(
            method='GET',
            url_suffix=f'/ariel/saved_searches{id_suffix}',
            additional_headers={'Range': range_} if not rule_group_id else None,
            params=assign_params(filter=filter_)
        )
        return [response] if id_suffix else response

    def qradar_searches_list(self, range_: str, filter_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches',
            additional_headers={'Range': range_},
            params=assign_params(filter=filter_)
        )

    def qradar_search_create(self, query_expression: Optional[str], saved_search_id: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/ariel/searches',
            params=assign_params(
                query_expression=query_expression,
                saved_search_id=saved_search_id
            )
        )

    def qradar_search_status_get(self, search_id: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}',
        )

    # def qradar_search_results_get

    def qradar_reference_sets_list(self, ref_name: Optional[str], range_: str, filter_: Optional[str]):
        name_suffix = f'/{ref_name}' if ref_name else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/reference_data/sets{name_suffix}',
            params=assign_params(filter=filter_),
            additional_headers={'Range': range_} if not ref_name else None
        )

    def qradar_reference_set_create(self, ref_name: Optional[str], element_type: Optional[str],
                                    timeout_type: Optional[str], time_to_live: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/reference_data/sets',
            params=assign_params(
                name=ref_name,
                element_type=element_type,
                timeout_type=timeout_type,
                time_to_live=time_to_live
            )
        )

    def qradar_reference_set_delete(self, ref_name: Optional[str]):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}'
        )

    # unsure about the date value def qradar_reference_set_value_upsert(self, ref_name: Optional[str],
    # value: Optional[str], source: Optional[str], date_value: Optional[str]):

    def qradar_reference_set_value_delete(self, ref_name: Optional[str], value: Optional[str]):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}/{value}'
        )

    def qradar_domains_list(self, domain_id: Optional[int], range_: Optional[str], filter_: Optional[str],
                            fields: Optional[str]):
        id_suffix = f'/{domain_id}' if domain_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/config/domain_management/domains{id_suffix}',
            additional_headers={'Range': range_} if not domain_id and range_ else None,
            params=assign_params(filter=filter_, fields=fields)
        )

    # discuss with arseny
    # def qradar_indicators_upload

    def qradar_geolocations_for_ip_get(self, filter_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/services/geolocations',
            params=assign_params(filter=filter_)
        )

    def qradar_log_sources_list(self, range_: str, filter_: Optional[str]):
        additional_headers = {
            'x-qrd-encryption-algorithm': 'AES256',
            'x-qrd-encryption-password': self.password
        }
        if range_:
            additional_headers['Range'] = range_
        return self.http_request(
            method='GET',
            url_suffix='/config/event_sources/log_source_management/log_sources',
            params=assign_params(filter=filter_),
            additional_headers=additional_headers
        )

    def qradar_offense_types(self, filter_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/siem/offense_types',
            params=assign_params(filter=filter_)
        )

    def qradar_source_addresses(self, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/siem/source_addresses',
            params=assign_params(filter=filter_)
        )


''' HELPER FUNCTIONS '''


def qradar_error_handler(res: Any):
    """

    Args:
        res:

    Returns:

    """
    err_msg = 'Error in API call [{}] - {}' \
        .format(res.status_code, res.reason)
    try:
        # Try to parse json error response
        error_entry = res.json()
        message = error_entry.get('message', '')
        err_message = f'Error in API call [{res.status_code}] - {message}'
        raise DemistoException(err_message, res=err_message)
    except ValueError:
        err_msg += '\n{}'.format(res.text)
        raise DemistoException(err_msg, res=res)


def add_iso_entries_to_dict(outputs: List[Dict]) -> None:
    """
    Takes list of outputs, for each output:
    For each field in the output that is contained in 'USECS_ENTRIES_MAPPING' keys,
    adds a new entry of the corresponding value to the key in 'USECS_ENTRIES_MAPPING',
    Value of the new entry will be the iso format corresponding to the timestamp from the 'USECS_ENTRIES_MAPPING' key.
    Args:
        outputs (List[Dict]): List of the outputs to be transformed.

    Returns:
        Modifies the outputs.
    """
    for output in outputs:
        for date_entry, date_entry_usecs in USECS_ENTRIES_MAPPING.items():
            if date_entry in output:
                output[date_entry_usecs] = output[date_entry]
                output[date_entry] = convert_epoch_time_to_datetime(output[date_entry])


def sanitize_outputs(outputs: Any) -> List[Dict]:
    """
    Gets a list of all the outputs, and sanitizes outputs.
    - Removes empty elements.
    - adds ISO entries to the outputs.
    Args:
        outputs (List[Dict]): List of the outputs to be sanitized.

    Returns:
        Sanitized outputs.
    """
    # outputs = [remove_empty_elements(output) for output in outputs]
    add_iso_entries_to_dict(outputs)
    return outputs


def convert_epoch_time_to_datetime(epoch_time: Optional[int]) -> Optional[str]:
    """
    Receives epoch time, and returns epoch_time representation as date with UTC timezone.
    If received epoch time is 0, or epoch_time does not exist, returns None.
    Args:
        epoch_time (int): The epoch_time to convert.
    Returns:
        - The date time with UTC timezone that matches the epoch time if 'epoch_time' is not 0.
        - None if 'epoch_time' is 0.
        - None if epoch_time is None.
    """
    if not epoch_time or epoch_time == 0:
        return None
    maybe_date_time = arg_to_datetime(epoch_time / 1000.0)
    if not maybe_date_time:
        return None
    return maybe_date_time.isoformat()


def replace_keys(output: Dict, old_new_dict: Dict) -> Dict:
    """
    Receives output, and a dict containing mapping of old key names to new key names.
    Returns dict of output values, overriding the old name contained in old_new_dict with its value.
    Args:
        output (Dict): Output to replace its keys.
        old_new_dict (Dict): Old key name mapped to new key name.

    Returns:
        (Dict) The dictionary with the transformed keys.
    """
    return {old_new_dict.get(k, k): v for k, v in output.items()}


def get_offense_types(client: Client, offenses: List[Dict]) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the offense type names
    matching the offense type IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {offense_type_id: offense_type_name}
    """
    offense_types_ids = {offense.get('offense_type') for offense in offenses if offense.get('offense_type')}
    if not offense_types_ids:
        return dict()
    offense_types = client.qradar_offense_types(f'''id in ({','.join(offense_types_ids)})''')
    return {offense_type.get('id'): offense_type.get('name') for offense_type in offense_types}


def get_offense_closing_reasons(client: Client, offenses: List[Dict]) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the closing reason names
    matching the closing reason IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {closing_reason_id: closing_reason_name}
    """
    closing_reason_ids = {offense.get('closing_reason_id') for offense in offenses if offense.get('closing_reason_id')}
    if not closing_reason_ids:
        return dict()
    closing_reasons = client.qradar_closing_reasons_list(None, None, f'''id in ({','.join(closing_reason_ids)})''',
                                                         None)
    return {closing_reason.get('id'): closing_reason.get('text') for closing_reason in closing_reasons}


def get_domain_names(client: Client, offenses: List[Dict]) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the domain names
    matching the domain IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {domain_id: domain_name}
    """
    domain_ids = {offense.get('domain_id') for offense in offenses if offense.get('domain_id')}
    if not domain_ids:
        return dict()
    domains_info = client.qradar_domains_list(None, None, f'''id in ({','.join(domain_ids)})''', fields='id,name')
    return {domain_info.get('id'): domain_info.get('name') for domain_info in domains_info}


def get_rules_names(client: Client, offenses: List[Dict]) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the rules names
    matching the rule IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {rule_id: rule_name}
    """
    rules_ids = {rule.get('id') for offense in offenses for rule in offense.get('rules', [])}
    if not rules_ids:
        return dict()
    rules = client.qradar_rules_list(None, None, f'''id in ({','.join(rules_ids)})''', fields='id,name')
    return {rule.get('id'): rule.get('name') for rule in rules}


def enrich_offenses_result(client: Client, offenses: List[Dict]) -> List[Dict]:
    """
    Receives list of offenses, and enriches the offenses with the following:
    - Changes offense_type value from the offense type ID to the offense type name.
    - Changes closing_reason_id value from closing reason ID to the closing reason name.
    - Adds a link to the URL of each offense.
    - Adds the domain name of the domain ID for each offense.
    - Adds to each rule of the offense its name.
    Args:
        client (Client): Client to perform the API calls.
        offenses (List[Dict]): List of all of the offenses to enrich.

    Returns:
        (List[Dict]): The enriched offenses.
    """
    offense_types_id_name_dict = get_offense_types(client, offenses)
    closing_reasons_id_name_dict = get_offense_closing_reasons(client, offenses)
    domain_id_name_dict = get_domain_names(client, offenses)
    rules_id_name_dict = get_rules_names(client, offenses)

    def create_enriched_offense(offense: Dict) -> Dict:
        enriches = {
            'offense_type': offense_types_id_name_dict.get(offense.get('offense_type')),
            'closing_reason_id': closing_reasons_id_name_dict.get(offense.get('closing_reason_id')),
            'LinkToOffense': f'{client.server}/console/do/sem/offensesummary?'
                             f'''appName=Sem&pageId=OffenseSummary&summaryId={offense.get('id')}''',
            'domain_name': domain_id_name_dict.get(offense.get('domain_id')),
            'rules': [
                {
                    'id': rule.get('id'),
                    'type': rule.get('type'),
                    'name': rules_id_name_dict.get(rule.get('id'))

                } for rule in offense.get('rules')
            ]
        }
        return dict(offense, **enriches)

    return [create_enriched_offense(offense) for offense in offenses]


def enrich_offense_source_addresses(client: Client, offense: Dict) -> Set[str]:
    """

    Args:
        client:
        offense:
    Returns:

    """

    def get_source_addresses_for_batch(b):
        response = client.qradar_source_addresses(filter_=f'''id in ({','.join(b)})''', fields='source_ip')
        return {output.get('source_ip') for output in response if output.get('source_ip')}

    source_addresses_ids = offense.get('source_address_ids', [])
    # Submit addresses in batches to avoid time out from QRadar service
    source_addresses_batches = [get_source_addresses_for_batch(b) for b
                                in batch(source_addresses_ids[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE))]
    return {source_address for addresses_batch in source_addresses_batches for source_address in addresses_batch}


# def enrich_offense_with_destination_address(client: Client, offense: Dict) -> List[str]:


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """
    Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Client to perform the API calls.

    Returns:
        - 'ok' if test passed
        - DemistoException if something had failed the test.
    """
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def qradar_offenses_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of offenses from QRadar service.
    possible arguments:
    - offense_id: Retrieves details of the specific offense that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    offense_id = args.get('offense_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.qradar_offenses_list(offense_id, range_, filter_, fields)
    outputs = sanitize_outputs(response)
    enriched_outputs = enrich_offenses_result(client, outputs)

    return CommandResults(
        readable_output=tableToMarkdown('offenses List', enriched_outputs),
        outputs_prefix='QRadar.offense',
        outputs_key_field='id',
        outputs=enriched_outputs,
        raw_response=response
    )


def qradar_offense_update_command(client: Client, args: Dict) -> CommandResults:
    """
    Updates offense that corresponds to the given offense ID.
    possible arguments:
    - offense_id (Required): Update offense that corresponds to ID given.
    - protected: Whether the offense is protected.
    - follow_up: Whether the offense should be marked for follow up.
    - status: Status of the offense. One of 'OPEN', 'HIDDEN', 'CLOSED'.
    - closing_reason_id: The ID of the reason the offense was closed. full list of closing reason IDs,
                         full list of closing reason IDs can be retrieved by 'qradar-closing-reasons' command.
    - assigned_to: The user whom to assign the offense to.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    offense_id = args.get('offense_id')
    protected = args.get('protected')
    follow_up = args.get('follow_up')

    status = args.get('status')
    closing_reason_id = args.get('closing_reason_id')
    if status == 'CLOSED' and not closing_reason_id:
        raise DemistoException(
            '''Closing reason ID must be provided when closing an offense. Available closing reasons can be achieved 
            by 'qradar-closing-reasons' command.'''
        )

    assigned_to = args.get('assigned_to')
    fields = args.get('fields')

    response = client.qradar_offense_update(offense_id, protected, follow_up, status, closing_reason_id, assigned_to,
                                            fields)
    outputs = sanitize_outputs(response)
    enriched_outputs = enrich_offenses_result(client, outputs)

    return CommandResults(
        readable_output=tableToMarkdown('offense Update', enriched_outputs),
        outputs_prefix='QRadar.offense',
        outputs_key_field='id',
        outputs=enriched_outputs,
        raw_response=response
    )


def qradar_closing_reasons_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of closing reasons from QRadar service.
    possible arguments:
    - closing_reason_id: Retrieves details of the specific closing reason that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    closing_reason_id = args.get('closing_reason_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.qradar_closing_reasons_list(closing_reason_id, range_, filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown('Closing Reasons List', outputs),
        outputs_prefix='QRadar.ClosingReason',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_offense_notes_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of notes corresponding to the ID of the offense ID given from QRadar service.
    possible arguments:
    - offense_id: The offense ID to retrieve the notes for.
    - note_id: The note ID to its details.
    - range: Range of notes to return for the offense corresponding to the offense ID (e.g.: 0-20, 3-5, 3-3).
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    offense_id = args.get('offense_id')
    note_id = args.get('note_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.qradar_offense_notes_list(offense_id, note_id, range_, filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown(f'offense Notes List For Offense ID {offense_id}', outputs),
        outputs_prefix='QRadar.offenseNote',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_offense_notes_create_command(client: Client, args: Dict) -> CommandResults:
    """
    Create a new note for the offense corresponding to the given offense ID with the note text given
    to QRadar service.
    possible arguments:
    - offense_id: The offense ID to add note to.
    - note_text: The note text.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    offense_id = args.get('offense_id')
    note_text = args.get('note_text')
    fields = args.get('fields')

    response = client.qradar_offense_notes_create(offense_id, note_text, fields)
    outputs = sanitize_outputs([response])
    print(json.dumps(outputs))

    return CommandResults(
        readable_output=tableToMarkdown('Create Note', outputs),
        outputs_prefix='QRadar.offenseNote',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_rules_list_command(client: Client, args: Dict) -> CommandResults:
    """

    Args:
        client:
        args:

    Returns:

    """
    rule_id = args.get('rule_id')
    rule_type = args.get('rule_type')
    filter_ = args.get('filter')
    range_ = args.get('range')
    if not filter_ and rule_type:
        filter_ = f'type={rule_type}'

    response = client.qradar_rules_list(rule_id, range_, filter_)
    raise NotImplementedError


def qradar_rule_groups_list_command(client: Client, args: Dict):
    rule_group_id = args.get('rule_group_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_rule_groups_list(rule_group_id, range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.RuleGroup',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_assets_list_command(client: Client, args: Dict):
    asset_id = args.get('asset_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    # If asset ID was given, override filter if both were given
    if asset_id:
        filter_ = f'id={asset_id}'

    response = client.qradar_assets_list(range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Asset',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_saved_searches_list_command(client: Client, args: Dict):
    rule_group_id = args.get('rule_group_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_saved_searches_list(rule_group_id, range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.SavedSearch',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_searches_list_command(client: Client, args: Dict):
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_searches_list(range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Search',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_search_create_command(client: Client, args: Dict):
    query_expression = args.get('query_expression')
    saved_search_id = args.get('saved_search_id')

    response = client.qradar_search_create(query_expression, saved_search_id)
    # QRadar.Search

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Search',
        outputs_key_field='search_id',
        # outputs=response,
        raw_response=response
    )


# def qradar_search_status_get_command
# def qradar_search_results_get_command

# waiting on value explanation
# def qradar_reference_sets_list_command

def qradar_reference_set_create_command(client: Client, args: Dict, ref_name: Optional[str],
                                        element_type: Optional[str],
                                        timeout_type: Optional[str], time_to_live: Optional[str]):
    ref_name = args.get('ref_name')
    element_type = args.get('element_type')
    timeout_type = args.get('timeout_type')
    time_to_live = args.get('time_to_live')

    response = client.qradar_reference_set_create(ref_name, element_type, timeout_type, time_to_live)
    # QRadar.ReferenceSet

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.ReferenceSet',
        outputs_key_field='name',
        # outputs=response,
        raw_response=response
    )


def qradar_reference_set_delete_command(client: Client, args: Dict):
    ref_name = args.get('ref_name')

    response = client.qradar_reference_set_delete(ref_name)
    # maybe add output for the task to be monitored
    raise NotImplementedError


# unsure about the date value def qradar_reference_set_value_upsert_command(self, ref_name: Optional[str],
# value: Optional[str], source: Optional[str], date_value: Optional[str]):

def qradar_reference_set_value_delete_command(client: Client, args: Dict):
    ref_name = args.get('ref_name')
    value = args.get('value')

    response = client.qradar_reference_set_value_delete(ref_name, value)
    human_readable = f'### value: {value} of reference: {ref_name} was deleted successfully'
    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def qradar_domains_list_command(client: Client, args: Dict):
    domain_id = args.get('domain_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_domains_list(domain_id, range_, filter_)
    # QRadar.Domain

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Domain',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


# discuss with arseny
# def qradar_indicators_upload_command

def qradar_geolocations_for_ip_get_command(client: Client, args: Dict):
    ips = argToList(args.get('ips'))
    if not ips:
        raise DemistoException('''IPs list cannot be empty for command 'qradar-geolocations-for-ip-get'.''')
    filter_ = f'''ip_address IN ({','.join(ips)})'''

    response = client.qradar_geolocations_for_ip_get(filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.GeoForIP',
        outputs_key_field='ip_address',
        # outputs=response,
        raw_response=response
    )


def qradar_log_sources_list_command(client: Client, args: Dict):
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_log_sources_list(range_, filter_)
    raise NotImplementedError


''' MAIN FUNCTION '''
"""
for removed versions
"Version (3.0) from header parameter (Version) has been removed and is no longer valid. Please refer to documentation 
for list of valid versions."
for unvalid versions
"Version (322.0123) from header parameter (Version) is not a valid version. Please refer to documentation for list
of valid versions."

Range argument
pattern: items=x-y
invalid range (items = 3-0)
"message": "Range of pages specified in \"Range\" header is negative. Non-negative page range must be specified."
"message": "Failed to parse Range header. The syntax of the Range header must follow this pattern: items=x-y"
 (items=-3-2)
 {
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 36,
    "description": "",
    "details": {},
    "message": "Failed to parse Range header. The syntax of the Range header must follow this pattern: items=x-y"
}
 
get offense by id
returns a dict (not a list) containing the offense details


update offense

closing offense without closing_reason_id
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid.",
    "details": {},
    "message": "closing_reason_id must be provided when closing an offense."
}

unknown status
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"status\" with a content type of \"TEXT_PLAIN\""
}



qradar-closing-reasons-list + by id
id - returns a dict, list - returns list of dicts

notes + notes id

not found note id

create note

empty note_text
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"note_text\" from query parameters"
}
example result
{
    "note_text": "asd",
    "create_time": 1612962518474,
    "id": 2,
    "username": "API_user: demisto"
}


rules + rule by id
list returns list of dicts, id returns dict

rules group list + by id
list returns list of dicts, id returns dict

saved searches list + id

searches list + id

create search
exactly one argument should be provided
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid.",
    "details": {},
    "message": "Exactly one parameter is required."
}

search results get not found search id

qradar reference set by name

create reference set
empty
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"name\" from query parameters"
}
name only
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"element_type\" from query parameters"
}
unknown element type
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"element_type\" with a content type of \"TEXT_PLAIN\""
}

unknown timeout type
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"timeout_type\" with a content type of \"TEXT_PLAIN\""
}

delete reference set
return on success
{
    "created_by": "demisto",
    "created": 1612971240237,
    "name": "Reference Data Deletion Task",
    "modified": 1612971240927,
    "started": null,
    "completed": null,
    "id": 71,
    "message": "Searching for items that depend on the Reference Data.",
    "status": "QUEUED"
}
Response Description
A status ID to retrieve the reference data set's deletion or purge status with at 
/api/system/task_management/tasks/{status_id}. You can also find the url in the Location header

add or update reference set
empty
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"value\" from query parameters"
}

upsert

value is in
    "data": [
        {
            "last_seen": 1612971683681,
            "first_seen": 1612971630849,
            "source": "reference data api",
            "value": "1.2.3.4",
            "domain_id": null
        }
    ],

unknown namepsace
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"namespace\" with a content type of \"TEXT_PLAIN\""
}
giving tenant
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1012,
    "description": "The namespace value of SHARED was expected",
    "details": {},
    "message": "Admin user can only access shared namespace"
}

config management domains

delete reference value

upload indicators
data not included
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 10,
    "description": "",
    "details": {},
    "message": "Request body must be populated for body parameter \"data\""
}
{
    "http_response": {
        "code": 500,
        "message": "Unexpected internal server error"
    },
    "code": 1020,
    "description": "An error occurred during the attempt to add or update data in the reference map.",
    "details": {},
    "message": "Adding/updating data to Map test_aas failed"
}

geolocation
syntax
ip_address = "127.0.0.1"
ip_address IN ( "127.0.0.1", "127.0.0.2" )

log sources list
too strong
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1003,
    "description": "The specified encryption strength is not available. Consider installing \"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy\" or using a weaker encryption.",
    "details": {},
    "message": "The specified encryption strength is not available. Consider installing \"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy\" or using a weaker encryption."
}
"""


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    server = urljoin(params.get('server'), '/api')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_version = params.get('api_version')
    if float(api_version) < MINIMUM_API_VERSION:
        raise DemistoException('Minimum API version is {MINIMUM_API_VERSION}')
    credentials = params.get('credentials')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            server=server,
            verify=verify_certificate,
            proxy=proxy,
            api_version=api_version,
            credentials=credentials)

        if command == 'test-module':
            result = test_module_command(client)
            return_results(result)

        elif command == 'fetch-incidents':
            raise NotImplementedError

        elif command == 'qradar-offenses-list':
            return_results(qradar_offenses_list_command(client, args))

        elif command == 'qradar-offense-update':
            return_results(qradar_offense_update_command(client, args))

        elif command == 'qradar-closing-reasons':
            return_results(qradar_closing_reasons_list_command(client, args))

        elif command == 'qradar-offense-notes-list':
            return_results(qradar_offense_notes_list_command(client, args))

        elif command == 'qradar-offense-note-create':
            return_results(qradar_offense_notes_create_command(client, args))

        elif command == 'qradar-rules-list':
            return_results(qradar_rules_list_command(client, args))
        # QRadar.Rule

        elif command == 'qradar-rule-groups-list':
            return_results(qradar_rule_groups_list_command(client, args))

        elif command == 'qradar-assets-list':
            return_results(qradar_assets_list_command(client, args))
        # QRadar.Asset

        elif command == 'qradar-saved-searches-list':
            return_results(qradar_saved_searches_list_command(client, args))

        # elif command == 'qradar-searches-list':
        #     return_results(qradar_searches_list_command(client, args))
        # QRadar.Search

        elif command == 'qradar-search-create':
            return_results(qradar_search_create_command(client, args))

        # might be united with searches list
        # elif command == 'qradar-search-status-get':
        #     return_results(qradar_search_status_get(client, args))
        # QRadar.SearchStatus

        # elif command == 'qradar-search-results-get':
        #     return_results(qradar_search_results_get_command(client, args))
        # QRadar.SearchResult

        # elif command == 'qradar-reference-sets-list':
        #     return_results(qradar_reference_sets_list_command(client, args))
        # QRadar.ReferenceSet

        elif command == 'qradar-reference-set-create':
            return_results(qradar_reference_set_create_command(client, args))

        elif command == 'qradar-reference-set-delete':
            return_results(qradar_reference_set_delete_command(client, args))

        # elif command == 'qradar-reference-set-value-upsert':
        #     return_results(qradar_reference_set_value_upsert(client, args))
        # QRadar.ReferenceSetValue

        elif command == 'qradar-reference-set-value-delete':
            return_results(qradar_reference_set_value_delete_command(client, args))

        elif command == 'qradar-domains-list':
            return_results(qradar_domains_list_command(client, args))

        # elif command == 'qradar-indicators-upload':
        #     return_results(qradar_indicators_upload_command(client, args))
        # QRadar.Indicator

        elif command == 'qradar-geolocations-for-ip-get':
            return_results(qradar_geolocations_for_ip_get_command(client, args))

        elif command == 'qradar-log-sources-list':
            return_results(qradar_log_sources_list_command(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
