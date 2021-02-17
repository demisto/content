import pytz
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
UTC_TIMEZONE = pytz.timezone('utc')

''' OUTPUT FIELDS REPLACEMENT MAPS '''
OFFENSE_OLD_NEW_NAMES_MAP = {
    "credibility": "Credibility",
    "relevance": "Relevance",
    "severity": "Severity",
    "assigned_to": "AssignedTo",
    "destination_networks": "DestinationHostname",
    "status": "Status",
    "closing_user": "ClosingUser",
    "closing_reason_id": "ClosingReason",
    "close_time": "CloseTime",
    "categories": "Categories",
    "follow_up": "Followup",
    "id": "ID",
    "description": "Description",
    "source_address_ids": "SourceAddress",
    "local_destination_address_ids": "DestinationAddress",
    "remote_destination_count": "RemoteDestinationCount",
    "start_time": "StartTime",
    "event_count": "EventCount",
    "flow_count": "FlowCount",
    "offense_source": "OffenseSource",
    "magnitude": "Magnitude",
    "last_updated_time": "LastUpdatedTime",
    "offense_type": "OffenseType",
    "protected": "Protected",
}

CLOSING_REASONS_OLD_NEW_MAP = {
    "id": "ID",
    "text": "Name",
    "is_reserved": "IsReserved",
    "is_deleted": "IsDeleted",
}

NOTES_OLD_NEW_MAP = {
    "id": "ID",
    "note_text": "Text",
    "create_time": "CreateTime",
    "username": "CreatedBy",
}

RULES_OLD_NEW_MAP = {
    "owner": "Owner",
    "identifier": "Identifier",
    "base_host_id": "BaseHostID",
    "capacity_timestamp": "CapacityTimestamp",
    "origin": "Origin",
    "creation_date": "CreationDate",
    "type": "Type",
    "enabled": "Enabled",
    "modification_date": "ModificationDate",
    "linked_rule_identifier": "LinkedRuleIdentifier",
    "name": "Name",
    "average_capacity": "AverageCapacity",
    "id": "ID",
    "base_capacity": "BaseCapacity"
}

RULES_GROUP_OLD_NEW_MAP = {
    'TODO': 'TODO'
}

SEARCH_OLD_NEW_MAP = {"search_id": "ID", "status": "Status"}

REFERENCE_SETS_OLD_NEW_MAP = {
    "number_of_elements": "NumberOfElements",
    "name": "Name",
    "creation_time": "CreationTime",
    "element_type": "ElementType",
    "time_to_live": "TimeToLive",
    "timeout_type": "TimeoutType",
    "data": "Data",
    "last_seen": "LastSeen",
    "source": "Source",
    "value": "Value",
    "first_seen": "FirstSeen",
}

DOMAIN_OLD_NEW_MAP = {
    "asset_scanner_ids": "AssetScannerIDs",
    "custom_properties": "CustomProperties",
    "deleted": "Deleted",
    "description": "Description",
    "event_collector_ids": "EventCollectorIDs",
    "flow_collector_ids": "FlowCollectorIDs",
    "flow_source_ids": "FlowSourceIDs",
    "id": "ID",
    "log_source_ids": "LogSourceIDs",
    "log_source_group_ids": "LogSourceGroupIDs",
    "name": "Name",
    "qvm_scanner_ids": "QVMScannerIDs",
    "tenant_id": "TenantID",
}

USECS_ENTRIES = {'last_persisted_time',
                 'start_time',
                 'close_time',
                 'create_time',
                 'creation_time',
                 'creation_date',
                 'last_updated_time',
                 'first_persisted_time',
                 'modification_date',
                 'last_seen',
                 'first_seen'}

''' ENRICHMENT MAPS '''
ASSET_PROPERTIES_NAME_MAP = {
    "Unified Name": "Name",
    "CVSS Collateral Damage Potential": "AggregatedCVSSScore",
    "Weight": "Weight",
}

FULL_ASSET_PROPERTIES_NAMES_MAP = {
    "Compliance Notes": "ComplianceNotes",
    "Compliance Plan": "CompliancePlan",
    "CVSS Collateral Damage Potential": "CollateralDamagePotential",
    "Location": "Location",
    "Switch ID": "SwitchID",
    "Switch Port ID": "SwitchPort",
    "Group Name": "GroupName",
    "Vulnerabilities": "Vulnerabilities",
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, server: str, verify: bool, proxy: bool, api_version: str, credentials: Dict):
        username = credentials.get('identifier')
        password = credentials.get('password')
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

    def offenses_list(self, offense_id: Optional[int], range_: str, filter_: Optional[str],
                      fields: Optional[str]):
        id_suffix = f'/{offense_id}' if offense_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses{id_suffix}',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if not offense_id else None
        )

    def offense_update(self, offense_id: Optional[int], protected: Optional[bool], follow_up: Optional[bool],
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

    def closing_reasons_list(self, closing_reason_id: Optional[int], range_: Optional[str], filter_: Optional[str],
                             fields: Optional[str]):
        id_suffix = f'/{closing_reason_id}' if closing_reason_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offense_closing_reasons{id_suffix}',
            additional_headers={'Range': range_} if not closing_reason_id and range_ else None,
            params=assign_params(filter=filter_, fields=fields)
        )

    def offense_notes_list(self, offense_id: Optional[int], note_id: Optional[int], range_: str,
                           filter_: Optional[str], fields: Optional[str]):
        note_id_suffix = f'/{note_id}' if note_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses/{offense_id}/notes{note_id_suffix}',
            additional_headers={'Range': range_} if not note_id else None,
            params=assign_params(filter=filter_, fields=fields)
        )

    def offense_notes_create(self, offense_id: Optional[int], note_text: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix=f'/siem/offenses/{offense_id}/notes',
            params=assign_params(note_text=note_text, fields=fields)
        )

    def rules_list(self, rule_id: Optional[int], range_: Optional[str], filter_: Optional[str], fields: Optional[str]):
        id_suffix = f'/{rule_id}' if rule_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/analytics/rules{id_suffix}',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if range_ else None
        )

    def rule_groups_list(self, rule_group_id: Optional[int], range_: str, filter_: Optional[str],
                         fields: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/analytics/rule_groups{id_suffix}',
            additional_headers={'Range': range_} if not rule_group_id else None,
            params=assign_params(filter=filter_, fields=fields)
        )

    def assets_list(self, range_: str, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/asset_model/assets',
            additional_headers={'Range': range_},
            params=assign_params(filter=filter_, fields=fields)
        )

    def saved_searches_list(self, saved_search_id: Optional[str], range_: str, filter_: Optional[str],
                            fields: Optional[str]):
        id_suffix = f'/{saved_search_id}' if saved_search_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/saved_searches{id_suffix}',
            additional_headers={'Range': range_} if not saved_search_id else None,
            params=assign_params(filter=filter_, fields=fields)
        )

    def searches_list(self, range_: str, filter_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/ariel/searches',
            additional_headers={'Range': range_},
            params=assign_params(filter=filter_)
        )

    def search_create(self, query_expression: Optional[str], saved_search_id: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/ariel/searches',
            params=assign_params(
                query_expression=query_expression,
                saved_search_id=saved_search_id
            )
        )

    def search_status_get(self, search_id: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}',
        )

    def search_results_get(self, search_id: Optional[str], range_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}/results',
            additional_headers={'Range': range_}
        )

    def reference_sets_list(self, ref_name: Optional[str], range_: str, filter_: Optional[str], fields: Optional[str]):
        name_suffix = f'/{ref_name}' if ref_name else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/reference_data/sets{name_suffix}',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if not ref_name else None
        )

    def reference_set_create(self, ref_name: Optional[str], element_type: Optional[str], timeout_type: Optional[str],
                             time_to_live: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/reference_data/sets',
            params=assign_params(
                name=ref_name,
                element_type=element_type,
                timeout_type=timeout_type,
                time_to_live=time_to_live,
                fields=fields
            )
        )

    def reference_set_delete(self, ref_name: Optional[str]):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}'
        )

    def reference_set_value_upsert(self, ref_name: Optional[str], value: Optional[str], source: Optional[str],
                                   fields: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix=f'/reference_data/sets/{ref_name}',
            params=assign_params(value=value, source=source, fields=fields)
        )

    def reference_set_value_delete(self, ref_name: Optional[str], value: Optional[str]):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}/{value}'
        )

    def domains_list(self, domain_id: Optional[int], range_: Optional[str], filter_: Optional[str],
                     fields: Optional[str]):
        id_suffix = f'/{domain_id}' if domain_id else ''
        return self.http_request(
            method='GET',
            url_suffix=f'/config/domain_management/domains{id_suffix}',
            additional_headers={'Range': range_} if not domain_id and range_ else None,
            params=assign_params(filter=filter_, fields=fields)
        )

    # discuss with arseny
    # def indicators_upload

    def geolocations_for_ip(self, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/services/geolocations',
            params=assign_params(filter=filter_, fields=fields)
        )

    def log_sources_list(self, qrd_encryption_algorithm: Optional[str], qrd_encryption_password: Optional[str],
                         range_: str, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/config/event_sources/log_source_management/log_sources',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={
                'x-qrd-encryption-algorithm': qrd_encryption_algorithm,
                'x-qrd-encryption-password': qrd_encryption_password,
                'Range': range_
            }
        )

    def offense_types(self, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/siem/offense_types',
            params=assign_params(filter=filter_, fields=fields)
        )

    def get_addresses(self, address_suffix: str, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/{address_suffix}',
            params=assign_params(filter=filter_, fields=fields)
        )

    def source_addresses(self, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/siem/source_addresses',
            params=assign_params(filter=filter_, fields=fields)
        )

    def destination_addresses(self, filter_: Optional[str], fields: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/siem/local_destination_addresses',
            params=assign_params(filter=filter_, fields=fields)
        )


''' HELPER FUNCTIONS '''


def qradar_error_handler(res: Any):
    """
    QRadar error handler for any error occurred during the API request.
    This function job is to translate the known exceptions returned by QRadar
    to human readable exception to help the user understand why the request have failed.
    If error returned is not in the expected error format, raises the exception as is.
    Args:
        res (Any): The error response returned by QRadar.

    Returns:
        - raises DemistoException.
    """
    err_msg = f'Error in API call [{res.status_code}] - {res.reason}'
    try:
        # Try to parse json error response
        error_entry = res.json()
        message = error_entry.get('message', '')
        err_msg += f'\n{message}'
        raise DemistoException(err_msg, res=res)
    except ValueError:
        err_msg += '\n{}'.format(res.text)
        raise DemistoException(err_msg, res=res)


def add_iso_entries_to_dict(dicts: List[Dict]) -> List[Dict]:
    """
    Takes list of dicts, for each dict:
    creates a new dict, and for each field in the output that
    is contained in 'USECS_ENTRIES', maps its value to be iso format corresponding to the value of the field.
    Args:
        dicts (List[Dict]): List of the dicts to be transformed.

    Returns:
        New dicts with iso entries for the corresponding items in 'USECS_ENTRIES'
    """
    return [{k: (get_time_parameter(v, iso_format=True) if k in USECS_ENTRIES else v)
             for k, v in dict_.items()} for dict_ in dicts]


def sanitize_outputs(outputs: Any, key_replace_dict: Optional[Dict] = None) -> List[Dict]:
    """
    Gets a list of all the outputs, and sanitizes outputs.
    - Removes empty elements.
    - adds ISO entries to the outputs.
    - Replaces keys by the given 'key_replace_dict' values.
    Args:
        outputs (List[Dict]): List of the outputs to be sanitized.
        key_replace_dict (Dict): Dict of the keys to transform their names

    Returns:
        Sanitized outputs.
    """
    if not isinstance(outputs, list):
        outputs = [outputs]
    outputs = [remove_empty_elements(output) for output in outputs]
    add_iso_entries_to_dict(outputs)
    return replace_keys(outputs, key_replace_dict) if key_replace_dict else outputs


def get_time_parameter(arg: Optional[str], iso_format: bool = False, epoch_format: bool = False):
    """
    parses arg into date time object with aware time zone if 'arg' exists.
    If no time zone is given, sets timezone to UTC.
    Returns the date time object created/ISO format/epoch format.
    Args:
        arg (str): The argument to turn into aware date time.
        iso_format (bool): Whether to return date or the parsed format of the date.
        epoch_format (bool): Whether to return date or the epoch format of the date.

    Returns:
        - (None) If 'arg' is None, returns None.
        - (datetime): If 'arg' is exists and 'iso_format' and 'epoch_format' are false, returns date time.
        - (str): If 'arg' is exists and parse_format is true, returns ISO format of the date time object.
        - (int): If 'arg' is exists and epoch_format is true, returns epoch format of the date time object.
    """
    maybe_unaware_date = arg_to_datetime(arg, is_utc=True)
    if not maybe_unaware_date:
        return None

    aware_time_date = maybe_unaware_date if maybe_unaware_date.tzinfo else UTC_TIMEZONE.localize(
        maybe_unaware_date)

    if iso_format:
        return aware_time_date.isoformat()
    if epoch_format:
        return int(aware_time_date.timestamp() * 1000)
    return aware_time_date


def replace_keys(outputs: Union[List[Dict], Dict], old_new_dict: Dict) -> List[Dict]:
    """
    Receives outputs, or a single output, and a dict containing mapping of old key names to new key names.
    Returns a list of outputs, overriding the old name contained in old_new_dict with its value.
    Args:
        outputs (Dict): Outputs to replace its keys.
        old_new_dict (Dict): Old key name mapped to new key name.

    Returns:
        (Dict) The dictionary with the transformed keys.
    """
    if isinstance(outputs, Dict):
        outputs = [outputs]
    return [{old_new_dict.get(k, k): v for k, v in output.items()} for output in outputs]


def build_headers(first_headers: List[str], all_headers: Set[str]) -> List[str]:
    """
    Receives headers to be shown first in entry room, and concat all the headers after first headers.
    Args:
        first_headers (Set[str]): First headers to be shown in the entry room.
        all_headers (Set[str]): List of all of the headers.

    Returns:
        (List[str]): List of all of the headers, where first_headers are first in the list.
    """
    return first_headers + list(set.difference(all_headers, first_headers))


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
    offense_types = client.offense_types(f'''id in ({','.join(map(str, offense_types_ids))})''',
                                         fields='id,name')
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
    closing_reasons = client.closing_reasons_list(None, None,
                                                  f'''id in ({','.join(map(str, closing_reason_ids))})''',
                                                  'id,text')
    return {closing_reason.get('id'): closing_reason.get('text') for closing_reason in closing_reasons}


def get_domain_names(client: Client, outputs: List[Dict]) -> Dict:
    """
    Receives list of outputs, and performs API call to QRadar service to retrieve the domain names
    matching the domain IDs of the outputs.
    Args:
        client (Client): Client to perform the API request to QRadar.
        outputs (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {domain_id: domain_name}
    """
    domain_ids = {offense.get('domain_id') for offense in outputs if offense.get('domain_id')}
    if not domain_ids:
        return dict()
    domains_info = client.domains_list(None, None, f'''id in ({','.join(map(str, domain_ids))})''', 'id,name')
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
    rules = client.rules_list(None, None, f'''id in ({','.join(map(str, rules_ids))})''', 'id,name')
    return {rule.get('id'): rule.get('name') for rule in rules}


def get_offense_source_addresses(client: Client, offenses: List[Dict]) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the source IP values
    matching the source IPs IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {source_address_id: source_address_name}
    """

    def get_source_addresses_for_batch(b: List):
        return client.source_addresses(f'''id in ({','.join(map(str, b))})''', 'id,source_ip')

    source_addresses_ids = [address_id for offense in offenses
                            for address_id in offense.get('source_address_ids', [])]

    # Submit addresses in batches to avoid time out from QRadar service
    source_addresses_batches = [get_source_addresses_for_batch(b) for b
                                in batch(source_addresses_ids[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE))]

    return {source_address.get('id'): source_address.get('source_ip')
            for addresses_batch in source_addresses_batches
            for source_address in addresses_batch}


def get_offense_destination_addresses(client: Client, offenses: List[Dict]) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the destination IP values
    matching the destination IPs IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {destination_address_id: destination_address_name}
    """

    def get_destination_addresses_for_batch(b: List):
        return client.destination_addresses(f'''id in ({','.join(map(str, b))})''', 'id,local_destination_ip')

    destination_addresses_ids = [address_id for offense in offenses
                                 for address_id in offense.get('local_destination_address_ids', [])]

    # Submit addresses in batches to avoid time out from QRadar service
    destination_addresses_batches = [get_destination_addresses_for_batch(b) for b
                                     in batch(destination_addresses_ids[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE))]

    return {destination_address.get('id'): destination_address.get('local_destination_ip')
            for addresses_batch in destination_addresses_batches
            for destination_address in addresses_batch}


def enrich_offenses_result(client: Client, offenses: List[Dict], enrich_ip_addresses: bool = False) -> List[Dict]:
    """
    Receives list of offenses, and enriches the offenses with the following:
    - Changes offense_type value from the offense type ID to the offense type name.
    - Changes closing_reason_id value from closing reason ID to the closing reason name.
    - Adds a link to the URL of each offense.
    - Adds the domain name of the domain ID for each offense.
    - Adds to each rule of the offense its name.
    - Adds enrichment to each source/destination IP ID to its address
    Args:
        client (Client): Client to perform the API calls.
        offenses (List[Dict]): List of all of the offenses to enrich.
        enrich_ip_addresses (bool): Whether to enrich the offense source/destination IP addresses.

    Returns:
        (List[Dict]): The enriched offenses.
    """
    offense_types_id_name_dict = get_offense_types(client, offenses)
    closing_reasons_id_name_dict = get_offense_closing_reasons(client, offenses)
    domain_id_name_dict = get_domain_names(client, offenses) if DOMAIN_ENRCH_FLG == 'True' else dict()
    rules_id_name_dict = get_rules_names(client, offenses) if RULES_ENRCH_FLG == 'True' else dict()
    source_addresses_id_ip_dict = get_offense_source_addresses(client, offenses) if enrich_ip_addresses else dict()
    destination_addresses_id_ip_dict = get_offense_destination_addresses(client,
                                                                         offenses) if enrich_ip_addresses else dict()

    def create_enriched_offense(offense: Dict) -> Dict:
        basic_enriches = {
            'offense_type': offense_types_id_name_dict.get(offense.get('offense_type')),
            'closing_reason_id': closing_reasons_id_name_dict.get(offense.get('closing_reason_id')),
            'LinkToOffense': f'{client.server}/console/do/sem/offensesummary?'
                             f'''appName=Sem&pageId=OffenseSummary&summaryId={offense.get('id')}''',
        }

        domain_enrich = {
            'domain_name': domain_id_name_dict.get(offense.get('domain_id'))
        } if DOMAIN_ENRCH_FLG == 'True' else dict()

        rules_enrich = {
            'rules': [
                {
                    'id': rule.get('id'),
                    'type': rule.get('type'),
                    'name': rules_id_name_dict.get(rule.get('id'))

                } for rule in offense.get('rules', [])
            ] if RULES_ENRCH_FLG == 'True' else dict()
        }

        source_addresses_enrich = {
            'source_address_ids': [source_addresses_id_ip_dict.get(source_address_id) for source_address_id in
                                   offense.get('source_address_ids', [])]
        } if enrich_ip_addresses else dict()

        destination_addresses_enrich = {
            'source_address_ids': [destination_addresses_id_ip_dict.get(destination_address_id) for
                                   destination_address_id in offense.get('local_destination_address_ids', [])]
        } if enrich_ip_addresses else dict()

        return dict(offense, **basic_enriches, **domain_enrich, **rules_enrich, **source_addresses_enrich,
                    **destination_addresses_enrich)

    return [create_enriched_offense(offense) for offense in offenses]


def enrich_asset_properties(interfaces: List, property_old_new_dict: Dict) -> Dict:
    """
    Receives list of interfaces of an asset, and properties to enrich, and returns a dict containing the enrichment
    Args:
        interfaces (List): List of interfaces of an asset.
        property_old_new_dict (Dict): Properties to be enriched.

    Returns:
        (List[Dict]) List of new assets with enrichment.
    """
    return {
        property_old_new_dict.get(prop.get('name')): {
            'Value': prop.get('value'),
            'LastUser': prop.get('last_reported_by')
        }
        for interface in interfaces for prop in interface.get('properties', [])
        if prop.get('name') in property_old_new_dict
    }


def enrich_assets_results(client: Client, assets: Any, full_enrichment: bool) -> List[Dict]:
    """
    Receives list of assets, and enriches each asset with 'Endpoint' entry containing the following:
    - IP addresses of all interfaces.
    - OS name.
    - MAC addresses of the interfaces, if full enrichment was requested.
    - Domain name if full enrichment was requested.
    - Properties enrichment.

    Args:
        client (Client): Client to perform API call to retrieve domain names corresponding to the domain IDs.
        assets (List[Dict]): List of assets to be enriched.
        full_enrichment (bool): Whether the asset should be full enriched.

    Returns:
        (List[Dict]) List of new assets with enrichment.
    """
    domain_id_name_dict = get_domain_names(client, assets) if full_enrichment else dict()

    def enrich_single_asset(asset: Dict) -> Dict:
        interfaces = asset.get('interfaces', [])
        domain_id = asset.get('domain_id')
        os_name = next(
            (prop.get('value') for interface in interfaces for prop in interface.get('properties', [])
             if prop.get('name') == 'Primary OS ID'), None)

        ip_enrichment = {
            'IPAddress': [ip_address.get('value') for interface in interfaces
                          for ip_address in interface.get("ip_addresses", [])]}

        os_enrichment = {'OS': os_name} if os_name else dict()

        mac_enrichment = {
            'MACAddress': [interface.get("mac_address") for interface in interfaces]} if full_enrichment else dict()

        domains_enrichment = {'Domain': domain_id_name_dict.get(domain_id)} if full_enrichment and domain_id else dict()

        endpoint_dict = {'Endpoint': dict(ip_enrichment, **os_enrichment, **mac_enrichment, **domains_enrichment)}

        basic_properties_enrichment = enrich_asset_properties(interfaces, ASSET_PROPERTIES_NAME_MAP)
        full_properties_enrichment = enrich_asset_properties(interfaces,
                                                             FULL_ASSET_PROPERTIES_NAMES_MAP) if full_enrichment else dict()

        return dict(asset, **endpoint_dict, **basic_properties_enrichment, **full_properties_enrichment)

    return [enrich_single_asset(asset) for asset in assets]


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
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
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

    response = client.offenses_list(offense_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, OFFENSE_OLD_NEW_NAMES_MAP)
    enriched_outputs = enrich_offenses_result(client, outputs)
    final_outputs = replace_keys(enriched_outputs, OFFENSE_OLD_NEW_NAMES_MAP)
    headers = build_headers(['ID', 'Description'], set(OFFENSE_OLD_NEW_NAMES_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Offenses List', enriched_outputs, headers=headers),
        outputs_prefix='QRadar.Offense',
        outputs_key_field='id',
        outputs=final_outputs,
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

    response = client.offense_update(offense_id, protected, follow_up, status, closing_reason_id, assigned_to,
                                     fields)
    outputs = sanitize_outputs(response, OFFENSE_OLD_NEW_NAMES_MAP)
    # TODO check
    enriched_outputs = enrich_offenses_result(client, outputs, enrich_ip_addresses=True)

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
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
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

    response = client.closing_reasons_list(closing_reason_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, CLOSING_REASONS_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name'], set(CLOSING_REASONS_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Closing Reasons', outputs, headers=headers),
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
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
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

    response = client.offense_notes_list(offense_id, note_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, NOTES_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown(f'Offense Notes List For Offense ID {offense_id}', outputs),
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

    response = client.offense_notes_create(offense_id, note_text, fields)
    outputs = sanitize_outputs(response, NOTES_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Create Note', outputs),
        outputs_prefix='QRadar.offenseNote',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


#
def qradar_rules_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of rules from QRadar service.
    possible arguments:
    - rule_id: Retrieves details of the specific rule that corresponds to the ID given.
    - rule_type: Retrieves rules corresponding to the given rule type.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    rule_id = args.get('rule_id')
    rule_type = args.get('rule_type')
    range_ = args.get('range')
    filter_ = args.get('filter')
    fields = args.get('fields')

    if not filter_ and rule_type:
        filter_ = f'type={rule_type}'

    response = client.rules_list(rule_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, RULES_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name'], set(RULES_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Rules List', outputs, headers=headers),
        outputs_prefix='QRadar.Rule',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_rule_groups_list_command(client: Client, args: Dict):
    rule_group_id = args.get('rule_group_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.rule_groups_list(rule_group_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, RULES_GROUP_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Rules Group List', outputs),
        outputs_prefix='QRadar.RuleGroup',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_assets_list_command(client: Client, args: Dict):
    """
    Retrieves list of assets from QRadar service.
    possible arguments:
    - asset_id: Retrieves details of the specific asset that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    asset_id = args.get('asset_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    # If asset ID was given, override filter if both were given
    if asset_id:
        filter_ = f'id={asset_id}'

    full_enrichment = True if asset_id else False

    response = client.assets_list(range_, filter_, fields)
    enriched_outputs = enrich_assets_results(client, response, full_enrichment)
    final_outputs = sanitize_outputs(enriched_outputs)

    return CommandResults(
        readable_output=tableToMarkdown('Assets List', final_outputs),
        outputs_prefix='QRadar.Asset',
        outputs_key_field='id',
        outputs=final_outputs,
        raw_response=response
    )


def qradar_saved_searches_list_command(client: Client, args: Dict):
    saved_search_id = args.get('saved_search_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.saved_searches_list(saved_search_id, range_, filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown('Saved Searches List', outputs),
        outputs_prefix='QRadar.SavedSearch',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_searches_list_command(client: Client, args: Dict):
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.searches_list(range_, filter_)
    outputs = sanitize_outputs(response, SEARCH_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Searches List', outputs),
        outputs_prefix='QRadar.Search',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_create_command(client: Client, args: Dict):
    query_expression = args.get('query_expression')
    saved_search_id = args.get('saved_search_id')

    response = client.search_create(query_expression, saved_search_id)
    outputs = sanitize_outputs(response, SEARCH_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Create Search', outputs),
        outputs_prefix='QRadar.Search',
        outputs_key_field='search_id',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_status_get_command(client: Client, args: Dict) -> CommandResults:
    search_id = args.get('search_id')

    response = client.search_status_get(search_id)
    outputs = sanitize_outputs(response, SEARCH_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown(f'Search Status For Search ID {search_id}', outputs),
        outputs_prefix='QRadar.SearchStatus',
        outputs_key_field='search_id',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_results_get_command(client: Client, args: Dict) -> CommandResults:
    search_id = args.get('search_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''

    response = client.search_results_get(search_id, range_)
    outputs = sanitize_outputs(response)
    # TODO figure result key
    # TODO add file naming (shown in integration design)

    return CommandResults(
        readable_output=tableToMarkdown(f'Search Status For Search ID {search_id}', outputs),
        outputs_prefix='QRadar.SearchStatus',
        outputs_key_field='search_id',
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_sets_list_command(client: Client, args: Dict) -> CommandResults:
    ref_name = args.get('ref_name')
    # value = args.get('value')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.reference_sets_list(ref_name, range_, filter_, fields)
    outputs = sanitize_outputs(response, REFERENCE_SETS_OLD_NEW_MAP)

    if ref_name:
        for output in outputs:
            add_iso_entries_to_dict(output.get('data', []))

    return CommandResults(
        readable_output=tableToMarkdown('Reference Sets List', outputs),
        outputs_prefix='QRadar.ReferenceSet',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )


#      TODO: understand what was done here

#       convert_date_elements = (
#         True if date_value == "True" and ref["ElementType"] == "DATE" else False
#     )


def qradar_reference_set_create_command(client: Client, args: Dict):
    """
    Create a new reference set.
    possible arguments:
    - ref_name (Required): The name of the new reference set.
    - element_type (Required): The type of the new reference set. Can be ALN (alphanumeric),
                               ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric),
                               PORT (port number) or DATE.
    - timeout_type: Indicates if the time_to_live interval is based on when the data was first seen or last seen.
                    The allowed values are "FIRST_SEEN", "LAST_SEEN" and "UNKNOWN". The default value is "UNKNOWN".
    - time_to_live: The time to live interval, for example: "1 month" or "5 minutes".
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name = args.get('ref_name')
    element_type = args.get('element_type')
    timeout_type = args.get('timeout_type')
    time_to_live = args.get('time_to_live')
    fields = args.get('fields')

    response = client.reference_set_create(ref_name, element_type, timeout_type, time_to_live, fields)
    outputs = sanitize_outputs(response, REFERENCE_SETS_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Reference Set Create', outputs),
        outputs_prefix='QRadar.ReferenceSet',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_set_delete_command(client: Client, args: Dict):
    ref_name = args.get('ref_name')

    response = client.reference_set_delete(ref_name)
    #     maybe add output for the task to be monitored. add to yml after decisions
    return CommandResults(
        raw_response=response,
        readable_output=f'### Reference {ref_name} is being deleted.')


def qradar_reference_set_value_upsert_command(client: Client, args: Dict) -> CommandResults:
    ref_name = args.get('ref_name')
    value = args.get('value')
    source = args.get('source')
    date_value = argToBoolean(args.get('date_value', False))
    fields = args.get('fields')

    if date_value:
        value = get_time_parameter(value, epoch_format=True)

    response = client.reference_set_value_upsert(ref_name, value, source, fields)
    outputs = sanitize_outputs(response, REFERENCE_SETS_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Reference Update Create', outputs),
        outputs_prefix='QRadar.ReferenceSetValue',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_set_value_delete_command(client: Client, args: Dict):
    ref_name = args.get('ref_name')
    value = args.get('value')
    date_value = argToBoolean(args.get('date_value', False))

    if date_value:
        value = get_time_parameter(value, epoch_format=True)

    response = client.reference_set_value_delete(ref_name, value)
    human_readable = f'### value: {value} of reference: {ref_name} was deleted successfully'

    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def qradar_domains_list_command(client: Client, args: Dict):
    domain_id = args.get('domain_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.domains_list(domain_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, DOMAIN_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Domains List', outputs),
        outputs_prefix='QRadar.Domain',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


# discuss with arseny
# def qradar_indicators_upload_command

def qradar_geolocations_for_ip_command(client: Client, args: Dict):
    ips = argToList(args.get('ips'))
    if not ips:
        raise DemistoException('''IPs list cannot be empty for command 'qradar-geolocations-for-ip-get'.''')
    filter_ = f'''ip_address IN ({','.join(map(str, ips))})'''
    fields = args.get('fields')

    response = client.geolocations_for_ip(filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown('Geolocation For IP', outputs),
        outputs_prefix='QRadar.GeoForIP',
        outputs_key_field='ip_address',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_sources_list_command(client: Client, args: Dict):
    qrd_encryption_algorithm = args.get('qrd_encryption_algorithm')
    qrd_encryption_password = args.get('qrd_encryption_password', client.password)
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.log_sources_list(qrd_encryption_algorithm, qrd_encryption_password, range_, filter_, fields)
    outputs = sanitize_outputs(response)

    # TODO finish
    return CommandResults(
        readable_output=tableToMarkdown('Log Sources List', outputs),
        raw_response=response
    )


''' MAIN FUNCTION '''


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
            return_results(test_module_command(client))

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

        elif command == 'qradar-rule-groups-list':
            return_results(qradar_rule_groups_list_command(client, args))

        elif command == 'qradar-assets-list':
            return_results(qradar_assets_list_command(client, args))

        elif command == 'qradar-saved-searches-list':
            return_results(qradar_saved_searches_list_command(client, args))

        elif command == 'qradar-searches-list':
            return_results(qradar_searches_list_command(client, args))

        elif command == 'qradar-search-create':
            return_results(qradar_search_create_command(client, args))
        #
        elif command == 'qradar-search-status-get':
            return_results(qradar_search_status_get_command(client, args))

        elif command == 'qradar-search-results-get':
            return_results(qradar_search_results_get_command(client, args))

        elif command == 'qradar-reference-sets-list':
            return_results(qradar_reference_sets_list_command(client, args))

        elif command == 'qradar-reference-set-create':
            return_results(qradar_reference_set_create_command(client, args))

        elif command == 'qradar-reference-set-delete':
            return_results(qradar_reference_set_delete_command(client, args))

        elif command == 'qradar-reference-set-value-upsert':
            return_results(qradar_reference_set_value_upsert_command(client, args))

        elif command == 'qradar-reference-set-value-delete':
            return_results(qradar_reference_set_value_delete_command(client, args))

        elif command == 'qradar-domains-list':
            return_results(qradar_domains_list_command(client, args))

        # elif command == 'qradar-indicators-upload':
        #     return_results(qradar_indicators_upload_command(client, args))
        # QRadar.Indicator

        elif command == 'qradar-geolocations-for-ip':
            return_results(qradar_geolocations_for_ip_command(client, args))

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
