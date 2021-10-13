import concurrent.futures
import secrets
from enum import Enum
from ipaddress import ip_address
from typing import Tuple

import pytz
import urllib3
from CommonServerUserPython import *  # noqa

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' ADVANCED GLOBAL PARAMETERS '''
SAMPLE_SIZE = 2  # number of samples to store in integration context
EVENTS_INTERVAL_SECS = 15  # interval between events polling
EVENTS_FAILURE_LIMIT = 3  # amount of consecutive failures events fetch will tolerate
FAILURE_SLEEP = 15  # sleep between consecutive failures events fetch
FETCH_SLEEP = 60  # sleep between fetches
BATCH_SIZE = 100  # batch size used for offense ip enrichment
OFF_ENRCH_LIMIT = BATCH_SIZE * 10  # max amount of IPs to enrich per offense
LOCK_WAIT_TIME = 0.5  # time to wait for lock.acquire
MAX_WORKERS = 8  # max concurrent workers used for events enriching
DOMAIN_ENRCH_FLG = 'true'  # when set to true, will try to enrich offense and assets with domain names
RULES_ENRCH_FLG = 'true'  # when set to true, will try to enrich offense with rule names
MAX_FETCH_EVENT_RETIRES = 3  # max iteration to try search the events of an offense
SLEEP_FETCH_EVENT_RETIRES = 10  # sleep between iteration to try search the events of an offense
MAX_NUMBER_OF_OFFENSES_TO_CHECK_SEARCH = 5  # Number of offenses to check during mirroring if search was completed.

ADVANCED_PARAMETERS_STRING_NAMES = [
    'DOMAIN_ENRCH_FLG',
    'RULES_ENRCH_FLG'
]
ADVANCED_PARAMETER_INT_NAMES = [
    'EVENTS_INTERVAL_SECS',
    'EVENTS_FAILURE_LIMIT',
    'FAILURE_SLEEP',
    'FETCH_SLEEP',
    'BATCH_SIZE',
    'OFF_ENRCH_LIMIT',
    'LOCK_WAIT_TIME',
    'MAX_WORKERS',
    'MAX_FETCH_EVENT_RETIRES',
    'SLEEP_FETCH_EVENT_RETIRES'
]

''' CONSTANTS '''
API_USERNAME = '_api_token_key'
RESET_KEY = 'reset'
LAST_FETCH_KEY = 'id'
MINIMUM_API_VERSION = 10.1
DEFAULT_RANGE_VALUE = '0-49'
DEFAULT_TIMEOUT_VALUE = '35'
DEFAULT_LIMIT_VALUE = 50
MAXIMUM_MIRROR_LIMIT = 100
DEFAULT_EVENTS_LIMIT = 20
MAXIMUM_OFFENSES_PER_FETCH = 50
DEFAULT_OFFENSES_PER_FETCH = 20
TERMINATING_SEARCH_STATUSES = {'CANCELED', 'ERROR', 'COMPLETED'}
DEFAULT_MIRRORING_DIRECTION = 'No Mirroring'
MIRROR_DIRECTION: Dict[str, Optional[str]] = {
    'No Mirroring': None,
    'Mirror Offense': 'In'
}
UTC_TIMEZONE = pytz.timezone('utc')
ID_QUERY_REGEX = re.compile(r'(?:\s+|^)id((\s)*)>(=?)((\s)*)((\d)+)(?:\s+|$)')
ASCENDING_ID_ORDER = '+id'
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
lock = Lock()

''' OUTPUT FIELDS REPLACEMENT MAPS '''
OFFENSE_OLD_NEW_NAMES_MAP = {
    'credibility': 'Credibility',
    'relevance': 'Relevance',
    'severity': 'Severity',
    'assigned_to': 'AssignedTo',
    'destination_networks': 'DestinationHostname',
    'status': 'Status',
    'closing_user': 'ClosingUser',
    'closing_reason_id': 'ClosingReason',
    'close_time': 'CloseTime',
    'categories': 'Categories',
    'follow_up': 'Followup',
    'id': 'ID',
    'description': 'Description',
    'source_address_ids': 'SourceAddress',
    'local_destination_address_ids': 'DestinationAddress',
    'remote_destination_count': 'RemoteDestinationCount',
    'start_time': 'StartTime',
    'event_count': 'EventCount',
    'flow_count': 'FlowCount',
    'offense_source': 'OffenseSource',
    'magnitude': 'Magnitude',
    'last_updated_time': 'LastUpdatedTime',
    'offense_type': 'OffenseType',
    'protected': 'Protected',
    'LinkToOffense': 'LinkToOffense',
    'rules': 'Rules',
    'domain_name': 'DomainName',
    'assets': 'Assets'
}

CLOSING_REASONS_OLD_NEW_MAP = {
    'id': 'ID',
    'text': 'Name',
    'is_reserved': 'IsReserved',
    'is_deleted': 'IsDeleted'
}

NOTES_OLD_NEW_MAP = {
    'id': 'ID',
    'note_text': 'Text',
    'create_time': 'CreateTime',
    'username': 'CreatedBy'
}

RULES_OLD_NEW_MAP = {
    'owner': 'Owner',
    'base_host_id': 'BaseHostID',
    'capacity_timestamp': 'CapacityTimestamp',
    'origin': 'Origin',
    'creation_date': 'CreationDate',
    'type': 'Type',
    'enabled': 'Enabled',
    'modification_date': 'ModificationDate',
    'name': 'Name',
    'average_capacity': 'AverageCapacity',
    'id': 'ID',
    'base_capacity': 'BaseCapacity'
}

RULES_GROUP_OLD_NEW_MAP = {
    'owner': 'Owner',
    'modified_time': 'ModifiedTime',
    'level': 'Level',
    'name': 'Name',
    'description': 'Description',
    'id': 'ID',
    'child_groups': 'ChildGroups',
    'child_items': 'ChildItems',
    'type': 'Type',
    'parent_id': 'ParentID'
}

ASSET_OLD_NEW_MAP = {
    'vulnerability_count': 'VulnerabilityCount',
    'interfaces': 'Interfaces',
    'risk_score_sum': 'RiskScoreSum',
    'hostnames': 'Hostnames',
    'id': 'ID',
    'users': 'Users',
    'domain_id': 'DomainID',
    'properties': 'Properties',
    'products': 'Products'
}

SEARCH_OLD_NEW_MAP = {'search_id': 'ID', 'status': 'Status'}

REFERENCE_SETS_OLD_NEW_MAP = {
    'number_of_elements': 'NumberOfElements',
    'name': 'Name',
    'creation_time': 'CreationTime',
    'element_type': 'ElementType',
    'time_to_live': 'TimeToLive',
    'timeout_type': 'TimeoutType',
    'data': 'Data',
}
REFERENCE_SET_DATA_OLD_NEW_MAP = {
    'last_seen': 'LastSeen',
    'source': 'Source',
    'value': 'Value',
    'first_seen': 'FirstSeen'
}

DOMAIN_OLD_NEW_MAP = {
    'asset_scanner_ids': 'AssetScannerIDs',
    'custom_properties': 'CustomProperties',
    'deleted': 'Deleted',
    'description': 'Description',
    'event_collector_ids': 'EventCollectorIDs',
    'flow_collector_ids': 'FlowCollectorIDs',
    'flow_source_ids': 'FlowSourceIDs',
    'id': 'ID',
    'log_source_ids': 'LogSourceIDs',
    'log_source_group_ids': 'LogSourceGroupIDs',
    'name': 'Name',
    'qvm_scanner_ids': 'QVMScannerIDs',
    'tenant_id': 'TenantID'
}

SAVED_SEARCH_OLD_NEW_MAP = {
    'owner': 'Owner',
    'description': 'Description',
    'creation_date': 'CreationDate',
    'uid': 'UID',
    'database': 'Database',
    'is_quick_search': 'QuickSearch',
    'name': 'Name',
    'modified_date': 'ModifiedDate',
    'id': 'ID',
    'aql': 'AQL',
    'is_shared': 'IsShared'
}

IP_GEOLOCATION_OLD_NEW_MAP = {
    'continent': 'Continent',
    'traits': 'Traits',
    'geo_json': 'Geolocation',
    'city': 'City',
    'ip_address': 'IPAddress',
    'represented_country': 'RepresentedCountry',
    'registered_country': 'RegisteredCountry',
    'is_local': 'IsLocalCountry',
    'location': 'Location',
    'postal': 'Postal',
    'physical_country': 'PhysicalCountry',
    'subdivisions': 'SubDivisions'
}

LOG_SOURCES_OLD_NEW_MAP = {
    'sending_ip': 'SendingIP',
    'internal': 'Internal',
    'protocol_parameters': 'ProtocolParameters',
    'description': 'Description',
    'enabled': 'Enabled',
    'group_ids': 'GroupIDs',
    'credibility': 'Credibility',
    'id': 'ID',
    'protocol_type_id': 'ProtocolTypeID',
    'creation_date': 'CreationDate',
    'name': 'Name',
    'modified_date': 'ModifiedDate',
    'auto_discovered': 'AutoDiscovered',
    'type_id': 'TypeID',
    'last_event_time': 'LastEventTime',
    'gateway': 'Gateway',
    'status': 'Status'
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
                 'first_seen',
                 'starttime',
                 'devicetime',
                 'last_reported',
                 'created',
                 'last_seen_profiler',
                 'last_seen_scanner',
                 'first_seen_scanner',
                 'first_seen_profiler',
                 'modified_time',
                 'last_event_time',
                 'modified_date',
                 'first_event_flow_seen',
                 'last_event_flow_seen'}

LOCAL_DESTINATION_IPS_OLD_NEW_MAP = {
    'domain_id': 'DomainID',
    'event_flow_count': 'EventFlowCount',
    'first_event_flow_seen': 'FirstEventFlowSeen',
    'id': 'ID',
    'last_event_flow_seen': 'LastEventFlowSeen',
    'local_destination_ip': 'LocalDestinationIP',
    'magnitude': 'Magnitude',
    'network': 'Network',
    'offense_ids': 'OffenseIDs',
    'source_address_ids': 'SourceAddressIDs'
}
SOURCE_IPS_OLD_NEW_MAP = {
    'domain_id': 'DomainID',
    'event_flow_count': 'EventFlowCount',
    'first_event_flow_seen': 'FirstEventFlowSeen',
    'id': 'ID',
    'last_event_flow_seen': 'LastEventFlowSeen',
    'local_destination_address_ids': 'LocalDestinationAddressIDs',
    'magnitude': 'Magnitude',
    'network': 'Network',
    'offense_ids': 'OffenseIDs',
    'source_ip': 'SourceIP'
}
''' ENRICHMENT MAPS '''

ASSET_PROPERTIES_NAME_MAP = {
    'Unified Name': 'Name',
    'CVSS Collateral Damage Potential': 'AggregatedCVSSScore',
    'Weight': 'Weight'
}

FULL_ASSET_PROPERTIES_NAMES_MAP = {
    'Compliance Notes': 'ComplianceNotes',
    'Compliance Plan': 'CompliancePlan',
    'Location': 'Location',
    'Switch ID': 'SwitchID',
    'Switch Port ID': 'SwitchPort',
    'Group Name': 'GroupName',
    'Vulnerabilities': 'Vulnerabilities',
}
LONG_RUNNING_REQUIRED_PARAMS = {'fetch_mode': 'Fetch mode',
                                'offenses_per_fetch': 'Number of offenses to pull per API call (max 50)',
                                'events_limit': 'Maximum number of events per incident.'}

''' ENUMS '''


class FetchMode(Enum):
    """
    Enums for the options of fetching the incidents.
    """
    no_events = 'Fetch Without Events'
    all_events = 'Fetch With All Events'
    correlations_events_only = 'Fetch Correlation Events Only'


''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, server: str, verify: bool, proxy: bool, api_version: str, credentials: Dict):
        username = credentials.get('identifier')
        password = credentials.get('password')
        if username == API_USERNAME:
            self.base_headers = {'Version': api_version, 'SEC': password}
            auth = None
        else:
            auth = (username, password)
            self.base_headers = {'Version': api_version}
        base_url = urljoin(server, '/api')
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)
        self.password = password
        self.server = server

    def http_request(self, method: str, url_suffix: str, params: Optional[Dict] = None,
                     json_data: Optional[Dict] = None, additional_headers: Optional[Dict] = None,
                     timeout: Optional[int] = None):
        headers = {**additional_headers, **self.base_headers} if additional_headers else self.base_headers
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            headers=headers,
            error_handler=self.qradar_error_handler,
            timeout=timeout
        )

    @staticmethod
    def qradar_error_handler(res: requests.Response):
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
            if 'items=x-y' in message:
                message = 'Failed to parse Range argument. The syntax of the Range argument must follow this pattern:' \
                          ' x-y'
            elif 'unauthorized to access' in err_msg or 'No SEC header present in request' in err_msg:
                message = 'Authorization Error: make sure credentials are correct.'
            elif 'The specified encryption strength is not available' in err_msg:
                err_msg = ''
                message = 'The specified encryption is not available, try using a weaker encrpytion (AES128).'
            err_msg += f'\n{message}'
            raise DemistoException(err_msg, res=res)
        except ValueError:
            err_msg += '\n{}'.format(res.text)
            raise DemistoException(err_msg, res=res)

    def offenses_list(self, range_: Optional[str] = None, offense_id: Optional[int] = None,
                      filter_: Optional[str] = None, fields: Optional[str] = None, sort: Optional[str] = None):
        id_suffix = f'/{offense_id}' if offense_id else ''
        params = assign_params(fields=fields) if offense_id else assign_params(filter=filter_, fields=fields, sort=sort)
        additional_headers = {'Range': range_} if not offense_id else None
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses{id_suffix}',
            params=params,
            additional_headers=additional_headers
        )

    def offense_update(self, offense_id: int, protected: Optional[str] = None, follow_up: Optional[str] = None,
                       status: Optional[str] = None, closing_reason_id: Optional[int] = None,
                       assigned_to: Optional[str] = None, fields: Optional[str] = None):
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

    def closing_reasons_list(self, closing_reason_id: Optional[int] = None, include_reserved: Optional[bool] = None,
                             include_deleted: Optional[bool] = None, range_: Optional[str] = None,
                             filter_: Optional[str] = None, fields: Optional[str] = None):
        id_suffix = f'/{closing_reason_id}' if closing_reason_id else ''
        params = assign_params(fields=fields) if closing_reason_id else assign_params(include_reserved=include_reserved,
                                                                                      include_deleted=include_deleted,
                                                                                      filter=filter_, fields=fields)
        additional_headers = {'Range': range_} if not closing_reason_id and range_ else None
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offense_closing_reasons{id_suffix}',
            additional_headers=additional_headers,
            params=params
        )

    def offense_notes_list(self, offense_id: int, range_: str, note_id: Optional[int] = None,
                           filter_: Optional[str] = None, fields: Optional[str] = None):
        note_id_suffix = f'/{note_id}' if note_id else ''
        params = assign_params(fields=fields) if note_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {'Range': range_} if not note_id else None
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses/{offense_id}/notes{note_id_suffix}',
            additional_headers=additional_headers,
            params=params
        )

    def offense_notes_create(self, offense_id: int, note_text: str, fields: Optional[str] = None):
        return self.http_request(
            method='POST',
            url_suffix=f'/siem/offenses/{offense_id}/notes',
            params=assign_params(note_text=note_text, fields=fields)
        )

    def rules_list(self, rule_id: Optional[str] = None, range_: Optional[str] = None, filter_: Optional[str] = None,
                   fields: Optional[str] = None):
        id_suffix = f'/{rule_id}' if rule_id else ''
        params = assign_params(fields=fields) if rule_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {'Range': range_} if range_ and not rule_id else None
        return self.http_request(
            method='GET',
            url_suffix=f'/analytics/rules{id_suffix}',
            params=params,
            additional_headers=additional_headers
        )

    def rule_groups_list(self, range_: str, rule_group_id: Optional[int] = None, filter_: Optional[str] = None,
                         fields: Optional[str] = None):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        additional_headers = {'Range': range_} if not rule_group_id else None
        params = assign_params(fields=fields) if rule_group_id else assign_params(filter=filter_, fields=fields)
        return self.http_request(
            method='GET',
            url_suffix=f'/analytics/rule_groups{id_suffix}',
            additional_headers=additional_headers,
            params=params
        )

    def assets_list(self, range_: Optional[str] = None, filter_: Optional[str] = None, fields: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix='/asset_model/assets',
            additional_headers={'Range': range_},
            params=assign_params(filter=filter_, fields=fields)
        )

    def saved_searches_list(self, range_: str, timeout: Optional[int], saved_search_id: Optional[str] = None,
                            filter_: Optional[str] = None, fields: Optional[str] = None):
        id_suffix = f'/{saved_search_id}' if saved_search_id else ''
        params = assign_params(fields=fields) if saved_search_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {'Range': range_} if not saved_search_id else None
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/saved_searches{id_suffix}',
            additional_headers=additional_headers,
            params=params,
            timeout=timeout
        )

    def searches_list(self, range_: str, filter_: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix='/ariel/searches',
            additional_headers={'Range': range_},
            params=assign_params(filter=filter_)
        )

    def search_create(self, query_expression: Optional[str] = None, saved_search_id: Optional[str] = None):
        return self.http_request(
            method='POST',
            url_suffix='/ariel/searches',
            params=assign_params(
                query_expression=query_expression,
                saved_search_id=saved_search_id
            )
        )

    def search_status_get(self, search_id: str):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}',
        )

    def search_results_get(self, search_id: str, range_: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}/results',
            additional_headers={'Range': range_} if range_ else None
        )

    def reference_sets_list(self, range_: Optional[str] = None, ref_name: Optional[str] = None,
                            filter_: Optional[str] = None, fields: Optional[str] = None):
        name_suffix = f'/{ref_name}' if ref_name else ''
        params = assign_params(fields=fields) if ref_name else assign_params(filter=filter_, fields=fields)
        additional_headers = {'Range': range_} if not ref_name else None
        return self.http_request(
            method='GET',
            url_suffix=f'/reference_data/sets{name_suffix}',
            params=params,
            additional_headers=additional_headers
        )

    def reference_set_create(self, ref_name: str, element_type: str, timeout_type: Optional[str] = None,
                             time_to_live: Optional[str] = None, fields: Optional[str] = None):
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

    def reference_set_delete(self, ref_name: str, purge_only: Optional[str] = None, fields: Optional[str] = None):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}',
            params=assign_params(purge_only=purge_only, fields=fields)
        )

    def reference_set_value_upsert(self, ref_name: str, value: str, source: Optional[str] = None,
                                   fields: Optional[str] = None):
        return self.http_request(
            method='POST',
            url_suffix=f'/reference_data/sets/{ref_name}',
            params=assign_params(value=value, source=source, fields=fields)
        )

    def reference_set_value_delete(self, ref_name: str, value: str):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}/{value}'
        )

    def domains_list(self, domain_id: Optional[int] = None, range_: Optional[str] = None, filter_: Optional[str] = None,
                     fields: Optional[str] = None):
        id_suffix = f'/{domain_id}' if domain_id else ''
        params = assign_params(fields=fields) if domain_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {'Range': range_} if not domain_id and range_ else None
        return self.http_request(
            method='GET',
            url_suffix=f'/config/domain_management/domains{id_suffix}',
            additional_headers=additional_headers,
            params=params
        )

    def indicators_upload(self, ref_name: str, indicators: Any, fields: Optional[str] = None):
        headers = {
            'Content-Type': 'application/json'
        }
        if fields:
            headers['fields'] = fields
        return self.http_request(
            method='POST',
            url_suffix=f'/reference_data/sets/bulk_load/{ref_name}',
            json_data=indicators,
            additional_headers=headers
        )

    def geolocations_for_ip(self, filter_: Optional[str] = None, fields: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix='/services/geolocations',
            params=assign_params(filter=filter_, fields=fields)
        )

    def log_sources_list(self, qrd_encryption_algorithm: str, qrd_encryption_password: str,
                         range_: str, filter_: Optional[str] = None, fields: Optional[str] = None):
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

    def custom_properties(self, range_: Optional[str] = None, filter_: Optional[str] = None,
                          fields: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix='/config/event_sources/custom_properties/regex_properties',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if range_ else None
        )

    def offense_types(self, filter_: Optional[str] = None, fields: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix='/siem/offense_types',
            params=assign_params(filter=filter_, fields=fields)
        )

    def get_addresses(self, address_suffix: str, filter_: Optional[str] = None, fields: Optional[str] = None,
                      range_: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/{address_suffix}',
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={'Range': range_} if range_ else None
        )

    def test_connection(self):
        """
        Test connection with databases (should always be up)
        """
        self.http_request(method='GET', url_suffix='/ariel/databases')
        return 'ok'


''' HELPER FUNCTIONS '''


def add_iso_entries_to_dict(dicts: List[Dict]) -> List[Dict]:
    """
    Takes list of dicts, for each dict:
    creates a new dict, and for each field in the output that
    is contained in 'USECS_ENTRIES', maps its value to be iso format corresponding to the value of the field.
    Args:
        dicts (List[Dict]): List of the dicts to be transformed.

    Returns:
        (List[Dict]): New dicts with iso entries for the corresponding items in 'USECS_ENTRIES'
    """
    return [{k: (get_time_parameter(v, iso_format=True) if k in USECS_ENTRIES else v)
             for k, v in dict_.items()} for dict_ in dicts]


def sanitize_outputs(outputs: Any, key_replace_dict: Optional[Dict] = None) -> List[Dict]:
    """
    Gets a list of all the outputs, and sanitizes outputs.
    - Removes empty elements.
    - adds ISO entries to the outputs.
    - Outputs only keys found in 'key_replace_dict', saving their names by 'key_replace_dict values,
      if 'key_replace_dict' is not None.
    Args:
        outputs (List[Dict]): List of the outputs to be sanitized.
        key_replace_dict (Dict): Dict of the keys to transform their names.

    Returns:
        (List[Dict]): Sanitized outputs.
    """
    if not isinstance(outputs, list):
        outputs = [outputs]
    outputs = [remove_empty_elements(output) for output in outputs]
    outputs = add_iso_entries_to_dict(outputs)
    return build_final_outputs(outputs, key_replace_dict) if key_replace_dict else outputs


def get_time_parameter(arg: Union[Optional[str], Optional[int]], iso_format: bool = False, epoch_format: bool = False):
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


def build_final_outputs(outputs: List[Dict], old_new_dict: Dict) -> List[Dict]:
    """
    Receives outputs, or a single output, and a dict containing mapping of old key names to new key names.
    Returns a list of outputs containing the new names contained in old_new_dict.
    Args:
        outputs (Dict): Outputs to replace its keys.
        old_new_dict (Dict): Old key name mapped to new key name.

    Returns:
        (Dict): The dictionary with the transformed keys and their values.
    """
    return [{old_new_dict.get(k): v for k, v in output.items() if k in old_new_dict} for output in outputs]


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


def is_valid_ip(ip: str) -> bool:
    try:
        ip_address(ip)
        return True
    except ValueError:
        print_debug_msg(f'IP {ip} was found invalid.')
        return False


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
    offense_types_ids = {offense.get('offense_type') for offense in offenses if offense.get('offense_type') is not None}
    if not offense_types_ids:
        return dict()
    offense_types = client.offense_types(filter_=f'''id in ({','.join(map(str, offense_types_ids))})''',
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
    closing_reason_ids = {offense.get('closing_reason_id') for offense in offenses
                          if offense.get('closing_reason_id') is not None}
    if not closing_reason_ids:
        return dict()
    closing_reasons = client.closing_reasons_list(filter_=f'''id in ({','.join(map(str, closing_reason_ids))})''',
                                                  fields='id,text')
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
    domain_ids = {offense.get('domain_id') for offense in outputs if offense.get('domain_id') is not None}
    if not domain_ids:
        return dict()
    domains_info = client.domains_list(filter_=f'''id in ({','.join(map(str, domain_ids))})''', fields='id,name')
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


def get_offense_addresses(client: Client, offenses: List[Dict], is_destination_addresses: bool) -> Dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the source IP values
    matching the source IPs IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.
        is_destination_addresses(bool): Whether addresses to enrich are destination IPs (or source).

    Returns:
        (Dict): Dictionary of {source_address_id: source_address_name}.
    """
    address_type = 'local_destination' if is_destination_addresses else 'source'
    address_field = f'{address_type}_ip'
    address_list_field = f'{address_type}_address_ids'
    url_suffix = f'{address_type}_addresses'

    def get_addresses_for_batch(b: List):
        return client.get_addresses(url_suffix, f'''id in ({','.join(map(str, b))})''', f'id,{address_field}')

    addresses_ids = [address_id for offense in offenses
                     for address_id in offense.get(address_list_field, [])]

    # Submit addresses in batches to avoid overloading QRadar service
    addresses_batches = [get_addresses_for_batch(b) for b
                         in batch(addresses_ids[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE))]

    return {address_data.get('id'): address_data.get(address_field)
            for addresses_batch in addresses_batches
            for address_data in addresses_batch}


def create_single_asset_for_offense_enrichment(asset: Dict) -> Dict:
    """
    Recieves one asset, and returns the expected asset values for enriching offense.
    Args:
        asset (Dict): Asset to enrich the offense with

    Returns:
        (Dict): The enriched asset.
    """
    interfaces = {'interfaces': [{
        'mac_address': interface.get('mac_address'),
        'id': interface.get('id'),
        'ip_addresses': [{
            'type': ip_add.get('type'),
            'value': ip_add.get('value')
        } for ip_add in interface.get('ip_addresses', [])]
    } for interface in asset.get('interfaces', [])]}
    properties = {prop.get('name'): prop.get('value') for prop in asset.get('properties', [])
                  if 'name' in prop and 'value' in prop}
    offense_without_properties = {k: v for k, v in asset.items() if k != 'properties'}
    return add_iso_entries_to_asset(dict(offense_without_properties, **properties, **interfaces))


def enrich_offense_with_assets(client: Client, offense_ips: List[str]) -> List[Dict]:
    """
    Receives list of offense's IPs, and performs API call to QRadar service to retrieve assets correlated to IPs given.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offense_ips (List[str]): List of all of the offense's IPs.

    Returns:
        (List[Dict]): List of all the correlated assets.
    """

    def get_assets_for_ips_batch(b: List):
        filter_query = ' or '.join([f'interfaces contains ip_addresses contains value="{ip}"' for ip in b])
        try:
            return client.assets_list(filter_=filter_query)
        except Exception as e:
            raise DemistoException(f'Error occurred during asset enrichment. Query: {filter_query}') from e

    offense_ips = [offense_ip for offense_ip in offense_ips if is_valid_ip(offense_ip)]
    # Submit addresses in batches to avoid overloading QRadar service
    assets = [asset for b in batch(offense_ips[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE))
              for asset in get_assets_for_ips_batch(b)]

    return [create_single_asset_for_offense_enrichment(asset) for asset in assets]


def enrich_offenses_result(client: Client, offenses: Any, enrich_ip_addresses: bool,
                           enrich_assets: bool) -> List[Dict]:
    """
    Receives list of offenses, and enriches the offenses with the following:
    - Changes offense_type value from the offense type ID to the offense type name.
    - Changes closing_reason_id value from closing reason ID to the closing reason name.
    - Adds a link to the URL of each offense.
    - Adds the domain name of the domain ID for each offense.
    - Adds to each rule of the offense its name.
    - Adds enrichment to each source/destination IP ID to its address (if enrich_ip_addresses is true).
    - Adds enrichment of assets to each offense (if enrich_assets is true).
    Args:
        client (Client): Client to perform the API calls.
        offenses (Any): List of all of the offenses to enrich.
        enrich_ip_addresses (bool): Whether to enrich the offense source/destination IP addresses.
        enrich_assets (bool): Whether to enrich the offense with assets.

    Returns:
        (List[Dict]): The enriched offenses.
    """
    if not isinstance(offenses, list):
        offenses = [offenses]

    print_debug_msg('Enriching offenses')
    offense_types_id_name_dict = get_offense_types(client, offenses)
    closing_reasons_id_name_dict = get_offense_closing_reasons(client, offenses)
    domain_id_name_dict = get_domain_names(client, offenses) if DOMAIN_ENRCH_FLG.lower() == 'true' else dict()
    rules_id_name_dict = get_rules_names(client, offenses) if RULES_ENRCH_FLG.lower() == 'true' else dict()
    source_addresses_id_ip_dict = get_offense_addresses(client, offenses, False) if enrich_ip_addresses else dict()
    destination_addresses_id_ip_dict = get_offense_addresses(client, offenses, True) if enrich_ip_addresses else dict()

    def create_enriched_offense(offense: Dict) -> Dict:
        link_to_offense_suffix = '/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId' \
                                 f'''={offense.get('id')}'''
        basic_enriches = {
            'offense_type': offense_types_id_name_dict.get(offense.get('offense_type')),
            'closing_reason_id': closing_reasons_id_name_dict.get(offense.get('closing_reason_id')),
            'LinkToOffense': urljoin(client.server, link_to_offense_suffix),
        }

        domain_enrich = {
            'domain_name': domain_id_name_dict.get(offense.get('domain_id'))
        } if DOMAIN_ENRCH_FLG.lower() == 'true' and domain_id_name_dict.get(offense.get('domain_id')) else dict()

        rules_enrich = {
            'rules': [{
                'id': rule.get('id'),
                'type': rule.get('type'),
                'name': rules_id_name_dict.get(rule.get('id'))
            } for rule in offense.get('rules', [])] if RULES_ENRCH_FLG.lower() == 'true' else dict()
        }

        source_addresses_enrich = {
            'source_address_ids': [source_addresses_id_ip_dict.get(source_address_id) for source_address_id in
                                   offense.get('source_address_ids', [])]
        } if enrich_ip_addresses else dict()

        destination_addresses_enrich = {
            'local_destination_address_ids': [destination_addresses_id_ip_dict.get(destination_address_id) for
                                              destination_address_id in
                                              offense.get('local_destination_address_ids', [])]
        } if enrich_ip_addresses else dict()

        if enrich_assets:
            source_ips: List = source_addresses_enrich.get('source_address_ids', [])
            destination_ips: List = destination_addresses_enrich.get('local_destination_address_ids', [])
            all_ips: List = source_ips + destination_ips
            asset_enrich = {'assets': enrich_offense_with_assets(client, all_ips)}
        else:
            asset_enrich = dict()

        return dict(offense, **basic_enriches, **domain_enrich, **rules_enrich, **source_addresses_enrich,
                    **destination_addresses_enrich, **asset_enrich)

    result = [create_enriched_offense(offense) for offense in offenses]
    print_debug_msg('Enriched offenses successfully.')
    return result


def enrich_asset_properties(properties: List, properties_to_enrich_dict: Dict) -> Dict:
    """
    Receives list of properties of an asset, and properties to enrich, and returns a dict containing the enrichment
    Args:
        properties (List): List of properties of an asset.
        properties_to_enrich_dict (Dict): Properties to be enriched.

    Returns:
        (List[Dict]) List of new assets with enrichment.
    """
    return {
        properties_to_enrich_dict.get(prop.get('name')): {
            'Value': prop.get('value'),
            'LastUser': prop.get('last_reported_by')
        } for prop in properties if prop.get('name') in properties_to_enrich_dict
    }


def add_iso_entries_to_asset(asset: Dict) -> Dict:
    """
    Transforms epoch entries to ISO entries in an asset.
    Requires a special treatment, because some of the usec entries are nested.
    Args:
        asset (Dict): Asset to transform its epoch entries to ISO.

    Returns:
        (Dict): Asset transformed.
    """

    def get_asset_entry(k: str, v: Any):
        if k == 'interfaces':
            return [{
                k: (get_time_parameter(v, iso_format=True) if k in USECS_ENTRIES
                    else add_iso_entries_to_dict(v) if k == 'ip_addresses' else v)
                for k, v in interface.items()
            } for interface in v]

        elif k == 'properties':
            return add_iso_entries_to_dict(v)

        elif k in USECS_ENTRIES:
            return get_time_parameter(v, iso_format=True)

        else:
            return v

    return {k: get_asset_entry(k, v) for k, v in asset.items()}


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
        updated_asset = add_iso_entries_to_asset(asset)
        interfaces = updated_asset.get('interfaces', [])
        properties = updated_asset.get('properties', [])
        domain_id = updated_asset.get('domain_id')
        os_name = next((prop.get('value') for prop in properties if prop.get('name') == 'Primary OS ID'), None)

        ip_enrichment = {
            'IPAddress': [ip_add.get('value') for interface in interfaces
                          for ip_add in interface.get('ip_addresses', [])
                          if ip_add.get('value')]
        }

        os_enrichment = {'OS': os_name} if os_name else dict()

        mac_enrichment = {
            'MACAddress': [interface.get('mac_address') for interface in interfaces if
                           interface.get('mac_address')]
        } if full_enrichment else dict()

        domains_enrichment = {'Domain': domain_id_name_dict.get(domain_id)} if full_enrichment and domain_id else dict()

        basic_properties_enrichment = enrich_asset_properties(properties, ASSET_PROPERTIES_NAME_MAP)
        full_properties_enrichment = enrich_asset_properties(properties,
                                                             FULL_ASSET_PROPERTIES_NAMES_MAP) \
            if full_enrichment else dict()

        enriched_asset = dict(asset, **basic_properties_enrichment, **full_properties_enrichment)
        return {'Asset': add_iso_entries_to_asset(enriched_asset),
                'Endpoint': dict(ip_enrichment, **os_enrichment, **mac_enrichment,
                                 **domains_enrichment)}

    return [enrich_single_asset(asset) for asset in assets]


def get_minimum_id_to_fetch(highest_offense_id: int, user_query: Optional[str]) -> int:
    """
    Receives the highest offense ID saved from last run, and user query.
    Checks if user query has a limitation for a minimum ID.
    If such ID exists, returns the maximum between 'highest_offense_id' and the minimum ID
    limitation received by the user query.
    Args:
        highest_offense_id (int): Minimum ID to fetch offenses by from last run.
        user_query (Optional[str]): User query for QRadar service.

    Returns:
        (int): The Minimum ID to fetch offenses by.
    """
    if user_query:
        id_query = ID_QUERY_REGEX.search(user_query)
        if id_query:
            id_query_raw = id_query.group(0)
            operator = '>=' if '>=' in id_query_raw else '>'
            # safe to int parse without catch because regex checks for number
            user_offense_id = int(id_query.group(0).split(operator)[1].strip())
            user_lowest_offense_id = user_offense_id if operator == '>' else user_offense_id - 1
            print_debug_msg(f'Found ID in user query: {user_lowest_offense_id}, last highest ID: {highest_offense_id}')
            return max(highest_offense_id, user_lowest_offense_id)
    return highest_offense_id


def get_offense_enrichment(enrichment: str) -> Tuple[bool, bool]:
    """
    Receives enrichment asked by the user, returns true or false values indicating which enrichment should be done.
    Args:
        enrichment (Optional[str]): Enrichment argument.

    Returns:
        (bool, bool): Tuple of (ip_enrich, asset_enrich).
    """
    if enrichment == 'IPs And Assets':
        return True, True
    if enrichment == 'IPs':
        return True, False
    return False, False


def print_debug_msg(msg: str):
    """
    Prints a message to debug with QRadarMsg prefix.
    Uses lock because calls can be concurrent.
    If lock cannot be acquired until timeout, will skip writing message to log.
    Args:
        msg (str): Message to be logged.

    """
    debug_msg = f'QRadarMsg - {msg}'
    if lock.acquire(timeout=LOCK_WAIT_TIME):
        demisto.debug(debug_msg)
        lock.release()


def is_reset_triggered(handle_reset: bool = False):
    """
    Checks if reset of integration context have been made by the user.
    Because fetch is long running execution, user communicates with us
    by calling 'qradar-reset-last-run' command which sets reset flag in
    context.
    Using lock because calls to this function concurrent
    Args:
        handle_reset (bool): Whether the reset should be handled by the caller.

    Returns:
        (bool):
        - True if reset flag was set. If 'handle_reset' is true, also resets integration context.
        - False if lock could not be acquired until timeout.
        - False if lock was acquired, and reset flag was not found in integration context.
    """
    if lock.acquire(timeout=LOCK_WAIT_TIME):
        ctx = get_integration_context()
        if ctx and RESET_KEY in ctx:
            if handle_reset:
                print_debug_msg('Reset fetch-incidents.')
                set_integration_context({'retry_compatible': True, 'samples': ctx.get('samples', '[]')})
            lock.release()
            return True
        lock.release()
    return False


def validate_long_running_params(params: Dict) -> None:
    """
    Receives params, checks whether the required parameters for long running execution is configured.
    Args:
        params (Dict): Cortex XSOAR params.

    Returns:
        (None): If all required params are set, raises DemistoException otherwise.
    """
    for param_field, param_display in LONG_RUNNING_REQUIRED_PARAMS.items():
        if param_field not in params:
            raise DemistoException(f'Parameter {param_display} is required when enabling long running execution.'
                                   ' Please set a value for it.')


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, params: Dict) -> str:
    """
    Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Client to perform the API calls.
        params (Dict): Demisto params.

    Returns:
        - (str): 'ok' if test passed
        - raises DemistoException if something had failed the test.
    """
    try:
        is_long_running = params.get('longRunning')
        if is_long_running:
            validate_long_running_params(params)
            ip_enrich, asset_enrich = get_offense_enrichment(params.get('enrichment', 'IPs And Assets'))
            get_incidents_long_running_execution(
                client=client,
                offenses_per_fetch=1,
                user_query=params.get('query', ''),
                fetch_mode=params.get('fetch_mode', ''),
                events_columns=params.get('events_columns', ''),
                events_limit=1,
                ip_enrich=ip_enrich,
                asset_enrich=asset_enrich,
                last_highest_id=int(json.loads(get_integration_context().get(LAST_FETCH_KEY, '0'))),
                incident_type=params.get('incident_type'),
                mirror_direction=MIRROR_DIRECTION.get(params.get('mirror_options', DEFAULT_MIRRORING_DIRECTION))
            )
        else:
            client.offenses_list(range_="items=0-0")
        message = 'ok'
    except DemistoException as e:
        err_msg = str(e)
        if 'unauthorized to access the requested resource' in err_msg or 'No SEC header present in request' in err_msg:
            message = 'Authorization Error: make sure credentials are correct.'
        else:
            raise e
    return message


def fetch_incidents_command() -> List[Dict]:
    """
    Fetch incidents implemented, for mapping purposes only.
    Returns list of samples saved by long running execution.

    Returns:
        (List[Dict]): List of incidents samples.
    """
    return json.loads(get_integration_context().get('samples', '[]'))


def create_search_with_retry(client: Client, fetch_mode: str, offense: Dict, event_columns: str, events_limit: int,
                             max_retries: int = EVENTS_FAILURE_LIMIT) -> Optional[Dict]:
    """
    Creates a search to retrieve events for an offense.
    Has retry mechanism, because QRadar service tends to return random errors when
    it is loaded.
    Therefore, 'max_retries' retries will be made, to try avoid such cases as much as possible.
    Args:
        client (Client): Client to perform the API calls.
        fetch_mode (str): Which enrichment mode was requested.
                          Can be 'Fetch With All Events', 'Fetch Correlation Events Only'
        offense (Dict): Offense ID to enrich with events.
        event_columns (str): Columns of the events to be extracted from query.
        events_limit (int): Maximum number of events to enrich the offense.
        max_retries (int): Number of retries.


    Returns:
        (Dict): If search was created successfully.
        None: If reset was triggered or number of retries exceeded limit.
    """
    additional_where = ''' AND LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine' ''' \
        if fetch_mode == FetchMode.correlations_events_only.value else ''
    # Decrease 1 minute from start_time to avoid the case where the minute queried of start_time equals end_time.
    offense_start_time = offense['start_time'] - 60 * 1000
    offense_id = offense['id']
    query_expression = (
        f'SELECT {event_columns} FROM events WHERE INOFFENSE({offense_id}) {additional_where} limit {events_limit} '
        f'START {offense_start_time}'
    )
    num_of_failures = 0
    while num_of_failures <= max_retries:
        if is_reset_triggered():
            return None
        try:
            return client.search_create(query_expression=query_expression)
        except Exception:
            print_debug_msg(f'Failed to create search for offense ID: {offense_id}. '
                            f'Retry number {num_of_failures}/{max_retries}.')
            print_debug_msg(traceback.format_exc())
            num_of_failures += 1
            if num_of_failures == max_retries:
                print_debug_msg(f'Max retries for creating search for offense: {offense_id}. Returning empty.')
                break
            time.sleep(FAILURE_SLEEP)
    return None


def poll_offense_events_with_retry(client: Client, search_id: str, offense_id: int,
                                   max_retries: int = EVENTS_FAILURE_LIMIT) -> List[Dict]:
    """
    Polls QRadar service for search ID given until status returned is within 'TERMINATING_SEARCH_STATUSES'.
    Afterwards, performs a call to retrieve the events returned by the search.
    Has retry mechanism, because QRadar service tends to return random errors when
    it is loaded.
    Therefore, 'max_retries' retries will be made, to try avoid such cases as much as possible.

    Args:
        client (Client): Client to perform the API calls.
        search_id (str): ID of the search to poll for its status.
        offense_id (int): ID of the offense to enrich with events returned by search. Used for logging purposes here.
        max_retries (int): Number of retries.

    Returns:
        (List[Dict]): List of events returned by query. Returns empty list if number of retries exceeded limit.
    """
    num_of_failures = 0
    start_time = time.time()
    while num_of_failures <= max_retries:
        try:
            if is_reset_triggered():
                return []
            search_status_response = client.search_status_get(search_id)
            query_status = search_status_response.get('status')
            # failures are relevant only when consecutive
            num_of_failures = 0
            if query_status in TERMINATING_SEARCH_STATUSES:
                search_results_response = client.search_results_get(search_id)
                events = search_results_response.get('events', [])
                sanitized_events = sanitize_outputs(events)
                print_debug_msg(f'Fetched {len(sanitized_events)} events for offense {offense_id}.')
                return sanitized_events
            elapsed = time.time() - start_time
            if elapsed >= FETCH_SLEEP:  # print status debug every fetch sleep (or after)
                print_debug_msg(f'Still fetching offense {offense_id} events, search_id: {search_id}.')
                start_time = time.time()
            time.sleep(EVENTS_INTERVAL_SECS)
        except Exception as e:
            print_debug_msg(
                f'Error while fetching offense {offense_id} events, search_id: {search_id}. Error details: {str(e)}')
            num_of_failures += 1
            if num_of_failures < max_retries:
                time.sleep(FAILURE_SLEEP)
    print_debug_msg(f'Could not fetch events for offense ID: {offense_id}, returning empty events array.')
    return []


def enrich_offense_with_events(client: Client, offense: Dict, fetch_mode: str, events_columns: str, events_limit: int,
                               max_retries: int = MAX_FETCH_EVENT_RETIRES):
    """
    Enriches offense given with events.
    Has retry mechanism for events returned by query to QRadar. This is needed because events might not be
    indexed when performing the search, and QRadar will return less events than expected.
    Retry mechanism here meant to avoid such cases as much as possible
    Args:
        client (Client): Client to perform the API calls.
        offense (Dict): Offense to enrich with events.
        fetch_mode (str): Which enrichment mode was requested.
                          Can be 'Fetch With All Events', 'Fetch Correlation Events Only'
        events_columns (str): Columns of the events to be extracted from query.
        events_limit (int): Maximum number of events to enrich the offense.
        max_retries (int): Number of retries.

    Returns:
        (Dict): Enriched offense with events.
    """
    if is_reset_triggered():
        return offense

    # decreasing 1 minute from the start_time to avoid the case where the minute queried of start_time equals end_time.
    for i in range(max_retries):
        # retry to check if we got all the event (its not an error retry), see docstring
        search_response = create_search_with_retry(client, fetch_mode, offense, events_columns,
                                                   events_limit)
        if not search_response:
            continue

        offense_id = offense['id']
        events = poll_offense_events_with_retry(client, search_response['search_id'], offense_id)
        min_events_size = min(offense.get('event_count', 0), events_limit)
        if len(events) >= min_events_size:
            offense = dict(offense, events=events)
            break
        print_debug_msg(f'Did not fetch enough events. Expected at least {min_events_size}. Retrying to fetch events '
                        f'for offense ID: {offense_id}. Retry number {i}/{max_retries}')
        if i < max_retries - 1:
            time.sleep(SLEEP_FETCH_EVENT_RETIRES)

    return offense


def get_incidents_long_running_execution(client: Client, offenses_per_fetch: int, user_query: str, fetch_mode: str,
                                         events_columns: str, events_limit: int, ip_enrich: bool, asset_enrich: bool,
                                         last_highest_id: int, incident_type: Optional[str],
                                         mirror_direction: Optional[str]) -> Tuple[Optional[List[Dict]], Optional[int]]:
    """
    Gets offenses from QRadar service, and transforms them to incidents in a long running execution.
    Args:
        client (Client): Client to perform the API calls.
        offenses_per_fetch (int): Maximum number of offenses to be fetched.
        user_query (str): If given, the user filters for fetching offenses from QRadar service.
        fetch_mode (str): Fetch mode of the offenses.
                          Can be 'Fetch Without Events', 'Fetch With All Events', 'Fetch Correlation Events Only'
        events_columns (str): Events columns to extract by search query for each offense. Only used when fetch mode
                              is not 'Fetch Without Events'.
        events_limit (int): Number of events to be fetched for each offense. Only used when fetch mode is not
                            'Fetch Without Events'.
        ip_enrich (bool): Whether to enrich offense by changing IP IDs of each offense to its IP value.
        asset_enrich (bool): Whether to enrich offense with assets
        last_highest_id (int): The highest ID of all the offenses that have been fetched from QRadar service.
        incident_type (Optional[str]): Incident type.
        mirror_direction (Optional[str]): Whether mirror in is activated or not.

    Returns:
        (List[Dict], int): List of the incidents, and the new highest ID for next fetch.
        (None, None): if reset was triggered
    """
    offense_highest_id = get_minimum_id_to_fetch(last_highest_id, user_query)

    user_query = f' AND {user_query}' if user_query else ''

    filter_fetch_query = f'id>{offense_highest_id}{user_query}'
    print_debug_msg(f'Filter query to QRadar: {filter_fetch_query}')
    range_max = offenses_per_fetch - 1 if offenses_per_fetch else MAXIMUM_OFFENSES_PER_FETCH - 1
    range_ = f'items=0-{range_max}'

    offenses = client.offenses_list(range_, filter_=filter_fetch_query, sort=ASCENDING_ID_ORDER)
    new_highest_offense_id = offenses[-1].get('id') if offenses else offense_highest_id
    print_debug_msg(f'New highest ID returned from QRadar offenses: {new_highest_offense_id}')

    if fetch_mode != FetchMode.no_events.value:
        futures = []
        for offense in offenses:
            futures.append(EXECUTOR.submit(
                enrich_offense_with_events,
                client=client,
                offense=offense,
                fetch_mode=fetch_mode,
                events_columns=events_columns,
                events_limit=events_limit,
            ))
        offenses = [future.result() for future in futures]

    if is_reset_triggered(handle_reset=True):
        return None, None
    offenses_with_mirror = [
        dict(offense, mirror_direction=mirror_direction, mirror_instance=demisto.integrationInstance())
        for offense in offenses] if mirror_direction else offenses
    enriched_offenses = enrich_offenses_result(client, offenses_with_mirror, ip_enrich, asset_enrich)
    final_offenses = sanitize_outputs(enriched_offenses)
    incidents = create_incidents_from_offenses(final_offenses, incident_type)
    return incidents, new_highest_offense_id


def create_incidents_from_offenses(offenses: List[Dict], incident_type: Optional[str]) -> List[Dict]:
    """
    Transforms list of offenses given into incidents for Demisto.
    Args:
        offenses (List[Dict]): List of the offenses to transform into incidents.
        incident_type (Optional[str]): Incident type to be used for each incident.

    Returns:
        (List[Dict]): Incidents list.
    """
    print_debug_msg(f'Creating {len(offenses)} incidents')
    return [{
        'name': f'''{offense.get('id')} {offense.get('description', '')}''',
        'rawJSON': json.dumps(offense),
        'occurred': get_time_parameter(offense.get('start_time'), iso_format=True),
        'type': incident_type
    } for offense in offenses]


def long_running_execution_command(client: Client, params: Dict):
    """
    Long running execution of fetching incidents from QRadar service.
    Will continue to fetch in an infinite loop offenses from QRadar,
    Enriching each offense with events/IPs/assets according to the
    configurations given in Demisto params.
    transforming the offenses into incidents and sending them to Demisto
    to save the incidents.
    Args:
        client (Client): Client to perform API calls.
        params (Dict): Demisto params.

    """
    validate_long_running_params(params)
    fetch_mode = params.get('fetch_mode', '')
    ip_enrich, asset_enrich = get_offense_enrichment(params.get('enrichment', 'IPs And Assets'))
    offenses_per_fetch = int(params.get('offenses_per_fetch'))  # type: ignore
    user_query = params.get('query', '')
    events_columns = params.get('events_columns', '')
    events_limit = int(params.get('events_limit') or DEFAULT_EVENTS_LIMIT)
    incident_type = params.get('incident_type')
    mirror_direction = MIRROR_DIRECTION.get(params.get('mirror_options', DEFAULT_MIRRORING_DIRECTION))
    while True:
        try:
            is_reset_triggered(handle_reset=True)
            ctx = get_integration_context()
            print_debug_msg(f'Starting fetch loop. Fetch mode: {fetch_mode}.')
            incidents, new_highest_id = get_incidents_long_running_execution(
                client=client,
                offenses_per_fetch=offenses_per_fetch,
                user_query=user_query,
                fetch_mode=fetch_mode,
                events_columns=events_columns,
                events_limit=events_limit,
                ip_enrich=ip_enrich,
                asset_enrich=asset_enrich,
                last_highest_id=int(json.loads(ctx.get(LAST_FETCH_KEY, '0'))),
                incident_type=incident_type,
                mirror_direction=mirror_direction
            )
            if incidents and new_highest_id:
                incident_batch_for_sample = incidents[:SAMPLE_SIZE] if incidents else json.loads(
                    ctx.get('samples', '[]'))
                if incident_batch_for_sample:
                    print_debug_msg(f'Saving New Highest ID: {new_highest_id}')
                    set_to_integration_context_with_retries({'samples': incident_batch_for_sample,
                                                             LAST_FETCH_KEY: new_highest_id})

                demisto.createIncidents(incidents)

        except Exception:
            demisto.error('Error occurred during long running loop')
            demisto.error(traceback.format_exc())

        finally:
            print_debug_msg('Finished fetch loop')
            time.sleep(FETCH_SLEEP)


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
    ip_enrich, asset_enrich = get_offense_enrichment(args.get('enrichment', 'None'))

    response = client.offenses_list(range_, offense_id, filter_, fields)
    enriched_outputs = enrich_offenses_result(client, response, ip_enrich, asset_enrich)
    final_outputs = sanitize_outputs(enriched_outputs, OFFENSE_OLD_NEW_NAMES_MAP)
    headers = build_headers(['ID', 'Description', 'OffenseType', 'Status', 'Severity'],
                            set(OFFENSE_OLD_NEW_NAMES_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Offenses List', final_outputs, headers=headers, removeNull=True),
        outputs_prefix='QRadar.Offense',
        outputs_key_field='ID',
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
    offense_id: int = int(args['offense_id'])
    protected = args.get('protected')
    follow_up = args.get('follow_up')
    closing_reason_name = args.get('closing_reason_name')

    status = args.get('status')
    closing_reason_id = args.get('closing_reason_id')
    if status == 'CLOSED' and (not closing_reason_id and not closing_reason_name):
        raise DemistoException(
            '''Closing reason ID must be provided when closing an offense. Available closing reasons can be achieved
             by 'qradar-closing-reasons' command.'''
        )

    if closing_reason_name:
        closing_reasons_list = client.closing_reasons_list(include_deleted=True, include_reserved=True)
        for closing_reason in closing_reasons_list:
            if closing_reason.get('text') == closing_reason_name:
                closing_reason_id = closing_reason.get('id')
        if not closing_reason_id:
            raise DemistoException(f'Could not find closing reason name {closing_reason_name}. Please provide a valid'
                                   ' closing reason name. Closing reasons can be retrieved by running the '
                                   'qradar-closing-reasons command.')

    assigned_to = args.get('assigned_to')
    fields = args.get('fields')
    ip_enrich, asset_enrich = get_offense_enrichment(args.get('enrichment', 'None'))

    response = client.offense_update(offense_id, protected, follow_up, status, closing_reason_id, assigned_to,
                                     fields)

    enriched_outputs = enrich_offenses_result(client, response, ip_enrich, asset_enrich)
    final_outputs = sanitize_outputs(enriched_outputs, OFFENSE_OLD_NEW_NAMES_MAP)
    headers = build_headers(['ID', 'Description', 'OffenseType', 'Status', 'Severity'],
                            set(OFFENSE_OLD_NEW_NAMES_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('offense Update', final_outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Offense',
        outputs_key_field='ID',
        outputs=final_outputs,
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
    include_reserved = argToBoolean(args.get('include_reserved', False))
    include_deleted = argToBoolean(args.get('include_deleted', False))
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.closing_reasons_list(closing_reason_id, include_reserved, include_deleted, range_, filter_,
                                           fields)
    outputs = sanitize_outputs(response, CLOSING_REASONS_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name'], set(CLOSING_REASONS_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Closing Reasons', outputs, headers=headers, removeNull=True),
        outputs_prefix='QRadar.Offense.ClosingReasons',
        outputs_key_field='ID',
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
    offense_id: int = int(args['offense_id'])
    note_id = args.get('note_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.offense_notes_list(offense_id, range_, note_id, filter_, fields)
    outputs = sanitize_outputs(response, NOTES_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Text', 'CreatedBy', 'CreateTime'], set(NOTES_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown(f'Offense Notes List For Offense ID {offense_id}', outputs, headers,
                                        removeNull=True),
        outputs_prefix='QRadar.Note',
        outputs_key_field='ID',
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
    offense_id: int = int(args['offense_id'])
    note_text: str = args.get('note_text', '')
    fields = args.get('fields')

    response = client.offense_notes_create(offense_id, note_text, fields)
    outputs = sanitize_outputs(response, NOTES_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Text', 'CreatedBy', 'CreateTime'], set(NOTES_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Create Note', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Note',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


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
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    if not filter_ and rule_type:
        filter_ = f'type={rule_type}'

    response = client.rules_list(rule_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, RULES_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name', 'Type'], set(RULES_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Rules List', outputs, headers=headers, removeNull=True),
        outputs_prefix='QRadar.Rule',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_rule_groups_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of rule groups from QRadar service.
    possible arguments:
    - rule_group_id: Retrieves details of the specific rule group that corresponds to the ID given.
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
    rule_group_id = arg_to_number(args.get('rule_group_id'))
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.rule_groups_list(range_, rule_group_id, filter_, fields)
    outputs = sanitize_outputs(response, RULES_GROUP_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name', 'Description', 'Owner'], set(RULES_GROUP_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Rules Group List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.RuleGroup',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_assets_list_command(client: Client, args: Dict) -> CommandResults:
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

    # If asset ID was given, override filter if both filter and asset ID were given.
    if asset_id:
        filter_ = f'id={asset_id}'

    full_enrichment = True if asset_id else False

    response = client.assets_list(range_, filter_, fields)
    enriched_outputs = enrich_assets_results(client, response, full_enrichment)
    assets_results = dict()
    assets_hr = []
    endpoints = []
    for output in enriched_outputs:
        output['Asset']['hostnames'] = add_iso_entries_to_dict(output.get('Asset', dict()).get('hostnames', []))
        output['Asset']['users'] = add_iso_entries_to_dict(output.get('Asset', dict()).get('users', []))
        output['Asset']['products'] = add_iso_entries_to_dict(output.get('Asset', dict()).get('products', []))
        output['Asset'] = sanitize_outputs(output.get('Asset'), ASSET_OLD_NEW_MAP)[0]
        assets_hr.append(output['Asset'])
        assets_results[f'''QRadar.Asset(val.ID === "{output['Asset']['ID']}")'''] = output['Asset']
        sanitized_endpoint = remove_empty_elements(output.get('Endpoint', dict()))
        if sanitized_endpoint:
            endpoints.append(sanitized_endpoint)

    asset_human_readable = tableToMarkdown('Assets List', assets_hr, removeNull=True)
    endpoints_human_readable = tableToMarkdown('Endpoints', endpoints, removeNull=True)

    if endpoints:
        assets_results['Endpoint'] = endpoints

    return CommandResults(
        readable_output=asset_human_readable + endpoints_human_readable,
        outputs=assets_results,
        raw_response=response
    )


def qradar_saved_searches_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of saved searches from QRadar service.
    possible arguments:
    - saved_search_id: Retrieves details of the specific saved search that corresponds to the ID given.
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
    saved_search_id = args.get('saved_search_id')
    timeout: Optional[int] = arg_to_number(args.get('timeout', DEFAULT_TIMEOUT_VALUE))
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.saved_searches_list(range_, timeout, saved_search_id, filter_, fields)
    outputs = sanitize_outputs(response, SAVED_SEARCH_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name', 'Description'], set(SAVED_SEARCH_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Saved Searches List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.SavedSearch',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_searches_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of searches IDs from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.searches_list(range_, filter_)
    outputs = [{'SearchID': search_id} for search_id in response]

    return CommandResults(
        readable_output=tableToMarkdown('Search ID List', outputs),
        outputs_prefix='QRadar.SearchID',
        outputs_key_field='SearchID',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_create_command(client: Client, args: Dict) -> CommandResults:
    """
    Create a search in QRadar service.
    possible arguments:
    - query_expression: The AQL query to execute. Mutually exclusive with saved_search_id.
    - saved_search_id: Saved search ID to execute. Mutually exclusive with query_expression.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    query_expression = args.get('query_expression')
    saved_search_id = args.get('saved_search_id')

    response = client.search_create(query_expression, saved_search_id)
    outputs = sanitize_outputs(response, SEARCH_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Create Search', outputs),
        outputs_prefix='QRadar.Search',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_status_get_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves search status from QRadar service.
    possible arguments:
    - search_id (Required): The search ID to retrieve its status.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    search_id: str = args.get('search_id', '')

    response = client.search_status_get(search_id)
    outputs = sanitize_outputs(response, SEARCH_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown(f'Search Status For Search ID {search_id}', outputs),
        outputs_prefix='QRadar.Search',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_results_get_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves search results from QRadar service.
    possible arguments:
    - search_id: Search ID to retrieve its results.
    - output_path: If specified, will be context output path prefix.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    search_id: str = args.get('search_id', '')
    output_path = args.get('output_path')
    # Using or instead of default value for QRadarFullSearch backward compatibility
    range_ = f'''items={args.get('range') or DEFAULT_RANGE_VALUE}'''

    response = client.search_results_get(search_id, range_)
    if not response:
        raise DemistoException('Unexpected response from QRadar service.')
    result_key = list(response.keys())[0]
    outputs = sanitize_outputs(response.get(result_key))

    outputs_prefix = output_path if output_path else f'QRadar.Search(val.ID === "{search_id}").Result.{result_key}'

    return CommandResults(
        readable_output=tableToMarkdown(f'Search Results For Search ID {search_id}', outputs),
        outputs_prefix=outputs_prefix,
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_sets_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of reference sets from QRadar service.
    possible arguments:
    - ref_name: Retrieves details of the specific reference that corresponds to the reference name given.
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
    ref_name = args.get('ref_name')
    convert_date_value = argToBoolean(args.get('date_value', False))
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.reference_sets_list(range_, ref_name, filter_, fields)
    if ref_name:
        outputs = dict(response)
        if convert_date_value and outputs.get('element_type') == 'DATE':
            for data_entry in outputs.get('data', []):
                data_entry['value'] = get_time_parameter(data_entry.get('value'), iso_format=True)
        outputs['data'] = sanitize_outputs(outputs.get('data', []), REFERENCE_SET_DATA_OLD_NEW_MAP)
    else:
        outputs = response

    final_outputs = sanitize_outputs(outputs, REFERENCE_SETS_OLD_NEW_MAP)
    headers = build_headers(['Name', 'ElementType', 'Data', 'TimeToLive', 'TimeoutType'],
                            set(REFERENCE_SETS_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Reference Sets List', final_outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Reference',
        outputs_key_field='Name',
        outputs=final_outputs,
        raw_response=response
    )


def qradar_reference_set_create_command(client: Client, args: Dict) -> CommandResults:
    """
    Create a new reference set.
    possible arguments:
    - ref_name (Required): The name of the new reference set.
    - element_type (Required): The type of the new reference set. Can be ALN (alphanumeric),
                               ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric),
                               PORT (port number) or DATE.
    - timeout_type: Indicates if the time_to_live interval is based on when the data was first seen or last seen.
                    The allowed values are 'FIRST_SEEN', 'LAST_SEEN' and 'UNKNOWN'. The default value is 'UNKNOWN'.
    - time_to_live: The time to live interval, for example: '1 month' or '5 minutes'.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name: str = args.get('ref_name', '')
    element_type: str = args.get('element_type', '')
    timeout_type = args.get('timeout_type')
    time_to_live = args.get('time_to_live')
    fields = args.get('fields')

    response = client.reference_set_create(ref_name, element_type, timeout_type, time_to_live, fields)
    outputs = sanitize_outputs(response, REFERENCE_SETS_OLD_NEW_MAP)
    headers = build_headers(['Name', 'ElementType', 'Data', 'TimeToLive', 'TimeoutType'],
                            set(REFERENCE_SETS_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Reference Set Create', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Reference',
        outputs_key_field='Name',
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_set_delete_command(client: Client, args: Dict) -> CommandResults:
    """
    Removes a reference set or purges its contents.
    possible arguments:
    - ref_name (Required): The name of the new reference set.
    - purge_only: Indicates if the reference set should have its contents purged (true),
                  keeping the reference set structure. If the value is 'false',
                  or not specified the reference set is removed completely.
                  Default is 'false'.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name: str = args.get('ref_name', '')
    purge_only = args.get('purge_only')
    fields = args.get('fields')

    response = client.reference_set_delete(ref_name, purge_only, fields)
    return CommandResults(
        raw_response=response,
        readable_output=f'Request to delete reference {ref_name} was submitted.'
                        f''' Current deletion status: {response.get('status', 'Unknown')}''')


def qradar_reference_set_value_upsert_command(client: Client, args: Dict) -> CommandResults:
    """
    Update or insert new value to a reference set from QRadar service.
    possible arguments:
    - ref_name (Required): The reference name to insert/update a value for.
    - values (Required): Comma separated list. All the values to be inserted/updated.
    - source: An indication of where the data originated. Default is reference data api.
    - date_value: Boolean, specifies if values given are dates or not.
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
    ref_name: str = args.get('ref_name', '')
    values: List[str] = argToList(args.get('value', ''))
    if not values:
        raise DemistoException('Value to insert must be given.')
    source = args.get('source')
    date_value = argToBoolean(args.get('date_value', False))
    fields = args.get('fields')

    if date_value:
        values = [get_time_parameter(value, epoch_format=True) for value in values]

    if len(values) == 1:
        response = client.reference_set_value_upsert(ref_name, values[0], source, fields)

    else:
        response = client.indicators_upload(ref_name, values, fields)

    outputs = sanitize_outputs(response, REFERENCE_SETS_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Reference Update Create', outputs,
                                        ['Name', 'ElementType', 'TimeToLive', 'TimeoutType', 'NumberOfElements',
                                         'CreationTime'], removeNull=True),
        outputs_prefix='QRadar.Reference',
        outputs_key_field='Name',
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_set_value_delete_command(client: Client, args: Dict) -> CommandResults:
    """
    Delete a value in reference set from QRadar service.
    possible arguments:
    - ref_name (Required): The reference name to insert/update a value for.
    - value (Required): Value to be deleted.
    - date_value: Boolean, specifies if values given are dates or not.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name: str = args.get('ref_name', '')
    value: str = args.get('value', '')
    date_value = argToBoolean(args.get('date_value', False))
    original_value = value

    if date_value:
        value = get_time_parameter(original_value, epoch_format=True)

    response = client.reference_set_value_delete(ref_name, value)
    human_readable = f'### value: {original_value} of reference: {ref_name} was deleted successfully'

    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def qradar_domains_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves list of domains sets from QRadar service.
    If you do not have the System Administrator or Security Administrator permissions,
    then for each domain assigned to your security profile you can only view the values
    for the id and name fields. All other values return null.
    possible arguments:
    - domain_id: Retrieves details of the specific domain that corresponds to the ID given.
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
    # backward compatibility for domain_id argument named is 'id' in QRadar v2.
    domain_id = args.get('domain_id') or args.get('id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.domains_list(domain_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, DOMAIN_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Domains List', outputs, removeNull=True),
        outputs_prefix='QRadar.Domains',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_indicators_upload_command(client: Client, args: Dict) -> CommandResults:
    """
    Uploads list of indicators from Demisto to a reference set in QRadar service.
    possible arguments:
    - ref_name (Required): Name of the reference set to upload indicators to.
    - query: The query for getting indicators from Demisto.
    - limit: Maximum number of indicators to fetch from Demisto.
    - page: The page from which to get the indicators.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name: str = args.get('ref_name', '')
    query = args.get('query')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT_VALUE))
    page = arg_to_number(args.get('page', 0))
    fields = args.get('fields')

    # Backward compatibility for QRadar V2 command. Create reference set for given 'ref_name' if does not exist.
    element_type = args.get('element_type', '')
    timeout_type = args.get('timeout_type')
    time_to_live = args.get('time_to_live')
    try:
        client.reference_sets_list(ref_name=ref_name)
    except DemistoException as e:
        # Create reference set if does not exist
        if e.message and f'{ref_name} does not exist' in e.message:
            client.reference_set_create(ref_name, element_type, timeout_type, time_to_live)
        else:
            raise e

    search_indicators = IndicatorsSearcher(page=page)
    indicators = search_indicators.search_indicators_by_version(query=query, size=limit).get('iocs', [])
    indicators_data = [{'Indicator Value': indicator.get('value'), 'Indicator Type': indicator.get('indicator_type')}
                       for indicator in indicators if 'value' in indicator and 'indicator_type' in indicator]
    indicator_values: List[Any] = [indicator.get('Indicator Value') for indicator in indicators_data]

    if not indicators_data:
        return CommandResults(
            readable_output=f'No indicators were found for reference set {ref_name}'
        )

    response = client.indicators_upload(ref_name, indicator_values, fields)
    outputs = sanitize_outputs(response)

    reference_set_hr = tableToMarkdown(f'Indicators Upload For Reference Set {ref_name}', outputs)
    indicators_uploaded_hr = tableToMarkdown('Indicators Uploaded', indicators_data)

    return CommandResults(
        readable_output=f'{reference_set_hr}\n{indicators_uploaded_hr}',
        outputs_prefix='QRadar.Reference',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )


def flatten_nested_geolocation_values(geolocation_dict: Dict, dict_key: str, nested_value_keys: List[str]) -> Dict:
    """
    Receives output from geolocation IPs command, and does:
    1) flattens output, takes nested keys values.
    2) Converts keys to prefix of 'dict_key' and suffix of nested key as camel case.
    Args:
        geolocation_dict (Dict): The dict to flatten.
        dict_key (Dict): The key of the inner dict to use his values.
        nested_value_keys (Dict): The keys inside inner dict to take.

    Returns:
        (Dict): dict of ({dict_key_name}{camel case nested key}: {nested key value}
    """
    return {f'{camelize_string(dict_key)}{camelize_string(k)}': geolocation_dict.get(dict_key, dict()).get(k) for k in
            nested_value_keys}


def qradar_geolocations_for_ip_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves the MaxMind geoip data for the given IP addresses.
    possible arguments:
    - ip (Required): Comma separated list. the IPs to retrieve data for.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ips = argToList(args.get('ip'))
    filter_ = f'''ip_address IN ({','.join(map(lambda ip: f'"{str(ip)}"', ips))})'''
    fields = args.get('fields')

    response = client.geolocations_for_ip(filter_, fields)
    outputs = []
    for output in response:
        city_values = flatten_nested_geolocation_values(output, 'city', ['name'])
        continent_values = flatten_nested_geolocation_values(output, 'continent', ['name'])
        location_values = flatten_nested_geolocation_values(output, 'location',
                                                            ['accuracy_radius', 'average_income', 'latitude',
                                                             'longitude', 'metro_code', 'population_density',
                                                             'timezone'])
        physical_country_values = flatten_nested_geolocation_values(output, 'physical_country', ['iso_code', 'name'])
        registered_country_values = flatten_nested_geolocation_values(output, 'registered_country',
                                                                      ['iso_code', 'name'])
        represented_country_values = flatten_nested_geolocation_values(output, 'represented_country',
                                                                       ['iso_code', 'name', 'confidence'])
        subdivision_values = flatten_nested_geolocation_values(output, 'subdivision',
                                                               ['name', 'iso_code', 'confidence'])
        non_nested_values = {
            'IPAddress': output.get('ip_address'),
            'Traits': output.get('traits'),
            'Coordinates': output.get('geo_json', dict()).get('coordinates'),
            'PostalCode': output.get('postal', dict()).get('postal_code'),
            'PostalCodeConfidence': output.get('postal', dict()).get('confidence')
        }
        final_output = dict(city_values, **continent_values, **location_values, **physical_country_values,
                            **registered_country_values, **represented_country_values, **subdivision_values,
                            **non_nested_values)
        outputs.append(final_output)

    final_outputs = sanitize_outputs(outputs)

    return CommandResults(
        readable_output=tableToMarkdown('Geolocation For IP', final_outputs),
        outputs_prefix='QRadar.GeoForIP',
        outputs_key_field='IPAddress',
        outputs=final_outputs,
        raw_response=response
    )


def qradar_log_sources_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of log sources from QRadar service.
    possible arguments:
    - qrd_encryption_algorithm: The algorithm to use for encrypting the sensitive data of this
        endpoint. Using AES 128
    - qrd_encryption_password: The password to use for encrypting the sensitive data of this endpoint.
        If argument was not given, will be randomly generated.
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
    qrd_encryption_algorithm: str = args.get('qrd_encryption_algorithm', 'AES128')
    qrd_encryption_password: str = args.get('qrd_encryption_password', secrets.token_urlsafe(20))
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')

    response = client.log_sources_list(qrd_encryption_algorithm, qrd_encryption_password, range_, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCES_OLD_NEW_MAP)
    headers = build_headers(['ID', 'Name', 'Description'], set(LOG_SOURCES_OLD_NEW_MAP.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Log Sources List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSource',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_get_custom_properties_command(client: Client, args: Dict) -> CommandResults:
    """
    Retrieves a list of event regex properties from QRadar service.
    possible arguments:
    - field_names: A comma-separated list of names of an exact properties to search for.
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
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT_VALUE))
    if limit:
        range_ = f'items=0-{limit - 1}'
    else:
        range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''

    like_names = argToList(args.get('like_name'))
    field_names = argToList(args.get('field_name'))
    filter_ = args.get('filter', '')
    fields = args.get('fields')
    if not filter_:
        if field_names:
            filter_ += f'''name IN ({','.join(map(lambda name: f'"{str(name)}"', field_names))})'''
        if like_names:
            filter_ += ' or '.join(map(lambda like: f' name ILIKE "%{like}%"', like_names))

    response = client.custom_properties(range_, filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown('Custom Properties', outputs, removeNull=True),
        outputs_prefix='QRadar.Properties',
        outputs_key_field='identifier',
        outputs=outputs,
        raw_response=response
    )


def perform_ips_command_request(client: Client, args: Dict[str, Any], is_destination_addresses: bool):
    """
    Performs request to QRadar IPs endpoint.
    Args:
        client (Client): Client to perform the request to QRadar service.
        args (Dict[str, Any]): XSOAR arguments.
        is_destination_addresses (bool): Whether request is for destination addresses or source addresses.

    Returns:
        - Request response.
    """
    range_: str = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_: Optional[str] = args.get('filter')
    fields: Optional[str] = args.get('fields')

    address_type = 'local_destination' if is_destination_addresses else 'source'
    ips_arg_name: str = f'{address_type}_ip'
    ips: List[str] = argToList(args.get(ips_arg_name, []))

    if ips and filter_:
        raise DemistoException(f'Both filter and {ips_arg_name} have been supplied. Please supply only one.')

    if ips:
        filter_ = ' OR '.join([f'{ips_arg_name}="{ip_}"' for ip_ in ips])
    url_suffix = f'{address_type}_addresses'

    response = client.get_addresses(url_suffix, filter_, fields, range_)

    return response


def qradar_ips_source_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get source IPS from QRadar service.
    Args:
        client (Client): Client to perform API calls to QRadar service.
        args (Dict[str, Any): XSOAR arguments.

    Returns:
        (CommandResults).
    """
    response = perform_ips_command_request(client, args, is_destination_addresses=False)
    outputs = sanitize_outputs(response, SOURCE_IPS_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Source IPs', outputs),
        outputs_prefix='QRadar.SourceIP',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_ips_local_destination_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get local destination IPS from QRadar service.
    Args:
        client (Client): Client to perform API calls to QRadar service.
        args (Dict[str, Any): XSOAR arguments.

    Returns:
        (CommandResults).
    """
    response = perform_ips_command_request(client, args, is_destination_addresses=True)
    outputs = sanitize_outputs(response, LOCAL_DESTINATION_IPS_OLD_NEW_MAP)

    return CommandResults(
        readable_output=tableToMarkdown('Local Destination IPs', outputs),
        outputs_prefix='QRadar.LocalDestinationIP',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_reset_last_run_command() -> str:
    """
    Puts the reset flag inside integration context.
    Returns:
        (str): 'fetch-incidents was reset successfully'.
    """
    ctx = get_integration_context()
    ctx[RESET_KEY] = True
    ctx['retry_compatible'] = True
    set_integration_context(ctx)
    return 'fetch-incidents was reset successfully.'


def qradar_get_mapping_fields_command(client: Client) -> Dict:
    """
    Returns Dict object containing the list of fields for an incident type.
    This command should be used for debugging purposes.
    Args:
        client (Client): Client to perform API calls.

    Returns:
        (Dict): Contains all the mapping.
    """
    offense = {
        'username_count': 'int',
        'description': 'str',
        'rules': {
            'id': 'int',
            'type': 'str',
            'name': 'str'
        },
        'event_count': 'int',
        'flow_count': 'int',
        'assigned_to': 'NoneType',
        'security_category_count': 'int',
        'follow_up': 'bool',
        'source_address_ids': 'str',
        'source_count': 'int',
        'inactive': 'bool',
        'protected': 'bool',
        'closing_user': 'str',
        'destination_networks': 'str',
        'source_network': 'str',
        'category_count': 'int',
        'close_time': 'str',
        'remote_destination_count': 'int',
        'start_time': 'str',
        'magnitude': 'int',
        'last_updated_time': 'str',
        'credibility': 'int',
        'id': 'int',
        'categories': 'str',
        'severity': 'int',
        'policy_category_count': 'int',
        'closing_reason_id': 'str',
        'device_count': 'int',
        'offense_type': 'str',
        'relevance': 'int',
        'domain_id': 'int',
        'offense_source': 'str',
        'local_destination_address_ids': 'int',
        'local_destination_count': 'int',
        'status': 'str',
        'domain_name': 'str'
    }
    events = {
        'events': {
            'qidname_qid': 'str',
            'logsourcename_logsourceid': 'str',
            'categoryname_highlevelcategory': 'str',
            'categoryname_category': 'str',
            'protocolname_protocolid': 'str',
            'sourceip': 'str',
            'sourceport': 'int',
            'destinationip': 'str',
            'destinationport': 'int',
            'qiddescription_qid': 'str',
            'username': 'NoneType',
            'rulename_creeventlist': 'str',
            'sourcegeographiclocation': 'str',
            'sourceMAC': 'str',
            'sourcev6': 'str',
            'destinationgeographiclocation': 'str',
            'destinationv6': 'str',
            'logsourcetypename_devicetype': 'str',
            'credibility': 'int',
            'severity': 'int',
            'magnitude': 'int',
            'eventcount': 'int',
            'eventDirection': 'str',
            'postNatDestinationIP': 'str',
            'postNatDestinationPort': 'int',
            'postNatSourceIP': 'str',
            'postNatSourcePort': 'int',
            'preNatDestinationPort': 'int',
            'preNatSourceIP': 'str',
            'preNatSourcePort': 'int',
            'utf8_payload': 'str',
            'starttime': 'str',
            'devicetime': 'int'
        }
    }
    assets = {
        'assets': {
            'interfaces': {
                'mac_address': 'str',
                'ip_addresses': {
                    'type': 'str',
                    'value': 'str'
                },
                'id': 'int',
                'Unified Name': 'str',
                'Technical User': 'str',
                'Switch ID': 'str',
                'Business Contact': 'str',
                'CVSS Availability Requirement': 'str',
                'Compliance Notes': 'str',
                'Primary OS ID': 'str',
                'Compliance Plan': 'str',
                'Switch Port ID': 'str',
                'Weight': 'str',
                'Location': 'str',
                'CVSS Confidentiality Requirement': 'str',
                'Technical Contact': 'str',
                'Technical Owner': 'str',
                'CVSS Collateral Damage Potential': 'str',
                'Description': 'str',
                'Business Owner': 'str',
                'CVSS Integrity Requirement': 'str'
            },
            'id': 'int',
            'domain_id': 'int',
            'domain_name': 'str'
        }
    }
    custom_fields = {
        'events': {field.get('name'): field.get('property_type')
                   for field in client.custom_properties()
                   if 'name' in field and 'property_type' in field}
    }
    fields = {
        'Offense': offense,
        'Events: Builtin Fields': events,
        'Events: Custom Fields': custom_fields,
        'Assets': assets,
    }
    return fields


def get_remote_data_command(client: Client, params: Dict[str, Any], args: Dict) -> GetRemoteDataResponse:
    """
    get-remote-data command: Returns an updated incident and entries

    Args:
        client (Client): QRadar client to perform the API calls.
        params (Dict): Demisto params.
        args (Dict):
            id: Offense id to retrieve.
            lastUpdate: When was the last time we data was retrieved in Epoch.

    Returns:
        GetRemoteDataResponse.
    """
    remote_args = GetRemoteDataArgs(args)
    ip_enrich, asset_enrich = get_offense_enrichment(params.get('enrichment', 'IPs And Assets'))
    offense_id = remote_args.remote_incident_id
    offense = client.offenses_list(offense_id=offense_id)
    offense_last_update = get_time_parameter(offense.get('last_persisted_time'))

    # versions below 6.1 compatibility
    last_update = get_time_parameter(args.get('lastUpdate'))
    if last_update and last_update > offense_last_update:
        demisto.debug('Nothing new in the ticket')
        return GetRemoteDataResponse({'id': offense_id, 'in_mirror_error': ''}, [])

    demisto.debug(f'Updating offense. Offense last update was {offense_last_update}')
    entries = []
    if offense.get('status') == 'CLOSED' and argToBoolean(params.get('close_incident', False)):
        demisto.debug(f'Offense is closed: {offense}')
        if closing_reason := offense.get('closing_reason_id', ''):
            closing_reason = client.closing_reasons_list(closing_reason).get('text')
        offense_close_time = offense.get('close_time', '')
        closed_offense_notes = client.offense_notes_list(offense_id, f'items={DEFAULT_RANGE_VALUE}',
                                                         filter_=f'create_time >= {offense_close_time}')
        # In QRadar UI, when you close a reason, a note is added with the reason and more details. Try to get note
        # if exists, else fallback to closing reason only, as closing QRadar through an API call does not create a note.
        close_reason_with_note = next((note.get('note_text') for note in closed_offense_notes if
                                       note.get('note_text').startswith('This offense was closed with reason:')),
                                      closing_reason)
        if not close_reason_with_note:
            print_debug_msg(f'Could not find closing reason or closing note for offense with offense id {offense_id}')
            close_reason_with_note = 'Unknown closing reason from QRadar'
        else:
            close_reason_with_note = f'From QRadar: {close_reason_with_note}'

        entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': close_reason_with_note
            },
            'ContentsFormat': EntryFormat.JSON
        })

    enriched_offense = enrich_offenses_result(client, offense, ip_enrich, asset_enrich)
    final_offense_data = sanitize_outputs(enriched_offense)[0]

    return GetRemoteDataResponse(final_offense_data, entries)


def get_modified_remote_data_command(client: Client, params: Dict[str, str],
                                     args: Dict[str, str]) -> GetModifiedRemoteDataResponse:
    """
    Performs API calls to QRadar service, querying for offenses that were updated in QRadar later than
    the last update time given in the argument 'lastUpdate'.
    Args:
        client (Client): QRadar client to perform the API calls.
        params (Dict): Demisto params.
        args (Dict): Demisto arguments.

    Returns:
        (GetModifiedRemoteDataResponse): IDs of the offenses that have been modified in QRadar.
    """
    ctx = get_integration_context()
    remote_args = GetModifiedRemoteDataArgs(args)
    highest_fetched_id = json.loads(ctx.get(LAST_FETCH_KEY, '0'))
    limit: int = int(params.get('mirror_limit', MAXIMUM_MIRROR_LIMIT))
    range_ = f'items=0-{limit - 1}'
    last_update_time = json.loads(ctx.get('last_mirror_update', '""'))
    if not last_update_time:
        last_update_time = remote_args.last_update
    last_update = get_time_parameter(last_update_time, epoch_format=True)

    offenses = client.offenses_list(range_=range_,
                                    filter_=f'id <= {highest_fetched_id} AND last_persisted_time > {last_update}',
                                    sort='+last_persisted_time',
                                    fields='id,last_persisted_time')
    new_modified_records_ids = [str(offense.get('id')) for offense in offenses if 'id' in offense]

    current_last_update = last_update if not offenses else offenses[-1].get('last_persisted_time')
    set_to_integration_context_with_retries({'last_mirror_update': json.dumps(current_last_update)})

    return GetModifiedRemoteDataResponse(new_modified_records_ids)


def change_ctx_to_be_compatible_with_retry() -> None:
    """
    In order to move QRadar from using set_integration_context to set_to_integration_context_with_retries, the fields
    need to change to JSON strings.
    Change is required due to race condition occurring between get-modified-remote-data to long-running-execution.

    Because some customers already have instances running where fields are not JSON fields, this function is needed
    to make them be compatible with new changes.
    Returns:
        (None): Modifies context to be compatible.
    """
    ctx = get_integration_context()
    if not ctx.get('retry_compatible'):
        ctx[LAST_FETCH_KEY] = json.dumps(ctx.get(LAST_FETCH_KEY, 0))
        ctx['samples'] = json.dumps(ctx.get('samples', []))
        ctx['last_mirror_update'] = json.dumps(ctx.get('last_mirror_update', ''))
        ctx['retry_compatible'] = True
        set_integration_context(ctx)


''' MAIN FUNCTION '''


def main() -> None:
    change_ctx_to_be_compatible_with_retry()
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    # handle allowed advanced parameters
    adv_params = params.get('adv_params')
    if adv_params:
        try:
            globals_ = globals()
            for adv_p in adv_params.split(','):
                adv_p_kv = [item.strip() for item in adv_p.split('=')]
                if len(adv_p_kv) != 2:
                    raise DemistoException(
                        f'Failed to parse advanced parameter: {adv_p} - please make sure you entered it correctly.')
                adv_param_name = adv_p_kv[0]
                if adv_param_name in ADVANCED_PARAMETERS_STRING_NAMES:
                    globals_[adv_p_kv[0]] = adv_p_kv[1]
                elif adv_param_name in ADVANCED_PARAMETER_INT_NAMES:
                    globals_[adv_p_kv[0]] = int(adv_p_kv[1])
                else:
                    raise DemistoException(
                        f'The parameter: {adv_p_kv[0]} is not a valid advanced parameter. Please remove it')
        except DemistoException as e:
            raise DemistoException(f'Failed to parse advanced params. Error: {e.message}')
        except Exception as e:
            raise DemistoException(f'Failed to parse advanced params. Error: {e}')

    server = params.get('server')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_version = params.get('api_version')
    if float(api_version) < MINIMUM_API_VERSION:
        raise DemistoException(f'API version cannot be lower than {MINIMUM_API_VERSION}')
    credentials = params.get('credentials')

    try:

        client = Client(
            server=server,
            verify=verify_certificate,
            proxy=proxy,
            api_version=api_version,
            credentials=credentials)
        # All command names with or are for supporting QRadar v2 command names for backward compatibility
        if command == 'test-module':
            return_results(test_module_command(client, params))

        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents_command())

        elif command == 'long-running-execution':
            long_running_execution_command(client, params)

        elif command == 'qradar-offenses-list' or command == 'qradar-offenses' or command == 'qradar-offense-by-id':
            return_results(qradar_offenses_list_command(client, args))

        elif command == 'qradar-offense-update' or command == 'qradar-update-offense':
            return_results(qradar_offense_update_command(client, args))

        elif command == 'qradar-closing-reasons' or command == 'qradar-get-closing-reasons':
            return_results(qradar_closing_reasons_list_command(client, args))

        elif command == 'qradar-offense-notes-list' or command == 'qradar-get-note':
            return_results(qradar_offense_notes_list_command(client, args))

        elif command == 'qradar-offense-note-create' or command == 'qradar-create-note':
            return_results(qradar_offense_notes_create_command(client, args))

        elif command == 'qradar-rules-list':
            return_results(qradar_rules_list_command(client, args))

        elif command == 'qradar-rule-groups-list':
            return_results(qradar_rule_groups_list_command(client, args))

        elif command == 'qradar-assets-list' or command == 'qradar-get-assets' or command == 'qradar-get-asset-by-id':
            return_results(qradar_assets_list_command(client, args))

        elif command == 'qradar-saved-searches-list':
            return_results(qradar_saved_searches_list_command(client, args))

        elif command == 'qradar-searches-list':
            return_results(qradar_searches_list_command(client, args))

        elif command == 'qradar-search-create' or command == 'qradar-searches':
            return_results(qradar_search_create_command(client, args))

        elif command == 'qradar-search-status-get' or command == 'qradar-get-search':
            return_results(qradar_search_status_get_command(client, args))

        elif command == 'qradar-search-results-get' or command == 'qradar-get-search-results':
            return_results(qradar_search_results_get_command(client, args))

        elif command == 'qradar-reference-sets-list' or command == 'qradar-get-reference-by-name':
            return_results(qradar_reference_sets_list_command(client, args))

        elif command == 'qradar-reference-set-create' or command == 'qradar-create-reference-set':
            return_results(qradar_reference_set_create_command(client, args))

        elif command == 'qradar-reference-set-delete' or command == 'qradar-delete-reference-set':
            return_results(qradar_reference_set_delete_command(client, args))

        elif command == 'qradar-reference-set-value-upsert' or command == 'qradar-create-reference-set-value' or \
                command == 'qradar-update-reference-set-value':
            return_results(qradar_reference_set_value_upsert_command(client, args))

        elif command == 'qradar-reference-set-value-delete' or command == 'qradar-delete-reference-set-value':
            return_results(qradar_reference_set_value_delete_command(client, args))

        elif command == 'qradar-domains-list' or command == 'qradar-get-domains' or \
                command == 'qradar-get-domain-by-id':
            return_results(qradar_domains_list_command(client, args))

        elif command == 'qradar-indicators-upload' or command == 'qradar-upload-indicators':
            return_results(qradar_indicators_upload_command(client, args))

        elif command == 'qradar-geolocations-for-ip':
            return_results(qradar_geolocations_for_ip_command(client, args))

        elif command == 'qradar-log-sources-list':
            return_results(qradar_log_sources_list_command(client, args))

        elif command == 'qradar-get-custom-properties':
            return_results(qradar_get_custom_properties_command(client, args))

        elif command == 'qradar-ips-source-get':
            return_results(qradar_ips_source_get_command(client, args))

        elif command == 'qradar-ips-local-destination-get':
            return_results(qradar_ips_local_destination_get_command(client, args))

        elif command == 'qradar-reset-last-run':
            return_results(qradar_reset_last_run_command())

        elif command == 'get-mapping-fields':
            return_results(qradar_get_mapping_fields_command(client))

        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, params, args))

        elif command == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, params, args))

        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
