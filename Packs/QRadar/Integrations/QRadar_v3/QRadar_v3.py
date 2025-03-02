import concurrent.futures
import secrets
from enum import Enum
from ipaddress import ip_address
from urllib import parse
import uuid

import pytz
import urllib3
from CommonServerUserPython import *  # noqa

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' ADVANCED GLOBAL PARAMETERS '''

FAILURE_SLEEP = 20  # sleep between consecutive failures events fetch
FETCH_SLEEP = arg_to_number(demisto.params().get("fetch_interval")) or 60  # sleep between fetches
BATCH_SIZE = 100  # batch size used for offense ip enrichment
OFF_ENRCH_LIMIT = BATCH_SIZE * 10  # max amount of IPs to enrich per offense
MAX_WORKERS = 8  # max concurrent workers used for events enriching
DOMAIN_ENRCH_FLG = 'true'  # when set to true, will try to enrich offense and assets with domain names
RULES_ENRCH_FLG = 'true'  # when set to true, will try to enrich offense with rule names
SLEEP_FETCH_EVENT_RETRIES = 10  # sleep between iteration to try search the events of an offense
MAX_NUMBER_OF_OFFENSES_TO_CHECK_SEARCH = 5  # Number of offenses to check during mirroring if search was completed.
DEFAULT_EVENTS_TIMEOUT = 30  # default timeout for the events enrichment in minutes
PROFILING_DUMP_ROWS_LIMIT = 20
MAX_RETRIES_CONTEXT = 5  # max number of retries to update the context
MAX_SEARCHES_QUEUE = 10  # maximum number of concurrent searches in mirroring

SAMPLE_SIZE = 2  # number of samples to store in integration context
EVENTS_INTERVAL_SECS = 60  # interval between events polling
EVENTS_MODIFIED_SECS = 5  # interval between events status polling in modified

EVENTS_SEARCH_TRIES = 3  # number of retries for creating a new search
EVENTS_POLLING_TRIES = 10  # number of retries for events polling
EVENTS_SEARCH_RETRY_SECONDS = 100  # seconds between retries to create a new search
CONNECTION_ERRORS_RETRIES = 5  # num of times to retry in case of connection-errors
CONNECTION_ERRORS_INTERVAL = 1  # num of seconds between each time to send an http-request in case of a connection error.


ADVANCED_PARAMETERS_STRING_NAMES = [
    'DOMAIN_ENRCH_FLG',
    'RULES_ENRCH_FLG',
]
ADVANCED_PARAMETER_INT_NAMES = [
    'EVENTS_INTERVAL_SECS',
    'MAX_SEARCHES_QUEUE',
    'EVENTS_SEARCH_RETRIES',
    'EVENTS_POLLING_RETRIES',
    'EVENTS_SEARCH_RETRY_SECONDS',
    'FAILURE_SLEEP',
    'FETCH_SLEEP',
    'BATCH_SIZE',
    'OFF_ENRCH_LIMIT',
    'MAX_WORKERS',
    'SLEEP_FETCH_EVENT_RETRIES',
    'DEFAULT_EVENTS_TIMEOUT',
    'PROFILING_DUMP_ROWS_LIMIT',
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
DEFAULT_MIRRORING_DIRECTION = 'No Mirroring'
MIRROR_OFFENSE_AND_EVENTS = 'Mirror Offense and Events'
MIRROR_DIRECTION: dict[str, Optional[str]] = {
    'No Mirroring': None,
    'Mirror Offense': 'In',
    MIRROR_OFFENSE_AND_EVENTS: 'In'
}
MIRRORED_OFFENSES_QUERIED_CTX_KEY = 'mirrored_offenses_queried'
MIRRORED_OFFENSES_FINISHED_CTX_KEY = 'mirrored_offenses_finished'
MIRRORED_OFFENSES_FETCHED_CTX_KEY = 'mirrored_offenses_fetched'

LAST_MIRROR_KEY = 'last_mirror_update'
LAST_MIRROR_CLOSED_KEY = 'last_mirror_closed_update'

UTC_TIMEZONE = pytz.timezone('utc')
ID_QUERY_REGEX = re.compile(r'(?:\s+|^)id((\s)*)>(=?)((\s)*)((\d)+)(?:\s+|$)')
NAME_AND_GROUP_REGEX = re.compile(r'^[\w-]+$')
ASCENDING_ID_ORDER = '+id'
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)

DEFAULT_EVENTS_COLUMNS = """QIDNAME(qid), LOGSOURCENAME(logsourceid), CATEGORYNAME(highlevelcategory), CATEGORYNAME(category), PROTOCOLNAME(protocolid), sourceip, sourceport, destinationip, destinationport, QIDDESCRIPTION(qid), username, PROTOCOLNAME(protocolid), RULENAME("creEventList"), sourcegeographiclocation, sourceMAC, sourcev6, destinationgeographiclocation, destinationv6, LOGSOURCETYPENAME(devicetype), credibility, severity, magnitude, eventcount, eventDirection, postNatDestinationIP, postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationPort, preNatSourceIP, preNatSourcePort, UTF8(payload), starttime, devicetime"""  # noqa: E501
DEFAULT_ASSETS_LIMIT = 100

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

CLOSING_REASONS_RAW_FORMATTED = {
    'id': 'ID',
    'text': 'Name',
    'is_reserved': 'IsReserved',
    'is_deleted': 'IsDeleted'
}

NOTES_RAW_FORMATTED = {
    'id': 'ID',
    'note_text': 'Text',
    'create_time': 'CreateTime',
    'username': 'CreatedBy'
}

RULES_RAW_FORMATTED = {
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

RULES_GROUP_RAW_FORMATTED = {
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

ASSET_RAW_FORMATTED = {
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

SEARCH_RAW_FORMATTED = {'search_id': 'ID', 'status': 'Status'}

REFERENCE_SETS_RAW_FORMATTED = {
    'number_of_elements': 'NumberOfElements',
    'name': 'Name',
    'creation_time': 'CreationTime',
    'element_type': 'ElementType',
    'time_to_live': 'TimeToLive',
    'timeout_type': 'TimeoutType',
    'data': 'Data',
}
REFERENCE_SET_DATA_RAW_FORMATTED = {
    'last_seen': 'LastSeen',
    'source': 'Source',
    'value': 'Value',
    'first_seen': 'FirstSeen'
}

DOMAIN_RAW_FORMATTED = {
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

SAVED_SEARCH_RAW_FORMATTED = {
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

IP_GEOLOCATION_RAW_FORMATTED = {
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

LOG_SOURCES_RAW_FORMATTED = {
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
    'status': 'Status',
    'target_event_collector_id': 'TargetEventCollectorID'
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

LOCAL_DESTINATION_IPS_RAW_FORMATTED = {
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
SOURCE_IPS_RAW_FORMATTED = {
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

EVENT_COLLECTOR_RAW_FORMATTED = {
    'component_name': 'ComponentName',
    'host_id': 'HostID',
    'id': 'ID',
    'name': 'Name'
}

WINCOLLECT_DESTINATION_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'Name',
    'host': 'Host',
    'tls_certificate': 'TlsCertificate',
    'port': 'Port',
    'transport_protocol': 'TransportProtocol',
    'inernal': 'IsInternal',
    'event_rate_throttle': 'EventRateThrottle'
}

DISCONNECTED_LOG_COLLECTOR_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'Name',
    'description': 'Description',
    'protocol': 'Protocol',
    'uuid': 'UUID',
    'version': 'Version'
}

LOG_SOURCE_TYPES_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'Name',
    'custom': 'Custom',
    'version': 'Version',
    'uuid': 'UUID',
    'supported_language_ids': 'SupportedLanguageIDs',
    'protocol_types': 'ProtocolTypes',
    'default_protocol_id': 'DefaultProtocolID',
    'internal': 'Internal',
    'latest_version': 'LatestVersion',
    'log_source_extension_id': 'LogSourceExtensionID',
}

LOG_SOURCE_PROTOCOL_TYPE_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'Name',
    'version': 'Version',
    'latest_version': 'LatestVersion',
    'gateway_supported': 'GatewaySupported',
    'inbound': 'Inbound',
    'parameters': 'Parameters',
    'parameter_groups': 'ParameterGroups',
    'testing_capabilities': 'TestingCapabilities'
}

LOG_SOURCE_EXTENSION_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'Name',
    'description': 'Description',
    'uuid': 'UUID',
}

LOG_SOURCE_LANGUAGE_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'Name'
}

LOG_SOURCE_GROUP_RAW_FORMATTED = {
    'id': 'ID',
    'name': 'GroupName',
    'description': 'Description',
    'parent_id': 'ParentID',
    'assignable': 'Assignable'
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


class FetchMode(str, Enum):
    """
    Enums for the options of fetching the incidents.
    """
    no_events = 'Fetch Without Events'
    all_events = 'Fetch With All Events'
    correlations_events_only = 'Fetch Correlation Events Only'


class QueryStatus(str, Enum):
    """
    Enums for the options of fetching the events.
    """
    WAIT = 'wait'
    ERROR = 'error'
    SUCCESS = 'success'
    PARTIAL = 'partial'


FIELDS_MIRRORING = 'id,start_time,event_count,last_persisted_time,close_time'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(
        self, server: str, verify: bool, proxy: bool, api_version: str, credentials: dict, timeout: Optional[int] = None
    ):
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
        self.timeout = timeout  # type: ignore[assignment]
        self.password = password
        self.server = server

    def http_request(self, method: str, url_suffix: str, params: Optional[dict] = None,
                     json_data: Optional[dict | list[dict]] = None, data: Optional[dict] = None,
                     additional_headers: Optional[dict] = None,
                     timeout: Optional[int] = None, resp_type: str = 'json') -> Any:
        headers = {**additional_headers, **self.base_headers} if additional_headers else self.base_headers
        for _time in range(1, CONNECTION_ERRORS_RETRIES + 1):
            try:
                return self._http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    json_data=json_data,
                    data=data,
                    headers=headers,
                    error_handler=self.qradar_error_handler,
                    timeout=timeout or self.timeout,
                    resp_type=resp_type,
                    with_metrics=True
                )
            except (DemistoException, requests.ReadTimeout) as error:
                demisto.error(f'Error {error} in time {_time}')
                if (
                    isinstance(
                        error, DemistoException
                    ) and not isinstance(
                        error.exception, requests.ConnectionError) or _time == CONNECTION_ERRORS_RETRIES
                ):
                    raise
                else:
                    time.sleep(CONNECTION_ERRORS_INTERVAL)  # pylint: disable=sleep-exists
        return None

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
                message = 'The specified encryption is not available, try using a weaker encryption (AES128).'
            elif 'User has insufficient capabilities to access this endpoint resource' in message:
                message = 'The given credentials do not have the needed permissions to perform the call the endpoint' \
                    f'\n{res.request.path_url}.\n' \
                    'Please supply credentials with the needed permissions as can be seen in the integration ' \
                    'description, or do not call or enrich offenses with the mentioned endpoint.'
            err_msg += f'\n{message}'
            raise DemistoException(err_msg, res=res)
        except ValueError as e:
            err_msg += f'\n{res.text}'
            raise DemistoException(err_msg, res=res) from e

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

    def search_delete(self, search_id: str):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/ariel/searches/{search_id}',
        )

    def search_cancel(self, search_id: str):
        return self.http_request(
            method='POST',
            url_suffix=f'/ariel/searches/{search_id}?status=CANCELED',
        )

    def search_results_get(self, search_id: str, range_: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}/results',
            additional_headers={'Range': range_} if range_ else None
        )

    def reference_sets_list(self, range_: Optional[str] = None, ref_name: Optional[str] = None,
                            filter_: Optional[str] = None, fields: Optional[str] = None):
        name_suffix = f'/{parse.quote(ref_name, safe="")}' if ref_name else ''
        params = assign_params(filter=filter_, fields=fields)
        additional_headers = {'Range': range_}
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
            url_suffix=f'/reference_data/sets/{parse.quote(parse.quote(ref_name, safe=""), safe="")}',
            params=assign_params(purge_only=purge_only, fields=fields)
        )

    def reference_set_value_upsert(self, ref_name: str, value: str, source: Optional[str] = None,
                                   fields: Optional[str] = None):
        return self.http_request(
            method='POST',
            url_suffix=f'/reference_data/sets/{parse.quote(ref_name, safe="")}',
            params=assign_params(value=value, source=source, fields=fields)
        )

    def reference_set_value_delete(self, ref_name: str, value: str):
        double_encoded_value = parse.quote(parse.quote(value, safe=""), safe="")
        double_encoded_ref_name = parse.quote(parse.quote(ref_name, safe=""), safe="")
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{double_encoded_ref_name}/{double_encoded_value}'
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

    def reference_set_bulk_load(self, ref_name: str, indicators: Any, fields: Optional[str] = None):
        headers = {
            'Content-Type': 'application/json'
        }
        if fields:
            headers['fields'] = fields
        return self.http_request(
            method='POST',
            url_suffix=f'/reference_data/sets/bulk_load/{parse.quote(ref_name, safe="")}',
            json_data=indicators,
            additional_headers=headers
        )

    def reference_set_entries(
        self,
        ref_name: str,
        indicators: Any,
        fields: Optional[str] = None,
        source: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        headers = {
            'Content-Type': 'application/json'
        }
        if fields:
            headers['fields'] = fields
        name = parse.quote(ref_name, safe='')
        sets = self.http_request(method='GET', url_suffix=f'/reference_data/sets/{name}')
        if not sets:
            raise DemistoException(f'Reference set {ref_name} does not exist.')
        set_id = sets.get('collection_id')
        return self.http_request(
            method='PATCH',
            url_suffix='/reference_data_collections/set_entries',
            json_data=[{"collection_id": set_id, "value": str(indicator), "source": source}
                       for indicator in indicators],  # type: ignore[arg-type]
            additional_headers=headers,
            timeout=timeout
        )

    def get_reference_data_bulk_task_status(self, task_id: int):
        return self.http_request(
            method='GET',
            url_suffix=f'/reference_data_collections/set_bulk_update_tasks/{task_id}'
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

    def get_log_source(self, qrd_encryption_algorithm: str, qrd_encryption_password: str, id: str,
                       fields: Optional[str] = None):
        return self.http_request(
            method='GET',
            url_suffix=f'/config/event_sources/log_source_management/log_sources/{id}',
            params=assign_params(fields=fields),
            additional_headers={
                'x-qrd-encryption-algorithm': qrd_encryption_algorithm,
                'x-qrd-encryption-password': qrd_encryption_password
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

    def create_and_update_remote_network_cidr(self, body: dict[str, Any], fields: str, update: bool = False):
        headers = {'fields': fields}

        return self.http_request(
            method='POST',
            url_suffix='/staged_config/remote_networks' + (f'/{body.get("id")}' if update else ''),
            json_data=body,
            additional_headers=headers
        )

    def get_remote_network_cidr(self, range_: Optional[str] = None, filter_: Optional[str] = None, fields: Optional[str] = None):
        headers = {'Range': range_}
        params = assign_params(filter=filter_, fields=fields)

        return self.http_request(
            method='GET',
            url_suffix='/staged_config/remote_networks',
            params=params,
            additional_headers=headers
        )

    def delete_remote_network_cidr(self, id_):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/staged_config/remote_networks/{id_}',
            resp_type='response'
        )

    def remote_network_deploy_execution(self, body):
        return self.http_request(
            method='POST',
            url_suffix='/staged_config/deploy_status',
            json_data=body
        )

    def get_resource_list(
            self,
            range_: str,
            endpoint: str,
            filter_: Optional[str] = None,
            fields: Optional[str] = None,
            additional_headers_: Optional[dict] = None):
        """
        Retrieve a list of resources from a specified endpoint.

        Args:
            range_ (str): The range of resources to retrieve. eg. items=0-49
            endpoint (str): The API endpoint to retrieve resources from.
            filter_ (Optional[str], optional): Optional filter query for the request. Defaults to None.
            fields (Optional[str], optional): The fields that the API should return. Defaults to None.
            additional_headers_ (Optional[dict], optional): Optional additional headers for the request. Defaults to None.

        Returns:
            Response: The response object from the HTTP request.
        """
        return self.http_request(
            method='GET',
            url_suffix=endpoint,
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={
                'Range': range_
            } if additional_headers_ is None
            else {
                'Range': range_,
                **additional_headers_
            }
        )

    def get_resource_by_id(self, id: str, endpoint: str, fields: Optional[str] = None, additional_headers: Optional[dict] = None):
        return self.http_request(
            method='GET',
            url_suffix=endpoint + f'/{id}',
            params=assign_params(fields=fields),
            additional_headers=additional_headers
        )

    def get_resource(
            self,
            id,
            range_: str,
            endpoint: str,
            filter_: Optional[str] = None,
            fields: Optional[str] = None,
            additional_headers_: Optional[dict] = None):
        return self.get_resource_list(range_, endpoint, filter_, fields, additional_headers_) if id is None \
            else [self.get_resource_by_id(id, endpoint, fields, additional_headers_)]

    def delete_log_source(self, id: str) -> requests.Response:
        return self.http_request(
            method='DELETE',
            url_suffix=f'/config/event_sources/log_source_management/log_sources/{id}',
            resp_type='response'
        )

    def create_log_source(self, log_source: dict):
        return self.http_request(
            method='POST',
            url_suffix='/config/event_sources/log_source_management/log_sources',
            json_data=log_source
        )

    def update_log_source(self, log_source: dict[str, Any]):
        return self.http_request(
            method='PATCH',
            url_suffix='/config/event_sources/log_source_management/log_sources',
            json_data=[log_source],
            resp_type='response'
        )

    def test_connection(self):
        """
        Test connection with databases (should always be up)
        """
        self.http_request(method='GET', url_suffix='/ariel/databases')
        return 'ok'


''' HELPER FUNCTIONS '''


def get_major_version(version: str) -> int:
    try:
        if '.' not in version:
            return int(version)
        return int(version.split('.')[0])
    except ValueError:
        print_debug_msg(f'Could not parse version {version} to int')
        return 17


def insert_values_to_reference_set_polling(client: Client,
                                           api_version: str,
                                           args: dict,
                                           from_indicators: bool = False,
                                           values: list[str] | None = None,
                                           ) -> PollResult:
    """This function inserts values to reference set using polling method.


    Args:
        client (Client): QRadar Client
        api_version (str): The API version of QRadar.
        args (dict): args of the command
        from_indicators (bool, optional): Whether to insert values from XSOAR indicators. Defaults to False.
        values (list[str] | None, optional): The values to insert. Defaults to None.

    Raises:
        DemistoException: If there are no values to insert

    Returns:
        PollResult: The result with the CommandResults
    """
    response = {}
    use_old_api = get_major_version(api_version) <= 15
    ref_name = args.get('ref_name', '')
    try:
        if use_old_api or 'task_id' not in args:
            if from_indicators:
                query = args.get('query')
                limit = arg_to_number(args.get('limit', DEFAULT_LIMIT_VALUE))
                page = arg_to_number(args.get('page', 0))

                # Backward compatibility for QRadar V2 command. Create reference set for given 'ref_name' if does not exist.
                element_type = args.get('element_type', '')
                timeout_type = args.get('timeout_type')
                time_to_live = args.get('time_to_live')
                try:
                    client.reference_sets_list(ref_name=ref_name)
                except DemistoException as e:
                    # Create reference set if does not exist
                    if e.message and f'{ref_name} does not exist' in e.message:
                        # if this call fails, raise an error and stop command execution
                        client.reference_set_create(ref_name, element_type, timeout_type, time_to_live)
                    else:
                        raise e

                search_indicators = IndicatorsSearcher(page=page)
                indicators = search_indicators.search_indicators_by_version(query=query, size=limit).get('iocs', [])
                indicators_data = [{'Indicator Value': indicator.get('value'), 'Indicator Type': indicator.get('indicator_type')}
                                   for indicator in indicators if 'value' in indicator and 'indicator_type' in indicator]
                values = [indicator.get('Indicator Value', '') for indicator in indicators_data]
                if not indicators_data:
                    return PollResult(CommandResults(
                        readable_output=f'No indicators were found for reference set {ref_name}',
                    ))

            if not values:
                raise DemistoException('Value to insert must be given.')
            source = args.get('source')
            date_value = argToBoolean(args.get('date_value', False))
            fields = args.get('fields')

            if date_value:
                values = [get_time_parameter(value, epoch_format=True) for value in values]
            if use_old_api:
                response = client.reference_set_bulk_load(ref_name, values, fields)
            else:
                response = client.reference_set_entries(ref_name, values, fields, source, timeout=300)
                args['task_id'] = response.get('id')
        if not use_old_api:
            response = client.get_reference_data_bulk_task_status(args["task_id"])
    except (DemistoException, requests.Timeout) as e:
        if 'task_id' in args:
            print_debug_msg(
                f"Polling task status {args['task_id']} failed due to {e}. "
                f"Will try to poll task status again in the next interval."
            )
        else:
            print_debug_msg(
                f"Failed inserting values to reference due to {e}, will retry in the insert in the next interval"
            )
        response = {}
    if use_old_api or response.get("status") == "COMPLETED":
        if not use_old_api:
            # get the reference set data
            response = client.reference_sets_list(ref_name=ref_name)
        key_replace_dict = {
            k: v for k, v in REFERENCE_SETS_RAW_FORMATTED.items()
            if k != "data" or not argToBoolean(args.get("quiet_mode") or False)
        }
        outputs = sanitize_outputs(response, key_replace_dict)

        command_results = CommandResults(
            readable_output=tableToMarkdown('Reference Update Create', outputs, removeNull=True),
            outputs_prefix='QRadar.Reference',
            outputs_key_field='Name',
            outputs=outputs,
            raw_response=response
        )
        return PollResult(command_results, continue_to_poll=False)
    return PollResult(
        partial_result=CommandResults(
            readable_output=f'Reference set {ref_name} is still being updated in task {args["task_id"]}'),
        continue_to_poll=True,
        args_for_next_run=args,
        response=None
    )


def get_remote_events(client: Client,
                      offense_id: str,
                      context_data: dict,
                      context_version: Any,
                      events_columns: str,
                      events_limit: int,
                      fetch_mode: str,
                      ) -> tuple[list[dict], str]:
    """
    Get the remote events of the `offense_id`
    It will update the context data as well

    Args:
        client (Client): QRadar client
        offense_id (str): Offense id to update
        context_data (dict): The current context data
        context_version (Any): The current context version
        events_columns (str): events columns of AQL
        events_limit (int): events limit of AQL
        fetch_mode (str): The fetch mode configure

    Returns:
        Tuple[list[dict], SearchQueryStatus]: List of events of the offense id, the status of the request
    """
    changed_ids_ctx = []
    offenses_queried = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    offenses_finished = context_data.get(MIRRORED_OFFENSES_FINISHED_CTX_KEY, {})
    offenses_fetched = context_data.get(MIRRORED_OFFENSES_FETCHED_CTX_KEY, {})

    events: list[dict] = []
    status = QueryStatus.ERROR.value
    if offenses_queried.get(offense_id) == QueryStatus.ERROR.value:
        return events, QueryStatus.ERROR.value
    if offense_id not in offenses_finished or \
            offenses_queried.get(offense_id, '') in {QueryStatus.WAIT.value, QueryStatus.ERROR.value}:
        # if our offense not in the finished list, we will create a new search
        # the value will be error because we don't want to wait until the search is complete
        search_id = create_events_search(client, fetch_mode, events_columns, events_limit, int(offense_id))
        offenses_queried[offense_id] = search_id
        changed_ids_ctx.append(offense_id)
    elif offense_id in offenses_finished:  # if our offense is in finished list, we will get the result
        search_id = offenses_finished[offense_id]
        try:
            search_results = client.search_results_get(search_id)
            events = search_results.get('events', [])
            del offenses_finished[offense_id]
            changed_ids_ctx.append(offense_id)
            status = QueryStatus.SUCCESS.value
        except Exception as e:
            # getting results failed, move back to queried queue to be queried again
            del offenses_finished[offense_id]
            changed_ids_ctx.append(offense_id)
            offenses_queried[offense_id] = QueryStatus.ERROR.value
            status = QueryStatus.ERROR.value
            print_debug_msg(f'No results for {offense_id}. Error: {e}. Stopping execution')
            time.sleep(FAILURE_SLEEP)
    elif offense_id in offenses_queried:  # if our offense is in the queried list, we will get the result
        search_id = offenses_queried[offense_id]
        events, status = poll_offense_events(client, search_id, should_get_events=True, offense_id=int(offense_id))
        if status == QueryStatus.SUCCESS.value:
            del offenses_queried[offense_id]
            changed_ids_ctx.append(offense_id)

    if status == QueryStatus.SUCCESS.value:
        offenses_fetched[offense_id] = get_num_events(events)
        context_data.update({MIRRORED_OFFENSES_FETCHED_CTX_KEY: offenses_fetched})

    context_data.update({MIRRORED_OFFENSES_QUERIED_CTX_KEY: offenses_queried})
    context_data.update({MIRRORED_OFFENSES_FINISHED_CTX_KEY: offenses_finished})

    safely_update_context_data(context_data, context_version, offense_ids=changed_ids_ctx)
    return events, status


def update_user_query(user_query: str) -> str:
    return f' AND ({user_query})' if user_query else ''


def insert_to_updated_context(context_data: dict,
                              offense_ids: list | None = None,
                              should_update_last_fetch: bool = False,
                              should_update_last_mirror: bool = False,
                              should_add_reset_key: bool = False,
                              should_force_update: bool = False
                              ):
    """When we have a race condition, insert the changed data from context_data to the updated context data

    Args:
        context_data (dict): Context data with relevant changes.
        updated_context_data (dict): Context data that was updated before.
        offense_ids (list, optional): Offense ids that were changed. Defaults to None.
        should_update_last_fetch (bool, optional): Should update the last_fetch. Defaults to False.
        should_update_last_mirror (bool, optional): Should update the last mirror. Defaults to False.
        should_add_reset_key (bool, optional): If we should add reset key. Defaults to False
        should_force_update (bool, optional): If we should force update the current context. Defaults to False

    """
    if offense_ids is None:
        offense_ids = []
    updated_context_data, version = get_integration_context_with_version()
    new_context_data = updated_context_data.copy()
    if should_force_update:
        return context_data, version

    if should_add_reset_key:
        new_context_data[RESET_KEY] = True
    for id_ in offense_ids:
        # Those are "trusted ids" from the changed context_data, we will keep the data (either update or delete it)
        for key in (MIRRORED_OFFENSES_QUERIED_CTX_KEY, MIRRORED_OFFENSES_FINISHED_CTX_KEY, MIRRORED_OFFENSES_FETCHED_CTX_KEY):
            if id_ in context_data[key]:
                new_context_data[key][id_] = context_data[key][id_]
            else:
                new_context_data[key].pop(id_, None)

    if should_update_last_fetch:
        # Last fetch is updated with the samples that were fetched
        new_context_data.update({LAST_FETCH_KEY: int(context_data.get(LAST_FETCH_KEY, 0)),
                                 'samples': context_data.get('samples', [])})

    if should_update_last_mirror:
        new_context_data.update({LAST_MIRROR_KEY: int(context_data.get(LAST_MIRROR_KEY, 0)),
                                 LAST_MIRROR_CLOSED_KEY: int(context_data.get(LAST_MIRROR_CLOSED_KEY, 0))})
    return new_context_data, version


def safely_update_context_data(
    context_data: dict,
    version: Any,
    offense_ids: list | None = None,
    should_update_last_fetch: bool = False,
    should_update_last_mirror: bool = False,
    should_add_reset_key: bool = False,
    should_force_update: bool = False,
) -> None:
    """Safely updates context

    Args:
        context_data (dict): The context data to save (encoded)
        version (Any): The context current version
        offense_ids (list, optional): List of offenses ids to change. Defaults to None.
        should_update_last_fetch (bool, optional): If we should update last fetch. Defaults to False
        should_update_last_mirror (bool, optional): If we should update last mirror. Defaults to False
        should_add_reset_key (bool, optional): If we should add reset key. Defaults to False
        should_force_update (bool, optional): If we should force update the current context. Defaults to False


    Raises:
        DemistoException: if could not update the context_data in all retries

    Returns:
    """
    if not offense_ids and \
            not should_update_last_fetch and \
            not should_update_last_mirror and \
            not should_add_reset_key and \
            not should_force_update:
        print_debug_msg('No need to update context, no ids and no last fetch/mirror')
        return
    print_debug_msg(f'Attempting to update context data after version {version}')
    updated_context = context_data.copy()
    new_version = version
    print_context_data_stats(updated_context, 'Safely update context - Before Update')

    for retry in range(MAX_RETRIES_CONTEXT):
        try:
            updated_context, new_version = insert_to_updated_context(context_data,
                                                                     offense_ids,
                                                                     should_update_last_fetch,
                                                                     should_update_last_mirror,
                                                                     should_add_reset_key,
                                                                     should_force_update)
            print_debug_msg(f"{updated_context=}")

            set_integration_context(updated_context, version=new_version)
            print_debug_msg(f'Updated integration context after version {new_version}.')
            break
        except Exception as e:
            # if someone else is updating the context, we will get a conflict error
            print_debug_msg(f'Could not set integration context in retry {retry + 1}. '
                            f'Error: {e}. Trying to resolve conflicts')
    else:
        raise DemistoException(f'Could not update integration context with version {new_version}.')

    print_context_data_stats(updated_context, 'Safely update context - After Update')


def add_iso_entries_to_dict(dicts: List[dict]) -> List[dict]:
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


def sanitize_outputs(outputs: Any, key_replace_dict: Optional[dict] = None) -> List[dict]:
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


def build_final_outputs(outputs: List[dict], old_new_dict: dict) -> List[dict]:
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


def build_headers(first_headers: List[str], all_headers: set[str]) -> List[str]:
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


def get_offense_types(client: Client, offenses: List[dict]) -> dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the offense type names
    matching the offense type IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {offense_type_id: offense_type_name}
    """
    try:
        offense_types_ids = {offense.get('offense_type') for offense in offenses if offense.get('offense_type') is not None}
        if not offense_types_ids:
            return {}
        offense_types = client.offense_types(filter_=f'''id in ({','.join(map(str, offense_types_ids))})''',
                                             fields='id,name')
        return {offense_type.get('id'): offense_type.get('name') for offense_type in offense_types}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offense type: {e}")
        return {}


def get_offense_closing_reasons(client: Client, offenses: List[dict]) -> dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the closing reason names
    matching the closing reason IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {closing_reason_id: closing_reason_name}
    """
    try:
        closing_reason_ids = {offense.get('closing_reason_id') for offense in offenses
                              if offense.get('closing_reason_id') is not None}
        if not closing_reason_ids:
            return {}
        closing_reasons = client.closing_reasons_list(filter_=f'''id in ({','.join(map(str, closing_reason_ids))})''',
                                                      fields='id,text')
        return {closing_reason.get('id'): closing_reason.get('text') for closing_reason in closing_reasons}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offense closing reasons: {e}")
        return {}


def get_domain_names(client: Client, outputs: List[dict]) -> dict:
    """
    Receives list of outputs, and performs API call to QRadar service to retrieve the domain names
    matching the domain IDs of the outputs.
    Args:
        client (Client): Client to perform the API request to QRadar.
        outputs (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {domain_id: domain_name}
    """
    try:
        domain_ids = {offense.get('domain_id') for offense in outputs if offense.get('domain_id') is not None}
        if not domain_ids:
            return {}
        domains_info = client.domains_list(filter_=f'''id in ({','.join(map(str, domain_ids))})''', fields='id,name')
        return {domain_info.get('id'): domain_info.get('name') for domain_info in domains_info}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offense domain names: {e}")
        return {}


def get_rules_names(client: Client, offenses: List[dict]) -> dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the rules names
    matching the rule IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {rule_id: rule_name}
    """
    try:
        rules_ids = {rule.get('id') for offense in offenses for rule in offense.get('rules', [])}
        if not rules_ids:
            return {}
        rules = client.rules_list(None, None, f'''id in ({','.join(map(str, rules_ids))})''', 'id,name')
        return {rule.get('id'): rule.get('name') for rule in rules}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offenses rules: {e}")
        return {}


def get_offense_addresses(client: Client, offenses: List[dict], is_destination_addresses: bool) -> dict:
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
        try:
            return client.get_addresses(url_suffix, f'''id in ({','.join(map(str, b))})''', f'id,{address_field}')
        except Exception as e:
            demisto.error(f'Failed getting address barch with error: {e}')
            return []

    addresses_ids = [address_id for offense in offenses
                     for address_id in offense.get(address_list_field, [])]

    # Submit addresses in batches to avoid overloading QRadar service
    addresses_batches = [get_addresses_for_batch(b) for b
                         in batch(addresses_ids[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE))]

    return {address_data.get('id'): address_data.get(address_field)
            for addresses_batch in addresses_batches
            for address_data in addresses_batch}


def create_single_asset_for_offense_enrichment(asset: dict) -> dict:
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


def enrich_offense_with_assets(client: Client, offense_ips: List[str], assets_limit: int | None = 100) -> List[dict]:
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
            demisto.error(f'Failed getting assets for filter_query: {filter_query}. {e}')
            return []

    offense_ips = [offense_ip for offense_ip in offense_ips if is_valid_ip(offense_ip)]
    # Submit addresses in batches to avoid overloading QRadar service
    assets: List = []
    for b in batch(offense_ips[:OFF_ENRCH_LIMIT], batch_size=int(BATCH_SIZE)):
        assets.extend(get_assets_for_ips_batch(b))
        if assets_limit and len(assets) >= assets_limit:
            assets = assets[:assets_limit]
            break

    return [create_single_asset_for_offense_enrichment(asset) for asset in assets]


def enrich_offenses_result(client: Client, offenses: Any, enrich_ip_addresses: bool,
                           enrich_assets: bool, assets_limit: int | None = None) -> List[dict]:
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
        assets_limit (int): The limit of assets to enrich the offense with.

    Returns:
        (List[Dict]): The enriched offenses.
    """
    if not isinstance(offenses, list):
        offenses = [offenses]

    print_debug_msg('Enriching offenses')
    offense_types_id_name_dict = get_offense_types(client, offenses)
    closing_reasons_id_name_dict = get_offense_closing_reasons(client, offenses)
    domain_id_name_dict = get_domain_names(client, offenses) if DOMAIN_ENRCH_FLG.lower() == 'true' else {}
    rules_id_name_dict = get_rules_names(client, offenses) if RULES_ENRCH_FLG.lower() == 'true' else {}
    source_addresses_id_ip_dict = get_offense_addresses(client, offenses, False) if enrich_ip_addresses else {}
    destination_addresses_id_ip_dict = get_offense_addresses(client, offenses, True) if enrich_ip_addresses else {}

    def create_enriched_offense(offense: dict) -> dict:
        link_to_offense_suffix = '/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId' \
                                 f'''={offense.get('id')}'''
        offense_type = offense.get('offense_type')
        closing_reason_id = offense.get('closing_reason_id')
        domain_id = offense.get('domain_id')
        basic_enriches = {
            'offense_type': offense_types_id_name_dict.get(offense_type, offense_type),
            'closing_reason_id': closing_reasons_id_name_dict.get(closing_reason_id, closing_reason_id),
            'LinkToOffense': urljoin(client.server, link_to_offense_suffix),
        }

        domain_enrich = {
            'domain_name': domain_id_name_dict.get(domain_id, domain_id)
        } if DOMAIN_ENRCH_FLG.lower() == 'true' and domain_id_name_dict.get(domain_id, domain_id) else {}

        rules_enrich = {
            'rules': [{
                'id': rule.get('id'),
                'type': rule.get('type'),
                'name': rules_id_name_dict.get(rule.get('id'), rule.get('id'))
            } for rule in offense.get('rules', [])] if RULES_ENRCH_FLG.lower() == 'true' else {}
        }

        source_addresses_enrich = {
            'source_address_ids': [source_addresses_id_ip_dict.get(source_address_id) for source_address_id in
                                   offense.get('source_address_ids', [])]
        } if enrich_ip_addresses else {}

        destination_addresses_enrich = {
            'local_destination_address_ids': [destination_addresses_id_ip_dict.get(destination_address_id) for
                                              destination_address_id in
                                              offense.get('local_destination_address_ids', [])]
        } if enrich_ip_addresses else {}

        if enrich_assets:
            source_ips: List = source_addresses_enrich.get('source_address_ids', [])
            destination_ips: List = destination_addresses_enrich.get('local_destination_address_ids', [])
            all_ips: List = source_ips + destination_ips
            asset_enrich = {'assets': enrich_offense_with_assets(client, all_ips, assets_limit)}
        else:
            asset_enrich = {}

        return dict(offense, **basic_enriches, **domain_enrich, **rules_enrich, **source_addresses_enrich,
                    **destination_addresses_enrich, **asset_enrich)

    result = [create_enriched_offense(offense) for offense in offenses]
    print_debug_msg('Enriched offenses successfully.')
    return result


def enrich_asset_properties(properties: List, properties_to_enrich_dict: dict) -> dict:
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


def add_iso_entries_to_asset(asset: dict) -> dict:
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


def enrich_assets_results(client: Client, assets: Any, full_enrichment: bool) -> List[dict]:
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
    domain_id_name_dict = get_domain_names(client, assets) if full_enrichment else {}

    def enrich_single_asset(asset: dict) -> dict:
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

        os_enrichment = {'OS': os_name} if os_name else {}

        mac_enrichment = {
            'MACAddress': [interface.get('mac_address') for interface in interfaces if
                           interface.get('mac_address')]
        } if full_enrichment else {}

        domains_enrichment = {'Domain': domain_id_name_dict.get(domain_id, domain_id)} \
            if full_enrichment and domain_id else {}

        basic_properties_enrichment = enrich_asset_properties(properties, ASSET_PROPERTIES_NAME_MAP)
        full_properties_enrichment = enrich_asset_properties(properties,
                                                             FULL_ASSET_PROPERTIES_NAMES_MAP) \
            if full_enrichment else {}

        enriched_asset = dict(asset, **basic_properties_enrichment, **full_properties_enrichment)
        return {'Asset': add_iso_entries_to_asset(enriched_asset),
                'Endpoint': dict(ip_enrichment, **os_enrichment, **mac_enrichment,
                                 **domains_enrichment)}

    return [enrich_single_asset(asset) for asset in assets]


def get_minimum_id_to_fetch(highest_offense_id: int, user_query: Optional[str], first_fetch: str, client: Client) -> int:
    """
    Receives the highest offense ID saved from last run, and user query.
    Checks if user query has a limitation for a minimum ID.
    If such ID exists, returns the maximum between 'highest_offense_id' and the minimum ID
    limitation received by the user query.
    Args:
        highest_offense_id (int): Minimum ID to fetch offenses by from last run.
        user_query (Optional[str]): User query for QRadar service.
        first_fetch (str): First fetch timestamp.
        client (Client): Client to perform the API calls.
    Returns:
        (int): The Minimum ID to fetch offenses by.
    """
    if not highest_offense_id:
        highest_offense_id = get_min_id_from_first_fetch(first_fetch, client)
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


def get_min_id_from_first_fetch(first_fetch: str, client: Client):
    """
    Receives first_fetch integration param
    and retrieve the lowest id (earliest offense) that was created after that time.
    Args:
        first_fetch (str): First fetch timestamp.
        client (Client): Client to perform the API calls.

    Returns:
        (int): The ID of the earliest offense created after first_fetch.
    """
    filter_fetch_query = f'start_time>{str(convert_start_fetch_to_milliseconds(first_fetch))}'
    raw_offenses = client.offenses_list(filter_=filter_fetch_query, sort=ASCENDING_ID_ORDER, range_="items=0-0", fields="id")
    return int(raw_offenses[0].get('id')) - 1 if raw_offenses else 0


def arg_to_real_number(arg, arg_name=None, required=False):
    # type: (Any, Optional[str], bool) -> Optional[int | float]
    """Converts an XSOAR argument to a Python int or float

    This function acts exactly like CommonServerPython's arg_to_number, but is able to return float
    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int | float`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int | float]``
    """

    if arg is None or arg == '':
        if required is True:
            if arg_name:
                raise ValueError(f'Missing "{arg_name}"')
            else:
                raise ValueError('Missing required argument')

        return None

    arg = encode_string_results(arg)

    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)

        try:
            return float(arg)
        except Exception:
            if arg_name:
                raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
            else:
                raise ValueError(f'"{arg}" is not a valid number')
    if isinstance(arg, int):
        return arg

    if arg_name:
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    else:
        raise ValueError(f'"{arg}" is not a valid number')


def convert_start_fetch_to_milliseconds(fetch_start_time: str):
    """
    Convert a timestamp string to milliseconds
    Args:
        fetch_start_time (str): First fetch timestamp.

    Returns:
        (int): time since (epoch - first_fetch) in milliseconds.
    """
    date = dateparser.parse(fetch_start_time, settings={'TIMEZONE': 'UTC'})
    if date is None:
        # if date is None it means dateparser failed to parse it
        raise ValueError(f'Invalid first_fetch format: {fetch_start_time}')
    return int(date.timestamp() * 1000)


def convert_dict_to_actual_values(input_dict: dict) -> dict[str, Any]:
    """
    Recursively converts string representations of values in a dictionary to their actual data types.

    Args:
        input_dict (dict): A dictionary with string representations of values.

    Returns:
        dict: A dictionary with actual values (numbers, booleans, etc.).
    """
    output_dict: dict[str, Any] = {}
    for key, value in input_dict.items():
        if isinstance(value, dict):
            output_dict[key] = convert_dict_to_actual_values(value)
        elif isinstance(value, list):
            output_dict[key] = convert_list_to_actual_values(value)
        elif isinstance(value, str):
            try:
                output_dict[key] = argToBoolean(value)
            except ValueError:
                try:
                    output_dict[key] = arg_to_real_number(value)
                except ValueError:
                    output_dict[key] = value
        else:
            output_dict[key] = value
    return output_dict


def convert_list_to_actual_values(input_list: list) -> list[Any]:
    """
    Recursively converts string representations of values in a list to their actual data types.

    Args:
        input_list (list): A list with string representations of values.

    Returns:
        dict: A list with actual values (numbers, booleans, etc.).
    """
    output_list: list[Any] = []
    for value in input_list:
        if isinstance(value, dict):
            output_list.append(convert_dict_to_actual_values(value))
        elif isinstance(value, list):
            output_list.append(convert_list_to_actual_values(value))
        elif isinstance(value, str):
            try:
                output_list.append(argToBoolean(value))
            except ValueError:
                try:
                    output_list.append(arg_to_real_number(value))
                except ValueError:
                    output_list.append(value)
        else:
            output_list.append(value)
    return output_list


def parse_log_source(create_args: dict[str, Any]):
    pp_pairs = create_args.get('protocol_parameters', '').split(',')
    protocol_parameters = []
    group_ids = create_args.get('group_ids', '').split(',') if create_args.get('group_ids') else []
    wincollect_external_destination_ids = (
        create_args.get('wincollect_external_destination_ids', '').split(',') if create_args.get('group_ids')
        else []
    )
    for pair in pp_pairs:
        # Split the pair into name and value using '=' as delimiter
        name, value = pair.split('=')
        # Add the pair to the dictionary
        protocol_parameters.append({'name': name.strip(), 'value': value.strip()})
    return convert_dict_to_actual_values({
        **create_args,
        'protocol_parameters': protocol_parameters,
        'group_ids': group_ids,
        'wincollect_external_destination_ids': wincollect_external_destination_ids
    })


def parse_partial_log_source(update_args: dict[str, Any]):
    protocol_parameters = update_args.get('protocol_parameters', '').split(',') if update_args.get('protocol_parameters') else []
    group_ids = update_args.get('group_ids', '').split(',') if update_args.get('group_ids') else None
    wincollect_external_destination_ids = (
        update_args.get('wincollect_external_destination_ids', '').split(',') if update_args.get('group_ids')
        else None
    )
    if protocol_parameters:
        for pair in protocol_parameters:
            # Split the pair into name and value using '=' as delimiter
            name, value = pair.split('=')
            # Add the pair to the dictionary
            protocol_parameters.append({'name': name.strip(), 'value': value.strip()})
    log_source_str = {**update_args}
    if protocol_parameters:
        log_source_str['protocol_parameters'] = protocol_parameters
    if group_ids:
        log_source_str['group_ids'] = group_ids
    if wincollect_external_destination_ids:
        log_source_str['wincollect_external_destination_ids'] = wincollect_external_destination_ids
    return convert_dict_to_actual_values(log_source_str)


def get_offense_enrichment(enrichment: str) -> tuple[bool, bool]:
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
    Args:
        msg (str): Message to be logged.

    """
    demisto.debug(f'QRadarMsg - {msg}')


def is_reset_triggered(ctx: dict | None = None, version: Any = None):
    """
    Checks if reset of integration context have been made by the user.
    Because fetch is long running execution, user communicates with us
    by calling 'qradar-reset-last-run' command which sets reset flag in
    context.

    Args:
        ctx (dict | None): The context data to check. If it is None it will get the context from the platform.
        version: The context data version.
    Returns:
        (bool):
        - True if reset flag was set. If 'handle_reset' is true, also resets integration context.
        - False if reset flag was not found in integration context.
    """
    if not ctx or not version:
        ctx, version = get_integration_context_with_version()
    if ctx and RESET_KEY in ctx:
        # if we need to reset we have to get the version of the context
        print_debug_msg('Reset fetch-incidents.')
        demisto.setLastRun({LAST_FETCH_KEY: 0})
        context_data: dict[str, Any] = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: {},
                                        MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
                                        'samples': []}
        safely_update_context_data(context_data, version=version, should_force_update=True)
        return True
    return False


def validate_long_running_params(params: dict) -> None:
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


def get_cidrs_indicators(query):
    """Extracts cidrs from a query"""
    if not query:
        return []

    res = demisto.searchIndicators(query=query)

    indicators = []
    for indicator in res.get('iocs', []):
        if indicator.get('indicator_type').lower() == 'cidr':
            indicators.append(indicator.get('value'))

    return indicators


def verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields):
    # verify that only one of the arguments is given
    if cidrs_list and cidrs_from_query:
        return 'Cannot specify both cidrs and query arguments.'

    # verify that at least one of the arguments is given
    if not cidrs_list and not cidrs_from_query:
        return 'Must specify either cidrs or query arguments.'

    # verify that the given cidrs are valid
    for cidr in cidrs_list:
        if not re.match(ipv4cidrRegex, cidr) and not re.match(ipv6cidrRegex, cidr):
            return f'{cidr} is not a valid CIDR.'

    # verify that the given name and group are valid
    if not NAME_AND_GROUP_REGEX.match(name) or not NAME_AND_GROUP_REGEX.match(group):
        return 'Name and group arguments only allow letters, numbers, \'_\' and \'-\'.'

    fields_list = argToList(fields)
    if fields_list:
        possible_fields = ['id', 'name', 'group', 'cidrs', 'description']
        for field in fields_list:
            if field not in possible_fields:
                return f'{field} is not a valid field. Possible fields are: {possible_fields}.'
        return None
    return None


def is_positive(*values: int | None) -> bool:
    # checks if all values are positive or None but not a negative numbers
    return all(value is None or value >= 1 for value in values)


def verify_args_for_remote_network_cidr_list(limit, page, page_size, filter_, group, id_, name):
    # verify that the given limit and page and page_size are valid
    if not is_positive(limit, page, page_size):
        return 'Limit, page and page_size arguments must be positive numbers.'

    # verify that only one of the arguments is given
    if limit and (page or page_size):
        return 'Please provide either limit argument or page and page_size arguments.'

    # verify that if page are given, page_size is also given and vice versa
    if (page and not page_size) or (page_size and not page):
        return 'Please provide both page and page_size arguments.'

    # verify that only one of the arguments is given
    if filter_ and (group or id_ or name):
        return 'You can not use filter argument with group, id or name arguments.'
    return None


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, params: dict) -> str:
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
        ctx = get_integration_context()
        print_context_data_stats(ctx, "Test Module")
        is_long_running = params.get('longRunning')
        if is_long_running:
            validate_long_running_params(params)
        client.offenses_list(range_="items=0-0")
        message = 'ok'
    except DemistoException as e:
        err_msg = str(e)
        if 'unauthorized to access the requested resource' in err_msg or 'No SEC header present in request' in err_msg:
            message = 'Authorization Error: make sure credentials are correct.'
        else:
            raise e
    return message


def fetch_incidents_command() -> List[dict]:
    """
    Fetch incidents implemented, for mapping purposes only.
    Returns list of samples saved by long running execution.

    Returns:
        (List[Dict]): List of incidents samples.
    """
    ctx = get_integration_context()
    return ctx.get('samples', [])


def create_search_with_retry(client: Client,
                             fetch_mode: str,
                             offense: dict,
                             event_columns: str,
                             events_limit: int,
                             max_retries: int = EVENTS_SEARCH_TRIES,
                             ) -> str:
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
        (str): The search id or `error` from `SearchQueryStatus`
    """
    offense_id = offense['id']
    for i in range(max_retries):
        search_id = create_events_search(client, fetch_mode, event_columns, events_limit, offense_id, offense['start_time'])
        if search_id == QueryStatus.ERROR.value:
            print_debug_msg(f'Failed to create search for offense ID: {offense_id}. '
                            f'Retry number {i+1}/{max_retries}.')
            print_debug_msg(traceback.format_exc())
        else:
            return search_id
    print_debug_msg(f'Reached max retries for creating a search for offense: {offense_id}. Returning error.')
    return QueryStatus.ERROR.value


def poll_offense_events(client: Client,
                        search_id: str,
                        should_get_events: bool,
                        offense_id: int | None,
                        ):
    try:
        print_debug_msg(f"Getting search status for {search_id}")
        search_status_response = client.search_status_get(search_id)
        print_debug_msg(f"Got search status for {search_id}")
        query_status = search_status_response.get('status')
        print_debug_msg(f'Search status for offense {offense_id} is {query_status}.')

        if query_status in {'CANCELED', 'ERROR'}:
            return [], QueryStatus.ERROR.value
        elif query_status == 'COMPLETED':
            print_debug_msg(f'Search for offense {offense_id} is completed.')
            if not should_get_events:
                return [], QueryStatus.SUCCESS.value
            print_debug_msg(f'Getting events for offense {offense_id}')
            search_results_response = client.search_results_get(search_id)
            print_debug_msg(f'Http response: {search_results_response.get("http_response", "Not specified - ok")}')
            events = search_results_response.get('events', [])
            sanitized_events = sanitize_outputs(events)
            print_debug_msg(f'Fetched events for offense {offense_id}.')
            return sanitized_events, QueryStatus.SUCCESS.value
        else:
            # still waiting for events
            return [], QueryStatus.WAIT.value
    except Exception as e:
        print_debug_msg(
            f'Error while fetching offense {offense_id} events, search_id: {search_id}. Error details: {str(e)} \n'
            f'{traceback.format_exc()}')
        time.sleep(FAILURE_SLEEP)
        return [], QueryStatus.ERROR.value


def poll_offense_events_with_retry(
    client: Client,
    search_id: str, offense_id: int,
    max_retries: int = EVENTS_POLLING_TRIES,
) -> tuple[List[dict], str]:
    """
    Polls QRadar service for search ID given until status returned is within '{'CANCELED', 'ERROR', 'COMPLETED'}'.
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
        (List[Dict], str): List of events returned by query. Returns empty list if number of retries exceeded limit,
                           A failure message in case an error occurred.
    """
    for retry in range(max_retries):
        print_debug_msg(f'Polling for events for offense {offense_id}. Retry number {retry+1}/{max_retries}')
        events, status = poll_offense_events(client, search_id, should_get_events=True, offense_id=int(offense_id))
        if status == QueryStatus.SUCCESS.value:
            return events, ''
        elif status == QueryStatus.ERROR.value:
            return [], 'Error while getting events.'
        # dont sleep in the last iteration
        if retry < max_retries - 1:
            time.sleep(EVENTS_INTERVAL_SECS)

    print_debug_msg(f'Max retries for getting events for offense {offense_id}. Cancel query search_id: {search_id}')
    # need to cancel query
    client.search_cancel(search_id=search_id)
    return [], 'Fetching events is in progress'


def enrich_offense_with_events(client: Client, offense: dict, fetch_mode: FetchMode, events_columns: str, events_limit: int):
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

    Returns:
        (Dict): Enriched offense with events.
    """
    offense_id = str(offense['id'])
    events_count = offense.get('event_count', 0)
    events: List[dict] = []
    failure_message = ''
    is_success = True
    for retry in range(EVENTS_SEARCH_TRIES):
        start_time = time.time()
        search_id = create_search_with_retry(client, fetch_mode, offense, events_columns,
                                             events_limit)
        if search_id == QueryStatus.ERROR.value:
            failure_message = 'Search for events was failed.'
        else:
            events, failure_message = poll_offense_events_with_retry(client, search_id, int(offense_id))
        events_fetched = get_num_events(events)
        offense['events_fetched'] = events_fetched
        offense['events'] = events
        if is_all_events_fetched(client, fetch_mode, offense_id, events_limit, events):
            break
        print_debug_msg(f'Not enough events were fetched for offense {offense_id}. Retrying in {FAILURE_SLEEP} seconds.'
                        f'Retry {retry+1}/{EVENTS_SEARCH_TRIES}')
        time_elapsed = int(time.time() - start_time)
        # wait for the rest of the time
        time.sleep(max(EVENTS_SEARCH_RETRY_SECONDS - time_elapsed, 0))
    else:
        print_debug_msg(f'Not all the events were fetched for offense {offense_id} (fetched {events_fetched}/{events_count}). '
                        f'If mirroring is enabled, it will be queried again in mirroring.')
        is_success = False
    mirroring_events_message = update_events_mirror_message(mirror_options=MIRROR_OFFENSE_AND_EVENTS,
                                                            events_limit=events_limit,
                                                            fetch_mode=fetch_mode,
                                                            events_count=events_count,
                                                            events_mirrored=events_fetched,
                                                            events_mirrored_collapsed=len(events),
                                                            failure_message=failure_message,
                                                            offense_id=int(offense_id),
                                                            )
    offense['mirroring_events_message'] = mirroring_events_message

    return offense, is_success


def get_num_events(events: list[dict]) -> int:
    return sum(int(event.get('eventcount', 1)) for event in events)


def get_current_concurrent_searches(context_data: dict) -> int:
    """This will return the number of concurrent searches that are currently running.

    Args:
        context_data (dict): context data

    Returns:
        int: number of concurrent searches
    """
    waiting_for_update = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    # we need offenses which we have a search_id for it in QRadar
    return len([offense_id for offense_id, status in waiting_for_update.items()
               if status not in list(QueryStatus)])


def delete_offense_from_context(offense_id: str, context_data: dict, context_version: Any):
    for key in (MIRRORED_OFFENSES_QUERIED_CTX_KEY, MIRRORED_OFFENSES_FINISHED_CTX_KEY):
        context_data[key].pop(offense_id, None)
    safely_update_context_data(context_data, context_version, offense_ids=[offense_id])


def is_all_events_fetched(client: Client, fetch_mode: FetchMode, offense_id: str, events_limit: int, events: list[dict]) -> bool:
    """
    This function checks if all events were fetched for a specific offense.

    Args:
        client (Client): QRadar client
        offense_id (str): offense id of qradar
        events_limit (int): event limit parameter for the integration
        events (list[dict]): list of events fetched

    Returns:
        bool: True if all events were fetched, False otherwise
    """
    if not offense_id:
        # if we don't have offense id, we can't know if we fetched all the events
        return True
    events_count = client.offenses_list(offense_id=int(offense_id)).get('event_count', 0)
    expected_events = min(events_count, events_limit) if events_limit else events_count
    num_events = get_num_events(events)
    print_debug_msg(f'Fetched {num_events}/{expected_events} events for offense {offense_id}')
    # if we're not fetching only correlation events, we can't know if we fetched all the events
    return num_events >= expected_events if fetch_mode == FetchMode.all_events else num_events > 0


def get_incidents_long_running_execution(client: Client, offenses_per_fetch: int, user_query: str, fetch_mode: str,
                                         events_columns: str, events_limit: int, ip_enrich: bool, asset_enrich: bool,
                                         last_highest_id: int, incident_type: Optional[str], mirror_direction: Optional[str],
                                         first_fetch: str, mirror_options: str, assets_limit: int) \
        -> tuple[Optional[List[dict]], Optional[int]]:
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
        first_fetch (str): First fetch timestamp.


    Returns:
        (List[Dict], int): List of the incidents, and the new highest ID for next fetch.
        (None, None): if reset was triggered
    """
    offense_highest_id = get_minimum_id_to_fetch(last_highest_id, user_query, first_fetch, client)

    user_query = update_user_query(user_query)

    filter_fetch_query = f'id>{offense_highest_id}{user_query}'
    print_debug_msg(f'Filter query to QRadar: {filter_fetch_query}')
    range_max = offenses_per_fetch - 1 if offenses_per_fetch else MAXIMUM_OFFENSES_PER_FETCH - 1
    range_ = f'items=0-{range_max}'

    # if it fails here we can't recover, retry again later
    raw_offenses = client.offenses_list(range_, filter_=filter_fetch_query, sort=ASCENDING_ID_ORDER)
    if raw_offenses:
        raw_offenses_len = len(raw_offenses)
        print_debug_msg(f'raw_offenses size: {raw_offenses_len}')
    else:
        print_debug_msg('empty raw_offenses')

    new_highest_offense_id = raw_offenses[-1].get('id') if raw_offenses else offense_highest_id
    print_debug_msg(f'New highest ID returned from QRadar offenses: {new_highest_offense_id}')

    offenses: list[dict] = []
    if fetch_mode != FetchMode.no_events.value:
        futures = []
        for offense in raw_offenses:
            futures.append(EXECUTOR.submit(
                enrich_offense_with_events,
                client=client,
                offense=offense,
                fetch_mode=fetch_mode,  # type: ignore
                events_columns=events_columns,
                events_limit=events_limit,
            ))
        offenses_with_metadata = [future.result() for future in futures]
        offenses = [offense for offense, _ in offenses_with_metadata]
        if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
            prepare_context_for_events(offenses_with_metadata)
    else:
        offenses = raw_offenses
    if is_reset_triggered():
        return None, None
    offenses_with_mirror = [
        dict(offense, mirror_direction=mirror_direction, mirror_instance=demisto.integrationInstance())
        for offense in offenses] if mirror_direction else offenses

    enriched_offenses = enrich_offenses_result(client, offenses_with_mirror, ip_enrich, asset_enrich, assets_limit)
    final_offenses = sanitize_outputs(enriched_offenses)
    incidents = create_incidents_from_offenses(final_offenses, incident_type)
    return incidents, new_highest_offense_id


def prepare_context_for_events(offenses_with_metadata):
    ctx, version = get_integration_context_with_version()
    changed_offense_ids = []
    for offense, is_success in offenses_with_metadata:
        if not is_success:
            offense_id = str(offense.get('id'))
            ctx[MIRRORED_OFFENSES_QUERIED_CTX_KEY][offense_id] = QueryStatus.WAIT.value
            changed_offense_ids.append(offense_id)
    safely_update_context_data(ctx, version, offense_ids=changed_offense_ids)


def create_incidents_from_offenses(offenses: List[dict], incident_type: Optional[str]) -> List[dict]:
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
        # NOTE: incident name will be updated in mirroring also with incoming mapper.
        'name': f'''{offense.get('id')} {offense.get('description', '')}''',
        'rawJSON': json.dumps(offense),
        'occurred': get_time_parameter(offense.get('start_time'), iso_format=True),
        'type': incident_type,
        "haIntegrationEventID": str(offense.get("id"))
    } for offense in offenses]


def print_context_data_stats(context_data: dict, stage: str) -> set[str]:
    """Print debug message with information about mirroring events.

    Args:
        context_data: The integration context data.
        stage: A prefix for the debug message.

    Returns: The ids of the mirrored offenses being currently processed.
    """
    if MIRRORED_OFFENSES_QUERIED_CTX_KEY not in context_data or MIRRORED_OFFENSES_FINISHED_CTX_KEY not in context_data:
        raise ValueError(f'Context data is missing keys: {MIRRORED_OFFENSES_QUERIED_CTX_KEY} or '
                         f'{MIRRORED_OFFENSES_FINISHED_CTX_KEY}')

    if not context_data:
        print_debug_msg("Not printing stats")
        return set()

    finished_queries = context_data.get(MIRRORED_OFFENSES_FINISHED_CTX_KEY, {})
    waiting_for_update = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    print_debug_msg(f'{finished_queries=}')
    print_debug_msg(f'{waiting_for_update=}')
    last_fetch_key = context_data.get(LAST_FETCH_KEY, 'Missing')
    last_mirror_update = context_data.get(LAST_MIRROR_KEY, 0)
    last_mirror_update_closed = context_data.get(LAST_MIRROR_CLOSED_KEY, 0)
    concurrent_mirroring_searches = get_current_concurrent_searches(context_data)
    samples = context_data.get('samples', [])
    sample_length = 0
    if samples:
        sample_length = len(samples[0])
    not_updated_ids = list(waiting_for_update)
    finished_queries_ids = list(finished_queries)
    print_debug_msg(f"Context Data Stats: {stage}\n Finished Offenses (id): {finished_queries_ids}"
                    f"\n Offenses ids waiting for update: {not_updated_ids}"
                    f"\n Concurrent mirroring events searches: {concurrent_mirroring_searches}"
                    f"\n Last Fetch Key {last_fetch_key}, Last mirror update {last_mirror_update}, "
                    f"Last mirror update closed: {last_mirror_update_closed}, "
                    f"sample length {sample_length}")
    return set(not_updated_ids + finished_queries_ids)


def perform_long_running_loop(client: Client, offenses_per_fetch: int, fetch_mode: str,
                              user_query: str, events_columns: str, events_limit: int, ip_enrich: bool,
                              asset_enrich: bool, incident_type: Optional[str], mirror_direction: Optional[str],
                              first_fetch: str, mirror_options: str, assets_limit: int, long_running_container_id: str):
    context_data, version = get_integration_context_with_version()

    if is_reset_triggered(context_data, version):
        last_highest_id = 0
    else:
        last_highest_id = int(context_data.get(LAST_FETCH_KEY, 0))
    print_debug_msg(f'Starting fetch loop. Fetch mode: {fetch_mode} on Container:{long_running_container_id}.')
    incidents, new_highest_id = get_incidents_long_running_execution(
        client=client,
        offenses_per_fetch=offenses_per_fetch,
        user_query=user_query,
        fetch_mode=fetch_mode,
        events_columns=events_columns,
        events_limit=events_limit,
        ip_enrich=ip_enrich,
        asset_enrich=asset_enrich,
        last_highest_id=last_highest_id,
        incident_type=incident_type,
        mirror_direction=mirror_direction,
        first_fetch=first_fetch,
        mirror_options=mirror_options,
        assets_limit=assets_limit
    )
    print_debug_msg(f'Got incidents, Creating incidents and updating context data. new highest id is {new_highest_id}')
    context_data, ctx_version = get_integration_context_with_version()
    if incidents and new_highest_id:
        incident_batch_for_sample = incidents[:SAMPLE_SIZE] if incidents else context_data.get('samples', [])
        if incident_batch_for_sample:
            print_debug_msg(f'Saving New Highest ID: {new_highest_id}')
            context_data.update({'samples': incident_batch_for_sample, LAST_FETCH_KEY: int(new_highest_id)})

        # if incident creation fails, it'll drop the data and try again in the next iteration
        demisto.createIncidents(incidents, {LAST_FETCH_KEY: str(new_highest_id)})
        safely_update_context_data(context_data=context_data,
                                   version=ctx_version,
                                   should_update_last_fetch=True)

        print_debug_msg(
            f'Successfully Created {len(incidents)} incidents. Incidents created: {[incident["name"] for incident in incidents]}')


def recover_from_last_run(ctx: dict | None = None, version: Any = None):
    """
    This recovers the integration context from the last run, if there is inconsistency between last run and context.
    It happens when the container crashes after `demisto.createIncidents` and the integration context is not updated.
    """
    if not ctx or not version:
        ctx, version = get_integration_context_with_version()
    assert isinstance(ctx, dict)
    last_run = demisto.getLastRun() or {}
    last_highest_id_last_run = int(last_run.get(LAST_FETCH_KEY, 0))
    print_debug_msg(f'Last highest ID from last run: {last_highest_id_last_run}')
    last_highest_id_context = int(ctx.get(LAST_FETCH_KEY, 0))
    if last_highest_id_last_run != last_highest_id_context and last_highest_id_last_run > 0:
        # if there is inconsistency between last run and context, we need to update the context
        print_debug_msg(
            f'Updating context data with last highest ID from last run: {last_highest_id_last_run}.'
            f'ID from context: {last_highest_id_context}')
        safely_update_context_data(ctx | {LAST_FETCH_KEY: int(last_highest_id_last_run)},
                                   version, should_update_last_fetch=True)


def long_running_execution_command(client: Client, params: dict):
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
    global EVENTS_SEARCH_TRIES
    validate_long_running_params(params)
    fetch_mode = params.get('fetch_mode', '')
    first_fetch = params.get('first_fetch', '3 days')
    ip_enrich, asset_enrich = get_offense_enrichment(params.get('enrichment', 'IPs And Assets'))
    offenses_per_fetch = int(params.get('offenses_per_fetch'))  # type: ignore
    user_query = params.get('query', '')
    events_columns = params.get('events_columns') or DEFAULT_EVENTS_COLUMNS
    events_limit = int(params.get('events_limit') or DEFAULT_EVENTS_LIMIT)
    incident_type = params.get('incident_type')
    mirror_options = params.get('mirror_options', DEFAULT_MIRRORING_DIRECTION)
    mirror_direction = MIRROR_DIRECTION.get(mirror_options)
    mirror_options = params.get('mirror_options', '')
    assets_limit = int(params.get('limit_assets', DEFAULT_ASSETS_LIMIT))
    if not argToBoolean(params.get('retry_events_fetch', True)):
        EVENTS_SEARCH_TRIES = 1
    context_data, version = get_integration_context_with_version()
    is_reset_triggered(context_data, version)
    recover_from_last_run(context_data, version)
    long_running_container_id = str(uuid.uuid4())
    print_debug_msg(f'Starting container with UUID: {long_running_container_id}')
    while True:
        try:
            perform_long_running_loop(
                client=client,
                offenses_per_fetch=offenses_per_fetch,
                fetch_mode=fetch_mode,
                user_query=user_query,
                events_columns=events_columns,
                events_limit=events_limit,
                ip_enrich=ip_enrich,
                asset_enrich=asset_enrich,
                incident_type=incident_type,
                mirror_direction=mirror_direction,
                first_fetch=first_fetch,
                mirror_options=mirror_options,
                assets_limit=assets_limit,
                long_running_container_id=long_running_container_id
            )
            demisto.updateModuleHealth('')

        except Exception as e:
            msg = f'Error occurred during long running loop: {e}'
            demisto.updateModuleHealth(msg)
            demisto.error(msg)
            demisto.error(traceback.format_exc())

        finally:
            print_debug_msg('Finished fetch loop')
            time.sleep(FETCH_SLEEP)


def qradar_offenses_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
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


def qradar_offense_update_command(client: Client, args: dict) -> CommandResults:
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
        # if this call fails, raise an error and stop command execution
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

    # if this call fails, raise an error and stop command execution
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


def qradar_closing_reasons_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.closing_reasons_list(closing_reason_id, include_reserved, include_deleted, range_, filter_,
                                           fields)
    outputs = sanitize_outputs(response, CLOSING_REASONS_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name'], set(CLOSING_REASONS_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Closing Reasons', outputs, headers=headers, removeNull=True),
        outputs_prefix='QRadar.Offense.ClosingReasons',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_offense_notes_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.offense_notes_list(offense_id, range_, note_id, filter_, fields)
    outputs = sanitize_outputs(response, NOTES_RAW_FORMATTED)
    headers = build_headers(['ID', 'Text', 'CreatedBy', 'CreateTime'], set(NOTES_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown(f'Offense Notes List For Offense ID {offense_id}', outputs, headers,
                                        removeNull=True),
        outputs_prefix='QRadar.Note',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_offense_notes_create_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.offense_notes_create(offense_id, note_text, fields)
    outputs = sanitize_outputs(response, NOTES_RAW_FORMATTED)
    headers = build_headers(['ID', 'Text', 'CreatedBy', 'CreateTime'], set(NOTES_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Create Note', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Note',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_rules_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.rules_list(rule_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, RULES_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name', 'Type'], set(RULES_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Rules List', outputs, headers=headers, removeNull=True),
        outputs_prefix='QRadar.Rule',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_rule_groups_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.rule_groups_list(range_, rule_group_id, filter_, fields)
    outputs = sanitize_outputs(response, RULES_GROUP_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name', 'Description', 'Owner'], set(RULES_GROUP_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Rules Group List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.RuleGroup',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_assets_list_command(client: Client, args: dict) -> CommandResults:
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

    full_enrichment = bool(asset_id)

    # if this call fails, raise an error and stop command execution
    response = client.assets_list(range_, filter_, fields)
    enriched_outputs = enrich_assets_results(client, response, full_enrichment)
    assets_results = {}
    assets_hr = []
    endpoints = []
    for output in enriched_outputs:
        output['Asset']['hostnames'] = add_iso_entries_to_dict(output.get('Asset', {}).get('hostnames', []))
        output['Asset']['users'] = add_iso_entries_to_dict(output.get('Asset', {}).get('users', []))
        output['Asset']['products'] = add_iso_entries_to_dict(output.get('Asset', {}).get('products', []))
        output['Asset'] = sanitize_outputs(output.get('Asset'), ASSET_RAW_FORMATTED)[0]
        assets_hr.append(output['Asset'])
        assets_results[f'''QRadar.Asset(val.ID === "{output['Asset']['ID']}")'''] = output['Asset']
        sanitized_endpoint = remove_empty_elements(output.get('Endpoint', {}))
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


def qradar_saved_searches_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.saved_searches_list(range_, timeout, saved_search_id, filter_, fields)
    outputs = sanitize_outputs(response, SAVED_SEARCH_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name', 'Description'], set(SAVED_SEARCH_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Saved Searches List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.SavedSearch',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_searches_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.searches_list(range_, filter_)
    outputs = [{'SearchID': search_id} for search_id in response]

    return CommandResults(
        readable_output=tableToMarkdown('Search ID List', outputs),
        outputs_prefix='QRadar.SearchID',
        outputs_key_field='SearchID',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_create_command(client: Client, params: dict, args: dict) -> CommandResults:
    """
    Create a search in QRadar service.
    possible arguments:
    - query_expression: The AQL query to execute. Mutually exclusive with saved_search_id.
    - saved_search_id: Saved search ID to execute. Mutually exclusive with query_expression.
    Args:
        client (Client): QRadar client to perform the API call.
        params (Dict): Demisto params.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    offense_id = args.get('offense_id', '')
    events_columns = args.get('events_columns', params.get('events_columns')) or DEFAULT_EVENTS_COLUMNS
    events_limit = args.get('events_limit', params.get('events_limit'))
    fetch_mode = args.get('fetch_mode', params.get('fetch_mode'))
    start_time = args.get('start_time')
    query_expression = args.get('query_expression')
    saved_search_id = args.get('saved_search_id')

    if not query_expression and not saved_search_id and not offense_id:
        raise DemistoException('Please provide one of the following args: `query_expression`, `saved_search_id` or `offense_id`.')

    if query_expression and offense_id:
        raise DemistoException('Could not use both `query_expression` and `offense_id`.')
    # if this call fails, raise an error and stop command execution
    if query_expression or saved_search_id:
        try:
            response = client.search_create(query_expression, saved_search_id)
        except Exception as e:
            if query_expression:
                raise DemistoException(f'Could not create search for query: {query_expression}.') from e
            if saved_search_id:
                raise DemistoException(f'Could not create search for saved_search_id: {saved_search_id}.') from e
    else:
        response = create_events_search(client,
                                        fetch_mode,
                                        events_columns,
                                        events_limit,
                                        int(offense_id),
                                        start_time,
                                        return_raw_response=True)
        if response == QueryStatus.ERROR.value:
            raise DemistoException(f'Could not create events search for offense_id: {offense_id}.')

    outputs = sanitize_outputs(response, SEARCH_RAW_FORMATTED)
    return CommandResults(
        readable_output=tableToMarkdown('Create Search', outputs),
        outputs_prefix='QRadar.Search',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_status_get_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.search_status_get(search_id)
    outputs = sanitize_outputs(response, SEARCH_RAW_FORMATTED)

    return CommandResults(
        readable_output=tableToMarkdown(f'Search Status For Search ID {search_id}', outputs),
        outputs_prefix='QRadar.Search',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_search_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Delete search from QRadar service.
    possible arguments:
    - search_id (Required): The search ID to delete.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    search_id: str = args.get('search_id', '')

    # if this call fails, raise an error and stop command execution
    response = client.search_delete(search_id)

    return CommandResults(
        readable_output=f'Search ID {search_id} was successfully deleted.',
        raw_response=response
    )


def qradar_search_cancel_command(client: Client, args: dict) -> CommandResults:
    """
    Cancelled search from QRadar service.
    possible arguments:
    - search_id (Required): The search ID to delete.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    search_id: str = args.get('search_id', '')

    # if this call fails, raise an error and stop command execution
    response = client.search_cancel(search_id)
    if response.get('status') == 'COMPLETED':
        output = f'Search ID {search_id} is already in a completed status.'
    else:
        output = f'Search ID {search_id} was successfully cancelled.'
    return CommandResults(
        readable_output=output,
        raw_response=response
    )


def qradar_search_results_get_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
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


def qradar_reference_sets_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.reference_sets_list(range_, ref_name, filter_, fields)
    if ref_name:
        outputs = dict(response)
        if convert_date_value and outputs.get('element_type') == 'DATE':
            for data_entry in outputs.get('data', []):
                data_entry['value'] = get_time_parameter(data_entry.get('value'), iso_format=True)
        outputs['data'] = sanitize_outputs(outputs.get('data', []), REFERENCE_SET_DATA_RAW_FORMATTED)
    else:
        outputs = response

    final_outputs = sanitize_outputs(outputs, REFERENCE_SETS_RAW_FORMATTED)
    headers = build_headers(['Name', 'ElementType', 'Data', 'TimeToLive', 'TimeoutType'],
                            set(REFERENCE_SETS_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Reference Sets List', final_outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Reference',
        outputs_key_field='Name',
        outputs=final_outputs,
        raw_response=response
    )


def qradar_reference_set_create_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.reference_set_create(ref_name, element_type, timeout_type, time_to_live, fields)
    outputs = sanitize_outputs(response, REFERENCE_SETS_RAW_FORMATTED)
    headers = build_headers(['Name', 'ElementType', 'Data', 'TimeToLive', 'TimeoutType'],
                            set(REFERENCE_SETS_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Reference Set Create', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.Reference',
        outputs_key_field='Name',
        outputs=outputs,
        raw_response=response
    )


def qradar_reference_set_delete_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.reference_set_delete(ref_name, purge_only, fields)
    return CommandResults(
        raw_response=response,
        readable_output=f'Request to delete reference {ref_name} was submitted.'
                        f''' Current deletion status: {response.get('status', 'Unknown')}''')


@polling_function(name='qradar-reference-set-value-upsert', requires_polling_arg=False)
def qradar_reference_set_value_upsert_command(args: dict, client: Client, params: dict) -> PollResult:
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
        PollResult.
    """
    return insert_values_to_reference_set_polling(client,
                                                  params.get('api_version', ''),
                                                  args,
                                                  values=argToList(args.get('value', '')))


def qradar_reference_set_value_delete_command(client: Client, args: dict) -> CommandResults:
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
        value = str(get_time_parameter(original_value, epoch_format=True))
    # if this call fails, raise an error and stop command execution
    try:
        response = client.reference_set_value_delete(ref_name, value)
    except DemistoException as e:
        response = str(e)
        if f"Set {ref_name} does not contain value {value}" not in response:
            raise e
    human_readable = f'### value: {original_value} of reference: {ref_name} was deleted successfully'

    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def qradar_domains_list_command(client: Client, args: dict) -> CommandResults:
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

    # if this call fails, raise an error and stop command execution
    response = client.domains_list(domain_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, DOMAIN_RAW_FORMATTED)

    return CommandResults(
        readable_output=tableToMarkdown('Domains List', outputs, removeNull=True),
        outputs_prefix='QRadar.Domains',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


@polling_function(name='qradar-indicators-upload', requires_polling_arg=False)
def qradar_indicators_upload_command(args: dict, client: Client, params: dict) -> PollResult:
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
        PollResult.
    """
    return insert_values_to_reference_set_polling(client, params.get('api_version', ''), args, from_indicators=True)


def flatten_nested_geolocation_values(geolocation_dict: dict, dict_key: str, nested_value_keys: List[str]) -> dict:
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
    return {f'{camelize_string(dict_key)}{camelize_string(k)}': geolocation_dict.get(dict_key, {}).get(k) for k in
            nested_value_keys}


def qradar_geolocations_for_ip_command(client: Client, args: dict) -> CommandResults:
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
    filter_ = f'''ip_address IN ({','.join((f'"{str(ip)}"' for ip in ips))})'''  # noqa: UP034
    fields = args.get('fields')

    # if this call fails, raise an error and stop command execution
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
            'Coordinates': output.get('geo_json', {}).get('coordinates'),
            'PostalCode': output.get('postal', {}).get('postal_code'),
            'PostalCodeConfidence': output.get('postal', {}).get('confidence')
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


def qradar_log_sources_list_command(client: Client, args: dict) -> CommandResults:
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
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    qrd_encryption_algorithm: str = args.get('qrd_encryption_algorithm', 'AES128')
    qrd_encryption_password: str = args.get('qrd_encryption_password', secrets.token_urlsafe(20))
    endpoint = '/config/event_sources/log_source_management/log_sources'
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')
    fields = args.get('fields')
    additional_headers = {
        'x-qrd-encryption-algorithm': qrd_encryption_algorithm,
        'x-qrd-encryption-password': qrd_encryption_password
    }
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields, additional_headers)
    outputs = sanitize_outputs(response, LOG_SOURCES_RAW_FORMATTED)
    readable_outputs = [{k: v for k, v in output.items() if k != 'ProtocolParameters'} for output in outputs]
    headers = build_headers(['ID', 'Name', 'Description'], set(LOG_SOURCES_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Log Sources List', readable_outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSource',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_get_custom_properties_command(client: Client, args: dict) -> CommandResults:
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
    range_ = f'items=0-{limit - 1}' if limit else f'items={args.get("range", DEFAULT_RANGE_VALUE)}'

    like_names = argToList(args.get('like_name'))
    field_names = argToList(args.get('field_name'))
    filter_ = args.get('filter', '')
    fields = args.get('fields')
    if not filter_:
        if field_names:
            filter_ += f'''name IN ({','.join(f'"{str(name)}"' for name in field_names)})'''
        if like_names:
            filter_ += ' or '.join(f' name ILIKE "%{like}%"' for like in like_names)

    # if this call fails, raise an error and stop command execution
    response = client.custom_properties(range_, filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown('Custom Properties', outputs, removeNull=True),
        outputs_prefix='QRadar.Properties',
        outputs_key_field='identifier',
        outputs=outputs,
        raw_response=response
    )


def perform_ips_command_request(client: Client, args: dict[str, Any], is_destination_addresses: bool):
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

    # if this call fails, raise an error and stop command execution
    response = client.get_addresses(url_suffix, filter_, fields, range_)

    return response


def qradar_ips_source_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get source IPS from QRadar service.
    Args:
        client (Client): Client to perform API calls to QRadar service.
        args (Dict[str, Any): XSOAR arguments.

    Returns:
        (CommandResults).
    """
    response = perform_ips_command_request(client, args, is_destination_addresses=False)
    outputs = sanitize_outputs(response, SOURCE_IPS_RAW_FORMATTED)

    return CommandResults(
        readable_output=tableToMarkdown('Source IPs', outputs),
        outputs_prefix='QRadar.SourceIP',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_ips_local_destination_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get local destination IPS from QRadar service.
    Args:
        client (Client): Client to perform API calls to QRadar service.
        args (Dict[str, Any): XSOAR arguments.

    Returns:
        (CommandResults).
    """
    response = perform_ips_command_request(client, args, is_destination_addresses=True)
    outputs = sanitize_outputs(response, LOCAL_DESTINATION_IPS_RAW_FORMATTED)

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
    ctx, version = get_integration_context_with_version()
    safely_update_context_data(ctx, version, should_add_reset_key=True)
    return 'fetch-incidents was reset successfully.'


def qradar_get_mapping_fields_command(client: Client) -> dict:
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
    # if this call fails, raise an error and stop command execution
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


def update_events_mirror_message(mirror_options: Optional[Any],
                                 events_limit: int,
                                 events_count: int,
                                 events_mirrored: int,
                                 events_mirrored_collapsed: int,
                                 fetch_mode: str,
                                 offense_id: int,
                                 failure_message: Optional[str] = None,
                                 ) -> str:
    """Return the offense's events' mirror error message.

    Args:
        mirror_options (str): The mirror options for the instance.
        events_limit (int): The events limit for the mirroring.
        failure_message (str): A failure message if there was a failure during fetching of events.
        events_count (int): The number of events in the offense.
        events_mirrored (int): The number of events mirrored in the offense

    Returns: (str) An updated offense events mirror message.
    """
    mirroring_events_message = 'Unknown'
    print_debug_msg(f"Events status for Offense {offense_id}:\n"
                    f"mirror_options {mirror_options}\n events_limit {events_limit} \n"
                    f"failure_message {failure_message}\n events_count {events_count}\n "
                    f"events_mirrored {events_mirrored}")

    if mirror_options != MIRROR_OFFENSE_AND_EVENTS:
        mirroring_events_message = ''
    elif failure_message:
        mirroring_events_message = failure_message
    elif fetch_mode == FetchMode.all_events.value and events_mirrored < min(events_count, events_limit):
        mirroring_events_message = 'Fetching events did not get all events of the offense'
    elif events_mirrored == events_count:
        mirroring_events_message = 'All available events in the offense were fetched.'
    elif events_mirrored_collapsed == events_limit:
        mirroring_events_message = 'Fetching events has reached events limit in this incident.'

    return mirroring_events_message


def get_remote_data_command(client: Client, params: dict[str, Any], args: dict) -> GetRemoteDataResponse:
    """
    get-remote-data command: Returns an updated incident and entries
    If offense's events were updated in the long running container, update the demisto incident.

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
    offense_id = str(remote_args.remote_incident_id)
    print_debug_msg(f'Starting get-remote-data for offense {offense_id}')
    # if this call fails, raise an error and stop command execution
    offense = client.offenses_list(offense_id=int(offense_id))
    offense_last_update = get_time_parameter(offense.get('last_persisted_time'))
    mirror_options = params.get('mirror_options')
    context_data, context_version = get_integration_context_with_version()
    events_columns = params.get('events_columns') or DEFAULT_EVENTS_COLUMNS
    events_limit = int(params.get('events_limit') or DEFAULT_EVENTS_LIMIT)
    fetch_mode = params.get('fetch_mode', '')
    print_context_data_stats(context_data, f"Starting Get Remote Data For "
                                           f"Offense {str(offense.get('id'))}")

    demisto.debug(f'Updating offense. Offense last update was {offense_last_update}')
    entries = []
    if offense.get('status') == 'CLOSED' and argToBoolean(params.get('close_incident', False)):
        demisto.debug(f'Offense is closed: {offense}')
        try:
            if closing_reason := offense.get('closing_reason_id', ''):
                closing_reason = client.closing_reasons_list(closing_reason).get('text')
            offense_close_time = offense.get('close_time', '')
            closed_offense_notes = client.offense_notes_list(int(offense_id), f'items={DEFAULT_RANGE_VALUE}',
                                                             filter_=f'create_time >= {offense_close_time}')
            # In QRadar UI, when you close a reason, a note is added with the reason and more details. Try to get note
            # if exists, else fallback to closing reason only, as closing QRadar through an API call does not create a note.
            closenotes = next((note.get('note_text') for note in closed_offense_notes if
                               note.get('note_text').startswith('This offense was closed with reason:')),
                              closing_reason)
            if not closing_reason:
                print_debug_msg(f'Could not find closing reason or closing note for offense with offense id {offense_id}')
                closing_reason = 'Unknown closing reason from QRadar'
                closenotes = 'Unknown closing note from QRadar'

        except Exception as e:
            demisto.error(f'Failed to get closing reason with error: {e}')
            closing_reason = 'Unknown closing reason from QRadar'
            closenotes = 'Unknown closing note from QRadar'
            time.sleep(FAILURE_SLEEP)
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': closing_reason,
                'closeNotes': f'From QRadar: {closenotes}'
            },
            'ContentsFormat': EntryFormat.JSON
        })
    already_mirrored = False
    if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
        if (num_events := context_data.get(MIRRORED_OFFENSES_FETCHED_CTX_KEY, {}).get(offense_id)) and \
                int(num_events) >= (events_limit := int(params.get('events_limit', DEFAULT_EVENTS_LIMIT))):
            print_debug_msg(f'Events were already fetched {num_events} for offense {offense_id}, '
                            f'and are more than the events limit, {events_limit}. '
                            f'Not fetching events again.')
            # delete the offense from the queue
            delete_offense_from_context(offense_id, context_data, context_version)
            already_mirrored = True
        else:
            events, status = get_remote_events(client,
                                               offense_id,
                                               context_data,
                                               context_version,
                                               events_columns,
                                               events_limit,
                                               fetch_mode,
                                               )
            print_context_data_stats(context_data, f"Get Remote Data events End for id {offense_id}")
            if status != QueryStatus.SUCCESS.value:
                # we raise an exception because we don't want to change the offense until all events are fetched.
                print_debug_msg(f'Events not mirrored yet for offense {offense_id}. Status: {status}')
                raise DemistoException(f'Events not mirrored yet for offense {offense_id}')
            offense['events'] = events

    enriched_offense = enrich_offenses_result(client, offense, ip_enrich, asset_enrich)

    final_offense_data = sanitize_outputs(enriched_offense)[0]
    if not already_mirrored:
        events_mirrored = get_num_events(final_offense_data.get('events', []))
        print_debug_msg(f'Offense {offense_id} mirrored events: {events_mirrored}')
        events_message = update_events_mirror_message(
            mirror_options=mirror_options,
            events_limit=events_limit,
            events_count=int(final_offense_data.get('event_count', 0)),
            events_mirrored=events_mirrored,
            events_mirrored_collapsed=len(final_offense_data.get('events', [])),
            fetch_mode=fetch_mode,
            offense_id=int(offense_id),
        )
        print_debug_msg(f'offense {offense_id} events_message: {events_message}')
        final_offense_data['last_mirror_in_time'] = datetime.now().isoformat()
        final_offense_data['mirroring_events_message'] = events_message
        final_offense_data['events_fetched'] = events_mirrored
    return GetRemoteDataResponse(final_offense_data, entries)


def add_modified_remote_offenses(client: Client,
                                 context_data: dict,
                                 version: str,
                                 mirror_options: str,
                                 new_modified_records_ids: set[str],
                                 new_last_update_modified: int,
                                 new_last_update_closed: int,
                                 events_columns: str,
                                 events_limit: int,
                                 fetch_mode: str
                                 ) -> set:
    """Add modified remote offenses to context_data and handle exhausted offenses.

    Args:
        client: Qradar client
        context_data: The context data to update.
        version: The version of the context data to update.
        mirror_options: The mirror options for the integration.
        new_modified_records_ids: The new modified offenses ids.
        new_last_update_modified: The current last mirror update modified.
        new_last_update_closed: The current last mirror update.
        events_columns: The events_columns param.
        events_limit: The events_limit param.

    Returns: The new modified records ids
    """
    new_context_data = context_data.copy()
    changed_ids_ctx = []
    if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
        # We query the search queue, to see if some searches were finished.
        # If so - move it to finished queue and add to modified ids.
        print_context_data_stats(new_context_data, "Get Modified Remote Data - Before update")
        mirrored_offenses_queries = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
        finished_offenses_queue = context_data.get(MIRRORED_OFFENSES_FINISHED_CTX_KEY, {})
        current_concurrent_searches = get_current_concurrent_searches(context_data)
        offense_ids_to_search = []

        for offense_id, search_id in mirrored_offenses_queries.copy().items():
            if search_id in {QueryStatus.WAIT.value, QueryStatus.ERROR.value}:
                # if search_id is waiting or error, we will try to search again
                offense_ids_to_search.append(offense_id)
                continue
            # If the search finished, move it to finished queue
            _, status = poll_offense_events(client, search_id, should_get_events=False, offense_id=int(offense_id))
            if status == QueryStatus.ERROR.value:
                time.sleep(FAILURE_SLEEP)
                print_debug_msg(f'offense {offense_id}, search query {search_id}, status is {status}')
                mirrored_offenses_queries[offense_id] = QueryStatus.ERROR.value
                current_concurrent_searches -= 1

            elif status == QueryStatus.SUCCESS.value:
                del mirrored_offenses_queries[offense_id]
                finished_offenses_queue[offense_id] = search_id
                # add the offense id to modified in order to run get_remote_data
                new_modified_records_ids.add(offense_id)
                changed_ids_ctx.append(offense_id)
                current_concurrent_searches -= 1
            else:
                print_debug_msg(f'offense {offense_id}, search query {search_id}, status is {status}')

        for offense_id in offense_ids_to_search:
            if current_concurrent_searches >= MAX_SEARCHES_QUEUE:
                print_debug_msg(f'Reached maximum concurrent searches ({MAX_SEARCHES_QUEUE}), will try again later.')
                break
            current_concurrent_searches += 1
            search_id = create_events_search(client, fetch_mode, events_columns, events_limit, int(offense_id))
            mirrored_offenses_queries[offense_id] = search_id
            changed_ids_ctx.append(offense_id)

        new_context_data.update({MIRRORED_OFFENSES_QUERIED_CTX_KEY: mirrored_offenses_queries})
        new_context_data.update({MIRRORED_OFFENSES_FINISHED_CTX_KEY: finished_offenses_queue})

    new_context_data.update({LAST_MIRROR_KEY: new_last_update_modified, LAST_MIRROR_CLOSED_KEY: new_last_update_closed})
    print_context_data_stats(new_context_data, "Get Modified Remote Data - After update")
    safely_update_context_data(
        new_context_data, version, offense_ids=changed_ids_ctx, should_update_last_mirror=True
    )
    return new_modified_records_ids


def create_events_search(client: Client,
                         fetch_mode: str,
                         events_columns: str,
                         events_limit: int,
                         offense_id: int,
                         offense_start_time: str | None = None,
                         return_raw_response: bool = False,
                         ) -> str:
    additional_where = ''
    if fetch_mode == FetchMode.correlations_events_only.value:
        additional_where = ''' AND LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine' '''
    try:
        # Get all the events starting from one hour after epoch
        if not offense_start_time:
            offense = client.offenses_list(offense_id=offense_id)
            offense_start_time = offense['start_time']
        query_expression = (
            f'SELECT {events_columns} FROM events WHERE INOFFENSE({offense_id}) {additional_where} limit {events_limit} '  # noqa: S608, E501
            f'START {offense_start_time}'
        )
        print_debug_msg(f'Creating search for offense ID: {offense_id}, '
                        f'query_expression: {query_expression}')
        search_response = client.search_create(query_expression)
        print_debug_msg(f'Created search for offense ID: {offense_id}, '
                        f'Start Time: {offense_start_time}, '
                        f'events_limit: {events_limit}, '
                        f'ret_value: {search_response}.')
        if return_raw_response:
            return search_response
        return search_response['search_id'] if search_response['search_id'] else QueryStatus.ERROR.value
    except Exception as e:
        print_debug_msg(f'Search for {offense_id} failed. Error: {e}')
        time.sleep(FAILURE_SLEEP)
        return QueryStatus.ERROR.value


def get_modified_remote_data_command(client: Client, params: dict[str, str],
                                     args: dict[str, str]) -> GetModifiedRemoteDataResponse:
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
    ctx, ctx_version = get_integration_context_with_version()
    remote_args = GetModifiedRemoteDataArgs(args)

    highest_fetched_id = ctx.get(LAST_FETCH_KEY, 0)
    limit: int = int(params.get('mirror_limit', MAXIMUM_MIRROR_LIMIT))
    fetch_mode = params.get('fetch_mode', '')
    range_ = f'items=0-{limit - 1}'
    last_update_modified = ctx.get(LAST_MIRROR_KEY, 0)
    if not last_update_modified:
        # This is the first mirror. We get the last update of the latest incident with a window of 5 minutes
        last_update = dateparser.parse(remote_args.last_update)
        if not last_update:
            last_update = datetime.now()
        last_update -= timedelta(minutes=5)
        last_update_modified = int(last_update.timestamp() * 1000)
    last_update_closed = ctx.get(LAST_MIRROR_CLOSED_KEY, last_update_modified)
    assert isinstance(last_update_modified, int)
    assert isinstance(last_update_closed, int)
    filter_modified = f'id <= {highest_fetched_id} AND status!=closed AND last_persisted_time > {last_update_modified}'
    filter_closed = f'id <= {highest_fetched_id} AND status=closed AND close_time > {last_update_closed}'
    print_debug_msg(f'Filter to get modified offenses is: {filter_modified}')
    print_debug_msg(f'Filter to get closed offenses is: {filter_closed}')
    # if this call fails, raise an error and stop command execution
    offenses_modified = client.offenses_list(range_=range_,
                                             filter_=filter_modified,
                                             sort='+last_persisted_time',
                                             fields=FIELDS_MIRRORING)
    offenses_closed = client.offenses_list(range_=range_,
                                           filter_=filter_closed,
                                           sort='+close_time',
                                           fields=FIELDS_MIRRORING)
    if offenses_modified:
        last_update_modified = int(offenses_modified[-1].get('last_persisted_time'))
    if offenses_closed:
        last_update_closed = int(offenses_closed[-1].get('close_time'))
    new_modified_records_ids = {str(offense.get('id')) for offense in offenses_modified + offenses_closed if 'id' in offense}
    print_debug_msg(f'Last update modified: {last_update_modified}, Last update closed: {last_update_closed}')
    events_columns = params.get('events_columns') or DEFAULT_EVENTS_COLUMNS
    events_limit = int(params.get('events_limit') or DEFAULT_EVENTS_LIMIT)

    new_modified_records_ids = add_modified_remote_offenses(client=client, context_data=ctx, version=ctx_version,
                                                            mirror_options=params.get('mirror_options', ''),
                                                            new_modified_records_ids=new_modified_records_ids,
                                                            new_last_update_modified=last_update_modified,
                                                            new_last_update_closed=last_update_closed,
                                                            events_columns=events_columns,
                                                            events_limit=events_limit,
                                                            fetch_mode=fetch_mode,
                                                            )

    return GetModifiedRemoteDataResponse(list(new_modified_records_ids))


def qradar_search_retrieve_events_command(
    client: Client,
    params,
    args,
) -> CommandResults:  # pragma: no cover (tested in test-playbook)
    """A polling command to get events from QRadar offense

    Args:
        client (Client): The QRadar client to use.
        params (dict): Parameters passed to the command.
        args (dict): Demisto arguments.

    Raises:
        DemistoException: If the search failed.

    Returns:
        CommandResults: The results of the command.
    """
    interval_in_secs = int(args.get('interval_in_seconds', 30))
    search_id = args.get('search_id')
    is_polling = argToBoolean(args.get('polling', True))
    timeout_in_secs = int(args.get('timeout_in_seconds', 600))
    search_command_results = None
    if not search_id:
        search_command_results = qradar_search_create_command(client, params, args)
        search_id = search_command_results.outputs[0].get('ID')  # type: ignore
    calling_context = demisto.callingContext.get('context', {})
    sm = get_schedule_metadata(context=calling_context)
    end_date: datetime | None = dateparser.parse(sm.get('end_date'))
    if not end_date or end_date.year == 1:
        end_date = None
    # determine if this is the last run of the polling command
    is_last_run = (datetime.now() + timedelta(seconds=interval_in_secs)).timestamp() >= end_date.timestamp() \
        if end_date else False
    try:
        events, status = poll_offense_events(client, search_id, should_get_events=True, offense_id=args.get('offense_id'))
    except (DemistoException, requests.Timeout) as e:
        if is_last_run:
            raise e
        print_debug_msg(f"Polling event failed due to {e}. Will try to poll again in the next interval.")
        events = []
        status = QueryStatus.WAIT.value
    if is_last_run and status == QueryStatus.WAIT.value:
        print_debug_msg("Its the last run of the polling, will cancel the query request. ")
        client.search_cancel(search_id=search_id)
        return CommandResults(
            readable_output='Got polling timeout. Quary got cancelled.',
        )
    if is_last_run and args.get('success') and not events:
        # if last run, we want to get the events that were fetched in the previous calls
        return CommandResults(
            readable_output='Not all events were fetched. partial data is available.',
        )

    if status == QueryStatus.ERROR.value:
        raise DemistoException('Polling for events failed')
    if status == QueryStatus.SUCCESS.value:
        # return the result only if the all events were retrieved, unless for the last call for this function
        offense_id = args.get('offense_id', '')
        events_limit = int(args.get('events_limit', params.get('events_limit')))
        fetch_mode: FetchMode = args.get('fetch_mode', params.get('fetch_mode'))
        if argToBoolean(args.get('retry_if_not_all_fetched', False)) and  \
            not is_last_run and not \
                is_all_events_fetched(client, fetch_mode, offense_id, events_limit, events):
            # return scheduled command result without search id to search again
            polling_args = {
                'interval_in_seconds': interval_in_secs,
                'timeout_in_seconds': timeout_in_secs,
                'success': True,
                **args
            }
            scheduled_command = ScheduledCommand(
                command='qradar-search-retrieve-events',
                next_run_in_seconds=interval_in_secs,
                args=polling_args,
                timeout_in_seconds=timeout_in_secs
            )
            return CommandResults(scheduled_command=scheduled_command if is_polling else None,
                                  readable_output='Not all events were fetched. Searching again.',
                                  outputs_prefix='QRadar.SearchEvents',
                                  outputs_key_field='ID',
                                  outputs={'Events': events, 'ID': search_id, 'Status': QueryStatus.PARTIAL},
                                  )

        return CommandResults(
            outputs_prefix='QRadar.SearchEvents',
            outputs_key_field='ID',
            outputs={'Events': events, 'ID': search_id, 'Status': QueryStatus.SUCCESS},
            readable_output=tableToMarkdown(f'{get_num_events(events)} Events returned from search_id {search_id}',
                                            events,
                                            ),
        )

    print_debug_msg(f'Still polling for search results for search ID: {search_id}.')
    polling_args = {
        'search_id': search_id,
        'interval_in_seconds': interval_in_secs,
        'timeout_in_seconds': timeout_in_secs,
        **args
    }
    scheduled_command = ScheduledCommand(
        command='qradar-search-retrieve-events',
        next_run_in_seconds=interval_in_secs,
        timeout_in_seconds=timeout_in_secs,
        args=polling_args,
    )
    outputs = {'ID': search_id, 'Status': QueryStatus.WAIT}
    return CommandResults(scheduled_command=scheduled_command if is_polling else None,
                          readable_output=f'Search ID: {search_id}',
                          outputs_prefix='QRadar.SearchEvents',
                          outputs_key_field='ID',
                          outputs=outputs,
                          )


def qradar_remote_network_cidr_create_command(client: Client, args) -> CommandResults:
    """Create remote network cidrs
    Args:
        client (Client): The QRadar client to use.
        args (dict): Demisto arguments.

    Raises:
        DemistoException: If the args are not valid.

    Returns:
        CommandResults.
    """
    cidrs_list = argToList(args.get('cidrs'))
    cidrs_from_query = get_cidrs_indicators(args.get('query'))
    name = args.get('name')
    description = args.get('description')
    group = args.get('group')
    fields = args.get('fields')

    error_message = verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields)
    if error_message:
        raise DemistoException(error_message)

    body = {
        "name": name,
        "description": description,
        "cidrs": cidrs_list or cidrs_from_query,
        "group": group
    }

    response = client.create_and_update_remote_network_cidr(body, fields)
    success_message = 'The new staged remote network was successfully created.'

    return CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(success_message, response)
    )


def qradar_remote_network_cidr_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Raises:
        DemistoException: If given both filter and group, id or name arguments.

    Returns:
        CommandResults.

    """
    limit = arg_to_number(args.get('limit'))
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    group = args.get('group')
    id_ = args.get('id')
    name = args.get('name')
    filter_ = args.get('filter', '')
    fields = args.get('fields')

    error_message = verify_args_for_remote_network_cidr_list(limit, page, page_size, filter_, group, id_, name)
    if error_message:
        raise DemistoException(error_message)

    if page and page_size:
        first_item = (int(page) - 1) * int(page_size)
        last_item = int(page) * int(page_size) - 1
        range_ = f'items={first_item}-{last_item}'
    else:
        range_ = f'items=0-{str(limit - 1) if limit else str(DEFAULT_LIMIT_VALUE - 1)}'

    if not filter_:
        if group:
            filter_ += f'group="{group}"'
        if id_:
            filter_ += f' AND id={id_}' if group else f'id={id_}'
        if name:
            filter_ += f' AND name="{name}"' if (group or id_) else f'name="{name}"'

    response = client.get_remote_network_cidr(range_, filter_, fields)
    outputs = [{'id': res.get('id'),
                'name': res.get('name'),
                'description': res.get('description')}
               for res in response]
    headers = ['id', 'name', 'group', 'cidrs', 'description']
    success_message = 'List of the staged remote networks'
    if response:
        readable_output = tableToMarkdown(success_message, response, headers=headers)
        readable_output += f"Above results are with page number: {page} and with size: {page_size}." if page and page_size \
            else f"Above results are with limit: {limit if limit else DEFAULT_LIMIT_VALUE}."
    else:
        readable_output = 'No results found.'

    return CommandResults(
        outputs_prefix='QRadar.RemoteNetworkCIDR',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )


def qradar_remote_network_cidr_delete_command(client: Client, args) -> CommandResults:
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Returns:
    Two CommandResults objects, one for the success and one for the failure.
    """
    ids = argToList(args.get('id'))
    success_delete_ids = []
    unsuccessful_delete_ids = []

    for id_ in ids:
        try:
            client.delete_remote_network_cidr(id_)
            success_delete_ids.append(id_)
        except DemistoException as e:
            unsuccessful_delete_ids.append(assign_params(ID=id_, Error=e.message))

    success_human_readable = tableToMarkdown('Successfully deleted the following remote network(s)',
                                             success_delete_ids, headers=['ID'])
    unsuccessful_human_readable = tableToMarkdown('Failed to delete the following remote network(s)',
                                                  unsuccessful_delete_ids, headers=['ID', 'Error'])

    return CommandResults(
        readable_output=((success_human_readable if success_delete_ids else '')
                         + (unsuccessful_human_readable if unsuccessful_delete_ids else ''))
    )


def qradar_remote_network_cidr_update_command(client: Client, args):
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Raises:
        DemistoException: If the args are not valid.

    Returns:
    CommandResults.
    """
    id_ = arg_to_number(args.get('id'))
    name = args.get('name')
    cidrs_list = argToList(args.get('cidrs'))
    cidrs_from_query = get_cidrs_indicators(args.get('query'))
    description = args.get('description')
    group = args.get('group')
    fields = args.get('fields')

    error_message = verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields)
    if error_message:
        raise DemistoException(error_message)

    body = {
        "name": name,
        "description": description,
        "cidrs": cidrs_list or cidrs_from_query,
        "id": id_,
        "group": group
    }

    response = client.create_and_update_remote_network_cidr(body, fields, update=True)
    success_message = 'The staged remote network was successfully updated'
    outputs = {'id': response.get('id'),
               'name': response.get('name'),
               'group': response.get('group'),
               'description': response.get('description')}

    return CommandResults(
        outputs_prefix='QRadar.RemoteNetworkCIDR',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown(success_message, response),
        raw_response=response
    )


def qradar_remote_network_deploy_execution_command(client: Client, args):
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Returns:
    CommandResults.
    """
    host_ip = args.get('host_ip')
    status = args.get('status', 'INITIATING')
    deployment_type = args.get('deployment_type')

    if not re.match(ipv4Regex, host_ip) and not re.match(ipv6Regex, host_ip):
        raise DemistoException('The host_ip argument is not a valid ip address.')
    if not status == 'INITIATING':
        raise DemistoException('The status argument must be INITIATING.')
    if deployment_type not in ['INCREMENTAL', 'FULL']:
        raise DemistoException('The deployment_type argument must be INCREMENTAL or FULL.')

    body = {"hosts": [{"ip": host_ip, "status": status}], "type": deployment_type}

    response = client.remote_network_deploy_execution(body)
    success_message = 'The remote network deploy execution was successfully created.'

    return CommandResults(
        outputs_prefix='QRadar.deploy',
        outputs={'status': response['status']},
        readable_output=success_message,
        raw_response=response
    )


def qradar_event_collectors_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of event collectors from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, '/config/event_sources/event_collectors', filter_, fields)
    outputs = sanitize_outputs(response, EVENT_COLLECTOR_RAW_FORMATTED)
    headers = build_headers(['ID'], set(EVENT_COLLECTOR_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Event Collectors List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.EventCollector',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_wincollect_destinations_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of WinCollect destinations from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/wincollect/wincollect_destinations'
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, WINCOLLECT_DESTINATION_RAW_FORMATTED)
    headers = build_headers(['ID'], set(WINCOLLECT_DESTINATION_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('WinCollect Destinations List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.WinCollectDestination',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_disconnected_log_collectors_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of disconnected log collectors from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/disconnected_log_collectors'
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, DISCONNECTED_LOG_COLLECTOR_RAW_FORMATTED)
    headers = build_headers(['ID'], set(DISCONNECTED_LOG_COLLECTOR_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Disconnected Log Collectors List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.DisconnectedLogCollector',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_types_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/log_source_management/log_source_types'
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_TYPES_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name', 'Custom', 'Version', 'UUID', 'SupportedLanguageIDs'], set())

    return CommandResults(
        readable_output=tableToMarkdown('Log Source Types List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSourceTypesList',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_protocol_types_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/log_source_management/protocol_types'
    id = args.get('id')
    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_PROTOCOL_TYPE_RAW_FORMATTED)
    headers = ['ID', 'Name', 'CanCollectEvents', 'Testable', 'CanAcceptSampleEvents']
    readable_outputs = ([{
        **protocol_type,
        'CanCollectEvents': protocol_type['TestingCapabilities']['can_collect_events'],
        'Testable': protocol_type['TestingCapabilities']['testable'],
        'CanAcceptSampleEvents': protocol_type['TestingCapabilities']['can_accept_sample_events'],
    } for protocol_type in outputs])

    return CommandResults(
        readable_output=tableToMarkdown('Log Source Protocol Types', readable_outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSourceProtocolType',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_extensions_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/log_source_management/log_source_extensions'
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_EXTENSION_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name', 'Description', 'UUID'], set())

    return CommandResults(
        readable_output=tableToMarkdown('Log Source Extensions List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSourceExtension',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_languages_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/log_source_management/log_source_languages'
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_LANGUAGE_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name'], set())

    return CommandResults(
        readable_output=tableToMarkdown('Log Source Languages List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSourceLanguage',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_groups_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get('filter')
    fields = args.get('fields')
    endpoint = '/config/event_sources/log_source_management/log_source_groups'
    id = args.get('id')

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_GROUP_RAW_FORMATTED)
    headers = build_headers(['ID', 'Name'], set(LOG_SOURCE_GROUP_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown('Log Source Groups List', outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSourceGroup',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Deletes a log source by id or by name.
    Possible arguments:
    - name: The unique name of the log source to be deleted. If you don't provide this argument, id is required.
    - id: The ID of the log source to be deleted. If you don't provide this argument, name is required.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.
    Returns:
        CommandResults.
    """
    name = args.get('name')
    id = args.get('id')

    if id is not None:
        try:
            client.delete_log_source(id)
            return CommandResults(
                readable_output=f'Log source {id} was deleted successfully'
            )
        except DemistoException as e:
            if e.res.status_code == 404:
                return CommandResults(
                    readable_output=f'Log source with id {id} does not exist'
                )
    if name is not None:
        log_source_list = client.get_resource_list(
            'items=0-0',
            'config/event_sources/log_source_management/log_sources',
            f'name="{name}"'
        )
        if not log_source_list:
            return CommandResults(
                readable_output=f'Log source with name {name} does not exist'
            )
        relevant_log_source = log_source_list[0]
        client.delete_log_source(relevant_log_source.get('id'))
        return CommandResults(
            readable_output=f'Log source {name} was deleted successfully'
        )
    raise Exception('At least one of the arguments: name, id must be provided.')


def qradar_log_source_create_command(client: Client, args: dict) -> CommandResults:
    """
    Creates a log source.
    Possible arguments:
    - name: Required. The unique name of the log source.
    - sending_ip: The ip of the system which the log source is associated to, or fed by.
    - protocol_type_id: Required. The type of protocol that is used by the log source.
    - type_id: Required. The type of the log source. Must correspond to an existing log source type.
      Must correspond to an existing protocol type.
    - protocol_parameters: Required. The list of protocol parameters corresponding with the selected protocol type id. The syntax
      for this argument should follow: protocol_parameters="name_1=value_1,name_2=value_2,...,name_n=value_n" where each name
      should correspond to a name of a protocol parameter from the protocol type and each value should fit the type of the
      protocol parameter.
    - descrption: The description of the log source
    - coalesce_events: Determines if events collected by this log source are coalesced based on common properties.
      If each individual event is stored, then the condition is set to false. Defaults to true.
    - enabled: Determines if the log source is enabled. Defaults to true.
    - parsing_order: The order in which log sources will parse if multiple exists with a common identifier.
    - group_ids: Required. The set of log source group IDs this log source is a member of.
      Each ID must correspond to an existing log source group.
    - credibility: On a scale of 0-10, the amount of credibility that the QRadar administrator places on this log source
    - store_event_payload: If the payloads of events that are collected by this log source are stored, the condition is set to
      'true'. If only the normalized event records are stored, then the condition is set to 'false'.
    - target_event_collector_id:  Required. The ID of the event collector where the log source sends its data.
      The ID must correspond to an existing event collector.
    - disconnected_log_collector_id:  The ID of the disconnected log collector where this log source will run.
      The ID must correspond to an existing disconnected log collector.
    - language_id: The language of the events that are being processed by this log source.
      Must correspond to an existing log source language.
    - requires_deploy: Set to 'true' if you need to deploy changes to enable the log source for use;
      otherwise, set to 'false' if the log source is already active.
    - wincollect_internal_destination_id : The internal WinCollect destination for this log source, if applicable.
      Log sources without an associated WinCollect agent have a null value. Must correspond to an existing WinCollect destination.
    - wincollect_external_destination_ids: The set of external WinCollect destinations for this log source, if applicable.
      Log Sources without an associated WinCollect agent have a null value.
      Each ID must correspond to an existing WinCollect destination.
    - gateway: If the log source is configured as a gateway, the condition is set to 'true';
      otherwise, the condition is set to 'false'. A gateway log source is a stand-alone protocol configuration.
      The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to
      feed other log sources. It acts as a "gateway" for events from multiple systems to enter the event pipeline.
    """
    log_source = parse_log_source(args)
    response = client.create_log_source(log_source)
    outputs = sanitize_outputs(response, LOG_SOURCES_RAW_FORMATTED)[0]
    headers = build_headers(['ID', 'Name', 'Description'], set(LOG_SOURCES_RAW_FORMATTED.values()))
    readable_outputs = {
        'ID': outputs['ID'],
        'Name': outputs['Name'],
        'CreationDate': outputs['CreationDate'],
        'Description': outputs['Description'],
        'Enabled': outputs['Enabled'],
        'Status': outputs['Status']['status'],
        'StatusLastUpdated': outputs['Status'].get('last_updated', ''),
        'StatusMessages': outputs['Status'].get('messages', ''),
    }
    return CommandResults(
        readable_output=tableToMarkdown('Log Source Created', readable_outputs, headers, removeNull=True),
        outputs_prefix='QRadar.LogSource',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=response
    )


def qradar_log_source_update_command(client: Client, args: dict) -> CommandResults:
    """
    Creates a log source.
    Possible arguments:
    - id: Required. The id of the log source.
    - name: The unique name of the log source.
    - sending_ip: The ip of the system which the log source is associated to, or fed by.
    - protocol_type_id: The type of protocol that is used by the log source.
    - type_id: The type of the log source. Must correspond to an existing log source type.
      Must correspond to an existing protocol type.
    - protocol_parameters: The list of protocol parameters corresponding with the selected protocol type id. The syntax
      for this argument should follow: protocol_parameters="name_1=value_1,name_2=value_2,...,name_n=value_n" where each name
      should correspond to a name of a protocol parameter from the protocol type and each value should fit the type of the
      protocol parameter.
    - descrption: The description of the log source
    - coalesce_events: Determines if events collected by this log source are coalesced based on common properties.
      If each individual event is stored, then the condition is set to false. Defaults to true.
    - enabled: Determines if the log source is enabled. Defaults to true.
    - parsing_order: The order in which log sources will parse if multiple exists with a common identifier.
    - group_ids: The set of log source group IDs this log source is a member of.
      Each ID must correspond to an existing log source group.
    - credibility: On a scale of 0-10, the amount of credibility that the QRadar administrator places on this log source
    - store_event_payload: If the payloads of events that are collected by this log source are stored, the condition is set to
      'true'. If only the normalized event records are stored, then the condition is set to 'false'.
    - target_event_collector_id:  The ID of the event collector where the log source sends its data.
      The ID must correspond to an existing event collector.
    - disconnected_log_collector_id:  The ID of the disconnected log collector where this log source will run.
      The ID must correspond to an existing disconnected log collector.
    - language_id: The language of the events that are being processed by this log source.
      Must correspond to an existing log source language.
    - requires_deploy: Set to 'true' if you need to deploy changes to enable the log source for use;
      otherwise, set to 'false' if the log source is already active.
    - wincollect_internal_destination_id : The internal WinCollect destination for this log source, if applicable.
      Log sources without an associated WinCollect agent have a null value. Must correspond to an existing WinCollect destination.
    - wincollect_external_destination_ids: The set of external WinCollect destinations for this log source, if applicable.
      Log Sources without an associated WinCollect agent have a null value.
      Each ID must correspond to an existing WinCollect destination.
    - gateway: If the log source is configured as a gateway, the condition is set to 'true';
      otherwise, the condition is set to 'false'. A gateway log source is a stand-alone protocol configuration.
      The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to
      feed other log sources. It acts as a "gateway" for events from multiple systems to enter the event pipeline.
    """
    id = args.get('id')
    log_source = parse_partial_log_source(args)
    client.update_log_source(log_source)
    return CommandResults(readable_output=f'Log source {id} was updated successfully')


def migrate_integration_ctx(ctx: dict) -> dict:
    """Migrates the old context to the current context

    Args:
        ctx: The context_data to simplify

    Returns: The cleared context_data
    """
    fetch_id_ctx: str = ctx.get(LAST_FETCH_KEY, '0')
    try:
        fetch_id = int(fetch_id_ctx)
    except ValueError:
        try:
            fetch_id = int(json.loads(fetch_id_ctx))
        except ValueError:
            print_debug_msg(f"Could not retrieve LAST_FETCH_KEY from {fetch_id_ctx} Setting to 0")
            fetch_id = 0

    last_update_ctx: str = ctx.get(LAST_MIRROR_KEY, '0')
    try:
        last_update = int(last_update_ctx)
    except ValueError:
        try:
            last_update = int(json.loads(last_update_ctx))
        except ValueError:
            print_debug_msg(f"Could not retrieve last_mirror_update from {last_update_ctx} Setting to 0")
            last_update = 0

    mirrored_offenses: dict[str, str] = {}
    try:
        for key in ('mirrored_offenses', 'updated_mirrored_offenses', 'resubmitted_mirrored_offenses'):
            mirrored_offenses |= {json.loads(offense).get(
                'id'): QueryStatus.WAIT.value for offense in json.loads(ctx.get(key, '[]'))}
    except Exception as e:
        print_debug_msg(f'Could not load mirrored_offenses from context_data. Error: {e}')

    return {LAST_FETCH_KEY: fetch_id,
            LAST_MIRROR_KEY: last_update,
            MIRRORED_OFFENSES_QUERIED_CTX_KEY: mirrored_offenses,
            MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
            MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
            'samples': []}


def validate_integration_context() -> None:
    """
    The new context structure consists two dictionaries of queried offenses and finished offenses.
    The structure consists the actual objects and JSON of them.

    Because some customers already have instances with the old context, we will try to convert the old context to the new one.
    to make them be compatible with new changes.
    Returns:
        (None): Modifies context to be compatible.
    """
    context_data, context_version = get_integration_context_with_version()
    new_ctx = context_data.copy()
    try:
        print_context_data_stats(context_data, "Checking ctx")
        print_debug_msg("Context is with the new mirroring standard")
        extract_works = True
    except Exception as e:
        print_debug_msg(f"Checking {context_data} failed, trying to make it retry compatible. Error was: {str(e)}")
        extract_works = False

    if not extract_works:
        cleared_ctx = migrate_integration_ctx(new_ctx)
        print_debug_msg(f"Change ctx context data was cleared and changing to {cleared_ctx}")
        safely_update_context_data(cleared_ctx, context_version, should_force_update=True)
        print_debug_msg(f"Change ctx context data was cleared and changed to {cleared_ctx}")
    elif MIRRORED_OFFENSES_FETCHED_CTX_KEY not in context_data:
        print_debug_msg(f"Adding {MIRRORED_OFFENSES_FETCHED_CTX_KEY} to context")
        new_ctx[MIRRORED_OFFENSES_FETCHED_CTX_KEY] = {}
        safely_update_context_data(new_ctx, context_version, should_force_update=True)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
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
            raise DemistoException(
                f'Failed to parse advanced params. Error: {e.message}'
            ) from e
        except Exception as e:
            raise DemistoException(f'Failed to parse advanced params. Error: {e}') from e

    server = params.get('server')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_version = params.get('api_version')
    if api_version and float(api_version) < MINIMUM_API_VERSION:
        raise DemistoException(f'API version cannot be lower than {MINIMUM_API_VERSION}')
    credentials = params.get('credentials')
    timeout = arg_to_number(params.get("timeout"))

    try:

        client = Client(
            server=server,
            verify=verify_certificate,
            proxy=proxy,
            api_version=api_version,
            credentials=credentials,
            timeout=timeout
        )
        # All command names with or are for supporting QRadar v2 command names for backward compatibility
        if command == 'test-module':
            validate_integration_context()
            return_results(test_module_command(client, params))

        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents_command())

        elif command == 'long-running-execution':
            validate_integration_context()
            support_multithreading()
            long_running_execution_command(client, params)

        elif command in [
            'qradar-offenses-list',
            'qradar-offenses',
            'qradar-offense-by-id',
        ]:
            return_results(qradar_offenses_list_command(client, args))

        elif command in ['qradar-offense-update', 'qradar-update-offense']:
            return_results(qradar_offense_update_command(client, args))

        elif command in ['qradar-closing-reasons', 'qradar-get-closing-reasons']:
            return_results(qradar_closing_reasons_list_command(client, args))

        elif command in ['qradar-offense-notes-list', 'qradar-get-note']:
            return_results(qradar_offense_notes_list_command(client, args))

        elif command in ['qradar-offense-note-create', 'qradar-create-note']:
            return_results(qradar_offense_notes_create_command(client, args))

        elif command == 'qradar-rules-list':
            return_results(qradar_rules_list_command(client, args))

        elif command == 'qradar-rule-groups-list':
            return_results(qradar_rule_groups_list_command(client, args))

        elif command in [
            'qradar-assets-list',
            'qradar-get-assets',
            'qradar-get-asset-by-id',
        ]:
            return_results(qradar_assets_list_command(client, args))

        elif command == 'qradar-saved-searches-list':
            return_results(qradar_saved_searches_list_command(client, args))

        elif command == 'qradar-searches-list':
            return_results(qradar_searches_list_command(client, args))

        elif command in ['qradar-search-create', 'qradar-searches']:
            return_results(qradar_search_create_command(client, params, args))

        elif command in ['qradar-search-status-get', 'qradar-get-search']:
            return_results(qradar_search_status_get_command(client, args))

        elif command in [
            'qradar-search-results-get',
            'qradar-get-search-results',
        ]:
            return_results(qradar_search_results_get_command(client, args))

        elif command == 'qradar-search-cancel':
            return_results(qradar_search_cancel_command(client, args))

        elif command == 'qradar-search-delete':
            return_results(qradar_search_delete_command(client, args))

        elif command in [
            'qradar-reference-sets-list',
            'qradar-get-reference-by-name',
        ]:
            return_results(qradar_reference_sets_list_command(client, args))

        elif command in [
            'qradar-reference-set-create',
            'qradar-create-reference-set',
        ]:
            return_results(qradar_reference_set_create_command(client, args))

        elif command in [
            'qradar-reference-set-delete',
            'qradar-delete-reference-set',
        ]:
            return_results(qradar_reference_set_delete_command(client, args))

        elif command in [
            'qradar-reference-set-value-upsert',
            'qradar-create-reference-set-value',
            'qradar-update-reference-set-value',
        ]:
            return_results(qradar_reference_set_value_upsert_command(args, client, params))

        elif command in [
            'qradar-reference-set-value-delete',
            'qradar-delete-reference-set-value',
        ]:
            return_results(qradar_reference_set_value_delete_command(client, args))

        elif command in [
            'qradar-domains-list',
            'qradar-get-domains',
            'qradar-get-domain-by-id',
        ]:
            return_results(qradar_domains_list_command(client, args))

        elif command in ['qradar-indicators-upload', 'qradar-upload-indicators']:
            return_results(qradar_indicators_upload_command(args, client, params))

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
            validate_integration_context()
            return_results(get_remote_data_command(client, params, args))

        elif command == 'get-modified-remote-data':
            validate_integration_context()
            return_results(get_modified_remote_data_command(client, params, args))

        elif command == 'qradar-search-retrieve-events':
            return_results(qradar_search_retrieve_events_command(client, params, args))

        elif command == 'qradar-remote-network-cidr-create':
            return_results(qradar_remote_network_cidr_create_command(client, args))

        elif command == 'qradar-remote-network-cidr-list':
            return_results(qradar_remote_network_cidr_list_command(client, args))

        elif command == 'qradar-remote-network-cidr-delete':
            return_results(qradar_remote_network_cidr_delete_command(client, args))

        elif command == 'qradar-remote-network-cidr-update':
            return_results(qradar_remote_network_cidr_update_command(client, args))

        elif command == 'qradar-remote-network-deploy-execution':
            return_results(qradar_remote_network_deploy_execution_command(client, args))

        elif command == 'qradar-event-collectors-list':
            return_results(qradar_event_collectors_list_command(client, args))

        elif command == 'qradar-wincollect-destinations-list':
            return_results(qradar_wincollect_destinations_list_command(client, args))

        elif command == 'qradar-disconnected-log-collectors-list':
            return_results(qradar_disconnected_log_collectors_list_command(client, args))

        elif command == 'qradar-log-source-types-list':
            return_results(qradar_log_source_types_list_command(client, args))

        elif command == 'qradar-log-source-protocol-types-list':
            return_results(qradar_log_source_protocol_types_list_command(client, args))

        elif command == 'qradar-log-source-extensions-list':
            return_results(qradar_log_source_extensions_list_command(client, args))

        elif command == 'qradar-log-source-languages-list':
            return_results(qradar_log_source_languages_list_command(client, args))

        elif command == 'qradar-log-source-groups-list':
            return_results(qradar_log_source_groups_list_command(client, args))

        elif command == 'qradar-log-source-delete':
            return_results(qradar_log_source_delete_command(client, args))

        elif command == 'qradar-log-source-create':
            return_results(qradar_log_source_create_command(client, args))

        elif command == 'qradar-log-source-update':
            return_results(qradar_log_source_update_command(client, args))

        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    except Exception as e:
        print_debug_msg(f"The integration context_data is {get_integration_context()}")
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}\nException is: {str(e)}')
    finally:
        #  CIAC-10628
        if command not in ("test-module", "fetch-incidents", "long-running-execution"):
            client._return_execution_metrics_results()
            client.execution_metrics.metrics = None


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    register_signal_handler_profiling_dump(profiling_dump_rows_limit=PROFILING_DUMP_ROWS_LIMIT)
    main()
