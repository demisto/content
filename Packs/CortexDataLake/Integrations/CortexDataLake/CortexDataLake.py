""" IMPORTS """
from CommonServerPython import *
import os
import requests
import json
from pancloud import QueryService, Credentials, exceptions
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Any, List, Tuple, Callable
from tempfile import gettempdir
from dateutil import parser

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL CONSTS '''
ACCESS_TOKEN_CONST = 'access_token'  # guardrails-disable-line
REFRESH_TOKEN_CONST = 'refresh_token'  # guardrails-disable-line
EXPIRES_IN = 'expires_in'
INSTANCE_ID_CONST = 'instance_id'
API_URL_CONST = 'api_url'
REGISTRATION_ID_CONST = 'reg_id'
ENCRYPTION_KEY_CONST = 'auth_key'
DEFAULT_API_URL = 'https://api.us.cdl.paloaltonetworks.com'
MINUTES_60 = 60 * 60
SECONDS_30 = 30


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, token_retrieval_url, registration_id, use_ssl, proxy, refresh_token, enc_key):
        headers = {
            'Authorization': registration_id,
            'Accept': 'application/json'
        }
        super().__init__(base_url=token_retrieval_url, headers=headers, verify=use_ssl, proxy=proxy)
        self.refresh_token = refresh_token
        self.enc_key = enc_key
        self.use_ssl = use_ssl
        # Trust environment settings for proxy configuration
        self.trust_env = proxy
        self._get_access_token()

    def _get_access_token(self):
        """
        Checks if access token exists in the integration context and return it if it exists, if not, a new token
        is generated and saved in the integration context along with the query api_url and the instance_id
        Returns:
            The access token from the integration context or from the request.
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get(ACCESS_TOKEN_CONST)
        valid_until = integration_context.get(EXPIRES_IN)
        if access_token and valid_until:
            if int(time.time()) < valid_until:
                self.access_token = access_token
                self.api_url = integration_context.get(API_URL_CONST, DEFAULT_API_URL)
                self.instance_id = integration_context.get(INSTANCE_ID_CONST)
        access_token, api_url, instance_id, refresh_token, expires_in = self._oproxy_authorize()
        updated_integration_context = {
            ACCESS_TOKEN_CONST: access_token,
            EXPIRES_IN: int(time.time()) + expires_in - SECONDS_30,
            API_URL_CONST: api_url,
            INSTANCE_ID_CONST: instance_id
        }
        if refresh_token:
            updated_integration_context.update({REFRESH_TOKEN_CONST: refresh_token})
        demisto.setIntegrationContext(updated_integration_context)
        self.access_token = access_token
        self.api_url = api_url
        self.instance_id = instance_id

    def _oproxy_authorize(self) -> Tuple[str, str, str, str, int]:
        oproxy_response = self._http_request('POST',
                                             '/cdl-token',
                                             json_data={'token': get_encrypted(self.refresh_token, self.enc_key)},
                                             timeout=(60 * 3, 60 * 3),
                                             retries=3,
                                             backoff_factor=10,
                                             status_list_to_retry=[400])
        access_token = oproxy_response.get(ACCESS_TOKEN_CONST)
        api_url = oproxy_response.get('url')
        refresh_token = oproxy_response.get(REFRESH_TOKEN_CONST)
        instance_id = oproxy_response.get(INSTANCE_ID_CONST)
        expires_in = int(oproxy_response.get(EXPIRES_IN, MINUTES_60))
        if not access_token or not api_url or not instance_id:
            raise DemistoException(f'Missing attribute in response: access_token, instance_id or api are missing.\n'
                                   f'Oproxy response: {oproxy_response}')
        return access_token, api_url, instance_id, refresh_token, expires_in

    def query_loggings(self, query: str) -> Tuple[List[dict], list]:
        """
        This function handles all the querying of Cortex Logging service

        Args:
            query: The sql string query.

        Returns:
            A list of records according to the query
        """
        query_data = {'query': self.add_instance_id_to_query(query),
                      'language': 'csql'}
        query_service = self.initial_query_service()
        response = query_service.create_query(query_params=query_data, enforce_json=True)
        query_result = response.json()

        if not response.ok:
            status_code = response.status_code
            try:
                # For some error responses the messages are in 'query_result['errors'] and for some they are simply
                # in 'query_result
                errors = query_result.get('errors', query_result)
                error_message = ''.join([message.get('message') for message in errors])
            except AttributeError:
                error_message = query_result

            raise DemistoException(f'Error in query to Cortex Data Lake [{status_code}] - {error_message}')

        try:
            raw_results = [r.json() for r in query_service.iter_job_results(job_id=query_result.get('jobId'),
                                                                            result_format='valuesDictionary',
                                                                            max_wait=2000)]
        except exceptions.HTTPError as e:
            raise DemistoException(f'Received error {str(e)} when querying logs.')

        extended_results: List[Dict] = []
        for result in raw_results:
            page = result.get('page', {})
            data = page.get('result', {}).get('data', [])
            if data:
                extended_results.extend(data)

        return extended_results, raw_results

    def initial_query_service(self) -> QueryService:
        credentials = Credentials(
            access_token=self.access_token,
            verify=self.use_ssl
        )
        query_service = QueryService(
            url=self.api_url,
            credentials=credentials,
            trust_env=self.trust_env
        )
        return query_service

    def add_instance_id_to_query(self, query: str) -> str:
        """
        On apollo v2 all table names must have the instance_id at the top of their hierarchy.
        This function adds the instance_id to the query.
        For example:
        For the query "SELECT * FROM `test`" with instance_id=1234 this function will return "SELECT * FROM `1234.test`"
        Args:
            query: A query for CDL
        Returns:
            A query with instance_id
        """
        FIND_FROM_STATEMENT_REGEX_PATTERN = r'(?i)FROM `'
        query = re.sub(FIND_FROM_STATEMENT_REGEX_PATTERN, f'FROM `{self.instance_id}.', query)
        return query


''' HELPER FUNCTIONS '''


def human_readable_time_from_epoch_time(epoch_time: int, utc_time: bool = False):
    """
    Divides the epoch time by 1e6 since the epoch format has 6 trailing zeroes
    Since incidents need the time in utc format (ends in 'Z') but the SQL syntax cannot parse a UTC formatted date well
    it is parameterized
    Args:
        utc_time: A boolean that states weather to add the 'Z' at the end of the date string
        epoch_time: Epoch time as it is in the raw_content
    Returns:
        human readable time in the format of '1970-01-01T02:00:00'
    """
    result = datetime.fromtimestamp(epoch_time / 1e6).isoformat() if epoch_time else None
    if result:
        result += 'Z' if utc_time else ''
    return result


def common_context_transformer(row_content):
    """
        This function retrieves data from a row of raw data into context path locations

        Args:
            row_content: a dict representing raw data of a row

        Returns:
            a dict with context paths and their corresponding value
        """
    return {
        'Action': row_content.get('action', {}).get('value'),
        'App': row_content.get('app'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'LogSourceName': row_content.get('log_source_name'),
        'IsNat': row_content.get('is_nat'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'AppCategory': row_content.get('app_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'FileSHA256': row_content.get('file_sha_256'),
        'FileName': row_content.get('file_name'),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0))
    }


def traffic_context_transformer(row_content: dict) -> dict:
    """
    This function retrieves data from a row of raw data into context path locations

    Args:
        row_content: a dict representing raw data of a row

    Returns:
        a dict with context paths and their corresponding value
    """

    return {
        'Action': row_content.get('action', {}).get('value'),
        'RiskOfApp': row_content.get('risk_of_app'),
        'NatSourcePort': row_content.get('nat_source_port'),
        'SessionID': row_content.get('session_id'),
        'Packets': row_content.get('packets_total'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'App': row_content.get('app'),
        'Vsys': row_content.get('vsys'),
        'IsNat': row_content.get('is_nat'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'SubcategoryOfApp': row_content.get('app_sub_category'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'DestinationPort': row_content.get('dest_port'),
        'TotalTimeElapsed': row_content.get('total_time_elapsed'),
        'LogSourceName': row_content.get('log_source_name'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'Users': row_content.get('users'),
        'TunneledApp': row_content.get('tunneled_app'),
        'IsPhishing': row_content.get('is_phishing'),
        'SessionEndReason': row_content.get('session_end_reason', {}).get('value'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'SessionStartIP': human_readable_time_from_epoch_time(row_content.get('session_start_time', 0)),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0)),
        'AppCategory': row_content.get('app_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'LogSourceID': row_content.get('log_source_id'),
        'TotalBytes': row_content.get('bytes_total'),
        'VsysID': row_content.get('vsys_id'),
        'ToZone': row_content.get('to_zone'),
        'URLCategory': row_content.get('url_category', {}).get('value'),
        'SourcePort': row_content.get('source_port'),
        'Tunnel': row_content.get('tunnel', {}).get('value')
    }


def threat_context_transformer(row_content: dict) -> dict:
    """
    This function retrieves data from a row of raw data into context path locations

    Args:
        row_content: a dict representing raw data of a row

    Returns:
        a dict with context paths and their corresponding value
    """
    return {
        'SessionID': row_content.get('session_id'),
        'Action': row_content.get('action', {}).get('value'),
        'App': row_content.get('app'),
        'IsNat': row_content.get('is_nat'),
        'SubcategoryOfApp': row_content.get('app_sub_category'),
        'PcapID': row_content.get('pcap_id'),
        'NatDestination': row_content.get('nat_dest', {}).get('value'),
        'Flags': row_content.get('flags'),
        'DestinationPort': row_content.get('dest_port'),
        'ThreatID': row_content.get('threat_id'),
        'NatSource': row_content.get('nat_source', {}).get('value'),
        'IsURLDenied': row_content.get('is_url_denied'),
        'Users': row_content.get('users'),
        'TimeGenerated': human_readable_time_from_epoch_time(row_content.get('time_generated', 0)),
        'IsPhishing': row_content.get('is_phishing'),
        'AppCategory': row_content.get('app_category'),
        'SourceLocation': row_content.get('source_location'),
        'DestinationLocation': row_content.get('dest_location'),
        'ToZone': row_content.get('to_zone'),
        'RiskOfApp': row_content.get('risk_of_app'),
        'NatSourcePort': row_content.get('nat_source_port'),
        'CharacteristicOfApp': row_content.get('characteristics_of_app'),
        'FromZone': row_content.get('from_zone'),
        'Vsys': row_content.get('vsys'),
        'Protocol': row_content.get('protocol', {}).get('value'),
        'NatDestinationPort': row_content.get('nat_dest_port'),
        'DestinationIP': row_content.get('dest_ip', {}).get('value'),
        'SourceIP': row_content.get('source_ip', {}).get('value'),
        'RuleMatched': row_content.get('rule_matched'),
        'ThreatCategory': row_content.get('threat_category', {}).get('value'),
        'LogSourceName': row_content.get('log_source_name'),
        'Subtype': row_content.get('sub_type', {}).get('value'),
        'Direction': row_content.get('direction_of_attack', {}).get('value'),
        'FileName': row_content.get('file_name'),
        'VendorSeverity': row_content.get('vendor_severity', {}).get('value'),
        'LogTime': human_readable_time_from_epoch_time(row_content.get('log_time', 0)),
        'LogSourceID': row_content.get('log_source_id'),
        'VsysID': row_content.get('vsys_id'),
        'URLDomain': row_content.get('url_domain'),
        'URLCategory': row_content.get('url_category', {}).get('value'),
        'SourcePort': row_content.get('source_port'),
        'FileSHA256': row_content.get('file_sha_256')
    }


def records_to_human_readable_output(fields: str, table_name: str, results: list) -> str:
    """
    This function gets all relevant data for the human readable output of a specific table.
    By design if the user queries all fields of the table (i.e. enters '*' in the query) than the outputs
    shown in the war room will be the same for each query - the outputs will be the headers list in the code.
    If the user selects different fields in the query than those fields will be shown to the user.

    Args:
        fields: The field of the table named table_name
        table_name: The name of the table
        results: The results needs to be shown

    Returns:
        A markdown table of the outputs
    """
    filtered_results: list = []

    if fields == '*':
        for result in results:
            filtered_result = {
                'Source Address': result.get('source_ip', {}).get('value'),
                'Destination Address': result.get('dest_ip', {}).get('value'),
                'Application': result.get('app'),
                'Action': result.get('action', {}).get('value'),
                'RuleMatched': result.get('rule_matched'),
                'TimeGenerated': human_readable_time_from_epoch_time(result.get('time_generated')),
            }
            filtered_results.append(filtered_result)
    else:
        for result in results:
            filtered_result = {}
            for root in result.keys():
                parsed_tree: dict = parse_tree_by_root_to_leaf_paths(root, result[root])
                filtered_result.update(parsed_tree)
            filtered_results.append(filtered_result)

    return tableToMarkdown(f'Logs {table_name} table', filtered_results, removeNull=True)


def parse_tree_by_root_to_leaf_paths(root: str, body) -> dict:
    """
    This function receives a dict (root and a body) and parses it according to the upcoming example:
    Input: root = 'a', body = {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}.
    So the dict is {'a': {'b': 2, 'c': 3, 'd': {'e': 5, 'f': 6, 'g': {'h': 8, 'i': 9}}}}
    The expected output is {'a.b': 2, 'a.c': 3, 'a.d.e': 5, 'a.d.f': 6, 'a.d.g.h': 8, 'a.d.g.i': 9}
    Basically what this function does is when it gets a tree it creates a dict from it which it's keys are all
    root to leaf paths and the corresponding values are the values in the leafs
    Please note that the implementation is similar to DFS on trees (which means we don't have to check for visited
    nodes since there are no cycles)

    Args:
        root: The root string
        body: The body of the root

    Returns:
        The parsed tree
    """
    parsed_tree: dict = {}
    help_stack: list = [(root, body)]

    while help_stack:
        node: tuple = help_stack.pop()
        root_to_node_path: str = node[0]
        body = node[1]
        if isinstance(body, dict):
            for key, value in body.items():
                # for each node we append a tuple of it's body and the path from the root to it
                help_stack.append((root_to_node_path + '.' + key, value))
        elif isinstance(body, list):
            for element in body:
                help_stack.append((root_to_node_path, element))
        else:
            parsed_tree[root_to_node_path] = body
    return parsed_tree


def build_where_clause(args: dict) -> str:
    """
    This function transforms the relevant entries of dict into the where part of a SQL query

    Args:
        args: The arguments dict

    Returns:
        A string represents the where part of a SQL query
    """

    args_dict = {
        'source_ip': 'source_ip.value',
        'dest_ip': 'dest_ip.value',
        'rule_matched': 'rule_matched',
        'from_zone': 'from_zone',
        'to_zone': 'to_zone',
        'source_port': 'source_port',
        'dest_port': 'dest_port',
        'action': 'action.value',
        'file_sha_256': 'file_sha_256',
        'file_name': 'file_name',
    }
    non_string_keys = {'dest_port', 'source_port'}
    if 'query' in args:
        # if query arg is supplied than we just need to parse it and only it
        return args['query'].strip()

    # We want to add only keys that are part of the query
    string_query_fields = {key: value for key, value in args.items() if key in args_dict and key not in non_string_keys}
    or_statements = []
    for key, values in string_query_fields.items():
        string_values_list: list = argToList(values)
        field = args_dict[key]
        or_statements.append(' OR '.join([f'{field} = "{value}"' for value in string_values_list]))
    # ports are digested as ints and cannot be sent as strings
    non_string_query_fields = {key: value for key, value in args.items() if key in non_string_keys}
    for key, values in non_string_query_fields.items():
        non_string_values_list: list = argToList(values)
        field = args_dict[key]
        or_statements.append(' OR '.join([f'{field} = {value}' for value in non_string_values_list]))
    where_clause = ' AND '.join([f'({or_statement})' for or_statement in or_statements if or_statement])
    return where_clause


def get_encrypted(auth_id: str, key: str) -> str:
    """

    Args:
        auth_id (str): auth_id from oproxy
        key (str): key from oproxy

    Returns:
        The encrypted auth_id with the time it was encrypted using AESGCM algorithm
    """

    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        """

        Args:
            enc_key (str):
            string (str):

        Returns:
            bytes:
        """
        # String to bytes
        decoded_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(decoded_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)

    now = int(time.time())
    return encrypt(f'{now}:{auth_id}', key).decode('utf-8')


def prepare_fetch_incidents_query(fetch_timestamp: str,
                                  fetch_severity: list,
                                  fetch_subtype: list,
                                  fetch_limit: str) -> str:
    """
    Prepares the SQL query for fetch incidents command
    Args:
        fetch_limit: Indicates how many incidents should be queried
        fetch_timestamp: The date from which threat logs should be queried
        fetch_severity: Severity associated with the incident.
        fetch_subtype: Identifies the log subtype.

    Returns:
        SQL query that matches the arguments
    """
    query = 'SELECT * FROM `firewall.threat` '  # guardrails-disable-line
    query += f'WHERE (TIME(time_generated) Between TIME(TIMESTAMP("{fetch_timestamp}")) ' \
             f'AND TIME(CURRENT_TIMESTAMP))'
    if fetch_subtype and 'all' not in fetch_subtype:
        sub_types = [f'sub_type.value = "{sub_type}"' for sub_type in fetch_subtype]
        query += f' AND ({" OR ".join(sub_types)})'
    if fetch_severity and 'all' not in fetch_severity:
        severities = [f'vendor_severity.value = "{severity}"' for severity in fetch_severity]
        query += f' AND ({" OR ".join(severities)})'
    query += f' ORDER BY time_generated ASC LIMIT {fetch_limit}'
    return query


def convert_log_to_incident(log: dict) -> dict:
    time_generated = log.get('time_generated', 0)
    occurred = human_readable_time_from_epoch_time(time_generated, utc_time=True)
    incident = {
        'name': 'Cortex Firewall Threat',
        'rawJSON': json.dumps(log, ensure_ascii=False),
        'occurred': occurred
    }
    return incident


''' COMMANDS FUNCTIONS '''


def test_module(client: Client):
    query = 'SELECT * FROM `firewall.traffic` limit 1'
    client.query_loggings(query)
    return_outputs('ok')


def query_logs_command(args: dict, client: Client) -> Tuple[str, Dict[str, List[dict]], List[Dict[str, Any]]]:
    """
    Return the result of querying the Logging service
    """
    query = args.get('query', '')
    limit = args.get('limit', '')

    if 'limit' not in query.lower():
        query += f' LIMIT {limit}'

    records, raw_results = client.query_loggings(query)

    table_name = get_table_name(query)
    transformed_results = [common_context_transformer(record) for record in records]
    human_readable = tableToMarkdown('Logs ' + table_name + ' table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging': transformed_results
    }
    return human_readable, ec, raw_results


def get_table_name(query: str) -> str:
    """
    Table name is stored in log_type attribute of the records
    Args:
        query: Query string, i.e SELECT * FROM firewall.threat LIMIT 1

    Returns:
        The query's table name
    """
    find_table_name_from_query = r'(FROM `)(\w+.\w+)(`)'
    search_result = re.search(find_table_name_from_query, query)
    if search_result:
        return search_result.group(2)
    return "Unrecognized table name"


def get_critical_logs_command(args: dict, client: Client) -> Tuple[str, Dict[str, List[dict]], List[Dict[str, Any]]]:
    """
    Queries Cortex Logging according to a pre-set query
    """
    logs_amount = args.get('limit')
    query_start_time, query_end_time = query_timestamp(args)
    query = 'SELECT * FROM `firewall.threat` WHERE severity = "Critical" '  # guardrails-disable-line
    query += f'AND (TIME(time_generated) BETWEEN TIME(TIMESTAMP("{query_start_time}")) AND ' \
             f'TIME(TIMESTAMP("{query_end_time}"))) LIMIT {logs_amount}'

    records, raw_results = client.query_loggings(query)

    transformed_results = [threat_context_transformer(record) for record in records]

    human_readable = tableToMarkdown('Logs threat table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging.Threat': transformed_results
    }
    return human_readable, ec, raw_results


def query_timestamp(args: dict) -> Tuple[datetime, datetime]:
    start_time = args.get('start_time', '')
    end_time = args.get('end_time', '')
    time_range = args.get('time_range', '')
    if time_range:
        query_start_time, query_end_time = parse_date_range(time_range)
    else:
        # parses user input to datetime object
        query_start_time = parser.parse(start_time)
        # if end_time is not given- will be replaced with current time
        query_end_time = parser.parse(end_time) if end_time else datetime.fromtimestamp(time.time())
    return query_start_time.replace(microsecond=0), query_end_time.replace(microsecond=0)


def get_social_applications_command(args: dict,
                                    client: Client) -> Tuple[str, Dict[str, List[dict]], List[Dict[str, Any]]]:
    """ Queries Cortex Logging according to a pre-set query """
    logs_amount = args.get('limit')
    query_start_time, query_end_time = query_timestamp(args)
    query = 'SELECT * FROM `firewall.traffic` WHERE app_sub_category = "social-networking" '  # guardrails-disable-line
    query += f' AND (TIME(time_generated) BETWEEN TIME(TIMESTAMP("{query_start_time}")) AND ' \
             f'TIME(TIMESTAMP("{query_end_time}"))) LIMIT {logs_amount}'

    records, raw_results = client.query_loggings(query)

    transformed_results = [traffic_context_transformer(record) for record in records]

    human_readable = tableToMarkdown('Logs traffic table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging.Traffic': transformed_results
    }
    return human_readable, ec, raw_results


def search_by_file_hash_command(args: dict, client: Client) -> Tuple[str, Dict[str, List[dict]], List[Dict[str, Any]]]:
    """
    Queries Cortex Logging according to a pre-set query
    """
    logs_amount = args.get('limit')
    file_hash = args.get('SHA256')

    query_start_time, query_end_time = query_timestamp(args)
    query = f'SELECT * FROM `firewall.threat` WHERE file_sha_256 = "{file_hash}" '  # guardrails-disable-line
    query += f'AND (TIME(time_generated) BETWEEN TIME(TIMESTAMP("{query_start_time}")) AND ' \
             f'TIME(TIMESTAMP("{query_end_time}"))) LIMIT {logs_amount}'

    records, raw_results = client.query_loggings(query)

    transformed_results = [threat_context_transformer(record) for record in records]

    human_readable = tableToMarkdown('Logs threat table', transformed_results, removeNull=True)
    ec = {
        'CDL.Logging.Threat': transformed_results
    }
    return human_readable, ec, raw_results


def query_traffic_logs_command(args: dict, client: Client) -> Tuple[str, dict, List[Dict[str, Any]]]:
    """
    The function of the command that queries firewall.traffic table

        Returns: a Demisto's entry with all the parsed data
    """
    table_name: str = 'traffic'
    context_transformer_function = traffic_context_transformer
    table_context_path: str = 'CDL.Logging.Traffic'
    return query_table_logs(args, client, table_name, context_transformer_function, table_context_path)


def query_threat_logs_command(args: dict, client: Client) -> Tuple[str, dict, List[Dict[str, Any]]]:
    """
    The function of the command that queries firewall.threat table

        Returns: a Demisto's entry with all the parsed data
    """
    query_table_name: str = 'threat'
    context_transformer_function = threat_context_transformer
    table_context_path: str = 'CDL.Logging.Threat'
    return query_table_logs(args, client, query_table_name, context_transformer_function, table_context_path)


def query_table_logs(args: dict,
                     client: Client,
                     table_name: str,
                     context_transformer_function: Callable[[dict], dict],
                     table_context_path: str) -> Tuple[str, dict, List[Dict[str, Any]]]:
    """
    This function is a generic function that get's all the data needed for a specific table of Cortex and acts as a
    regular command function

    Args:
        args: demisto args
        client: The client
        table_name: the name of the table in Cortex
        context_transformer_function:  the context transformer function to parse the data
        table_context_path: the context path where the parsed data should be located
    """
    fields, query = build_query(args, table_name)
    results, raw_results = client.query_loggings(query)
    outputs = [context_transformer_function(record) for record in results]
    human_readable = records_to_human_readable_output(fields, table_name, results)

    context_outputs: dict = {table_context_path: outputs}
    return human_readable, context_outputs, raw_results


def build_query(args, table_name):
    fields = args.get('fields', 'all')
    fields = '*' if 'all' in fields else fields
    where = build_where_clause(args)
    query_start_time, query_end_time = query_timestamp(args)
    timestamp_limitation = f'(TIME(time_generated) BETWEEN TIME(TIMESTAMP("{query_start_time}")) AND ' \
                           f'TIME(TIMESTAMP("{query_end_time}"))) '
    limit = args.get('limit', '5')
    where += f' AND {timestamp_limitation}' if where else timestamp_limitation
    query = f'SELECT {fields} FROM `firewall.{table_name}` WHERE {where} LIMIT {limit}'
    return fields, query


def fetch_incidents(client: Client,
                    first_fetch_timestamp: str,
                    fetch_severity: list,
                    fetch_subtype: list,
                    fetch_limit: str,
                    last_run: dict) -> Tuple[Dict[str, str], list]:
    last_fetched_event_timestamp = last_run.get('lastRun')

    if last_fetched_event_timestamp:
        last_fetched_event_timestamp = parser.parse(last_fetched_event_timestamp)
    else:
        last_fetched_event_timestamp, _ = parse_date_range(first_fetch_timestamp)
        last_fetched_event_timestamp = last_fetched_event_timestamp.replace(microsecond=0)
    query = prepare_fetch_incidents_query(last_fetched_event_timestamp, fetch_severity, fetch_subtype, fetch_limit)
    demisto.debug('Query being fetched: {}'.format(query))
    records, _ = client.query_loggings(query)
    if not records:
        return {'lastRun': str(last_fetched_event_timestamp)}, []

    incidents = [convert_log_to_incident(record) for record in records]
    max_fetched_event_timestamp = max(records, key=lambda record: record.get('time_generated', 0)).get('time_generated',
                                                                                                       0)
    next_run = {'lastRun': human_readable_time_from_epoch_time(max_fetched_event_timestamp)}
    return next_run, incidents


''' EXECUTION CODE '''


def main():
    os.environ['PAN_CREDENTIALS_DBFILE'] = os.path.join(gettempdir(), 'pancloud_credentials.json')
    params = demisto.params()
    registration_id_and_url = params.get(REGISTRATION_ID_CONST).split('@')
    if len(registration_id_and_url) != 2:
        token_retrieval_url = "https://oproxy.demisto.ninja"  # guardrails-disable-line
    else:
        token_retrieval_url = registration_id_and_url[1]
    registration_id = registration_id_and_url[0]
    # If there's a stored token in integration context, it's newer than current
    refresh_token = demisto.getIntegrationContext().get(REFRESH_TOKEN_CONST) or params.get(REFRESH_TOKEN_CONST)
    enc_key = params.get(ENCRYPTION_KEY_CONST)
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    client = Client(token_retrieval_url, registration_id, use_ssl, proxy, refresh_token, enc_key)
    args = demisto.args()
    command = demisto.command()
    LOG(f'command is {command}')
    try:
        if command == 'test-module':
            test_module(client)
        elif command == 'cdl-query-logs':
            return_outputs(*query_logs_command(args, client))
        elif command == 'cdl-get-critical-threat-logs':
            return_outputs(*get_critical_logs_command(args, client))
        elif command == 'cdl-get-social-applications':
            return_outputs(*get_social_applications_command(args, client))
        elif command == 'cdl-search-by-file-hash':
            return_outputs(*search_by_file_hash_command(args, client))
        elif command == 'cdl-query-traffic-logs':
            return_outputs(*query_traffic_logs_command(args, client))
        elif command == 'cdl-query-threat-logs':
            return_outputs(*query_threat_logs_command(args, client))
        elif command == 'fetch-incidents':
            first_fetch_timestamp = params.get('first_fetch_timestamp', '24 hours').strip()
            fetch_severity = params.get('firewall_severity')
            fetch_subtype = params.get('firewall_subtype')
            fetch_limit = params.get('limit')
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client,
                                                  first_fetch_timestamp,
                                                  fetch_severity,
                                                  fetch_subtype,
                                                  fetch_limit,
                                                  last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
    except Exception as e:
        error_message = str(e)
        return_error(error_message)


if __name__ in ('__main__', 'builtins'):
    main()
