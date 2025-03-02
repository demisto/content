import secrets
import string
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import copy
import json
from typing import Tuple

urllib3.disable_warnings()
DEFAULT_LIMIT = 100
SERVER_VERSION = '8.7.0'
BUILD_VERSION = '1247804'
# To use apiCall, the machine must have a version greater than 8.7.0-1247804,
# and is_using_engine()=False.
IS_CORE_AVAILABLE = is_xsiam() and is_demisto_version_ge(version=SERVER_VERSION,
                                                         build_number=BUILD_VERSION) and not is_using_engine()


class CoreClient(BaseClient):

    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False,
                 is_core: bool = False):
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)
        self.timeout = timeout
        self.is_core = is_core

    def _http_request(self, method, url_suffix='', full_url=None, headers=None, json_data=None,  # type: ignore[override]
                      params=None, data=None, timeout=None, raise_on_status=False, ok_codes=None,
                      error_handler=None, with_metrics=False, resp_type='json', response_data_type=None):
        '''
        """A wrapper for requests lib to send our requests and handle requests and responses.

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.


            :type url_suffix: ``str``
            :param url_suffix: The API endpoint.


            :type full_url: ``str``
            :param full_url:
                Bypasses the use of self._base_url + url_suffix. This is useful if you need to
                make a request to an address outside of the scope of the integration
                API.


            :type headers: ``dict``
            :param headers: Headers to send in the request. If None, will use self._headers.


            :type params: ``dict``
            :param params: URL parameters to specify the query.


            :type data: ``dict``
            :param data: The data to send in a 'POST' request.


            :type raise_on_status ``bool``
                :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                    whether we should raise an exception, or return a response,
                    if status falls in ``status_forcelist`` range and retries have
                    been exhausted.


            :type timeout: ``float`` or ``tuple``
            :param timeout:
                The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
                can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).


            :type resp_type: ``str``
            :param resp_type: Response type when using the _http_request


            :type response_data_type: ``str`` or None
            :param response_data_type: Response type when using the apiCall- 'bin' if we expect a 'binary' response and None as
            default.
        '''
        if self.is_core and not IS_CORE_AVAILABLE:
            raise DemistoException(f"Using the XQL Query Engine from the core Pack is available only from version "
                                   f"{SERVER_VERSION}-{BUILD_VERSION}.")
        if (not IS_CORE_AVAILABLE):
            return BaseClient._http_request(self,  # we use the standard base_client http_request without overriding it
                                            method=method,
                                            url_suffix=url_suffix,
                                            full_url=full_url,
                                            headers=headers,
                                            json_data=json_data, params=params, data=data,
                                            timeout=timeout,
                                            raise_on_status=raise_on_status,
                                            ok_codes=ok_codes,
                                            error_handler=error_handler,
                                            with_metrics=with_metrics,
                                            resp_type=resp_type)
        headers = headers if headers else self._headers
        data = json.dumps(json_data) if json_data else data
        address = full_url if full_url else urljoin(self._base_url, url_suffix)
        response = demisto._apiCall(
            method=method,
            path=address,
            data=data,
            headers=headers,
            timeout=timeout,
            response_data_type=response_data_type
        )
        if ok_codes and response.get('status') not in ok_codes:
            self._handle_error(error_handler, response, with_metrics)
        try:
            return json.loads(response['data'])
        except json.JSONDecodeError:
            demisto.debug(f"Converting data to json was failed. Return it as is. The data's type is {type(response['data'])}")
            return response['data']

    def start_xql_query(self, data: dict) -> str:
        try:
            res = self._http_request(method='POST', url_suffix='/xql/start_xql_query', json_data=data)
            execution_id = res.get('reply', "")
            return execution_id
        except Exception as e:
            if 'reached max allowed amount of parallel running queries' in str(e).lower():
                return "FAILURE"
            raise e

    def get_xql_query_results(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_query_results', json_data=data)
        query_results = res.get('reply', "")
        return query_results

    def get_query_result_stream(self, data: dict) -> bytes:
        res = self._http_request(method='POST', url_suffix='/xql/get_query_results_stream', json_data=data,
                                 resp_type='response', response_data_type='bin')
        if self.is_core:
            return base64.b64decode(res)
        return res.content

    def get_xql_quota(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_quota', json_data=data)
        return res

# =========================================== Built-In Queries Helpers ===========================================#


def wrap_list_items_in_double_quotes(string_of_argument: str = ''):
    """receive a string of arguments and return a string with each argument wrapped in double quotes.
    example:
        string_of_argument: '12345678, 87654321'
        output: '"12345678","87654321"'
        string_of_argument: ''
        output: '""'

    Args:
        string_of_argument (str): The string s of_argument to format.

    Returns:
        str: The new formatted string
    """
    list_of_args = argToList(string_of_argument) if string_of_argument else ['']
    return ','.join(f'"{item}"' for item in list_of_args)


def get_file_event_query(endpoint_ids: str, args: dict) -> str:
    """Create the file event query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns: The created query.
        str: The created query.
    """
    file_sha256_list = args.get('file_sha256', '')
    file_sha256_list = wrap_list_items_in_double_quotes(file_sha256_list)
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = FILE and action_file_sha256
 in ({file_sha256_list})| fields agent_hostname, agent_ip_addresses, agent_id, action_file_path, action_file_sha256,
 actor_process_file_create_time'''


def get_process_event_query(endpoint_ids: str, args: dict) -> str:
    """Create the process event query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    process_sha256_list = args.get('process_sha256', '')
    process_sha256_list = wrap_list_items_in_double_quotes(process_sha256_list)
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = PROCESS and
 action_process_image_sha256 in ({process_sha256_list}) | fields agent_hostname, agent_ip_addresses, agent_id,
 action_process_image_sha256, action_process_image_name,action_process_image_path, action_process_instance_id,
 action_process_causality_id, action_process_signature_vendor, action_process_signature_product,
 action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_instance_id,
 actor_process_causality_id'''


def get_dll_module_query(endpoint_ids: str, args: dict) -> str:
    """Create the DLL module query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    loaded_module_sha256 = args.get('loaded_module_sha256', '')
    loaded_module_sha256 = wrap_list_items_in_double_quotes(loaded_module_sha256)
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = LOAD_IMAGE and
 action_module_sha256 in ({loaded_module_sha256})| fields agent_hostname, agent_ip_addresses, agent_id,
 actor_effective_username, action_module_sha256, action_module_path, action_module_file_info,
 action_module_file_create_time, actor_process_image_name, actor_process_image_path, actor_process_command_line,
 actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id'''


def get_network_connection_query(endpoint_ids: str, args: dict) -> str:
    """Create the network connection query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    remote_ip_list = args.get('remote_ip', '')
    remote_ip_list = wrap_list_items_in_double_quotes(remote_ip_list)
    local_ip_filter = ''
    if args.get('local_ip'):
        local_ip_list = wrap_list_items_in_double_quotes(args.get('local_ip', ''))
        local_ip_filter = f'and action_local_ip in({local_ip_list})'
    port_list = args.get('port')
    port_list_filter = f'and action_remote_port in({port_list})' if port_list else ''
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = STORY
 {local_ip_filter} and action_remote_ip in({remote_ip_list}) {port_list_filter}|
 fields agent_hostname, agent_ip_addresses, agent_id, actor_effective_username, action_local_ip, action_remote_ip,
 action_remote_port, dst_action_external_hostname, action_country, actor_process_image_name, actor_process_image_path,
 actor_process_command_line, actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id'''


def get_registry_query(endpoint_ids: str, args: dict) -> str:
    """Create the registry query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    reg_key_name = args.get('reg_key_name', '')
    reg_key_name = wrap_list_items_in_double_quotes(reg_key_name)
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = REGISTRY and
 action_registry_key_name in ({reg_key_name}) | fields agent_hostname, agent_id, agent_ip_addresses, agent_os_type,
 agent_os_sub_type, event_type, event_sub_type, action_registry_key_name, action_registry_value_name,
 action_registry_data'''


def get_event_log_query(endpoint_ids: str, args: dict) -> str:
    """Create the event log query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    event_id = args.get('event_id', '')
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = EVENT_LOG and
 action_evtlog_event_id in ({event_id}) | fields agent_hostname, agent_id, agent_ip_addresses, agent_os_type,
 agent_os_sub_type, action_evtlog_event_id, event_type, event_sub_type, action_evtlog_message,
 action_evtlog_provider_name'''


def get_dns_query(endpoint_ids: str, args: dict) -> str:
    """Create the DNS query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    if not args.get('external_domain') and not args.get('dns_query'):
        raise DemistoException('Please provide at least one of the external_domain, dns_query arguments.')
    external_domain_list = wrap_list_items_in_double_quotes(args.get('external_domain', ''))
    dns_query_list = wrap_list_items_in_double_quotes(args.get('dns_query', ''))
    return f'''dataset = xdr_data | filter (agent_id in ({endpoint_ids}) and event_type = STORY) and
 (dst_action_external_hostname in ({external_domain_list}) or dns_query_name in ({dns_query_list}))| fields
 agent_hostname, agent_id, agent_ip_addresses, agent_os_type, agent_os_sub_type, action_local_ip, action_remote_ip,
 action_remote_port, dst_action_external_hostname, dns_query_name, action_app_id_transitions, action_total_download,
 action_total_upload, action_country, action_as_data, os_actor_process_image_path, os_actor_process_command_line,
 os_actor_process_instance_id, os_actor_process_causality_id'''


def get_file_dropper_query(endpoint_ids: str, args: dict) -> str:
    """Create the file dropper query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    if not args.get('file_path') and not args.get('file_sha256'):
        raise DemistoException('Please provide at least one of the file_path, file_sha256 arguments.')
    file_path_list = wrap_list_items_in_double_quotes(args.get('file_path', ''))
    file_sha256_list = wrap_list_items_in_double_quotes(args.get('file_sha256', ''))

    return f'''dataset = xdr_data | filter (agent_id in ({endpoint_ids}) and event_type = FILE and event_sub_type in (
 FILE_WRITE, FILE_RENAME)) and (action_file_path in ({file_path_list}) or action_file_sha256 in ({file_sha256_list})) |
 fields agent_hostname, agent_ip_addresses, agent_id, action_file_sha256, action_file_path, actor_process_image_name,
 actor_process_image_path, actor_process_image_path, actor_process_command_line, actor_process_signature_vendor,
 actor_process_signature_product, actor_process_image_sha256, actor_primary_normalized_user,
 os_actor_process_image_path, os_actor_process_command_line, os_actor_process_signature_vendor,
 os_actor_process_signature_product, os_actor_process_image_sha256, os_actor_effective_username,
 causality_actor_remote_host,causality_actor_remote_ip'''


def get_process_instance_network_activity_query(endpoint_ids: str, args: dict) -> str:
    """Create the process instance networks activity query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    process_instance_id_list = args.get('process_instance_id', '')
    process_instance_id_list = wrap_list_items_in_double_quotes(process_instance_id_list)
    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = NETWORK and
 actor_process_instance_id in ({process_instance_id_list}) | fields agent_hostname, agent_ip_addresses, agent_id,
 action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname, dns_query_name,
 action_app_id_transitions, action_total_download, action_total_upload, action_country, action_as_data,
 actor_process_image_sha256, actor_process_image_name , actor_process_image_path, actor_process_signature_vendor,
 actor_process_signature_product, actor_causality_id, actor_process_image_command_line, actor_process_instance_id'''


def get_process_causality_network_activity_query(endpoint_ids: str, args: dict) -> str:
    """Create the process causality network activity query.

    Args:
        endpoint_ids (str): The endpoint IDs to use.
        args (dict): The arguments to pass to the query.

    Returns:
        str: The created query.
    """
    process_causality_id_list = args.get('process_causality_id', '')
    process_causality_id_list = wrap_list_items_in_double_quotes(process_causality_id_list)

    return f'''dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = NETWORK
 and actor_process_causality_id in ({process_causality_id_list}) | fields agent_hostname, agent_ip_addresses,agent_id,
 action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname,dns_query_name,
 action_app_id_transitions, action_total_download, action_total_upload, action_country,action_as_data,
 actor_process_image_sha256, actor_process_image_name , actor_process_image_path,actor_process_signature_vendor,
 actor_process_signature_product, actor_causality_id,actor_process_image_command_line, actor_process_instance_id'''


# =========================================== Helper Functions ===========================================#


def convert_timeframe_string_to_json(time_to_convert: str) -> Dict[str, int]:
    """Convert a timeframe string to a json requred for XQL queries.

    Args:
        time_to_convert (str): The time frame string to convert (supports seconds, minutes, hours, days, months, years, between).

    Returns:
        dict: The timeframe parameters in JSON.
    """
    try:
        time_to_convert_lower = time_to_convert.strip().lower()
        if time_to_convert_lower.startswith('between '):
            tokens = time_to_convert_lower[len('between '):].split(' and ')
            if len(tokens) == 2:
                time_from = dateparser.parse(tokens[0], settings={'TIMEZONE': 'UTC'})
                time_to = dateparser.parse(tokens[1], settings={'TIMEZONE': 'UTC'})
                assert time_from is not None
                assert time_to is not None
                return {'from': int(time_from.timestamp()) * 1000, 'to': int(time_to.timestamp()) * 1000}
        else:
            relative = dateparser.parse(time_to_convert, settings={'TIMEZONE': 'UTC'})
            now_date = datetime.utcnow()
            assert now_date is not None
            assert relative is not None
            return {'relativeTime': int((now_date - relative).total_seconds()) * 1000}

        raise ValueError(f'Invalid timeframe: {time_to_convert}')
    except Exception as exc:
        raise DemistoException(f'Please enter a valid time frame (seconds, minutes, hours, days, weeks, months, '
                               f'years, between).\n{str(exc)}')


def start_xql_query(client: CoreClient, args: Dict[str, Any]) -> str:
    """Execute an XQL query.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        str: The query execution ID.
    """
    query = args.get('query', '')
    if not query:
        raise ValueError('query is not specified')

    if 'limit' not in query:  # if user did not provide a limit in the query, we will use the default one.
        query = f'{query} \n| limit {str(DEFAULT_LIMIT)}'
    data: Dict[str, Any] = {
        'request_data': {
            'query': query,
        }
    }
    time_frame = args.get('time_frame')
    if time_frame:
        data['request_data']['timeframe'] = convert_timeframe_string_to_json(time_frame)
    # The arg is called 'tenant_id', but to avoid BC we will also support 'tenant_ids'.
    tenant_ids = argToList(args.get('tenant_id') or args.get('tenant_ids'))
    if tenant_ids:
        data['request_data']['tenants'] = tenant_ids
    # call the client function and get the raw response
    execution_id = client.start_xql_query(data)
    return execution_id


def get_xql_query_results(client: CoreClient, args: dict) -> Tuple[dict, Optional[bytes]]:
    """Retrieve results of an executed XQL query API. returns the general response and
    a file data if the query has more than 1000 results.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        dict: The query results.
    """
    query_id = args.get('query_id')
    if not query_id:
        raise ValueError('query ID is not specified')
    data = {
        'request_data': {
            'query_id': query_id,
            'pending_flag': True,
            'format': 'json',
        }
    }

    # Call the Client function and get the raw response
    response = client.get_xql_query_results(data)
    response['execution_id'] = query_id
    results = response.get('results', {})
    stream_id = results.get('stream_id')
    if stream_id:
        file_data = get_query_result_stream(client, stream_id)
        return response, file_data
    response['results'] = results.get('data')
    return response, None


def get_query_result_stream(client: CoreClient, stream_id: str) -> bytes:
    """Retrieve XQL query results with more than 1000 results.

    Args:
        client (Client): The XDR Client.
        stream_id (str): The stream ID of the query.

    Returns:
        bytes: The query results.
    """
    if not stream_id:
        raise ValueError('stream_id is not specified')
    data = {
        'request_data': {
            'stream_id': stream_id,
            'is_gzip_compressed': True,
        }
    }
    # Call the Client function and get the raw response
    return client.get_query_result_stream(data)


def format_item(item_to_format: Any) -> Any:
    """
        Format the given item to the correct format.

    Args:
        item_to_format (Any): Item to format.

    Returns:
        Any: Formatted item.
    """
    mapper = {
        'FALSE': False,
        'TRUE': True,
        'NULL': None,
    }
    return mapper[item_to_format] if item_to_format in mapper else item_to_format


def is_empty(item_to_check: Any) -> bool:
    """
        Checks if a given item is empty or not

    Args:
        item_to_check (Any): The item to check.

    Returns:
        bool: True if empty, False otherwise.
    """

    return item_to_check is not False and not item_to_check


def handle_timestamp_item(item_to_convert: Any) -> Union[Any, str]:
    """
        Try to convert a given value to datestring.

    Args:
        item_to_convert (Any): The item to convert.

    Returns:
        Union[Any, str]: The converted timestamp if convert was successful, otherwise return the original item.
    """

    try:
        return timestamp_to_datestring(item_to_convert)
    except Exception:  # cannot convert item
        return item_to_convert


def format_results(list_to_format: list, remove_empty_fields: bool = True) -> list:
    """
    Recursively format a list of dictionaries and remove empty lists, empty dicts, or None elements from it if desired.

    Args:
        list_to_format (list): Input list to format.
        remove_empty_fields (bool): True if the user wants to remove the empty fields.

    Returns:
        list: Formatted list.
    """

    def format_dict(item_to_format: Any) -> Any:

        if not isinstance(item_to_format, (dict, list)):  # recursion stopping condition, formatting field
            return format_item(item_to_format)

        elif isinstance(item_to_format, list):
            return [v for v in (format_dict(v) for v in item_to_format) if v]
        else:
            new_dict = {}
            for key, value in item_to_format.items():
                formatted_res = format_dict(value)
                if is_empty(formatted_res) and remove_empty_fields:
                    continue  # do not add item to the new dict
                if 'time' in key:
                    new_dict[key] = handle_timestamp_item(formatted_res)
                else:
                    new_dict[key] = formatted_res
            return new_dict

    for i, item in enumerate(list_to_format):
        list_to_format[i] = format_dict(item)

    return list_to_format


def get_outputs_prefix(command_name: str) -> str:
    """
    Get the correct output output prefix.

    Args:
        command_name (str): The executed command.

    Returns:
        str: The output prefix.
    """

    if command_name in GENERIC_QUERY_COMMANDS:
        return 'PaloAltoNetworksXQL.GenericQuery'
    else:  # built in command
        query_name = BUILT_IN_QUERY_COMMANDS[command_name].get('name')
        return f'PaloAltoNetworksXQL.{query_name}'


def get_nonce() -> str:
    """
    Generate a 64 bytes random string.

    Returns:
        str: The 64 bytes random string.
    """
    return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])


# ========================================== Generic Query ===============================================#


def test_module(client: CoreClient, args: Dict[str, Any]) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.get_xql_quota({'request_data': {}})
        return 'ok'
    except Exception as err:
        if any(error in str(err) for error in ['Forbidden', 'Authorization', 'Unauthorized']):
            raise DemistoException('Authorization failed, make sure API Key is correctly set')
        elif 'Not Found' in str(err):
            raise DemistoException('Authorization failed, make sure the URL is correct')
        else:
            raise err


def start_xql_query_polling_command(client: CoreClient, args: dict) -> Union[CommandResults, list]:
    """Execute an XQL query as a scheduled command.
       If 'start_xql_query' fails, the command will use a polling mechanism to start the XQL query again.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        CommandResults: The command results.
    """
    if not args.get('query_name'):
        raise DemistoException('Please provide a query name')
    execution_id = start_xql_query(client, args)
    if execution_id == 'FAILURE':
        # the 'start_xql_query' function failed because it reached the maximum allowed number of parallel running queries.
        # running the command again using polling with an interval of 'interval_in_secs' seconds.
        command_results = CommandResults()
        interval_in_secs = int(args.get('interval_in_seconds', 5))
        scheduled_command = ScheduledCommand(command='xdr-xql-generic-query', next_run_in_seconds=interval_in_secs,
                                             args=args, timeout_in_seconds=600)
        command_results.scheduled_command = scheduled_command
        command_results.readable_output = (f'The maximum allowed number of parallel running queries has been reached.'
                                           f' The query will be executed in the next interval, in {interval_in_secs} seconds.')
        return command_results

    if not execution_id:
        raise DemistoException('Failed to start query\n')
    args['query_id'] = execution_id
    args['command_name'] = demisto.command()

    return get_xql_query_results_polling_command(client, args)


def get_xql_query_results_polling_command(client: CoreClient, args: dict) -> Union[CommandResults, list]:
    """Retrieve results of an executed XQL query API executes as a scheduled command.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        Union[CommandResults, dict]: The command results.
    """
    # get the query data either from the integration context (if its not the first run) or from the given args.
    parse_result_file_to_context = argToBoolean(args.get('parse_result_file_to_context', 'false'))
    command_name = args.get('command_name', demisto.command())
    interval_in_secs = int(args.get('interval_in_seconds', 10))
    max_fields = arg_to_number(args.get('max_fields', 20))
    if max_fields is None:
        raise DemistoException('Please provide a valid number for max_fields argument.')
    outputs, file_data = get_xql_query_results(client, args)  # get query results with query_id
    outputs.update({'query_name': args.get('query_name', '')})
    outputs_prefix = get_outputs_prefix(command_name)
    command_results = CommandResults(outputs_prefix=outputs_prefix, outputs_key_field='execution_id', outputs=outputs,
                                     raw_response=copy.deepcopy(outputs))
    # if there are more than 1000 results
    if file_data:
        if not parse_result_file_to_context:
            #  Extracts the results into a file only
            file = fileResult(filename="results.gz", data=file_data)
            command_results.readable_output = 'More than 1000 results were retrieved, see the compressed gzipped file below.'
            return [file, command_results]
        else:
            # Parse the results to context:
            data = gzip.decompress(file_data).decode()
            outputs['results'] = [json.loads(line) for line in data.split("\n") if len(line) > 0]

    # if status is pending, the command will be called again in the next run until success.
    if outputs.get('status') == 'PENDING':
        scheduled_command = ScheduledCommand(command='xdr-xql-get-query-results', next_run_in_seconds=interval_in_secs,
                                             args=args, timeout_in_seconds=600)
        command_results.scheduled_command = scheduled_command
        command_results.readable_output = 'Query is still running, it may take a little while...'
        return command_results

    results_to_format = outputs.pop('results')
    # create Human Readable output
    query = args.get('query', '')
    time_frame = args.get('time_frame')
    extra_for_human_readable = ({'query': query, 'time_frame': time_frame})
    outputs.update(extra_for_human_readable)
    command_results.readable_output = tableToMarkdown('General Information', outputs,
                                                      headerTransform=string_to_table_header,
                                                      removeNull=True)
    [outputs.pop(key) for key in list(extra_for_human_readable.keys())]

    # if no fields were given in the query then the default fields are returned (without empty fields).
    if results_to_format:
        formatted_list = format_results(results_to_format, remove_empty_fields=False) \
            if 'fields' in query else format_results(results_to_format)
        if formatted_list and command_name == 'xdr-xql-generic-query' and len(formatted_list[0].keys()) > max_fields:
            raise DemistoException('The number of fields per result has exceeded the maximum number of allowed fields, '
                                   'please select specific fields in the query or increase the maximum number of '
                                   'allowed fields.')
        outputs.update({'results': formatted_list})
        command_results.outputs = outputs

    command_results.readable_output += tableToMarkdown('Data Results', outputs.get('results'),
                                                       headerTransform=string_to_table_header)

    return command_results


def get_xql_quota_command(client: CoreClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the amount of query quota available and used.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        dict: The quota results.
    """

    data: dict = {
        'request_data': {
        }
    }
    # Call the Client function and get the raw response
    result = client.get_xql_quota(data).get('reply', {})
    readable_output = tableToMarkdown('Quota Results', result, headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        outputs_prefix='PaloAltoNetworksXQL.Quota',
        outputs_key_field='',
        outputs=result,
        readable_output=readable_output
    )


# =========================================== Built-In Queries ===========================================#

def get_built_in_query_results_polling_command(client: CoreClient, args: dict) -> Union[CommandResults, list]:
    """Retrieve results of a built in XQL query, execute as a scheduled command.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        Union[CommandResults, dict]: The command results.
    """
    # build query, if no endpoint_id was given, the query will search in every endpoint_id (*).
    endpoint_id_list = wrap_list_items_in_double_quotes(args.get('endpoint_id', '*'))
    built_in_func = BUILT_IN_QUERY_COMMANDS.get(demisto.command(), {}).get('func')
    query = built_in_func(endpoint_id_list, args) if callable(built_in_func) else ''

    # add extra fields to query
    extra_fields = argToList(args.get('extra_fields', []))
    if extra_fields:
        extra_fields_list = ", ".join(str(e) for e in extra_fields)
        query = f'{query}, {extra_fields_list}'

    # add limit to query
    if 'limit' in args:
        query = f"{query} | limit {args.get('limit')}"

    query_args = {
        'query': query,
        'query_name': args.get('query_name'),
        'tenants': argToList(args.get('tenants', [])),
        'time_frame': args.get('time_frame', '')
    }
    return start_xql_query_polling_command(client, query_args)


''' COMMANDS DICTS'''

BUILT_IN_QUERY_COMMANDS = {
    'xdr-xql-file-event-query': {
        'func': get_file_event_query,
        'name': 'FileEvent',
    },
    'xdr-xql-process-event-query': {
        'func': get_process_event_query,
        'name': 'ProcessEvent',
    },
    'xdr-xql-dll-module-query': {
        'func': get_dll_module_query,
        'name': 'DllModule',
    },
    'xdr-xql-network-connection-query': {
        'func': get_network_connection_query,
        'name': 'NetworkConnection',
    },
    'xdr-xql-registry-query': {
        'func': get_registry_query,
        'name': 'Registry',
    },
    'xdr-xql-event-log-query': {
        'func': get_event_log_query,
        'name': 'EventLog',
    },
    'xdr-xql-dns-query': {
        'func': get_dns_query,
        'name': 'DNS',
    },
    'xdr-xql-file-dropper-query': {
        'func': get_file_dropper_query,
        'name': 'FileDropper',
    },
    'xdr-xql-process-instance-network-activity-query': {
        'func': get_process_instance_network_activity_query,
        'name': 'ProcessInstanceNetworkActivity',
    },
    'xdr-xql-process-causality-network-activity-query': {
        'func': get_process_causality_network_activity_query,
        'name': 'ProcessCausalityNetworkActivity',
    },
}

GENERIC_QUERY_COMMANDS = {
    'test-module': test_module,
    'xdr-xql-generic-query': start_xql_query_polling_command,
    'xdr-xql-get-query-results': get_xql_query_results_polling_command,
    'xdr-xql-get-quota': get_xql_quota_command,
}
