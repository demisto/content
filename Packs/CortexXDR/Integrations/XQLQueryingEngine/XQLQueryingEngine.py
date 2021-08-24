import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import copy
import hashlib
import requests
import traceback
import secrets
import string
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def start_xql_query(self, data: dict) -> str:
        res = self._http_request(method='POST', url_suffix='/xql/start_xql_query', json_data=data)
        execution_id = res.get('reply', "")
        return execution_id

    def get_xql_query_results(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_query_results', json_data=data)
        query_results = res.get('reply', "")
        return query_results

    def get_query_result_stream(self, data: dict) -> bytes:
        res = self._http_request(method='POST', url_suffix='/xql/get_query_results_stream', json_data=data,
                                 resp_type='response')
        return res.content

    def get_xql_quota(self, data: dict) -> dict:
        res = self._http_request(method='POST', url_suffix='/xql/get_quota', json_data=data)
        return res


# =========================================== Built-In Queries Helpers ===========================================#
def init_built_in_commands():
    """Initializing built in query commands dictionary.

    :return: The available commands.
    :rtype: ``dict``
    """
    return {
        'xdr-xql-file-event-query': {'func': get_file_event_query, 'name': 'FileEvent'},
        'xdr-xql-process-event-query': {'func': get_process_event_query, 'name': 'ProcessEvent'},
        'xdr-xql-dll-module-query': {'func': get_dll_module_query, 'name': 'DllModule'},
        'xdr-xql-network-connection-query': {'func': get_network_connection_query, 'name': 'NetworkConnection'},
        'xdr-xql-registry-query': {'func': get_registry_query, 'name': 'Registry'},
        'xdr-xql-event-log-query': {'func': get_event_log_query, 'name': 'EventLog'},
        'xdr-xql-dns-query': {'func': get_dns_query, 'name': 'DNS'},
        'xdr-xql-file-dropper-query': {'func': get_file_dropper_query, 'name': 'FileDropper'},
        'xdr-xql-process-instance-network-activity-query': {'func': get_process_instance_network_activity_query,
                                                            'name': 'ProcessInstanceNetworkActivity'},
        'xdr-xql-process-causality-network-activity-query': {'func': get_process_causality_network_activity_query,
                                                             'name': 'ProcessCausalityNetworkActivity'},
    }


def format_arg(str_to_format: str):
    """Format a string list to fit the query expected input.
    example:
        str_to_format: '12345678, 87654321'
        output: '"12345678","87654321"'

    :type str_to_format: ``str``
    :param str_to_format: The string input to format.

    :return: The formatted string.
    :rtype: ``str``
    """
    if not str_to_format:
        str_to_format = ''
    return ','.join(map('"{0}"'.format, argToList(str_to_format)))


def get_file_event_query(endpoint_ids: str, args: dict) -> str:
    """Create the file event query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    file_sha256_list = args.get('file_sha256', '')
    if not file_sha256_list:
        raise DemistoException('Please provide a file_sha256 argument.')
    file_sha256_list = format_arg(file_sha256_list)
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) ' \
           f'and event_type = FILE and action_file_sha256 in ({file_sha256_list})| ' \
           f'fields agent_hostname, agent_ip_addresses, agent_id, action_file_path, ' \
           f'action_file_sha256, actor_process_file_create_time'


def get_process_event_query(endpoint_ids: str, args: dict) -> str:
    """Create the process event query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    process_sha256_list = args.get('process_sha256', '')
    if not process_sha256_list:
        raise DemistoException('Please provide a process_sha256 argument.')
    process_sha256_list = format_arg(process_sha256_list)
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and ' \
           f'event_type = PROCESS and ' \
           f'action_process_image_sha256 in ({process_sha256_list}) | ' \
           f'fields agent_hostname, agent_ip_addresses, agent_id, action_process_image_sha256, action_process_image_name, ' \
           f'action_process_image_path, action_process_instance_id, action_process_causality_id, ' \
           f'action_process_signature_vendor, action_process_signature_product, ' \
           f'action_process_image_command_line, actor_process_image_name, actor_process_image_path, ' \
           f'actor_process_instance_id, actor_process_causality_id'


def get_dll_module_query(endpoint_ids: str, args: dict) -> str:
    """Create the DLL module query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    loaded_module_sha256 = args.get('loaded_module_sha256', '')
    if not loaded_module_sha256:
        raise DemistoException('Please provide a loaded_module_sha256 argument.')
    loaded_module_sha256 = format_arg(loaded_module_sha256)
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) ' \
           f'and event_type = LOAD_IMAGE and action_module_sha256 in ({loaded_module_sha256})| ' \
           f'fields agent_hostname, agent_ip_addresses, agent_id, actor_effective_username, action_module_sha256, ' \
           f'action_module_path, action_module_file_info, action_module_file_create_time, actor_process_image_name, ' \
           f'actor_process_image_path, actor_process_command_line, actor_process_image_sha256, actor_process_instance_id, ' \
           f'actor_process_causality_id'


def get_network_connection_query(endpoint_ids: str, args: dict) -> str:
    """Create the network connection query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    remote_ip_list = args.get('remote_ip', '')
    if not remote_ip_list:
        raise DemistoException('Please provide a remote_ip argument.')
    local_ip_list = format_arg(args.get('local_ip', '*'))
    remote_ip_list = format_arg(remote_ip_list)
    port_list = args.get('port', '*')
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = STORY and ' \
           f'action_local_ip in({local_ip_list}) and action_remote_ip in({remote_ip_list}) and ' \
           f'action_remote_port in({port_list}) | fields agent_hostname, agent_ip_addresses, agent_id, ' \
           f'actor_effective_username, action_local_ip, action_remote_ip, action_remote_port, ' \
           f'dst_action_external_hostname, action_country, actor_process_image_name, actor_process_image_path, ' \
           f'actor_process_command_line, actor_process_image_sha256, actor_process_instance_id, actor_process_causality_id'


def get_registry_query(endpoint_ids: str, args: dict) -> str:
    """Create the registry query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    reg_key_name = args.get('reg_key_name', '')
    if not reg_key_name:
        raise DemistoException('Please provide a reg_key_name argument.')
    reg_key_name = format_arg(reg_key_name)
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = REGISTRY and ' \
           f'action_registry_key_name in ({reg_key_name}) | fields agent_hostname, agent_id, agent_ip_addresses, ' \
           f'agent_os_type, agent_os_sub_type, event_type, event_sub_type, action_registry_key_name, ' \
           f'action_registry_value_name, action_registry_data'


def get_event_log_query(endpoint_ids: str, args: dict) -> str:
    """Create the event log query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    event_id = args.get('event_id', '')
    if not event_id:
        raise DemistoException('Please provide a event_id argument.')
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = EVENT_LOG and ' \
           f'action_evtlog_event_id in ({event_id}) | fields agent_hostname, agent_id, agent_ip_addresses, ' \
           f'agent_os_type, agent_os_sub_type, action_evtlog_event_id, event_type, event_sub_type, ' \
           f'action_evtlog_message, action_evtlog_provider_name'


def get_dns_query(endpoint_ids: str, args: dict) -> str:
    """Create the DNS query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    if not args.get('external_domain') and not args.get('dns_query'):
        raise DemistoException('Please provide at least one of the external_domain, dns_query arguments.')
    external_domain_list = format_arg(args.get('external_domain', '*'))
    dns_query_list = format_arg(args.get('dns_query', '*'))
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = STORY and ' \
           f'dst_action_external_hostname in ({external_domain_list}) or dns_query_name in ({dns_query_list})' \
           f'| fields agent_hostname, agent_id, agent_ip_addresses, agent_os_type, agent_os_sub_type, action_local_ip, ' \
           f'action_remote_ip, action_remote_port, dst_action_external_hostname, dns_query_name, action_app_id_transitions, ' \
           f'action_total_download, action_total_upload, action_country, action_as_data, os_actor_process_image_path, ' \
           f'os_actor_process_command_line, os_actor_process_instance_id, os_actor_process_causality_id'


def get_file_dropper_query(endpoint_ids: str, args: dict) -> str:
    """Create the file dropper query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    if not args.get('file_path') and not args.get('file_sha256'):
        raise DemistoException('Please provide at least one of the file_path, file_sha256 arguments.')
    file_path_list = format_arg(args.get('file_path', '*'))
    file_sha256_list = format_arg(args.get('file_sha256', '*'))

    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = FILE and ' \
           f'event_sub_type in (FILE_WRITE, FILE_RENAME) and action_file_path in ({file_path_list}) or ' \
           f'action_file_sha256 in ({file_sha256_list}) | fields agent_hostname, agent_ip_addresses, agent_id, ' \
           f'action_file_sha256, action_file_path, actor_process_image_name, actor_process_image_path, ' \
           f'actor_process_image_path, actor_process_command_line, actor_process_signature_vendor, ' \
           f'actor_process_signature_product, actor_process_image_sha256, actor_primary_normalized_user, ' \
           f'os_actor_process_image_path, os_actor_process_command_line, os_actor_process_signature_vendor, ' \
           f'os_actor_process_signature_product, os_actor_process_image_sha256, os_actor_effective_username, ' \
           f'causality_actor_remote_host,causality_actor_remote_ip'


def get_process_instance_network_activity_query(endpoint_ids: str, args: dict) -> str:
    """Create the process instance networks activity query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    process_instace_id_list = args.get('process_instace_id', '')
    if not process_instace_id_list:
        raise DemistoException('Please provide a process_instace_id argument.')
    process_instace_id_list = format_arg(process_instace_id_list)
    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = NETWORK and ' \
           f'actor_process_instance_id in ({process_instace_id_list}) | fields agent_hostname, agent_ip_addresses, ' \
           f'agent_id, action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname, ' \
           f'dns_query_name, action_app_id_transitions, action_total_download, action_total_upload, action_country, ' \
           f'action_as_data, actor_process_image_sha256, actor_process_image_name , actor_process_image_path, ' \
           f'actor_process_signature_vendor, actor_process_signature_product, actor_causality_id, ' \
           f'actor_process_image_command_line, actor_process_instance_id'


def get_process_causality_network_activity_query(endpoint_ids: str, args: dict) -> str:
    """Create the process causality network activity query.

    :type endpoint_ids: ``str``
    :param endpoint_ids: The endpoint IDs to use.
    :type args: ``dict``
    :param args: The arguments to pass to the query.

    :return: The created query.
    :rtype: ``str``
    """
    process_causality_id_list = args.get('process_causality_id', '')
    if not process_causality_id_list:
        raise DemistoException('Please provide a process_causality_id argument.')
    process_causality_id_list = format_arg(process_causality_id_list)

    return f'dataset = xdr_data | filter agent_id in ({endpoint_ids}) and event_type = NETWORK and ' \
           f'actor_process_causality_id in ({process_causality_id_list}) | fields agent_hostname, agent_ip_addresses, ' \
           f'agent_id, action_local_ip, action_remote_ip, action_remote_port, dst_action_external_hostname, ' \
           f'dns_query_name, action_app_id_transitions, action_total_download, action_total_upload, action_country, ' \
           f'action_as_data, actor_process_image_sha256, actor_process_image_name , actor_process_image_path, ' \
           f'actor_process_signature_vendor, actor_process_signature_product, actor_causality_id, ' \
           f'actor_process_image_command_line, actor_process_instance_id'


# =========================================== Helper Functions ===========================================#

def init_generic_commands() -> dict:
    """Initializing generic commands dictionary.

    :return: The available commands.
    :rtype: ``dict``
    """
    return {
        'test-module': test_module,
        'xdr-xql-query': start_xql_query_polling_command,
        'xdr-get-xql-query-results': get_xql_query_results_polling_command,
        'xdr-get-xql-quota': get_xql_quota_command,
    }


def convert_relative_time_to_milliseconds(time_to_convert: str) -> int:
    """Convert a relative time string to its Unix timestamp representation in milliseconds.

    :type time_to_convert: ``str``
    :param time_to_convert: The relative time to convert (supports seconds, minutes, hours, days, months, years)

    :return: The Unix timestamp representation in milliseconds
    :rtype: ``int``
    """
    try:
        time_multiples = {
            'second': 1000,
            'minute': 60 * 1000,
            'hour': 60 * 60 * 1000,
            'day': 24 * 60 * 60 * 1000,
            'month': 30 * 24 * 60 * 60 * 1000,
            'year': 12 * 30 * 24 * 60 * 60 * 1000
        }
        for k in time_multiples.keys():
            if k in time_to_convert:
                num = int(time_to_convert.split(' ')[0])
                return time_multiples[k] * num
        raise ValueError
    except ValueError:
        raise DemistoException('Please enter a valid time frame (seconds, minutes, hours, days, months, years).')


def start_xql_query(client: Client, args: Dict[str, Any]) -> str:
    """Execute an XQL query.

    :type client: ``Client``
    :param client: The XDR Client.
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: The query execution ID.
    :rtype: ``str``
    """
    query = args.get('query', '')
    if not query:
        raise ValueError('query is not specified')
    if '//' in query:
        raise DemistoException('Please remove notes (//) from query')

    limit = args.get('limit')
    if limit and limit in query:
        return_warning('It is best to use a limit argument rather than inserting a limit directly into the query.')
        query = f'{query} | limit {limit}'
    data = {
        'request_data': {
            'query': query,
        }
    }
    time_frame = args.get('time_frame')
    if time_frame:
        converted_time = convert_relative_time_to_milliseconds(time_frame)
        data['request_data']['timeframe'] = {'relativeTime': converted_time}
    tenant_ids = argToList(args.get('tenant_ids'))
    if tenant_ids:
        data['request_data']['tenants'] = tenant_ids
    # Call the Client function and get the raw response
    execution_id = client.start_xql_query(data)
    return execution_id


def get_xql_query_results(client: Client, args: dict) -> Tuple[dict, Optional[bytes]]:
    """Retrieve results of an executed XQL query API. returns the general response and
    a file data if the query has more than 1000 results.

    :type client: ``Client``
    :param client: The XDR Client.
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: The query results.
    :rtype: ``dict`` or tuple
    """

    query_id = args.get('query_id')
    if not query_id:
        raise ValueError('query ID is not specified')
    format_method = args.get('format', 'json')
    data = {
        'request_data': {
            'query_id': query_id,
            'pending_flag': True,
            'format': format_method
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


def get_query_result_stream(client: Client, stream_id: str) -> bytes:
    """Retrieve XQL query results with more than 1000 results.

    :type client: ``Client``
    :param client: The XDR Client.
    :type stream_id: ``str``
    :param stream_id: The stream ID of the query.

    :return: The query results.
    :rtype: ``bytes``
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


def format_results(list_to_format: list, remove_empty_fields: bool = True) -> list:
    """
    Recursively format a list of dictionaries and remove empty lists, empty dicts, or None elements from it if desired.
    :param list_to_format: Input list to format.
    :type list_to_format: ``list``
    :param remove_empty_fields: True if the user wants to remove the empty fields.
    :type remove_empty_fields: ``bool``

    :return: Formatted list.
    :rtype: ``list``
    """

    def format_dict(d: Any) -> Any:

        if not isinstance(d, (dict, list)):  # format some of the API response fields
            if d == 'FALSE':
                return False
            elif d == 'TRUE':
                return True
            elif d == 'NULL':
                return None
            else:
                return d

        elif isinstance(d, list):
            return [v for v in (format_dict(v) for v in d) if v]
        else:
            new_dict = {}
            for k, v in d.items():
                res = format_dict(v)
                if (res is None or res == {} or res == []) and remove_empty_fields:
                    continue
                if 'time' in k:  # Convert timestamp to datestring
                    try:
                        new_dict[k] = timestamp_to_datestring(res)
                    except Exception:
                        new_dict[k] = res
                else:
                    new_dict[k] = res
            return new_dict

    for i, item in enumerate(list_to_format):
        list_to_format[i] = format_dict(item)

    return list_to_format


def get_outputs_prefix(command_name: str) -> str:
    """
    Get the correct output output prefix.

    :param command_name: The executed command
    :type command_name: ``str``
    :return: the output prefix.
    :rtype: ``str``
    """
    if command_name in init_generic_commands():
        return 'PaloAltoNetworksXDR.XQL.GenericQuery'
    elif command_name in init_built_in_commands():
        query_name = init_built_in_commands()[command_name].get('name')
        return f'PaloAltoNetworksXDR.XQL.BuiltInQuery.{query_name}'
    raise NotImplementedError(f'Command {command_name} does not exist.')


''' COMMAND FUNCTIONS '''

# ========================================== Generic Query ===============================================#


def test_module(client: Client, args: Dict[str, Any]) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_xql_quota({'request_data': {}})
        message = 'ok'
    except DemistoException as e:
        if any(error in str(e) for error in ['Forbidden', 'Authorization', 'Unauthorized']):
            message = 'Authorization failed, make sure API Key is correctly set'
        elif 'Not Found' in str(e):
            message = 'Authorization failed, make sure the URL is correct'
        else:
            raise e
    return message


def start_xql_query_polling_command(client: Client, args: dict) -> Union[CommandResults, list]:
    """Execute an XQL query as a scheduled command.

    :type client: ``Client``
    :param client: The XDR Client.
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: The command results.
    :rtype: ``CommandResults``
    """
    execution_id = start_xql_query(client, args)
    if not execution_id:
        raise DemistoException('Failed to start query\n')
    args['query_id'] = execution_id
    return get_xql_query_results_polling_command(client, args)


def get_xql_query_results_polling_command(client: Client, args: dict) -> Union[CommandResults, list]:
    """Retrieve results of an executed XQL query API executes as a scheduled command.

    :type client: ``Client``
    :param client: The XDR Client.
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: The command results.
    :rtype: ``Union[CommandResults, dict]``
    """
    query = args.get('query', '')
    time_frame = args.get('time_frame')
    # get the first executed command in the polling
    command_name = args.get('command_name', '') if 'command_name' in args else demisto.command()
    interval_in_secs = int(args.get('interval_in_seconds', 10))
    outputs, file_data = get_xql_query_results(client, args)  # get query results with query_id
    outputs_prefix = get_outputs_prefix(command_name)
    command_results = CommandResults(outputs_prefix=outputs_prefix, outputs_key_field='execution_id', outputs=outputs,
                                     raw_response=copy.deepcopy(outputs))

    # if there are more then 1000 results - a file is returned
    if file_data:
        file = fileResult(filename="results.gz", data=file_data)
        return [file, command_results]

    # if status is pending, the command will be called again in the next run until success.
    if outputs.get('status') == 'PENDING':
        polling_args = {**args, 'command_name': command_name}
        scheduled_command = ScheduledCommand(command='xdr-get-xql-query-results', next_run_in_seconds=interval_in_secs,
                                             args=polling_args, timeout_in_seconds=600)
        command_results.scheduled_command = scheduled_command
        command_results.readable_output = 'Query is still running, it may take a little while...'
        return command_results

    results_to_format = outputs.pop('results')

    # create Human Readable output
    extra_for_human_readable = ({'query': query, 'time_frame': time_frame})
    outputs.update(extra_for_human_readable)
    command_results.readable_output = tableToMarkdown('General Results', outputs, headerTransform=string_to_table_header,
                                                      removeNull=True)
    [outputs.pop(key) for key in list(extra_for_human_readable.keys())]

    # if no fields were given in the query then the default fields are returned (without empty fields).
    if results_to_format:
        formatted_list = format_results(results_to_format, remove_empty_fields=False) \
            if 'fields' in query else format_results(results_to_format)
        outputs.update({'results': formatted_list})
        command_results.outputs = outputs

    command_results.readable_output += tableToMarkdown('Data Results', outputs.get('results'),
                                                       headerTransform=string_to_table_header)
    return command_results


def get_xql_quota_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the amount of query quota available and used.

    :type client: ``Client``
    :param client: The XDR Client.
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: The quota results.
    :rtype: ``dict``
    """

    data: dict = {
        'request_data': {
        }
    }
    # Call the Client function and get the raw response
    result = client.get_xql_quota(data).get('reply', {})
    readable_output = tableToMarkdown('Quota Results', result, headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        outputs_prefix='PaloAltoNetworksXDR.XQL.Quota',
        outputs_key_field='',
        outputs=result,
        readable_output=readable_output
    )


# =========================================== Built-In Queries ===========================================#

def get_built_in_query_results_polling_command(client: Client, args: dict) -> Union[CommandResults, list]:
    """Retrieve results of a built in XQL query, execute as a scheduled command.

    :type client: ``Client``
    :param client: The XDR Client.
    :type args: ``dict``
    :param args: The arguments to pass to the API call.

    :return: The command results.
    :rtype: ``Union[CommandResults, dict]``
    """
    # build query, if no endpoint_id was given, the query will search in every endpoint_id (*).
    endpoint_id_list = format_arg(args.get('endpoint_id', '*'))
    available_commands = init_built_in_commands()
    query = available_commands.get(demisto.command(), {}).get('func')(endpoint_id_list, args)

    # add extra fields to query
    extra_fields_list = ", ".join(str(e) for e in argToList(args.get('extra_fields', [])))
    extra_fields_list = f', {extra_fields_list}' if extra_fields_list else ''  # add comma to the beginning of fields
    query = f'{query}{extra_fields_list}'

    # add limit to query
    limit = args.get('limit', '200')
    query = f'{query} | limit {limit}'

    query_args = {
        'query': query,
        'tenants': argToList(args.get('tenants', [])),
        'time_frame': args.get('time_frame', '')
    }
    return start_xql_query_polling_command(client, query_args)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    args = demisto.args()
    params = demisto.params()
    api_key = params.get('apikey')
    api_key_id = params.get('apikey_id')
    base_url = urljoin(params['url'], '/public_api/v1')
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
        timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
        auth_key = "%s%s%s" % (api_key, nonce, timestamp)
        api_key_hash = hashlib.sha256(auth_key.encode("utf-8")).hexdigest()

        headers = {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": api_key_hash
        }

        client = Client(
            base_url=base_url,
            verify=verify_cert,
            headers=headers,
            proxy=proxy)
        generic_commands = init_generic_commands()
        built_in_commands = init_built_in_commands()
        if command in generic_commands:
            return_results(generic_commands[command](client, args))
        elif command in built_in_commands:
            return_results(get_built_in_query_results_polling_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} does not exist.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
