import demistomock as demisto
from CommonServerPython import *
from cbc_sdk import endpoint_standard, CBCloudAPI, errors
import ntpath
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
CBD_LR_PREFIX = 'cbd-lr'


# Using Py API
def put_file_command(api_client: CBCloudAPI, sensor_id: str, destination_path: str, file_id: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    file_path = demisto.getFilePath(file_id).get('path')
    session.put_file(open(file_path, 'rb'), destination_path)
    return f'File: {file_id} is successfully put to the remote destination {destination_path}'


# Using Py API
def get_file_command(api_client: CBCloudAPI, sensor_id: str, source_path: str, timeout: Union[int, str] = None,
                     delay: Union[float, str] = None):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()

    if delay:
        delay = float(delay)
    file_data = session.get_file(file_name=source_path, timeout=arg_to_number(timeout), delay=delay)
    file_name = ntpath.split(source_path)[1]
    return fileResult(file_name, file_data)


# Using Py API
def delete_file_command(api_client: CBCloudAPI, sensor_id: str, source_path: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    session.delete_file(filename=source_path)
    return f'The file: {source_path} was deleted successfully.'


# Using Py API
def list_directory_command(api_client: CBCloudAPI, sensor_id: str, directory_path: str):
    """
       Get list of directory entries in th remote sensor

       :param api_client: The API client

       :param sensor_id: The sensor id

       :param directory_path: Directory to list. This parameter should end with the path separator

       :return: CommandResult represent the API command result
       :rtype: ``CommandResults``
    """
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    directories_readable = []
    headers = ['name', 'type', 'date_modified', 'size']
    dir_content = session.list_directory(directory_path)
    context_entry = dict(content=dir_content, sensor_id=sensor_id)
    for item in dir_content:
        directories_readable.append({
            'name': item['filename'],
            'type': 'Directory' if item['attributes'] and 'DIRECTORY' in item['attributes'] else 'File',
            'date_modified': timestamp_to_datestring(item['last_write_time']),
            'size': item['size']
        })

    readable_output = tableToMarkdown('Carbon Black Defense Live Response Directory content',
                                      t=directories_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefenseLR.Directory',
        outputs_key_field='sensor_id',
        outputs=context_entry,
        readable_output=readable_output,
        raw_response=dir_content
    )


# Using Py API
def create_reg_key_command(api_client: CBCloudAPI, sensor_id: str, reg_path: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    session.create_registry_key(reg_path)
    return f'Reg key: {reg_path}, was created successfully.'


# Using Py API
def set_reg_value_command(
        api_client: CBCloudAPI, sensor_id: str, reg_path: str,
        value_data: Any, value_type: str, overwrite: Union[bool, str]):

    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    session.set_registry_value(reg_path, value_data, overwrite=argToBoolean(overwrite), value_type=value_type)
    return f'Value was set to the reg key: {reg_path} successfully.'


# Using Py API
def list_reg_sub_keys_command(api_client: CBCloudAPI, sensor_id: str, reg_path: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    sub_keys = session.list_registry_keys_and_values(reg_path).get('sub_keys', [])
    context_entry = dict(sub_keys=sub_keys, sensor_id=sensor_id, key=reg_path)
    if not sub_keys:
        return f'The key: {reg_path} does not contain any sub keys'

    human_readable = tableToMarkdown(name='Carbon Black Defense Live Response Registry sub keys',
                                     t=sub_keys,
                                     headers=['Sub keys'])
    return CommandResults(
        outputs_prefix='CarbonBlackDefenseLR.RegistrySubKeys',
        outputs_key_field='sensor_id',
        outputs=context_entry,
        readable_output=human_readable,
        raw_response=sub_keys
    )


# Using Py API
def get_reg_values_command(api_client: CBCloudAPI, sensor_id: str, reg_path: str):
    """Get the values of the given registry key in the remote sensor"""
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    values = session.list_registry_values(reg_path)
    context_entry = dict(key=reg_path, values=values, sensor_id=sensor_id)
    if not values:
        return f'The key: {reg_path} does not contain any value'

    human_readable = [dict(name=val['value_name'], type=val['value_type'], data=val['value_data']) for val in values]

    readable_output = tableToMarkdown('Carbon Black Defense Live Response Registry key values',
                                      human_readable,
                                      headers=['name', 'type', 'data'],
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefenseLR.RegistryValues',
        outputs_key_field='sensor_id',
        outputs=context_entry,
        readable_output=readable_output,
        raw_response=values
    )


# Using Py API
def delete_reg_value_command(api_client: CBCloudAPI, sensor_id: str, reg_path: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    session.delete_registry_value(reg_path)
    return f'Registry value: {reg_path} was deleted successfully.'


# Using Py API
def delete_reg_key_command(api_client: CBCloudAPI, sensor_id: str, reg_path: str):
    """Delete a registry key on the remote machine, the key must be without any sub keys"""

    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    session.delete_registry_key(reg_path)
    return f'Registry key: {reg_path} was deleted successfully.'


# Using Py API
def list_processes_command(api_client: CBCloudAPI, sensor_id: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    processes = session.list_processes()
    if not processes:
        return 'There is no active processes in the remote sensor'

    headers = ['path', 'pid', 'command_line', 'username']
    processes_readable = [dict(
        path=process['path'],
        pid=process['pid'],
        command_line=process['command_line'],
        user_name=process['username']) for process in processes]
    context_entry = dict(sensor_id=sensor_id, processes=processes)

    readable_output = tableToMarkdown('Carbon Black Defense Live Response Processes',
                                      headers=headers,
                                      t=processes_readable,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)
    return CommandResults(
        'CarbonBlackDefenseLR.Processes',
        outputs_key_field='sensor_id',
        outputs=context_entry,
        readable_output=readable_output,
        raw_response=processes,
    )


# Using Py API
def kill_process_command(api_client: CBCloudAPI, sensor_id: str, pid: Any):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    success = session.kill_process(pid)  # the API returns True if success, False if failure
    if not success:
        return_error(f'Can not kill the process: {pid}')

    return f'The process: {pid} was killed successfully.'


# Using Py API
def create_process_command(
        api_client: CBCloudAPI, sensor_id: str,
        command_string: str,
        wait_timeout: Union[int, str] = 30,
        wait_for_output: Union[bool, str] = True,
        wait_for_completion: Union[bool, str] = True,
        **additional_params):
    # additional_param may include: remote_output_file_name: str, working_directory: str

    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    process_results_bytes = session.create_process(
        command_string=command_string,
        wait_timeout=arg_to_number(wait_timeout),
        wait_for_output=argToBoolean(wait_for_output),
        wait_for_completion=argToBoolean(wait_for_completion),
        **additional_params,
    )

    process_results_str = str(process_results_bytes)
    if wait_for_output and process_results_bytes:
        human_readable = tableToMarkdown(name='Carbon Black Defense Live Response Process Execution Result',
                                         t=[process_results_str],
                                         headers=['Process output'])
    else:
        human_readable = f'Process: {command_string} was successfully executed.'

    return CommandResults(outputs_prefix='CarbonBlackDefenseLR.ExecuteProcess',
                          outputs_key_field='sensor_id',
                          outputs=dict(return_value=process_results_str, sensor_id=sensor_id),
                          readable_output=human_readable,
                          raw_response=process_results_str,
                          )


# Using Py API
def memdump_command(api_client: CBCloudAPI, sensor_id: str, target_path: str):
    session = api_client.select(endpoint_standard.Device, sensor_id).lr_session()
    session.start_memdump(remote_filename=target_path).wait()
    return f'Memory was successfully dumped to {target_path}.'


def command_test_module(api_client: CBCloudAPI) -> str:
    try:
        api_client.api_json_request(method='GET', uri='/integrationServices/v3/cblr/session/')
    except errors.UnauthorizedError:
        return_error('Authorization Error: Check your API Credentials')
    except Exception as e:
        return_error(f'An error occurred.\n {str(e)}')

    return 'ok'


def main():
    commands = {
        'test-module': command_test_module,

        f'{CBD_LR_PREFIX}-file-put': put_file_command,
        f'{CBD_LR_PREFIX}-file-get': get_file_command,
        f'{CBD_LR_PREFIX}-file-delete': delete_file_command,

        f'{CBD_LR_PREFIX}-reg-key-create': create_reg_key_command,
        f'{CBD_LR_PREFIX}-reg-value-set': set_reg_value_command,
        f'{CBD_LR_PREFIX}-reg-sub-keys': list_reg_sub_keys_command,
        f'{CBD_LR_PREFIX}-reg-get-values': get_reg_values_command,
        f'{CBD_LR_PREFIX}-reg-value-delete': delete_reg_value_command,
        f'{CBD_LR_PREFIX}-reg-key-delete': delete_reg_key_command,

        f'{CBD_LR_PREFIX}-directory-listing': list_directory_command,

        f'{CBD_LR_PREFIX}-ps': list_processes_command,
        f'{CBD_LR_PREFIX}-kill': kill_process_command,
        f'{CBD_LR_PREFIX}-execute': create_process_command,
        f'{CBD_LR_PREFIX}-memdump': memdump_command
    }

    url = demisto.params().get('url')
    cb_custom_key = demisto.params().get('custom_key')
    cb_custom_id = demisto.params().get('custom_id')
    cb_org_key = demisto.params().get('org_key')
    verify_certificate = not demisto.params().get('insecure', True)
    handle_proxy()

    command = demisto.command()
    if command not in commands:
        raise NotImplementedError(f'Command: {command} not implemented')
    demisto.debug(f'Command being called is {command}')
    try:
        credentials = dict(
            url=url,
            ssl_verify=verify_certificate,
            token=f'{cb_custom_key}/{cb_custom_id}',
            org_key=cb_org_key
        )
        api = CBCloudAPI(**credentials)
        result = commands[command](api_client=api, **demisto.args())  # type: ignore
        return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
