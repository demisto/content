import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from cbc_sdk.errors import ObjectNotFoundError

from cbc_sdk import platform, CBCloudAPI, errors
import ntpath
import urllib3

# Disable insecure warnings
CONNECTION_ERROR_MSG = 'Connection Error - check your server URL'
AUTHORIZATION_ERROR_MSG = 'Authorization Error - check your API Credentials'
ORG_ID_ERROR_MSG = 'Authorization Error - check your Organization Key'
PROXY_ERROR_MSG = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                  ' selected, try clearing the checkbox.'
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
CBD_LR_PREFIX = 'cbd-lr'
IGNORED_FILES_IN_DIR = {'.', '..'}


# Using Py API
def put_file_command(api_client: CBCloudAPI, device_id: str, destination_path: str, file_id: str):
    session = api_client.select(platform.Device, device_id).lr_session()
    path = demisto.getFilePath(file_id)
    with open(path['path'], 'rb') as _file:
        session.put_file((path['name'], _file), destination_path)
    return f'File: {file_id} is successfully put to the remote destination {destination_path}'


# Using Py API
def get_file_command(api_client: CBCloudAPI, device_id: str, source_path: str, timeout: Union[int, str] = None,
                     delay: Union[float, str] = None):
    session = api_client.select(platform.Device, device_id).lr_session()

    if delay:
        delay = float(delay)
    file_data = session.get_file(file_name=source_path, timeout=arg_to_number(timeout), delay=delay)
    file_name = ntpath.split(source_path)[1]
    return fileResult(file_name, file_data)


# Using Py API
def delete_file_command(api_client: CBCloudAPI, device_id: str, source_path: str):
    session = api_client.select(platform.Device, device_id).lr_session()
    session.delete_file(filename=source_path)
    return f'The file: {source_path} was deleted successfully.'


# Using Py API
def list_directory_command(api_client: CBCloudAPI, device_id: str, directory_path: str, limit: Union[int, str]):
    """
       Get list of directory entries in the remote device

       :param api_client: The API client

       :param device_id: The device id

       :param directory_path: Directory to list. This parameter should end with the path separator

       :param limit: Limit the result entries count to be the given limit

       :return: CommandResult represent the API command result
       :rtype: ``CommandResults``
    """
    session = api_client.select(platform.Device, device_id).lr_session()
    items = [item for item in session.list_directory(directory_path) if item['filename'] not in IGNORED_FILES_IN_DIR]
    items, partial_res_msg = get_limited_results(original_results=items, limit=limit)

    directories_readable = []
    context_entry_items = []
    headers = ['name', 'type', 'date_modified', 'size']
    for item in items:
        context_entry_items.append(item)
        directories_readable.append({
            'name': item['filename'],
            'type': 'Directory' if item['attributes'] and 'DIRECTORY' in item['attributes'] else 'File',
            'date_modified': item['last_write_time'],
            'size': item['size'],
        })

    context_entry = dict(content=context_entry_items, device_id=device_id, directory_path=directory_path)

    readable_output = tableToMarkdown(f'Directory of {directory_path}{partial_res_msg}',
                                      t=directories_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefenseLR.Directory',
        outputs_key_field=['device_id', 'directory_path'],
        outputs=context_entry,
        readable_output=readable_output,
        raw_response=items,
    )


# Using Py API
def create_reg_key_command(api_client: CBCloudAPI, device_id: str, reg_path: str):
    session = api_client.select(platform.Device, device_id).lr_session()
    session.create_registry_key(reg_path)
    return f'Reg key: {reg_path}, was created successfully.'


# Using Py API
def set_reg_value_command(
        api_client: CBCloudAPI, device_id: str, reg_path: str,
        value_data: Any, value_type: str, overwrite: Union[bool, str]):

    session = api_client.select(platform.Device, device_id).lr_session()
    session.set_registry_value(reg_path, value_data, overwrite=argToBoolean(overwrite), value_type=value_type)
    return f'Value was set to the reg key: {reg_path} successfully.'


# Using Py API
def list_reg_sub_keys_command(api_client: CBCloudAPI, device_id: str, reg_path: str, limit: Union[int, str]):
    session = api_client.select(platform.Device, device_id).lr_session()
    sub_keys = session.list_registry_keys_and_values(reg_path).get('sub_keys', [])
    if not sub_keys:
        return f'The key: {reg_path} does not contain any sub keys'

    sub_keys, partial_res_msg = get_limited_results(original_results=sub_keys, limit=limit)

    context_entry = dict(sub_keys=sub_keys, device_id=device_id, key=reg_path)
    human_readable = tableToMarkdown(name=f'Carbon Black Defense Live Response Registry sub keys{partial_res_msg}',
                                     t=sub_keys,
                                     headers=['Sub keys'])
    return CommandResults(
        outputs_prefix='CarbonBlackDefenseLR.RegistrySubKeys',
        outputs_key_field=['device_id', 'key'],
        outputs=context_entry,
        readable_output=human_readable,
        raw_response=sub_keys,
    )


# Using Py API
def get_reg_values_command(api_client: CBCloudAPI, device_id: str, reg_path: str, limit: Union[int, str]):
    """Get the values of the given registry key in the remote device"""
    session = api_client.select(platform.Device, device_id).lr_session()
    values = session.list_registry_values(reg_path)
    if not values:
        return f'The key: {reg_path} does not contain any value'

    values, partial_res_msg = get_limited_results(original_results=values, limit=limit)

    context_entry = dict(key=reg_path, values=values, device_id=device_id)
    human_readable = [dict(name=val['registry_name'], type=val['registry_type'], data=val['registry_data']) for val in values]

    readable_output = tableToMarkdown(f'Carbon Black Defense Live Response Registry key values{partial_res_msg}',
                                      human_readable,
                                      headers=['name', 'type', 'data'],
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefenseLR.RegistryValues',
        outputs_key_field=['device_id', 'key'],
        outputs=context_entry,
        readable_output=readable_output,
        raw_response=values,
    )


# Using Py API
def delete_reg_value_command(api_client: CBCloudAPI, device_id: str, reg_path: str):
    session = api_client.select(platform.Device, device_id).lr_session()
    session.delete_registry_value(reg_path)
    return f'Registry value: {reg_path} was deleted successfully.'


# Using Py API
def delete_reg_key_command(api_client: CBCloudAPI, device_id: str, reg_path: str, force: Union[bool, str] = False):
    """Delete a registry key on the remote machine, the key must be without any sub keys"""

    session = api_client.select(platform.Device, device_id).lr_session()
    if argToBoolean(force):
        delete_reg_key_recursive(session, reg_path)
    else:
        session.delete_registry_key(reg_path)

    return f'Registry key: {reg_path} was deleted successfully.'


# Using Py API
def list_processes_command(api_client: CBCloudAPI, device_id: str, limit: Union[int, str]):
    session = api_client.select(platform.Device, device_id).lr_session()
    processes = session.list_processes()
    if not processes:
        return 'There is no active processes in the remote device'

    processes, partial_res_msg = get_limited_results(original_results=processes, limit=limit)

    headers = ['path', 'pid', 'command_line', 'username']
    processes_readable = [dict(
        path=process['process_path'],
        pid=process['process_pid'],
        command_line=process['process_cmdline'],
        user_name=process['process_username']) for process in processes]
    context_entry = dict(device_id=device_id, processes=processes)

    readable_output = tableToMarkdown(f'Carbon Black Defense Live Response Processes{partial_res_msg}',
                                      headers=headers,
                                      t=processes_readable,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)
    return CommandResults(
        'CarbonBlackDefenseLR.Processes',
        outputs_key_field='device_id',
        outputs=context_entry,
        readable_output=readable_output,
        raw_response=processes,
    )


# Using Py API
def kill_process_command(api_client: CBCloudAPI, device_id: str, pid: Union[int, str]):
    session = api_client.select(platform.Device, device_id).lr_session()
    success = session.kill_process(arg_to_number(pid))  # the API returns True if success, False if failure
    if not success:
        return_error(f'Can not kill the process: {pid}')

    return f'The process: {pid} was killed successfully.'


# Using Py API
def create_process_command(
        api_client: CBCloudAPI, device_id: str,
        command_string: str,
        wait_timeout: Union[int, str] = 30,
        wait_for_output: Union[bool, str] = True,
        wait_for_completion: Union[bool, str] = True,
        **additional_params):
    # additional_param may include: remote_output_file_name: str, working_directory: str

    session = api_client.select(platform.Device, device_id).lr_session()
    process_results_bytes = session.create_process(
        command_string=command_string,
        wait_timeout=arg_to_number(wait_timeout),
        wait_for_output=argToBoolean(wait_for_output),
        wait_for_completion=argToBoolean(wait_for_completion),
        **additional_params,
    )
    process_results_str = None
    if wait_for_output and process_results_bytes:
        process_results_str = process_results_bytes.decode('utf-8')
        human_readable = process_results_str
    else:
        human_readable = f'Process: {command_string} was successfully executed.'

    context_output = dict(return_value=process_results_str,
                          device_id=device_id,
                          command_string=command_string,
                          )

    return CommandResults(outputs_prefix='CarbonBlackDefenseLR.ExecuteProcess',
                          outputs_key_field=['device_id', 'command_string'],
                          outputs=context_output,
                          readable_output=human_readable,
                          raw_response=process_results_str,
                          )


# Using Py API
def memdump_command(api_client: CBCloudAPI, device_id: str, target_path: str):
    session = api_client.select(platform.Device, device_id).lr_session()
    session.start_memdump(remote_filename=target_path).wait()
    return f'Memory was successfully dumped to {target_path}.'


def command_test_module(api_client: CBCloudAPI) -> str:
    try:
        not_exist_device_id = -1
        api_client.live_response.request_session(not_exist_device_id)
    except ObjectNotFoundError as e:
        if 'org_id' in str(e):
            raise DemistoException(ORG_ID_ERROR_MSG)
    except errors.UnauthorizedError:
        raise DemistoException(AUTHORIZATION_ERROR_MSG)
    except errors.ConnectionError as e:
        if 'ProxyError' in str(e):
            raise DemistoException(PROXY_ERROR_MSG)
        raise DemistoException(CONNECTION_ERROR_MSG)
    except Exception as e:
        raise DemistoException(f'An error occurred.\n {str(e)}')

    return 'ok'


def delete_reg_key_recursive(session, reg_path: str):
    sub_keys = session.list_registry_keys_and_values(reg_path).get('sub_keys', [])
    if sub_keys:
        for key in sub_keys:
            delete_reg_key_recursive(session, f'{reg_path}\\{key}')

    session.delete_registry_key(reg_path)


def get_limited_results(original_results, limit):
    limit = arg_to_number(limit)
    size = len(original_results)
    if limit and size > limit:
        return original_results[:limit], f',{limit}/{size} results'
    return original_results, ''


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

    params = demisto.params()
    url = params.get('url')
    cb_custom_key = params.get('credentials_custom_id', {}).get('password') or params.get('custom_key')
    cb_custom_id = params.get('credentials_custom_id', {}).get('identifier') or params.get('custom_id')
    cb_org_key = params.get('credentials_org_key', {}).get('password') or params.get('org_key')
    if not (cb_custom_key and cb_custom_id and cb_org_key):
        raise DemistoException('Custom Key, Custom ID and Organization Key must be provided.')
    verify_certificate = not params.get('insecure', True)
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
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
