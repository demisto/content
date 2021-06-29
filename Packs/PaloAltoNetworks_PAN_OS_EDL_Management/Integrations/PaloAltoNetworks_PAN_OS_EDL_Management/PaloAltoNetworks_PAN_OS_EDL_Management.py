import shutil
import subprocess
import tempfile
from urllib.parse import urlparse, urlunparse

from CommonServerUserPython import *

from CommonServerPython import *

''' GLOBALS '''

AUTHENTICATION: Union[str, Dict[Any, Any]] = {}
HOSTNAME = ''
USERNAME = ''
PORT = ''
SSH_EXTRA_PARAMS = ''
SCP_EXTRA_PARAMS = ''
DOCUMENT_ROOT = ''
CERTIFICATE_FILE = tempfile.NamedTemporaryFile(delete=False, mode='w')


def initialize_instance(params: Dict[str, str]):
    global AUTHENTICATION, HOSTNAME, USERNAME, PORT, SSH_EXTRA_PARAMS, SCP_EXTRA_PARAMS, DOCUMENT_ROOT, CERTIFICATE_FILE

    AUTHENTICATION = params.get('Authentication', {})

    HOSTNAME = str(params.get('hostname', ''))
    USERNAME = str(AUTHENTICATION.get('identifier', ''))
    PORT = str(params.get('port')) if params.get('port', '') and len(params.get('port')) > 0 else ''  # type: ignore

    SSH_EXTRA_PARAMS = params.get('ssh_extra_params').split() if params.get(
        'ssh_extra_params') else None  # type: ignore
    SCP_EXTRA_PARAMS = params.get('scp_extra_params').split() if params.get(
        'scp_extra_params') else None  # type: ignore
    DOCUMENT_ROOT = f'/{params.get("document_root")}' if params.get('document_root') else ''

    create_certificate_file(AUTHENTICATION)


def create_certificate_file(authentication: dict):
    password = authentication.get('password', None)
    certificate = None
    if 'credentials' in authentication and 'sshkey' in authentication['credentials'] and len(
            authentication['credentials']['sshkey']) > 0:
        certificate = authentication.get('credentials', None).get('sshkey')

    if certificate:
        CERTIFICATE_FILE.write(certificate)
        CERTIFICATE_FILE.flush()
        os.chmod(CERTIFICATE_FILE.name, 0o400)
    elif password:
        # check that password field holds a certificate and not a password
        if password.find('-----') == -1:
            return_error('Password parameter must contain a certificate.')
        # split certificate by dashes
        password_list = password.split('-----')
        # replace spaces with newline characters
        password_fixed = '-----'.join(password_list[:2] + [password_list[2].replace(' ', '\n')] + password_list[3:])
        CERTIFICATE_FILE.write(password_fixed)
        CERTIFICATE_FILE.flush()
        os.chmod(CERTIFICATE_FILE.name, 0o400)
    else:
        return_error('To connect to the remote server, provide a certificate.')


''' UTILS '''


def ssh_execute(command: str):
    if PORT and SSH_EXTRA_PARAMS:
        param_list = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, '-p',
                      PORT] + SSH_EXTRA_PARAMS + [USERNAME + '@' + HOSTNAME, command]  # type: ignore
        result = subprocess.run(param_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elif PORT:
        result = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, '-p', PORT,
             USERNAME + '@' + HOSTNAME, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elif SSH_EXTRA_PARAMS:
        param_list = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name] + SSH_EXTRA_PARAMS + [
            USERNAME + '@' + HOSTNAME, command]  # type: ignore
        result = subprocess.run(param_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        result = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, USERNAME + '@' + HOSTNAME, command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        if result.stderr:
            if result.stderr.find("Warning: Permanently added") != -1:
                return result.stdout  # ignore addition of new hosts warnings
            elif result.stderr.find("Permission denied") != -1:
                return_error(
                    'Permission denied, check your username and certificate.\n' + 'Got error: ' + result.stderr)
            else:
                return_error(result.stderr)
        elif command.find('grep') != -1 and result.returncode == 1:
            #  a search command that did not find any value
            demisto.results({
                'Type': 11,
                'Contents': 'Search string was not found in the external file path given.',
                'ContentsFormat': formats['text']
            })
            sys.exit(0)
        else:
            return_error('Command failed with exit status: ' + str(result.returncode))

    return result.stdout


def scp_execute(file_name: str, file_path: str):
    if SCP_EXTRA_PARAMS:
        param_list = ['scp', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name] + SCP_EXTRA_PARAMS + [
            file_name, USERNAME + '@' + HOSTNAME + ':' + f'\'{file_path}\'']  # type: ignore
        result = subprocess.run(param_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        param_list = ['scp', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, file_name,
                      USERNAME + '@' + HOSTNAME + ':' + f'\'{file_path}\'']
        result = subprocess.run(param_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        if result.stderr:
            if result.stderr.find("Warning: Permanently added") != -1:
                return True  # ignore addition of new hosts warnings
            else:
                return_error(result.stderr)
        else:
            return_error('Command failed with exit status: ' + str(result.returncode))
    else:
        return True


def parse_url(item: str) -> str:
    """ Parse url if in url form to valid EDL form - without http / https

    Args:
        item(str): Item to parse.

    Returns:
        str: parsed item, if URL returned without http / https

    Examples:
        >>> parse_url('http://google.com')
        'google.com'
        >>> parse_url('https://google.com')
        'google.com'
        >>> parse_url('https://google.com/hello_world')
        'google.com/hello_world'
        >>> parse_url('not url')
        'not url'
    """
    try:
        url_obj = urlparse(item)._replace(scheme='')
        return urlunparse(url_obj).replace('//', '')
    except ValueError:
        return item


def parse_items(items: str) -> List[str]:
    """ Parse list of item to update, parsing steps:
        1. Remove http and https from

    Args:
        items(str): items for update

    Returns:
        list: list of parsed items.
    """
    return [parse_url(item) for item in argToList(items)]


''' COMMANDS '''


def edl_get_external_file(file_path: str, retries: int = 1):
    command = f'cat \'{file_path}\''
    while retries > 0:
        result = ssh_execute(command)
        # counting newlines as in some edge cases the external web server returns the file content intermittently
        # with newline as every other char
        num_lines = float(result.count('\n'))
        if num_lines > len(result) / 3:
            demisto.info(f'The number of newlines chars in the file is too big. Try number {retries} before failure.')
            retries -= 1
        else:
            return result

    # if we get here, we failed as the file contains too many newlines to be valid
    raise DemistoException('The file contains too many newlines to be valid. '
                           'Please check the file contents on the external web server manually.')


def edl_get_external_file_command(args):
    """
    Get external file from web-server and prints to Warroom
    """
    file_path = args.get('file_path')
    retries = int(args.get('retries', '1'))

    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)

    result = edl_get_external_file(file_path, retries)

    md = tableToMarkdown('File Content:', result, headers=['List'])
    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def edl_search_external_file(file_path: str, search_string: str):
    return ssh_execute(f'grep \'{search_string}\' \'{file_path}\'')


def edl_search_external_file_command(args: dict):
    """
    Search the external file and return all matching entries to Warroom
    """
    file_path: str = str(args.get('file_path', ''))
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    search_string: str = str(args.get('search_string', ''))

    result = edl_search_external_file(file_path, search_string)

    md = tableToMarkdown('Search Results', result, headers=['Result'])

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def edl_update_external_file(file_path: str, list_name: str, verbose: bool):
    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name)

    file_name = file_path.rsplit('/', 1)[-1]
    if not file_name.endswith('.txt'):
        file_name += '.txt'

    try:
        with open(file_name, 'w') as file:
            file.write("\n".join(list_data))
        success = scp_execute(file_name, file_path)
    finally:
        shutil.rmtree(file_name, ignore_errors=True)

    if not success:
        return_error('External file was not updated successfully.')
    else:
        if verbose:
            external_file_items = ssh_execute(f'cat \'{file_path}\'')
            if external_file_items:
                md = tableToMarkdown('Updated File Data:', external_file_items, headers=['Data'])
            else:
                md = 'External file has no items.'
        else:
            md = 'External file updated successfully.'

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': md,
            'ContentsFormat': formats['markdown']
        })


def edl_update_external_file_command(args: dict):
    """
    Overrides external file path with internal list
    """
    file_path: str = str(args.get('file_path', ''))
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name: str = str(args.get('list_name', ''))
    verbose = args.get('verbose') == 'true'

    edl_update_external_file(file_path, list_name, verbose)


def edl_update_internal_list(list_name: str, list_items: list, add: bool, verbose: bool):
    dict_of_lists = demisto.getIntegrationContext()

    if not dict_of_lists:
        demisto.debug('PAN-OS EDL Management integration context is empty.')
        dict_of_lists = {list_name: list_items}
        if verbose:
            md = tableToMarkdown('List items:', list_items, headers=[list_name])
        else:
            md = 'Instance context updated successfully.'
    else:
        if not dict_of_lists.get(list_name, None) and not add:
            raise Exception(f'Cannot remove items from an empty list: {list_name}.')

        if dict_of_lists.get(list_name, None):
            if add:
                chosen_list = dict_of_lists.get(list_name)
                if not isinstance(chosen_list, list):
                    chosen_list = [chosen_list]

                list_items = list(set(chosen_list + list_items))
            else:  # remove
                list_items = [item for item in dict_of_lists.get(list_name) if item not in list_items]

        if not add and len(list_items) == 0:
            # delete list from instance context, can happen only upon remove of objects
            demisto.debug(f'PAN-OS EDL Management deleting {list_name} from the integration context.')
            dict_of_lists.pop(list_name, None)
            md = 'List is empty, deleted from instance context.'
        else:
            # update list in instance context, can happen upon removal or addition of objects
            dict_of_lists.update({list_name: list_items})
            if verbose:
                md = tableToMarkdown('List items:', list_items, headers=[list_name])
            else:
                md = 'Instance context updated successfully.'

    if not dict_of_lists:  # to be removed, debugging purposes only
        demisto.debug('PAN-OS EDL Management updating an empty object to the integration context.')

    demisto.debug(f'PAN-OS EDL Management updating {list_name} with {len(list_items)} in the integration context.')
    demisto.setIntegrationContext(dict_of_lists)

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def edl_update_internal_list_command(args: dict):
    """
        Updates the instance context with the list name and items given
    """
    list_name: str = str(args.get('list_name', ''))
    list_items: list = argToList(str(args.get('list_items', '')))
    if args.get('add_or_remove') not in ['add', 'remove']:
        raise Exception('add_or_remove argument is not \'add\' neither \'remove\'.')
    add = args.get('add_or_remove') == 'add'
    verbose = args.get('verbose') == 'true'

    edl_update_internal_list(list_name, list_items, add, verbose)


def edl_update(args: dict):
    """
    Updates the instance context with the list name and items given
    Overrides external file path with internal list
    """
    file_path: str = str(args.get('file_path', ''))
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)

    # Parse list items
    list_name: str = str(args.get('list_name', ''))
    list_items = parse_items(items=str(args.get('list_items', '')))
    if args.get('add_or_remove') not in ['add', 'remove']:
        return_error('add_or_remove argument is neither \'add\' nor \'remove\'.')
    add = args.get('add_or_remove') == 'add'
    verbose = args.get('verbose') == 'true'

    # update internal list
    edl_update_internal_list(list_name, list_items, add, verbose)

    # scp internal list to file_path
    edl_update_external_file(file_path, list_name, verbose)


def edl_update_from_external_file(list_name: str, file_path: str, type_: str, retries: int):
    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)
    file_data = edl_get_external_file(file_path, retries)

    if list_data:
        set_internal = set(list_data)
        set_external = set(file_data.split('\n'))
        set_external.discard('')
        if type_ == 'merge':
            unified = set_internal.union(set_external)
            list_data_new = list(unified)
        else:  # type_ == 'override'
            list_data_new = list(set_external)
        dict_of_lists.update({list_name: list_data_new})
        demisto.setIntegrationContext(dict_of_lists)
        return list_data_new
    else:
        dict_of_lists.update({list_name: file_data})
        demisto.setIntegrationContext(dict_of_lists)
        return file_data


def edl_update_from_external_file_command(args: dict):
    """
    Updates internal list data with external file contents
    """
    file_path: str = str(args.get('file_path', ''))
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name: str = str(args.get('list_name', ''))
    type_: str = args.get('type', 'false')
    verbose: bool = args.get('verbose') == 'true'
    retries: int = int(args.get('retries', '1'))

    list_data_new = edl_update_from_external_file(list_name, file_path, type_, retries)

    if verbose:
        md = tableToMarkdown('List items:', list_data_new, headers=[list_name])
    else:
        md = 'Instance context updated successfully'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': md,
        'ContentsFormat': formats['markdown']
    })


def edl_delete_external_file(file_path: str):
    ssh_execute(f'rm -f \'{file_path}\'')
    return 'File deleted successfully'


def edl_delete_external_file_command(args: dict):
    """
    Delete external file
    """
    file_path = str(args.get('file_path', ''))
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    result = edl_delete_external_file(file_path)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['text']
    })


def edl_list_internal_lists_command():
    """
    List all instance context lists
    """
    dict_of_lists = demisto.getIntegrationContext()
    list_names = list(dict_of_lists.keys())

    md = tableToMarkdown('Instance context Lists:', list_names, headers=['List names'])

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def edl_search_internal_list_command(args: dict):
    """
    Search a string on internal list
    """
    list_name = args.get('list_name')
    search_string = args.get('search_string')

    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)

    if not list_data:
        demisto.results({
            'Type': 11,
            'Contents': 'List was not found in instance context.',
            'ContentsFormat': formats['text']
        })
    elif search_string in list_data:
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': 'Search string is in internal list.',
            'ContentsFormat': formats['text']
        })
    else:
        demisto.results({
            'Type': 11,
            'Contents': 'Search string was not found in instance context list.',
            'ContentsFormat': formats['text']
        })


def edl_print_internal_list_command(args: dict):
    """
    Print to the warroom instance context list
    """
    list_name = args.get('list_name')
    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)

    if not list_data:
        demisto.results({
            'Type': 11,
            'Contents': 'List was not found in instance context.',
            'ContentsFormat': formats['text']
        })
    else:
        md = tableToMarkdown('List items:', list_data, headers=[list_name])
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': md,
            'ContentsFormat': formats['markdown']
        })


def edl_dump_internal_list_command(args: dict):
    """
    Dumps an instance context list to either a file or incident context
    """
    destination = args.get('destination')
    list_name = args.get('list_name')

    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)
    if not list_data:
        demisto.results({
            'Type': 11,
            'Contents': 'List was not found in instance context or has no data.',
            'ContentsFormat': formats['text']
        })
        sys.exit(0)
    if destination == 'file':  # dump list as file
        internal_file_path = demisto.uniqueFile()

        try:
            with open(internal_file_path, 'w') as f:
                f.write("\n".join(list_data))
            file_type = entryTypes['entryInfoFile']
            with open(internal_file_path, 'rb') as file:
                file_entry = fileResult(internal_file_path, file.read(), file_type)
            demisto.results(file_entry)
        finally:
            shutil.rmtree(internal_file_path, ignore_errors=True)

    else:  # update incident context
        md = tableToMarkdown('List items:', list_data, headers=[list_name])
        ec = {
            'ListName': list_name,
            'ListItems': list_data
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': md,
            'ContentsFormat': formats['markdown'],
            'EntryContext': {
                "PANOSEDL(val.ListName == obj.ListName)": ec
            }
        })


def edl_compare_command(args: dict):
    list_name = str(args.get('list_name', ''))
    file_path = str(args.get('file_path', ''))
    retries = int(args.get('retries', '1'))

    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)

    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)
    if not list_data:
        demisto.results({
            'Type': 11,
            'Contents': 'List was not found in instance context.',
            'ContentsFormat': formats['text']
        })
        sys.exit(0)

    file_data = edl_get_external_file(file_path, retries)
    if not file_data:
        demisto.results({
            'Type': 11,
            'Contents': 'file was not found in external web-server.',
            'ContentsFormat': formats['text']
        })
        sys.exit(0)

    set_internal = set(list_data)
    set_external = set(file_data.split('\n'))
    set_external.discard('')

    unique_internal = set_internal - set_external
    unique_external = set_external - set_internal

    md = ''
    if unique_external:
        md += '### Warning: External file contains values that are not in the internal Demisto list.\n'
        md += '#### If these changes are unexpected, check who has permission to write to the external file.\n'
        md += tableToMarkdown('', list(unique_external),
                              headers=[file_path.rsplit('/')[-1]])
    if unique_internal:
        md += '### Warning: Internal list contains values that are not in the external file.\n'
        md += '#### If these changes are unexpected, check who has permission to write to the external file.\n'
        md += tableToMarkdown('', list(unique_internal), headers=[list_name])
    if len(md) == 0:
        md = 'Internal list and external file have the same values.'

    demisto.results({
        'Type': 11 if unique_external or unique_internal else entryTypes['note'],
        'Contents': md,
        'ContentsFormat': formats['markdown'],
    })


def edl_get_external_file_metadata_command(args: dict):
    file_path = str(args.get('file_path', ''))
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)

    result = ssh_execute(f'stat \'{file_path}\'')

    file_size = int(result.split("Size: ", 1)[1].split(" ", 1)[0])
    file_name = file_path.split("/")[-1]
    if len(file_name) < 0:
        file_name = file_path
    last_modified_parts = result.split("Change: ", 1)[1].split(" ", 2)[0:2]
    last_modified = ' '.join(last_modified_parts)

    number_of_lines = int(ssh_execute(f'wc -l < \'{file_path}\'')) + 1

    metadata_outputs = {
        'FileName': file_name,
        'Size': file_size,
        'LastModified': last_modified,
        'NumberOfLines': number_of_lines
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('File metadata:', metadata_outputs,
                                         ['FileName', 'Size', 'NumberOfLines', 'LastModified'], removeNull=True),
        'EntryContext': {"PANOSEDL(val.FileName == obj.FileName)": metadata_outputs}
    })


''' EXECUTION '''


def main():
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()
    initialize_instance(params=params)
    LOG(f'command is {command}')
    try:
        if command == 'test-module':
            ssh_execute('echo 1')
            demisto.results('ok')

        elif command == 'pan-os-edl-get-external-file':
            edl_get_external_file_command(args)

        elif command == 'pan-os-edl-search-external-file':
            edl_search_external_file_command(args)

        elif command == 'pan-os-edl-update-internal-list':
            edl_update_internal_list_command(args)

        elif command == 'pan-os-edl-update-external-file':
            edl_update_external_file_command(args)

        elif command == 'pan-os-edl-update':
            edl_update(args)

        elif command == 'pan-os-edl-update-from-external-file':
            edl_update_from_external_file_command(args)

        elif command == 'pan-os-edl-delete-external-file':
            edl_delete_external_file_command(args)

        elif command == 'pan-os-edl-list-internal-lists':
            edl_list_internal_lists_command()

        elif command == 'pan-os-edl-search-internal-list':
            edl_search_internal_list_command(args)

        elif command == 'pan-os-edl-print-internal-list':
            edl_print_internal_list_command(args)

        elif command == 'pan-os-edl-dump-internal-list':
            edl_dump_internal_list_command(args)

        elif command == 'pan-os-edl-compare':
            edl_compare_command(args)

        elif command == 'pan-os-edl-get-external-file-metadata':
            edl_get_external_file_metadata_command(args)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        if str(err).find('warning') != -1:
            LOG(str(err))
        else:
            return_error(f'Error: {str(err)}\nTrace:\n{traceback.format_exc()}')

    finally:
        shutil.rmtree(CERTIFICATE_FILE.name, ignore_errors=True)  # type: ignore
        LOG.print_log()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
