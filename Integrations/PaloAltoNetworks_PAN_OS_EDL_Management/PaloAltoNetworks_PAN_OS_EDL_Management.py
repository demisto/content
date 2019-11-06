import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''

import tempfile
import subprocess
import shutil
import os

''' GLOBALS '''


def create_certificate_file(authentication: dict):
    password = authentication.get('password', None)
    certificate = None
    if 'credentials' in authentication and 'sshkey' in authentication['credentials'] and len(
            authentication['credentials']['sshkey']) > 0:
        certificate = authentication.get('credentials', None).get('sshkey')

    cert_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
    if certificate:
        cert_file.write(certificate)
        cert_file.flush()
        os.chmod(cert_file.name, 0o400)
    elif password:
        # check that password field holds a certificate and not a password
        if password.find('-----') == -1:
            return_error('Password parameter must contain a certificate.')
        # split certificate by dashes
        password_list = password.split('-----')
        # replace spaces with newline characters
        password_fixed = '-----'.join(password_list[:2] + [password_list[2].replace(' ', '\n')] + password_list[3:])
        cert_file.write(password_fixed)
        cert_file.flush()
        os.chmod(cert_file.name, 0o400)
    else:
        return_error('To connect to the remote server, provide a certificate.')

    return cert_file


AUTHENTICATION = demisto.params().get('Authentication')

HOSTNAME = demisto.params().get('hostname')
USERNAME = AUTHENTICATION.get('identifier')
PORT = str(demisto.params().get('port')) if demisto.params().get('port', None) and len(
    demisto.params().get('port')) > 0 else None

SSH_EXTRA_PARAMS = demisto.params().get('ssh_extra_params').split() if demisto.params().get('ssh_extra_params',
                                                                                            None) else None
SCP_EXTRA_PARAMS = demisto.params().get('scp_extra_params').split() if demisto.params().get('scp_extra_params',
                                                                                            None) else None
DOCUMENT_ROOT = '/' + demisto.params().get('document_root') if demisto.params().get('document_root', None) else None

CERTIFICATE_FILE = create_certificate_file(AUTHENTICATION)

''' UTILS '''


def ssh_execute(command: str):
    if PORT and SSH_EXTRA_PARAMS:
        param_list = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, '-p',
                      PORT] + SSH_EXTRA_PARAMS + [USERNAME + '@' + HOSTNAME, command]
        result = subprocess.run(param_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elif PORT:
        result = subprocess.run(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, '-p', PORT,
             USERNAME + '@' + HOSTNAME, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elif SSH_EXTRA_PARAMS:
        param_list = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name] + SSH_EXTRA_PARAMS + [
            USERNAME + '@' + HOSTNAME, command]
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
            file_name, USERNAME + '@' + HOSTNAME + ':' + f'\'{file_path}\'']
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


''' COMMANDS '''


def edl_get_external_file(file_path: str):
    command = f'cat {file_path}'
    result = ssh_execute(command)
    return result


def edl_get_external_file_command():
    """
    Get external file from web-server and prints to Warroom
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)

    result = edl_get_external_file(file_path)

    md = tableToMarkdown('File Content:', result, headers=['List'])
    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def edl_search_external_file(file_path: str, search_string: str):
    return ssh_execute(f'grep \'{search_string}\' \'{file_path}\'')


def edl_search_external_file_command():
    """
    Search the external file and return all matching entries to Warroom
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    search_string = demisto.args().get('search_string')

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


def edl_update_external_file_command():
    """
    Overrides external file path with internal list
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name = demisto.args().get('list_name')
    verbose = demisto.args().get('verbose') == 'true'

    edl_update_external_file(file_path, list_name, verbose)


def edl_update_internal_list(list_name: str, list_items, add, verbose: bool):
    dict_of_lists = demisto.getIntegrationContext()
    if not dict_of_lists:
        dict_of_lists = {list_name: list_items}
        if verbose:
            md = tableToMarkdown('List items:', list_items, headers=[list_name])
        else:
            md = 'Instance context updated successfully.'
    else:
        if not dict_of_lists.get(list_name, None) and not add:
            return_error('Cannot remove items from an empty list.')
        if dict_of_lists.get(list_name, None):
            if add:
                list_items = list(set(dict_of_lists.get(list_name) + list_items))
            else:
                list_items = [item for item in dict_of_lists.get(list_name) if item not in list_items]

        if len(list_items) == 0:  # delete list from instance context
            dict_of_lists.pop(list_name, None)
            md = 'List is empty, deleted from instance context.'
        else:
            dict_of_lists.update({list_name: list_items})
            if verbose:
                md = tableToMarkdown('List items:', list_items, headers=[list_name])
            else:
                md = 'Instance context updated successfully.'

    demisto.setIntegrationContext(dict_of_lists)

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def edl_update_internal_list_command():
    """
        Updates the instance context with the list name and items given
    """
    list_name = demisto.args().get('list_name')
    list_items = argToList(demisto.args().get('list_items'))
    if demisto.args().get('add_or_remove') not in ['add', 'remove']:
        return_error('add_or_remove argument is not \'add\' neither \'remove\'.')
    add = demisto.args().get('add_or_remove') == 'add'
    verbose = demisto.args().get('verbose') == 'true'

    edl_update_internal_list(list_name, list_items, add, verbose)


def edl_update():
    """
    Updates the instance context with the list name and items given
    Overrides external file path with internal list
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name = demisto.args().get('list_name')
    list_items = argToList(demisto.args().get('list_items'))
    if demisto.args().get('add_or_remove') not in ['add', 'remove']:
        return_error('add_or_remove argument is not \'add\' neither \'remove\'.')
    add = demisto.args().get('add_or_remove') == 'add'
    verbose = demisto.args().get('verbose') == 'true'

    # update internal list
    edl_update_internal_list(list_name, list_items, add, verbose)

    # scp internal list to file_path
    edl_update_external_file(file_path, list_name, verbose)


def edl_update_from_external_file(list_name: str, file_path: str, type_: str):
    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)
    file_data = edl_get_external_file(file_path)

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


def edl_update_from_external_file_command():
    """
    Updates internal list data with external file contents
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name = demisto.args().get('list_name')
    type_ = demisto.args().get('type')
    verbose = demisto.args().get('verbose') == 'true'

    list_data_new = edl_update_from_external_file(list_name, file_path, type_)

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


def edl_delete_external_file_command():
    """
    Delete external file
    """
    file_path = demisto.args().get('file_path')
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


def edl_search_internal_list_command():
    """
    Search a string on internal list
    """
    list_name = demisto.args().get('list_name')
    search_string = demisto.args().get('search_string')

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


def edl_print_internal_list_command():
    """
    Print to warroom instance context list
    """
    list_name = demisto.args().get('list_name')
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


def edl_dump_internal_list_command():
    """
    Dumps an instance context list to either a file or incident context
    """
    destination = demisto.args().get('destination')
    list_name = demisto.args().get('list_name')

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


def edl_compare_command():
    list_name = demisto.args().get('list_name')
    file_path = demisto.args().get('file_path')
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

    file_data = edl_get_external_file(file_path)
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
        md += '### Warning: External file contain values which are not in the internal demisto list.\n'
        md += '#### If these changes are unexpected, Please check who has writing permissions to the external file.\n'
        md += tableToMarkdown('', list(unique_external),
                              headers=[file_path.rsplit('/')[-1]])
    if unique_internal:
        md += '### Warning: Internal list has values which are not in the external file.\n'
        md += '#### If these changes are unexpected, Please check who has writing permissions to the external file.\n'
        md += tableToMarkdown('', list(unique_internal), headers=[list_name])
    if len(md) == 0:
        md = 'Internal list and External file have the same values.'

    demisto.results({
        'Type': 11 if unique_external or unique_internal else entryTypes['note'],
        'Contents': md,
        'ContentsFormat': formats['markdown'],
    })


def edl_get_external_file_metadata_command():
    file_path = demisto.args().get('file_path')
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
    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            ssh_execute('echo 1')
            demisto.results('ok')

        elif demisto.command() == 'pan-os-edl-get-external-file':
            edl_get_external_file_command()

        elif demisto.command() == 'pan-os-edl-search-external-file':
            edl_search_external_file_command()

        elif demisto.command() == 'pan-os-edl-update-internal-list':
            edl_update_internal_list_command()

        elif demisto.command() == 'pan-os-edl-update-external-file':
            edl_update_external_file_command()

        elif demisto.command() == 'pan-os-edl-update':
            edl_update()

        elif demisto.command() == 'pan-os-edl-update-from-external-file':
            edl_update_from_external_file_command()

        elif demisto.command() == 'pan-os-edl-delete-external-file':
            edl_delete_external_file_command()

        elif demisto.command() == 'pan-os-edl-list-internal-lists':
            edl_list_internal_lists_command()

        elif demisto.command() == 'pan-os-edl-search-internal-list':
            edl_search_internal_list_command()

        elif demisto.command() == 'pan-os-edl-print-internal-list':
            edl_print_internal_list_command()

        elif demisto.command() == 'pan-os-edl-dump-internal-list':
            edl_dump_internal_list_command()

        elif demisto.command() == 'pan-os-edl-compare':
            edl_compare_command()

        elif demisto.command() == 'pan-os-edl-get-external-file-metadata':
            edl_get_external_file_metadata_command()

        else:
            return_error('Unrecognized command: ' + demisto.command())

    except Exception as ex:
        if str(ex).find('warning') != -1:
            LOG(str(ex))
        else:
            return_error(str(ex))

    finally:
        shutil.rmtree(CERTIFICATE_FILE.name, ignore_errors=True)
        LOG.print_log()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
