import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''

import tempfile
import subprocess
import shutil
import os

''' GLOBALS '''

HOSTNAME = demisto.params().get('hostname')

PORT = demisto.params().get('port', None)
if PORT:
    PORT = str(PORT)

authentication = demisto.params().get('Authentication')

USERNAME = authentication.get('identifier')

CERTIFICATE = authentication.get('credentials').get(
    'sshkey') if 'credentials' in authentication and 'sshkey' in authentication.get('credentials') and len(
    authentication.get('credentials').get('sshkey')) > 0 else authentication.get('password')
if not CERTIFICATE:
    return_error('Provide a certificate in order to connect to the remote server.')
CERTIFICATE_FILE = tempfile.NamedTemporaryFile()
with open(CERTIFICATE_FILE.name, "w") as f:
    f.write(CERTIFICATE)
os.chmod(CERTIFICATE_FILE.name, 0o400)

SSH_EXTRA_PARAMS = demisto.params().get('ssh_extra_params').split() if demisto.params().get('ssh_extra_params',
                                                                                            None) else None
SCP_EXTRA_PARAMS = demisto.params().get('scp_extra_params').split() if demisto.params().get('scp_extra_params',
                                                                                            None) else None

DOCUMENT_ROOT = demisto.params().get('document_root', None)

''' UTILS '''


def ssh_execute(command):
    out = ''
    try:
        if PORT and SSH_EXTRA_PARAMS:
            param_list = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, '-p',
                          PORT] + SSH_EXTRA_PARAMS + [USERNAME + '@' + HOSTNAME, command]
            out = subprocess.check_output(param_list, text=True)
        elif PORT:
            out = subprocess.check_output(
                ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, '-p', PORT,
                 USERNAME + '@' + HOSTNAME, command], text=True)
        elif SSH_EXTRA_PARAMS:
            param_list = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name] + SSH_EXTRA_PARAMS + [
                USERNAME + '@' + HOSTNAME, command]
            out = subprocess.check_output(param_list, text=True)
        else:
            out = subprocess.check_output(
                ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, USERNAME + '@' + HOSTNAME,
                 command], text=True)

    except Exception as ex:
        if str(ex).find('warning') != -1:
            LOG(str(ex))

    return out


def scp_execute(file_name, file_path):
    try:
        if SCP_EXTRA_PARAMS:
            param_list = ['scp', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name] + SCP_EXTRA_PARAMS + [
                file_name, USERNAME + '@' + HOSTNAME + ':' + file_path]
            subprocess.check_output(param_list)
        else:
            subprocess.check_output(['scp', '-o', 'StrictHostKeyChecking=no', '-i', CERTIFICATE_FILE.name, file_name,
                                     USERNAME + '@' + HOSTNAME + ':' + file_path])
        return True
    except Exception as ex:
        if str(ex).find('warning') != -1:
            LOG(str(ex))
            return True
        else:
            return False


''' COMMANDS '''


def rfm_get_external_file(file_path):
    command = f'cat {file_path}'
    result = ssh_execute(command)
    return result


def rfm_get_external_file_command():
    """
    Get external file from web-server and prints to Warroom
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)

    result = rfm_get_external_file(file_path)

    md = tableToMarkdown('File Content:', result, headers=['List'])
    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def rfm_search_external_file(file_path, search_string):
    return ssh_execute(f'grep {search_string} {file_path}')


def rfm_search_external_file_command():
    """
    Search the external file and return all matching entries to Warroom
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    search_string = demisto.args().get('search_string')

    result = rfm_search_external_file(file_path, search_string)
    if len(result) > 0:
        md = tableToMarkdown('Search Results', result, headers=['Results'])

        demisto.results({
            'ContentsFormat': formats['markdown'],
            'Type': entryTypes['note'],
            'Contents': md
        })
    else:
        demisto.results({
            'Type': 11,
            'Contents': 'Search string was not found in the external file path given.',
            'ContentsFormat': formats['text']
        })


def rfm_update_external_file(file_path, list_name, verbose):
    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name)

    file_name = file_path.rsplit('/', 1)[-1] + '.txt'
    try:
        with open(file_name, 'w') as file:
            file.write("\n".join(list_data))
        success = scp_execute(file_name, file_path)
    finally:
        shutil.rmtree(file_name, ignore_errors=True)

    if not success:
        return False
    else:
        if verbose:
            return ssh_execute(f'cat {file_path}')
        else:
            return True


def rfm_update():
    """
    Updates the instance context with the list name and items given
    Overrides external file path with internal list
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name = demisto.args().get('list_name')
    list_items = argToList(demisto.args().get('list_items'))
    add = demisto.args().get('add_or_remove') == 'add'
    verbose = demisto.args().get('verbose') == 'true'

    # update internal list
    dict_of_lists = demisto.getIntegrationContext()
    if not dict_of_lists:
        dict_of_lists = {list_name: list_items}
        if verbose:
            md = tableToMarkdown('List items:', list_items, headers=[list_name])
        else:
            md = 'Instance context updated successfully'
    else:
        if not dict_of_lists.get(list_name, None) and not add:
            return_error('Cannot remove items from an empty list')
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
                md = 'Instance context updated successfully'

    demisto.setIntegrationContext(dict_of_lists)

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })

    # scp internal list to file_path
    result = rfm_update_external_file(file_path, list_name, verbose)
    if result:
        if verbose:
            md = tableToMarkdown('Updated File Data:', result, headers=['Data'])
        else:
            md = 'External file updated successfully'

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': md,
            'ContentsFormat': formats['markdown']
        })


def rfm_update_from_external_file(list_name, file_path, type_):
    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)
    file_data = rfm_get_external_file(file_path)

    set_internal = set(list_data)
    set_external = set(file_data.split('\n'))
    set_external.discard('')

    if type_ == 'merge':
        list_data_new = list(set_internal + set_external)
    else:  # type_ == 'override'
        list_data_new = list(set_external)

    dict_of_lists.update({list_name: list_data_new})

    return list_data_new


def rfm_update_from_external_file_command():
    """
    Updates internal list data with external file contents
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    list_name = demisto.args().get('list_name')
    type_ = demisto.args().get('type')
    verbose = demisto.args().get('verbose') == 'true'

    list_data_new = rfm_update_from_external_file(list_name, file_path, type_)

    if verbose:
        md = tableToMarkdown('List items:', list_data_new, headers=[list_name])
    else:
        md = 'Instance context updated successfully'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': md,
        'ContentsFormat': formats['markdown']
    })


def rfm_delete_external_file(file_path):
    ssh_execute('rm -f ' + file_path)
    return 'File deleted successfully'


def rfm_delete_external_file_command():
    """
    Delete external file
    """
    file_path = demisto.args().get('file_path')
    if DOCUMENT_ROOT:
        file_path = os.path.join(DOCUMENT_ROOT, file_path)
    result = rfm_delete_external_file(file_path)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['text']
    })


def rfm_list_internal_lists_command():
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


def rfm_search_internal_list_command():
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


def rfm_print_internal_list_command():
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


def rfm_dump_internal_list_command():
    """
    Dumps an instance context list to either a file or incident context
    """
    destination = demisto.args().get('destination')
    list_name = demisto.args().get('list_name')

    dict_of_lists = demisto.getIntegrationContext()
    list_data = dict_of_lists.get(list_name, None)

    if destination == 'file':  # dump list as file
        internal_file_path = demisto.uniqueFile()

        try:
            with open(internal_file_path, 'w') as f:
                f.write("\n".join(list_data))
            file_type = entryTypes['entryInfoFile']
            with open(internal_file_path, 'r') as f:
                file_entry = fileResult(internal_file_path, f.read(), file_type)
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
                "RemoteFileManagement(val.ListName == obj.ListName)": ec
            }
        })


def rfm_compare_command():
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

    file_data = rfm_get_external_file(file_path)
    if not file_data:
        demisto.results({
            'Type': 11,
            'Contents': 'file was not found in external web-server.',
            'ContentsFormat': formats['text']
        })

    set_internal = set(list_data)
    set_external = set(file_data.split('\n'))
    set_external.discard('')

    unique_internal = set_internal - set_external
    unique_external = set_external - set_internal

    md = ''
    if unique_internal:
        md += tableToMarkdown('Unique internal items:', list(unique_internal), headers=[list_name])
    if unique_external:
        md += tableToMarkdown('Unique external items:', list(unique_external), headers=[file_path.rsplit('/')[-1]])
    if len(md) == 0:
        md = 'Internal list and External file have the same values'

    demisto.results({
        'Type': 11 if unique_external else entryTypes['note'],
        'Contents': md,
        'ContentsFormat': formats['markdown'],
    })


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            ssh_execute('echo 1')
            demisto.results('ok')

        elif demisto.command() == 'rfm-get-external-file':
            rfm_get_external_file_command()

        elif demisto.command() == 'rfm-search-external-file':
            rfm_search_external_file_command()

        elif demisto.command() == 'rfm-update':
            rfm_update()

        elif demisto.command() == 'rfm-update-from-external-file':
            rfm_update_from_external_file_command()

        elif demisto.command() == 'rfm-delete-external-file':
            rfm_delete_external_file_command()

        elif demisto.command() == 'rfm-list-internal-lists':
            rfm_list_internal_lists_command()

        elif demisto.command() == 'rfm-search-internal-list':
            rfm_search_internal_list_command()

        elif demisto.command() == 'rfm-print-internal-list':
            rfm_print_internal_list_command()

        elif demisto.command() == 'rfm-dump-internal-list':
            rfm_dump_internal_list_command()

        elif demisto.command() == 'rfm-compare':
            rfm_compare_command()

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
