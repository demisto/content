import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import paramiko
from scp import SCPClient
import shutil
import warnings

warnings.filterwarnings(action='ignore', module='.*paramiko.*')

''' GLOBALS '''

HOSTNAME = demisto.params().get('hostname')
PORT = int(demisto.params().get('port'))
USERNAME = demisto.params().get('Username').get('identifier')
PASSWORD = demisto.params().get('Username').get('password')

CLIENT = paramiko.SSHClient()
CLIENT.load_system_host_keys()
CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
CLIENT.connect(HOSTNAME, port=PORT, username=USERNAME, password=PASSWORD)

''' UTILS '''


def run_command(shell_command):
    stdin, stdout, stderr = CLIENT.exec_command(shell_command)
    out = stdout.read()
    return out


''' COMMANDS '''


def rfm_get_external_file(file_path):
    command = 'cat ' + file_path
    result = run_command(command)
    return result


def rfm_get_external_file_command():
    """
    Get external file from web-server and prints to Warroom
    """
    file_path = demisto.args().get('file_path')

    result = rfm_get_external_file(file_path)

    if result:
        md = tableToMarkdown('File Content:', result, headers=['List'])
        demisto.results({
            'ContentsFormat': formats['markdown'],
            'Type': entryTypes['note'],
            'Contents': md
        })
    else:
        demisto.results({
            'Type': 11,
            'Contents': 'File was not found on the web-server.',
            'ContentsFormat': formats['text']
        })


def rfm_search_external_file(file_path, search_string):
    return run_command('grep "' + search_string + '" ' + file_path)


def rfm_search_external_file_command():
    """
    Search the external file and return all matching entries to Warroom
    """
    file_path = demisto.args().get('file_path')
    search_string = demisto.args().get('search_string')

    result = rfm_search_external_file(file_path, search_string)

    if result:
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

    try:
        unique_path = demisto.uniqueFile()
        with open(unique_path, 'w') as f:
            f.write("\n".join(list_data))
        with SCPClient(CLIENT.get_transport()) as scp:
            scp.put(unique_path, recursive=False, remote_path=file_path)
    finally:
        shutil.rmtree(file_path, ignore_errors=True)

    if verbose:
        return run_command('cat ' + file_path)
    else:
        return True


def rfm_update_external_file_command():
    """
    Update external file with Append entry to BlockList file if not already there
    """
    file_path = demisto.args().get('file_path')
    list_name = demisto.args().get('list_name')
    verbose = demisto.args().get('verbose') == 'true'

    result = rfm_update_external_file(file_path, list_name, verbose)

    if verbose:
        md = tableToMarkdown('Updated File Data:', result, headers=['Data'])
    else:
        md = 'External file updated successfully'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': md,
        'ContentsFormat': formats['markdown']
    })


def rfm_delete_external_file(file_path):
    run_command('rm -f ' + file_path)
    return 'File deleted successfully'


def rfm_delete_external_file_command():
    """
    Delete external file
    """
    file_path = demisto.args().get('file_path')
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
    list_names = dict_of_lists.keys()
    md = tableToMarkdown('Instance context Lists:', list_names, headers=['List names'])
    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
    })


def rfm_update_internal_list_command():
    """
    Updates an instance context list
    """
    list_items = argToList(demisto.args().get('list_items'))
    list_name = demisto.args().get('list_name')
    add = demisto.args().get('add_or_remove') == 'add'
    verbose = demisto.args().get('verbose') == 'true'

    dict_of_lists = demisto.getIntegrationContext()

    if verbose:
        md = tableToMarkdown('List items:', list_items, headers=[list_name])
    else:
        md = 'Instance context updated successfully'

    if not dict_of_lists:
        dict_of_lists = {list_name: list_items}
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

    demisto.setIntegrationContext(dict_of_lists)

    demisto.results({
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': md
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
        file_path = demisto.uniqueFile()

        try:
            with open(file_path, 'w') as f:
                f.write("\n".join(list_data))
            file_type = entryTypes['entryInfoFile']
            with open(file_path, 'rb') as f:
                file_entry = fileResult(file_path, f.read(), file_type)
            demisto.results(file_entry)
        finally:
            shutil.rmtree(file_path, ignore_errors=True)

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


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'test-module':
            command = 'echo 1'
            # result = connect(command)
            result = run_command(command)
            demisto.results('ok')

        elif demisto.command() == 'rfm-get-external-file':
            rfm_get_external_file_command()

        elif demisto.command() == 'rfm-search-external-file':
            rfm_search_external_file_command()

        elif demisto.command() == 'rfm-update-external-file':
            rfm_update_external_file_command()

        elif demisto.command() == 'rfm-delete-external-file':
            rfm_delete_external_file_command()

        elif demisto.command() == 'rfm-list-internal-lists':
            rfm_list_internal_lists_command()

        elif demisto.command() == 'rfm-update-internal-list':
            rfm_update_internal_list_command()

        elif demisto.command() == 'rfm-print-internal-list':
            rfm_print_internal_list_command()

        elif demisto.command() == 'rfm-dump-internal-list':
            rfm_dump_internal_list_command()

        else:
            return_error('Unrecognized command: ' + demisto.command())

    except Exception as ex:
        return_error(str(ex))

    finally:
        CLIENT.close()
        LOG.print_log()


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
