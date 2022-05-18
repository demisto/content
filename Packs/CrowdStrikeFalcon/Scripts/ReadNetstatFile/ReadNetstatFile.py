from CommonServerPython import *

CONTEXT_PATH_TO_READ_PROCESS_FILE_NAME_FROM = "CrowdStrike.Command"
COMMAND_NAME = 'netstat'


def get_file_name_from_context() -> str:
    file_name = ""
    all_command_files = demisto.get(demisto.context(), CONTEXT_PATH_TO_READ_PROCESS_FILE_NAME_FROM)
    if all_command_files and isinstance(all_command_files, dict):
        netstat_files = all_command_files.get(COMMAND_NAME, [])
        if netstat_files:
            if isinstance(netstat_files, list):
                # we want to get the last file name
                file_name = netstat_files[len(netstat_files) - 1].get('Filename')
            elif isinstance(netstat_files, dict):
                file_name = netstat_files.get('Filename')  # type:ignore
    return file_name


def get_file_entry_id(file_name):
    file_entry_id = ""
    if file_name:
        entries = demisto.executeCommand('getEntries', {})
        for entry in entries:
            file_entry = demisto.get(entry, 'File')
            is_correct_file = file_name.lower() == file_entry.lower()
            if is_correct_file:
                file_entry_id = entry['ID']
                break
    return file_entry_id


def get_file_content(file_entry_id):
    if file_entry_id:
        res = execute_command('getFilePath', {'id': file_entry_id})
        file_path = res.get('path')
        with open(file_path, 'r') as f:
            file_content = f.read()
        return file_content


def main():
    file_name = get_file_name_from_context()
    if file_name:
        demisto.results(get_file_content(get_file_entry_id(file_name)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
