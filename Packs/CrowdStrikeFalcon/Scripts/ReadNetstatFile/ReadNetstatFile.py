from CommonServerPython import *

COMMAND_NAME = 'netstat'


def get_netstat_file_name(command_files):
    if command_files and isinstance(command_files, dict):
        netstat_files = command_files.get(COMMAND_NAME, [])
        if netstat_files:
            if isinstance(netstat_files, list):
                # we want to get the last file name
                return netstat_files[len(netstat_files) - 1].get('Filename')
            elif isinstance(netstat_files, dict):
                return netstat_files.get('Filename')  # type:ignore


def get_file_name_from_context() -> str:
    crowdstrike_context = demisto.context().get('CrowdStrike', {})
    all_command_files = []
    if isinstance(crowdstrike_context, list):
        for ctx in crowdstrike_context:
            if cmd_ctx := ctx.get('Command'):
                all_command_files.append(cmd_ctx)
    elif isinstance(crowdstrike_context, dict) and (cmd_ctx := crowdstrike_context.get('Command')):
        all_command_files.append(cmd_ctx)
    for command_file in all_command_files[::-1]:  # get last file in context
        if file_name := get_netstat_file_name(command_file):
            return file_name
    return ""


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
