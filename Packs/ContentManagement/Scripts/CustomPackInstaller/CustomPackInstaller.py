from typing import Tuple

import demistomock as demisto
from CommonServerPython import *

SCRIPT_NAME = 'CustomPackInstaller'


def install_custom_pack(pack_id: str) -> Tuple[bool, str]:
    """Installs a custom pack in the machine.

    Args:
        pack_id (str): The ID of the pack to install.

    Returns:
        - bool. Whether the installation of the pack was successful or not.
        - str. In case of failure, the error message.

    Notes:
        Assumptions: The zipped file is in the war-room, and the context includes the data related to it.

    """
    pack_file_entry_id = ''

    instance_context = demisto.context()
    context_files = instance_context.get('File', [])
    if not isinstance(context_files, list):
        context_files = [context_files]

    for file_in_context in context_files:
        if file_in_context['Name'] == f'{pack_id}.zip':
            pack_file_entry_id = file_in_context['EntryID']
            break

    if pack_file_entry_id:
        status, res = execute_command(
            'demisto-api-multipart',
            {'uri': '/contentpacks/installed/upload', 'entryID': pack_file_entry_id},
            fail_on_error=False,
        )

        if not status:
            error_message = f'{SCRIPT_NAME} - {res}'
            demisto.debug(error_message)
            return False, f'Issue occurred while installing the pack on the machine.\n{res}'

    else:
        error_message = 'Could not find file entry ID.'
        demisto.debug(f'{SCRIPT_NAME}, "{pack_id}" - {error_message}.')
        return False, error_message

    return True, ''


def main():
    args = demisto.args()
    pack_id = args.get('pack_id')

    try:
        installation_status, error_message = install_custom_pack(pack_id)

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup.CustomPacks',
                outputs_key_field='packid',
                outputs={
                    'packid': pack_id,
                    'installationstatus': 'Success.' if installation_status else error_message,
                },
            )
        )

        if not installation_status:
            return_error(error_message)

    except Exception as e:
        return_error(f'{SCRIPT_NAME} - Error occurred while installing custom pack "{pack_id}".\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
