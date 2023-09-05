import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


SCRIPT_NAME = 'CustomPackInstaller'


def install_custom_pack(pack_id: str, skip_verify: bool, skip_validation: bool, instance_name: str = '') -> tuple[bool, str]:
    """Installs a custom pack in the machine.

    Args:
        pack_id (str): The ID of the pack to install.
        skip_verify (bool): If true will skip pack signature validation.
        skip_validation (bool) if true will skip all pack validations.
        instance_name (str) Demisto REST API instance name.

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
        file_in_context_name = file_in_context.get('Name', '')
        if file_in_context_name.split('/')[-1] == f'{pack_id}.zip' or file_in_context_name == f'{pack_id}.zip':
            pack_file_entry_id = file_in_context.get('EntryID')
            break

    if pack_file_entry_id:
        args = {'entry_id': pack_file_entry_id, 'skip_verify': str(skip_verify),
                'skip_validation': str(skip_validation)}
        if instance_name:
            args['using'] = instance_name

        status, res = execute_command(
            'core-api-install-packs',
            args,
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
    skip_verify = args.get('skip_verify')
    skip_validation = args.get('skip_validation')
    instance_name = args.get('using')

    try:
        installation_status, error_message = install_custom_pack(pack_id, skip_verify, skip_validation, instance_name)

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
