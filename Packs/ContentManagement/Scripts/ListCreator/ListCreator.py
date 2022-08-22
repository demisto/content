import demistomock as demisto
from CommonServerPython import *

SCRIPT_NAME = 'ListCreator'


def configure_list(list_name: str, list_data: str) -> bool:
    """Create system lists using the createList built-in method.
    """
    demisto.debug(f'{SCRIPT_NAME} - Setting "{list_name}" list.')

    res = demisto.executeCommand('createList', {'listName': list_name, 'listData': list_data})
    if is_error(res):
        error_message = f'{SCRIPT_NAME} - {get_error(res)}'
        demisto.debug(error_message)
        return False

    return True


def main():
    args = demisto.args()
    list_name = args.get('list_name')
    list_data = args.get('list_data')

    try:
        configuration_status = configure_list(list_name, list_data)

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup.Lists',
                outputs_key_field='listname',
                outputs={
                    'listname': list_name,
                    'creationstatus': 'Success.' if configuration_status else 'Failure.',
                },
            )
        )

    except Exception as e:
        return_error(f'{SCRIPT_NAME} - Error occurred while setting up machine.\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
