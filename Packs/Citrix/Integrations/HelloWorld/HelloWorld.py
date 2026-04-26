import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

""" CONSTANTS """

VENDOR = "hello"
PRODUCT = "world"

''' MAIN FUNCTION '''


def main() -> None:
    """Main function, parses params and runs command functions."""
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            return_results('ok')
        elif command == 'helloworld-get-events':
            raise NotImplementedError('The helloworld-get-events command is not implemented.')
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
