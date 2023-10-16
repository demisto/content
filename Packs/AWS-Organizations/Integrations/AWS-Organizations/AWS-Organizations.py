import demistomock as demisto  # noqa: E402
from CommonServerPython import *  # noqa: E402
import boto3

''' CONSTANTS '''

''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''

''' MAIN FUNCTION '''


def main() -> None:

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    base_url = urljoin(params['url'], '/api/v1')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    client = boto3.client('organizations')


    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'test-module':
            pass
        elif command == '':
            return_results(args)
        else:
            raise NotImplementedError(f'AWS-Organizations error: command {command!r} is not implemented')

    except Exception as error:
        demisto.debug(f'{error.args=}')
        return_error(f'Failed to execute {command!r}.\nError:\n{error}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
