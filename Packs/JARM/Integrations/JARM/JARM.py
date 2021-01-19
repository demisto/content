import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Tuple, Any
from jarm.scanner.scanner import Scanner

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

DEFAULT_PORT = 443

''' CLIENT CLASS '''


class Client:
    def jarm_fingerprint(self, host: str, port: int) -> Tuple[str, str, int]:
        return Scanner.scan(host, port)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    return 'ok'


def jarm_fingerprint_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    host = args.get('host')
    if not host:
        raise ValueError('Host name not specified')
    port = arg_to_number(args.get('port'))
    if not port:
        port = DEFAULT_PORT

    result = client.jarm_fingerprint(host, port)

    output = {
        "Host": result[1],
        "Port": result[2],
        "Fingerprint": result[0]
    }

    return CommandResults(
        outputs_prefix='JARM',
        outputs_key_field=['Host', 'Port'],
        outputs=output,
    )


''' MAIN FUNCTION '''


def main() -> None:

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        handle_proxy()
        client = Client()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'jarm-fingerprint':
            return_results(jarm_fingerprint_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
