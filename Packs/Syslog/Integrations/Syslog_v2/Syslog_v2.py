import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any
from socket import *
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_samples() -> None:
    """
    Retrieves samples from context.
    """
    demisto.incidents(get_integration_context().get('samples'))


def perform_long_running_execution(host_address, port, log_format, protocol, message_regex):
    # Set the socket parameters
    buf = 1024
    address = (host_address, port)

    # Create socket and bind to address
    udp_sock = socket(AF_INET, SOCK_DGRAM)
    udp_sock.bind(address)

    # Receive messages
    while 1:
        data, addr = udp_sock.recvfrom(buf)
        if not data:
            demisto.debug("SYSLOG:: Client has exited!")
            break
        else:
            demisto.debug(f"SYSLOG:: received message: {data}")

    # Close socket
    udp_sock.close()
    pass


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    host_address: str = params.get('host_address', '')
    port: str = params.get('port', '')
    log_format: str = params.get('log_format', '')
    protocol: str = params.get('protocol', '')
    message_regex: str = params.get('message_regex', '')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            fetch_samples()
        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'long-running-execution':
            perform_long_running_execution(
                host_address,
                port,
                log_format,
                protocol,
                message_regex
            )
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
