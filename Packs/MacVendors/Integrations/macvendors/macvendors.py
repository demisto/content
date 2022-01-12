import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from typing import Dict, Any
import urllib.parse


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S:000 UTC-00:00"  # ISO8601 format with UTC, default in XSOAR
DEFAULT_LIMIT = 100


# =========================================== Helper Functions ===========================================#


# ========================================== Generic Query ===============================================#


def test_module(client: BaseClient, params: Dict[str, Any]):
    try:
        test_mac = urllib.parse.quote("00:0c:29:00:00:00")
        client._http_request('GET', url_suffix=f'query/{test_mac}')
        return_results('ok')
    except Exception as err:
        raise DemistoException(err)


def lookup_mac_command(client: BaseClient, params: Dict[str, Any], args: Dict[str, Any]):
    mac_address = urllib.parse.quote(args.get('mac'))
    res = client._http_request('GET', url_suffix=f"query/{mac_address}", timeout=300)
    return_error(res)


# =========================================== Built-In Queries ===========================================#


''' MAIN FUNCTION '''

# COMMAND CONSTANTS

commands = {
    'test-module': test_module,
    'macvendors-lookup-mac': lookup_mac_command
}


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = "https://api.macvendors.com"
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command: str=demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_cert,
            proxy=proxy,
        )
        commands[command](client, params, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
