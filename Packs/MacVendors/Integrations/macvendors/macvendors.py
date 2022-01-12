import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from typing import Dict, Any
import urllib.parse


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''


# =========================================== Helper Functions ===========================================#


# ========================================== Generic Query ===============================================#


def test_module(client: BaseClient):
    try:
        test_mac = urllib.parse.quote("00:0c:29:00:00:00")
        client._http_request(
            'GET',
            resp_type="response",
            url_suffix=test_mac,
            ok_codes=[200])
        return_results('ok')
    except Exception as err:
        raise DemistoException(err)


def lookup_mac_command(client: BaseClient, params: Dict[str, Any], args: Dict[str, Any]):
    mac_address = args.get('mac')
    res = client._http_request(
        'GET',
        url_suffix=urllib.parse.quote(mac_address),
        ok_codes=[200,404],
        resp_type="response"
    )
    command_results = CommandResults(
        outputs_prefix="MacVendors",
        outputs_key_field="address",
        outputs={
            "address": mac_address,
            "vendor": "Unknown"
        }
    )
    if res.status_code == 200:
        command_results.outputs['vendor'] = res.text
        command_results.readable_output = f"{mac_address} - {res.text}"
    else:
        command_results. readable_output = f"{mac_address} - Unknown"
    return_results(command_results)


# =========================================== Built-In Queries ===========================================#


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = "https://api.macvendors.com"
    verify_cert = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_cert,
            proxy=proxy,
        )
        if command == "test-module":
            test_module(client)
        elif command == "macvendors-lookup-mac":
            lookup_mac_command(client, params, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
