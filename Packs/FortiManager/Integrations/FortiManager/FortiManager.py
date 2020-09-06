import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, url, credentials, verify, proxy, adom):
        super().__init__(base_url=url.rstrip('/'), verify=verify, proxy=proxy, ok_codes=(200, 204))
        self.username = credentials["identifier"]
        self.password = credentials["password"]
        self.session_token = self.get_session_token()
        self.adom = adom

    def get_session_token(self):
        body = {
            "id": 1,
            "method": "exec",
            "params": [{
                "url": "/sys/login/user",
                "data": {
                    "user": self.username,
                    "passwd": self.password
                }
            }]
        }

        response = self._http_request(
            method='POST',
            url_suffix='jsonrpc',
            json_data=body
        )
        return response.get('session')

    def fortimanager_http_request(self, method, url):
        body = {
            "id": 1,
            "method": method,
            "params": [{
                "url": url
            }],
            "session": self.session_token
        }

        response = self._http_request(
            method='POST',
            url_suffix='jsonrpc',
            json_data=body
        )

        return response.get('result')[0].get('data')


def list_adom_devices_command(client):
    devices_data = client.fortimanager_http_request("get", f"/dvmdb/adom/{client.adom}/device")

    return CommandResults(
        outputs_prefix='FortiManager.Device',
        outputs_key_field='name',
        outputs=devices_data,
        readable_output=tableToMarkdown(f"ADOM {client.adom} Devices", devices_data, removeNull=True,
                                        headerTransform=string_to_table_header),
        raw_response=devices_data,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    creds = demisto.params().get('creds')

    # get the service API url
    base_url = demisto.params().get('url')

    adom = demisto.params().get('adom')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            url=base_url,
            credentials=creds,
            verify=verify_certificate,
            proxy=proxy,
            adom=adom
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results("ok")

        elif demisto.command() == 'fortimanager-devices-list':
            return_results(list_adom_devices_command(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
