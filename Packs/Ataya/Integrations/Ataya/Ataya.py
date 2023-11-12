import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key

        self._headers = {
            'Content-Type': 'application/json',
            'x-api-key': self.api_key
        }

    def getNode(self):
        return self._http_request(method='GET', url_suffix='api/v1/mgmt/5gc/networks/default/nodes')

    def assignUser(self, imsi):
        return self._http_request(method='PUT', url_suffix='api/v1/mgmt/5gc/clientAction/setstatus',
                                  json_data={"status": "assigned", "resources": [imsi]})


''' HELPER FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    Returning 'ok' indicates that connection to the service is successful.
    Raises exceptions if something goes wrong.
    """

    try:
        response = client.getNode()

        success = demisto.get(response, 'count')  # Safe access to response['count']
        if success < 1:
            return f'Unexpected result from the service: success={success} (expected success > 1)'

        return 'ok'

    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


''' COMMAND FUNCTIONS '''


def assign_command(client: Client, imsi=""):
    if imsi == "":
        raise DemistoException('the imsi argument cannot be empty.')

    response = client.assignUser(imsi=imsi)
    userStatus = demisto.get(response, 'status')

    if userStatus == 'unassigned':
        raise DemistoException('Assign User Fail', res=response)

    return f'User {imsi} {userStatus}'


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get('url')
    api_key = params.get('apiToken', {}).get('password')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = Client(api_key=api_key, base_url=base_url,
                        verify=verify, proxy=proxy)
        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            return_results(test_module(client))

        elif command == 'ataya-assign-user':
            return_results(assign_command(client, **args))

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join(("Failed to execute {command} command.",
                                "Error:",
                                str(e))))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
