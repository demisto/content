from CommonServerPython import *
import demistomock as demisto

''' IMPORTS '''
from typing import Callable
from google.oauth2 import service_account
import google.auth.transport.requests

''' CONSTANTS '''
BASE_URL = 'https://admin.googleapis.com/'


requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, customer_id: str, service_account_json: Dict[str, str], auth: tuple = None):
        self._headers = {'Content-Type': 'application/json'}
        self._customer_id = customer_id
        self._service_account_json = service_account_json
        self._credentials = service_account.Credentials.from_service_account_info(
            self._service_account_json,
        )
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=self._headers, auth=auth)

    def http_request(self, url_suffix: str, method: str, ok_codes: tuple = (200, 204),
                     resp_type: str = 'json') -> dict:
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  resp_type=resp_type,
                                  ok_codes=ok_codes)

    def test_client_connection(self):
        try:
            token = self.get_oauth_token(scopes=['https://www.googleapis.com/auth/admin.directory.device.mobile',
                                                 'https://www.googleapis.com/auth/admin.directory.device.chromeos'])
            self._headers['Authorization'] = f'Bearer {token}'
            response = self._http_request('GET', f'admin/directory/v1/customer/{client._customer_id}/devices/mobile',
                                          headers=headers)
            return_results('ok')
        except DemistoException as e:
            raise e

    def get_oauth_token(self, scopes: List[str]):
        """ In charge or retrieving the OAuth token in order to make HTTP requests """
        scoped_credentials: service_account.Credentials = self._credentials.with_scopes(scopes)
        if(not scoped_credentials.valid):
            request = google.auth.transport.requests.Request()
            scoped_credentials.refresh(request)
            if(not scoped_credentials.valid):
                raise DemistoException('Could not refresh token')
            request.session.close()
        return scoped_credentials.token

    def google_mobiledevice_action_request(self, customerid, resourceid, action):
        data = {"action": action}
        headers = self._headers
        response = self._http_request(
            'POST', f'admin/directory/v1/customer/{customerid}/devices/mobile/{resourceid}/action', json_data=data, headers=headers)
        return response

    def google_mobiledevice_list_request(self, customerid, projection, query, orderby, sortorder, pagetoken, maxresults):
        params = assign_params(projection=projection, query=query, orderBy=orderby,
                               sortOrder=sortorder, pageToken=pagetoken, maxResults=maxresults)
        headers = self._headers
        response = self._http_request(
            'GET', f'admin/directory/v1/customer/{customerid}/devices/mobile', params=params, headers=headers)
        return response

    def google_chromeosdevice_action_request(self, customerid, resourceid):
        headers = self._headers
        response = self._http_request(
            'POST', f'admin/directory/v1/customer/{customerid}/devices/chromeos/{resourceid}/action', headers=headers)
        return response


def google_mobiledevice_action_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    customerid = args.get('customerid')
    resourceid = args.get('resourceid')
    action = args.get('action')
    response = client.google_mobiledevice_action_request(customerid, resourceid, action)
    command_results = CommandResults(
        outputs_prefix='GoogleWorkspaceAdmin.GoogleMobiledeviceAction',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def google_mobiledevice_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    customerid = args.get('customerid')
    projection = args.get('projection')
    query = args.get('query')
    orderby = args.get('orderby')
    sortorder = args.get('sortorder')
    pagetoken = args.get('pagetoken')
    maxresults = args.get('maxresults')
    response = client.google_mobiledevice_list_request(
        customerid, projection, query, orderby, sortorder, pagetoken, maxresults)
    command_results = CommandResults(
        outputs_prefix='GoogleWorkspaceAdmin.GoogleMobiledeviceList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def google_chromeosdevice_action_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    customerid = args.get('customerid')
    resourceid = args.get('resourceid')
    response = client.google_chromeosdevice_action_request(customerid, resourceid)
    command_results = CommandResults(
        outputs_prefix='GoogleWorkspaceAdmin.GoogleChromeosdeviceAction',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def google_chromeosdevice_list_command():
    pass


def test_module(client: Client) -> None:
    # Test functions here
    return client.test_client_connection


def test_module_test(client: Client) -> None:
    # Test functions here
    from google.oauth2 import service_account

    credentials = service_account.Credentials.from_service_account_file(
        'Integrations/GoogleWorkspaceAdmin/delta-heading-367810-a433b2f4eaad.json', scopes=['https://www.googleapis.com/auth/admin.directory.device.mobile '])
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {credentials.token}'
    }
    response = client._http_request(
        'GET', f'admin/directory/v1/customer/{customer_id}/devices/mobile', headers=headers)
    return_results('ok')


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        customer_id = params.get('customer_id')
        service_account_json = json.loads(params.get('user_service_account_json'), strict=False)
        verify_certificate: bool = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        client: Client = Client(base_url=BASE_URL, verify=verify_certificate, proxy=proxy,
                                customer_id=customer_id, service_account_json=service_account_json, auth=None)
        commands: Dict[str, Callable] = {
            'google-mobiledevice-action': google_mobiledevice_action_command,
            'google-mobiledevice-list': google_mobiledevice_list_command,
            'google-chromeosdevice-action': google_chromeosdevice_action_command,
            'google_chromeosdevice_list': google_chromeosdevice_list_command
        }
        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        print(str(e))
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
