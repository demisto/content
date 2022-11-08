from CommonServerPython import *
import demistomock as demisto

''' IMPORTS '''
import googleapiclient.discovery
''' CONSTANTS '''
BASE_URL = 'https://admin.googleapis.com/'

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

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


def test_module(client: Client) -> None:
    # Test functions here
    from google.oauth2 import service_account
    customer_id = 'C02f0zfqw'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ya29.a0AeTM1iftg_DsvbhAJ2qj5jn-gMr9-OUZUHemMZPQQMfPMYYjfXR18nEgiX-PYiRAjyluo0ZUIp6B3REMJ2V8IGXy9Y6M4r0sCZXePAR-0jF3b3hb7zNiG3yoscYgOTX0uvEmUwipfUIk4LcMst48tM0PLNo9GdvKrbW8zwaCgYKAbsSARASFQHWtWOmDJaqSIsPmOK66HZvxrsFbA0173'
    }
    response = client._http_request(
        'GET', f'admin/directory/v1/customer/{customer_id}/devices/mobile', headers=headers)
    credentials = service_account.Credentials.from_service_account_file(
        'Integrations/GoogleWorkspaceAdmin/delta-heading-367810-a433b2f4eaad.json', scopes=['https://www.googleapis.com/auth/admin.directory.device.mobile '])
    return_results('ok')


def test_module_test(client: Client) -> None:
    # Test functions here
    from google.oauth2 import service_account
    import google.auth.transport.requests
    credentials = service_account.Credentials.from_service_account_file(
        'Integrations/GoogleWorkspaceAdmin/delta-heading-367810-a433b2f4eaad.json', scopes=['https://www.googleapis.com/auth/admin.directory.device.mobile '])
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    customer_id = 'C02f0zfqw'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {credentials.token}'
    }
    response = client._http_request(
        'GET', f'admin/directory/v1/customer/{customer_id}/devices/mobile', headers=headers)
    return_results('ok')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    headers = {}
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        customer_id = params.get('customer_id')
        service_account_json = params.get('user_service_account_json')
        verify_certificate: bool = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        client: Client = Client(BASE_URL, verify_certificate, proxy, headers=headers, auth=None)
        test_module_test(client=client)
        return
        commands = {
            'googleworkspaceadmin-google-mobiledevice-action': google_mobiledevice_action_command,
            'googleworkspaceadmin-google-mobiledevice-list': google_mobiledevice_list_command,
            'googleworkspaceadmin-google-chromeosdevice-action': google_chromeosdevice_action_command,
        }
        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        print(str(e))
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
