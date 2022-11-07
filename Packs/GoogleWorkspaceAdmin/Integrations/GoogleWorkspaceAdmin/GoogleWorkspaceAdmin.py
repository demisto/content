from CommonServerPython import *
import demistomock as demisto

''' IMPORTS '''


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
    return_results('ok')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)
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
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    from GSuiteApiModule import *
    temp = GSuiteClient.strip_dict(demisto.args())
    main()
