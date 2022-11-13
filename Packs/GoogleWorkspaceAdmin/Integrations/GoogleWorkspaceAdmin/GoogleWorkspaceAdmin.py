from CommonServerPython import *
import demistomock as demisto

''' IMPORTS '''
from typing import Callable
import requests
from google.oauth2 import service_account
import google.auth.transport.requests
from enum import Enum

''' CONSTANTS '''
BASE_URL = 'https://admin.googleapis.com/'
OUTPUT_PREFIX = 'Google'


class Devices(Enum):
    CHROMEOS_DEVICE = 0
    MOBILE_DEVICE = 1


requests.packages.urllib3.disable_warnings()

""" OAuth tokens are correlated with scopes, so if a new HTTP request requires different scopes, a new token is required """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, customer_id: str, service_account_json: Dict[str, str],
                 auth: tuple = None):
        self._headers = {'Content-Type': 'application/json'}
        self._customer_id = customer_id
        self._service_account_json = service_account_json
        self._credentials = self._init_credentials()
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=self._headers, auth=auth)

    def _init_credentials(self) -> service_account.Credentials:
        try:
            credentials = service_account.Credentials.from_service_account_info(
                self._service_account_json,
            )
            return credentials
        except Exception:
            raise DemistoException('Please check the service account\'s json content')

    def http_request(self, method: str, url_suffix: str, headers: Dict[str, str], params: dict = None,
                     ok_codes: tuple = (200, 204),
                     resp_type: str = 'json', json_data: dict = None) -> Any:
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  resp_type=resp_type,
                                  ok_codes=ok_codes,
                                  json_data=json_data,
                                  headers=headers,
                                  params=params)

    def test_client_connection(self):
        try:
            token = self._get_oauth_token(scopes=['https://www.googleapis.com/auth/admin.directory.device.mobile.readonly',
                                                  ])
            headers = self._headers | {'Authorization': f'Bearer {token}'}
            _ = self._http_request('GET', f'admin/directory/v1/customer/{self._customer_id}/devices/mobile',
                                          headers=headers)
            return 'ok'
        except DemistoException as e:
            if 'Forbidden' in str(e) or 'Not Authorized' in str(e):
                raise DemistoException('Please make sure the service account has the relevant authorizations')
            else:
                raise e
        except Exception as e:
            raise e

    def _get_oauth_token(self, scopes: List[str]):
        """ In charge or retrieving the OAuth token in order to make HTTP requests """

        #  It is enough to check the scopes' list using == operator since each HTTP request requires at most
        #  one level of scope
        if(scopes != self._credentials.scopes):
            self._credentials = self._credentials.with_scopes(scopes)

        if(not self._credentials.valid):
            try:
                request = google.auth.transport.requests.Request()
            except google.auth.exceptions.TransportError:
                raise DemistoException('An error has occurred while requesting a request adapter')

            self._credentials.refresh(request)
            if(not self._credentials.valid):
                request.session.close()
                raise DemistoException('Could not refresh token')
            request.session.close()
        return self._credentials.token

    def google_mobile_device_action_request(self, resource_id: str, action: str):
        json_body = {'action': action}
        scopes = ['https://www.googleapis.com/auth/admin.directory.device.mobile.action']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/mobile/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_mobile_device_list_request(self, projection: str | None = None, query: str | None = None,
                                          order_by: str | None = None, sort_order: str | None = None,
                                          page_token: str | None = None, max_results: int | None = None) -> dict:
        params = assign_params(projection=projection, query=query, orderBy=order_by,
                               sortOrder=sort_order, pageToken=page_token, maxResults=max_results)
        scopes = ['https://www.googleapis.com/auth/admin.directory.device.mobile.readonly']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/mobile',
            params=params, headers=headers
        )
        return response

    def google_chromeos_device_action_request(self, resource_id: str, action: str, deprovision_reason: str = ''):
        json_body = {'action': action}
        if not deprovision_reason:
            json_body['deprovisionReason'] = deprovision_reason
        scopes = ['https://www.googleapis.com/auth/admin.directory.device.chromeos']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_chromeos_device_list_request(self, projection: str | None = None, query: str | None = None,
                                            order_by: str | None = None, sort_order: str | None = None,
                                            org_unit_path: str | None = None, page_token: str | None = None,
                                            max_results: int | None = None) -> dict:
        params = assign_params(projection=projection, query=query, orderBy=order_by, orgUnitPath=org_unit_path,
                               sortOrder=sort_order, pageToken=page_token, maxResults=max_results)
        scopes = ['https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos',
            params=params, headers=headers
        )
        return response


def google_mobile_device_action_command(client: Client, resource_id: str, action: str) -> CommandResults:
    readable_output = 'Success'
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can mark this
        # request as failure
        client.google_mobile_device_action_request(resource_id, action)
    except DemistoException as e:
        demisto.debug(str(e))
        if 'Error in API call' in str(e):
            readable_output = 'Failure'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.MobileDeviceAction',
        readable_output=readable_output,
        outputs={'Response': readable_output},
    )
    return command_results


def chromeos_device_list_to_context_data(response: dict) -> dict:
    # TODO Should I add the nextPageToken?
    return {'chromeosListObjects': response.get('chromeosdevices')}


def mobile_device_list_to_context_data(response: dict) -> dict:
    # TODO Should I add the nextPageToken?
    return {'mobileListObjects': response.get('mobiledevices')}


def device_list_to_context_data(response: dict, device_list_type: Devices) -> dict:
    context_data = {'resourceKind': response.get('kind'), 'ETag': response.get('etag')}
    if device_list_type == Devices.CHROMEOS_DEVICE:
        context_data |= chromeos_device_list_to_context_data(response=response)

    elif device_list_type == Devices.MOBILE_DEVICE:
        context_data |= mobile_device_list_to_context_data(response=response)

    return context_data


def google_mobile_device_list_command(client: Client, projection: str | None = None, query: str | None = None,
                                      order_by: str | None = None, sort_order: str | None = None,
                                      limit: str | None = None, page_token: str | None = None) -> CommandResults:
    response = client.google_mobile_device_list_request(projection=projection, query=query, order_by=order_by,
                                                        sort_order=sort_order, page_token=page_token,
                                                        max_results=arg_to_number(limit))
    context_data = device_list_to_context_data(response=response, device_list_type=Devices.MOBILE_DEVICE)
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileEvent',
        readable_output='Data has been returned',
        outputs=context_data,
        raw_response=response,
    )
    return command_results


def google_chromeos_device_action_command(client: Client, resource_id: str, action: str,
                                          deprovision_reason: str) -> CommandResults:
    readable_output = 'Success'
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can mark this
        # request as failure
        client.google_chromeos_device_action_request(
            resource_id=resource_id, action=action, deprovision_reason=deprovision_reason)
    except DemistoException as e:
        demisto.debug(str(e))
        if 'Error in API call' in str(e):
            readable_output = 'Failure'
        else:
            raise e
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.ChromeOSAction',
        readable_output=readable_output,
        outputs={'Response': readable_output},
    )
    return command_results


def google_chromeos_device_list_command(client: Client, projection: str | None = None, query: str | None = None,
                                        order_by: str | None = None, sort_order: str | None = None,
                                        org_unit_path: str | None = None, limit: str | None = None,
                                        page_token: str | None = None):
    response = client.google_chromeos_device_list_request(projection=projection, query=query, order_by=order_by,
                                                          sort_order=sort_order, page_token=page_token,
                                                          org_unit_path=org_unit_path, max_results=arg_to_number(limit))
    context_data = device_list_to_context_data(response=response, device_list_type=Devices.CHROMEOS_DEVICE)

    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.chromeosEvent',
        readable_output='Data has been returned',
        outputs=context_data,
        raw_response=response,
    )
    return command_results


def test_module(client: Client) -> str:
    # Test functions here
    return client.test_client_connection()


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    commands: Dict[str, Callable] = {
        'google-mobiledevice-action': google_mobile_device_action_command,
        'google-mobiledevice-list': google_mobile_device_list_command,
        'google-chromeosdevice-action': google_chromeos_device_action_command,
        'google_chromeosdevice_list': google_chromeos_device_list_command
    }
    demisto.debug(f'Command being called is {command}')
    try:
        customer_id = params.get('customer_id')
        service_account_json = json.loads(params.get('user_service_account_json'), strict=False)
        verify_certificate: bool = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        client: Client = Client(base_url=BASE_URL, verify=verify_certificate, proxy=proxy,
                                customer_id=customer_id, service_account_json=service_account_json, auth=None)

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        print(str(e))
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
