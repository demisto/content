from CommonServerPython import *
import demistomock as demisto


''' IMPORTS '''
from typing import Callable
import requests
from google.oauth2 import service_account
import google.auth.transport.requests


''' CONSTANTS '''
BASE_URL = 'https://admin.googleapis.com/'
OUTPUT_PREFIX = 'Google'
INTEGRATION_NAME = 'Google Workspace Admin'

CHROMEOS_DEVICE_ACTION = ['deprovision', 'disable', 'reenable', 'pre_provisioned_disable', 'pre_provisioned_reenable']
CHROMEOS_DEVICE_DEPROVISION_REASON = ['different_model_replacement', 'retiring_device', 'same_model_replacement',
                                      'upgrade_transfer']
CHROMEOS_DEVICE_ORDER_BY = ['annotated_location', 'annotated_user', 'last_sync', 'notes', 'serial_number', 'status']
CHROMEOS_DEVICE_PROJECTION = ['basic', 'full']
CHROMEOS_DEVICE_SORT_ORDER = ['ascending', 'descending']

MOBILE_DEVICE_ACTION = ['admin_remote_wipe', 'admin_account_wipe', 'approve',
                        'block', 'cancel_remote_wipe_then_activate', 'cancel_remote_wipe_then_block']
MOBILE_DEVICE_ORDER_BY = ['device_id', 'email', 'last_sync', 'model', 'name', 'os', 'status', 'type']
MOBILE_DEVICE_PROJECTION = ['basic', 'full']
MOBILE_DEVICE_SORT_ORDER = ['ascending', 'descending']

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50


class ActionCommandIncorrectArguments(Exception):
    """
    This class is in charge of catching errors that occur when the user supplies incorrect arguments
    to the commands that affect the device by supplying an action.
    """
    pass


requests.packages.urllib3.disable_warnings()

""" OAuth tokens are correlated with scopes, so if a new HTTP request requires different scopes, a new token is required """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, customer_id: str, service_account_json: Dict[str, str]):
        self._headers = {'Content-Type': 'application/json'}
        self._customer_id = customer_id
        self._service_account_json = service_account_json
        self._credentials = self._init_credentials()
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=self._headers)

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
            request.session.close()

        if(not self._credentials.valid):
            raise DemistoException('Could not refresh token')
        return self._credentials.token

    def google_mobile_device_action_request(self, resource_id: str, action: str):
        if action not in MOBILE_DEVICE_ACTION:
            raise ActionCommandIncorrectArguments(
                f'Unsupported argument value {action if action else "of empty string"} for action.')
        json_body = {'action': action}
        scopes = ['https://www.googleapis.com/auth/admin.directory.device.mobile.action']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/mobile/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_mobile_device_list_request(self, query_params: dict) -> dict:
        # TODO Don't forget to delete the following lines (these are for testing purposes)
        max_results = query_params['maxResults']
        query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = ['https://www.googleapis.com/auth/admin.directory.device.mobile.readonly']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/mobile',
            params=query_params, headers=headers
        )
        return response

    def google_chromeos_device_action_request(self, resource_id: str, action: str, deprovision_reason: str = ''):
        json_body = {'action': action}
        if action not in CHROMEOS_DEVICE_ACTION:
            raise ActionCommandIncorrectArguments(
                f'Unsupported argument value {action if action else "of empty string"} for action.')
        elif action == 'deprovision':
            if deprovision_reason not in CHROMEOS_DEVICE_DEPROVISION_REASON:
                raise ActionCommandIncorrectArguments(
                    (f'Unsupported argument value'
                     f' {deprovision_reason if deprovision_reason else "of empty string"} for deprovision_reason.'))
            json_body['deprovisionReason'] = deprovision_reason

        scopes = ['https://www.googleapis.com/auth/admin.directory.device.chromeos']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_chromeos_device_list_request(self, query_params: dict) -> dict:
        # TODO Don't forget to delete the following lines (these are for testing purposes)
        max_results = query_params['maxResults']
        query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = ['https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos',
            params=query_params, headers=headers
        )
        return response


# def trim_extra_double_quotes_from_string(value: str) -> str:
#     value_length = len(value)
#     first_element = value[0]
#     last_element = value[value_length - 1]
#     if((first_element == '"' or first_element == "'") and (last_element == '"' or last_element == "'")):
#         return value[1:value_length - 1]
#     return value


def device_list_manual_pagination(api_request: Callable, to_human_readable: Callable, query_params: dict, page: Optional[int],
                                  page_size: int, table_headers: List[str], table_title: str,
                                  response_devices_list_key: str, cd_devices_list_key: str) -> CommandResults:
    """_summary_

    Args:
        api_request (Callable): _description_
        to_human_readable (Callable): _description_
        query_params (dict): _description_
        page (int): _description_
        page_size (int): _description_
        table_headers (List[str]): _description_
        table_title (str): _description_
        response_devices_list_key (str): _description_
        cd_devices_list_key (str): _description_

    Returns:
        CommandResults: _description_
    """
    """
    Executes the command mobile-device-list using manual pagination, and returns a CommandResult
    that holds the data to return to the user.
    """
    query_params['maxResults'] = page_size
    relevant_response = {}  # This will hold the relevant response that holds the page that was requested
    context_data = {}  # This will hold the context data to return to the user
    next_page_token: str | None = None
    get_data_from_api = True  # This will decide if we should continue requesting from the API or that we should stop
    current_page_number = 0
    page_found = True  # This will tell us if the required page was found or not
    while get_data_from_api:
        query_params['pageToken'] = next_page_token
        response = api_request(query_params=query_params)
        next_page_token = response.get('nextPageToken')
        current_page_number += 1
        if(current_page_number == page):
            get_data_from_api = False
            context_data['resourceKind'] = response.get('kind')
            # context_data['ETag'] = trim_extra_double_quotes_from_string(value=response.get('etag'))
            context_data[cd_devices_list_key] = response.get(response_devices_list_key, [])
            relevant_response = response
        elif(not next_page_token):
            get_data_from_api = False
            page_found = False

    markdown = ''
    if not page_found:
        markdown = (f'No results were found. The maximum number of pages is {current_page_number}'
                    f' for page size of {page_size}')
    else:
        human_readable = to_human_readable(context_data=context_data)
        markdown = tableToMarkdown(table_title, human_readable, headers=table_headers)

    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileEvent',
        readable_output=markdown,
        outputs=context_data,
        raw_response=relevant_response,
    )
    return command_results


def device_list_automatic_pagination(api_request: Callable, to_human_readable: Callable, query_params: dict,
                                     limit: int, table_headers: List[str], table_title: str,
                                     response_devices_list_key: str, cd_devices_list_key) -> CommandResults:
    # TODO add documentation
    results_limit = limit
    context_data = {}  # This will hold the context data to return to the user
    mobile_devices = []  # This will hold all aggregated mobile devices returned from the API requests
    responses = []  # This will hold all the responses from the API requests
    next_page_token: str | None = None
    get_data_from_api = True  # This will decide if we should continue requesting from the API or that we should stop
    while get_data_from_api:
        query_params['maxResults'] = results_limit
        query_params['pageToken'] = next_page_token
        response = api_request(query_params=query_params)
        responses.append(response)
        response_mobile_devices = response.get(response_devices_list_key, [])
        next_page_token = response.get('nextPageToken')

        mobile_devices.extend(response_mobile_devices)
        results_limit -= len(response_mobile_devices)
        if(results_limit <= 0 or not next_page_token):
            context_data['resourceKind'] = response.get('kind')
            # context_data['ETag'] = trim_extra_double_quotes_from_string(value=response.get('etag'))
            context_data[cd_devices_list_key] = mobile_devices
            get_data_from_api = False
    human_readable = to_human_readable(context_data=context_data)
    markdown = tableToMarkdown(table_title, human_readable, headers=table_headers,
                               metadata=f'{len(context_data[cd_devices_list_key])} results were found')
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileEvent',
        readable_output=markdown,
        outputs=context_data,
        raw_response=responses,
    )
    return command_results


def prepare_pagination_arguments(args: dict) -> dict:
    """ The function gets the arguments from the user and checks the content of the pagination arguments,
        and if everything is valid, it returns a dictionary that holds the pagination information.

    Args:
        args (dict): The arguments from the user

    Returns:
        _type_: A dictionary that holds the pagination information.
    """
    if('page' in args or 'page_size' in args):
        if('limit' in args):
            raise DemistoException(('In order to use pagination, please supply either the argument limit,'
                                    ' or the argument page, or the arguments page and page_size together.'))
        page = arg_to_number(args.get('page', None))
        if not page:
            raise DemistoException(message='Please insert a page number')
        page_size = arg_to_number(args.get('page_size', None))
        page_size = page_size if page_size else DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise DemistoException(f'The maximum page size is {MAX_PAGE_SIZE}')
        return {'page_size': page_size, 'page': page}

    limit = arg_to_number(args.get('limit', None))
    limit = limit if limit else DEFAULT_LIMIT
    return {'limit': limit}


def mobile_device_list_create_query_parameters(args: dict) -> dict:
    projection = args.get('projection', '').lower()
    if(projection and projection not in MOBILE_DEVICE_PROJECTION):
        raise DemistoException(f'Unsupported argument value {projection if projection else "of empty string"} for projection.')

    order_by = args.get('order_by', '').lower()
    if(order_by and order_by not in MOBILE_DEVICE_ORDER_BY):
        raise DemistoException(f'Unsupported argument value {order_by if order_by else "of empty string"} for order_by.')

    sort_order = args.get('sort_order', '').lower()
    if(sort_order and sort_order not in MOBILE_DEVICE_SORT_ORDER):
        raise DemistoException(f'Unsupported argument value {sort_order if sort_order else "of empty string"} for sort_order.')

    if(sort_order and not order_by):
        raise DemistoException('sort_order argument must be used with the order_by parameter.')
    query_params = assign_params(projection=projection,
                                 query=args.get('query', ''),
                                 orderBy=order_by,
                                 sortOrder=sort_order,
                                 )
    return query_params


def mobile_device_list_to_human_readable(context_data: dict) -> List[dict]:
    human_readable: List[dict] = []
    for mobile_device in context_data.get('mobileListObjects', []):
        human_readable.append({'Serial Number': mobile_device.get('deviceId'),
                               'User Names': mobile_device.get('name'),
                               'Model Name': mobile_device.get('model'),
                               'OS': mobile_device.get('os'),
                               'Type': mobile_device.get('type'),
                               'Status': mobile_device.get('status')
                               })

    return human_readable


def google_mobile_device_list_command(client: Client, **kwargs) -> CommandResults:
    query_params = mobile_device_list_create_query_parameters(kwargs)
    table_headers = ['Serial Number', 'User Names', 'Model Name', 'OS', 'Type', 'Status']
    table_title = f'{INTEGRATION_NAME} - Mobile Devices List'
    response_devices_list_key = 'mobiledevices'
    cd_devices_list_key = 'mobileListObjects'
    pagination_args = prepare_pagination_arguments(args=kwargs)
    if 'limit' in pagination_args:
        return device_list_automatic_pagination(api_request=client.google_mobile_device_list_request,
                                                to_human_readable=mobile_device_list_to_human_readable,
                                                table_headers=table_headers,
                                                table_title=table_title,
                                                response_devices_list_key=response_devices_list_key,
                                                cd_devices_list_key=cd_devices_list_key,
                                                query_params=query_params, **pagination_args)

    return device_list_manual_pagination(api_request=client.google_mobile_device_list_request,
                                         to_human_readable=mobile_device_list_to_human_readable,
                                         table_headers=table_headers,
                                         table_title=table_title,
                                         response_devices_list_key=response_devices_list_key,
                                         cd_devices_list_key=cd_devices_list_key,
                                         query_params=query_params, **pagination_args)


def chromeos_device_list_create_query_parameters(args: dict) -> dict:
    projection = args.get('projection', '').lower()
    if(projection and projection not in CHROMEOS_DEVICE_PROJECTION):
        raise DemistoException(f'Unsupported argument value {projection if projection else "of empty string"} for projection.')

    order_by = args.get('order_by', '').lower()
    if(order_by and order_by not in CHROMEOS_DEVICE_ORDER_BY):
        raise DemistoException(f'Unsupported argument value {order_by if order_by else "of empty string"} for order_by.')

    sort_order = args.get('sort_order', '').lower()
    if(sort_order and sort_order not in CHROMEOS_DEVICE_SORT_ORDER):
        raise DemistoException(f'Unsupported argument value {sort_order if sort_order else "of empty string"} for sort_order.')

    if(sort_order and not order_by):
        raise DemistoException('sort_order argument must be used with the order_by parameter.')

    include_child_org_units = argToBoolean(args.get('include_child_org_units', False))
    org_unit_path = args.get('org_unit_path', '')
    if(include_child_org_units and not org_unit_path):
        raise DemistoException('If include_child_org_units is set to true, org_unit_path must be provided')

    query_params = assign_params(projection=projection,
                                 query=args.get('query', None),
                                 orderBy=order_by,
                                 sortOrder=sort_order,
                                 orgUnitPath=org_unit_path,
                                 includeChildOrgunits=str(include_child_org_units)
                                 )
    return query_params


def chromeos_device_list_to_human_readable(context_data: dict) -> List[dict]:
    human_readable: List[dict] = []
    for mobile_device in context_data.get('chromeosListObjects', []):
        human_readable.append({'Serial Number': mobile_device.get('serialNumber'),
                               'User Name': mobile_device.get('annotatedUser'),
                               'Model': mobile_device.get('model'),
                               'OS': mobile_device.get('osVersion'),
                               'Status': mobile_device.get('status')
                               })

    return human_readable


def google_chromeos_device_list_command(client: Client, **kwargs) -> CommandResults:
    query_params = chromeos_device_list_create_query_parameters(args=kwargs)
    table_headers = ['Serial Number', 'User Name', 'Model Name', 'OS', 'Status']
    table_title = f'{INTEGRATION_NAME} - ChromeOs Devices List'
    response_devices_list_key = 'chromeosdevices'
    cd_devices_list_key = 'chromeosListObjects'
    pagination_args = prepare_pagination_arguments(args=kwargs)
    if 'limit' in pagination_args:
        return device_list_automatic_pagination(api_request=client.google_chromeos_device_list_request,
                                                to_human_readable=chromeos_device_list_to_human_readable,
                                                table_headers=table_headers,
                                                table_title=table_title,
                                                response_devices_list_key=response_devices_list_key,
                                                cd_devices_list_key=cd_devices_list_key,
                                                query_params=query_params, **pagination_args)
    return device_list_manual_pagination(api_request=client.google_chromeos_device_list_request,
                                         to_human_readable=chromeos_device_list_to_human_readable,
                                         table_headers=table_headers,
                                         table_title=table_title,
                                         response_devices_list_key=response_devices_list_key,
                                         cd_devices_list_key=cd_devices_list_key,
                                         query_params=query_params, **pagination_args)


def google_mobile_device_action_command(client: Client, resource_id: str, action: str) -> CommandResults:
    readable_output = 'Success'
    failure_reason = {}
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can mark this
        # request as failure
        client.google_mobile_device_action_request(resource_id, action)
    except ActionCommandIncorrectArguments as e:
        readable_output = 'Failure'
        failure_reason['Reason'] = str(e)
    except DemistoException as e:
        demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        readable_output = 'Failure'
        # TODO Should I add the reason as str(e)?
        # raise e
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileAction',
        readable_output=readable_output,
        outputs=failure_reason | {'Response': readable_output},
    )
    return command_results


def google_chromeos_device_action_command(client: Client, resource_id: str, action: str,
                                          deprovision_reason: str = '') -> CommandResults:
    readable_output = 'Success'
    failure_reason = {}
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can mark this
        # request as failure
        client.google_chromeos_device_action_request(resource_id, action, deprovision_reason=deprovision_reason)
    except ActionCommandIncorrectArguments as e:
        readable_output = 'Failure'
        failure_reason['Reason'] = str(e)
    except DemistoException as e:
        demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        readable_output = 'Failure'
        # TODO Should I add the reason as str(e)?
        # raise e
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.chromeOSAction',
        readable_output=readable_output,
        outputs=failure_reason | {'Response': readable_output},
    )
    return command_results


def test_module(client: Client) -> str:
    # Test functions here
    return client.test_client_connection()


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    commands: Dict[str, Callable] = {
        'google-mobiledevice-action': google_mobile_device_action_command,
        'google-mobiledevice-list': google_mobile_device_list_command,
        'google-chromeosdevice-action': google_chromeos_device_action_command,
        'google-chromeosdevice-list': google_chromeos_device_list_command
    }
    demisto.debug(f'Command being called is {command}')
    try:
        customer_id = params.get('customer_id')
        service_account_json = json.loads(params.get('user_service_account_json'), strict=False)
        verify_certificate: bool = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        client: Client = Client(base_url=BASE_URL, verify=verify_certificate, proxy=proxy,
                                customer_id=customer_id, service_account_json=service_account_json)

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
