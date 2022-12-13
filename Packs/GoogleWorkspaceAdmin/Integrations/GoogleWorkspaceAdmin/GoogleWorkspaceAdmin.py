from CommonServerPython import *
import demistomock as demisto


''' IMPORTS '''
from typing import Callable
from typing import NamedTuple
from google.oauth2 import service_account
import google.auth.transport.requests


''' CONSTANTS '''
OUTPUT_PREFIX = 'GoogleWorkspaceAdmin'
INTEGRATION_NAME = 'Google Workspace Admin'
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50

''' SCOPES '''
MOBILE_DEVICE_LIST_SCOPE = 'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly'
MOBILE_DEVICE_ACTION_SCOPE = 'https://www.googleapis.com/auth/admin.directory.device.mobile.action'

CHROMEOS_DEVICE_ACTION_SCOPE = 'https://www.googleapis.com/auth/admin.directory.device.chromeos'
CHROMEOS_DEVICE_LIST_SCOPE = 'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly'

''' ERROR CONSTANTS '''
INVALID_CUSTOMER_ID_ERROR = 'Please check the customer ID parameter.'
INVALID_RESOURCE_ID_ERROR = 'Please check the resource_id argument.'
UNAUTHORIZED_SERVICE_ACCOUNT_ERROR = 'Please check the authorizations of the configured service account.'
REQUEST_ADAPTER_ERROR = 'An error has occurred while requesting a request adapter.'
REFRESH_TOKEN_ERROR = 'Could not refresh token.'
LIMIT_ARG_INVALID_ERROR = 'The limit argument can\'t be negative or equal to zero.'
INVALID_PAGINATION_ARGS_SUPPLIED = ('In order to use pagination, please supply either the argument limit,'
                                    ' or the argument page_token, or the arguments page_token and page_size together.')
ACCOUNT_NOT_FOUND = 'Please check if the account supplied in the service account exists.'
INVALID_ORG_UNIT_PATH = 'Please insert a valid organization unit path (org_unit_path)'
EXCEEDED_MAX_PAGE_SIZE_ERROR = f'The maximum page size is {MAX_PAGE_SIZE}'
SERVICE_ACCOUNT_JSON_LOAD_ERROR = 'Please validate the structure of the service account\'s json data'
# The following dictionary is used to map error messages returned from the API that don't
# share enough information to meaningful error messages.
ERROR_MESSAGES_MAPPING = {
    'Bad Request': 'Please check the customer ID parameter.',
    'Internal error encountered.': 'Please check the resource_id argument.',
    'Not Authorized to access this resource/api': 'Please check the authorizations of the configured service account.',
    'Delinquent account.': 'Please check the resource_id argument.'
}


class DevicesCommandConfig(NamedTuple):
    table_headers: list[str]
    table_title: str
    response_devices_list_key: str
    cd_devices_list_key: str
    outputs_prefix: str


class PaginationResult(NamedTuple):
    data: list[dict]
    raw_response: list
    next_page_token: str = ''


MobileDevicesConfig = DevicesCommandConfig(table_headers=['Serial Number', 'User Names', 'Model Name', 'OS', 'Type', 'Status'],
                                           table_title=f'{INTEGRATION_NAME} - Mobile Devices List',
                                           response_devices_list_key='mobiledevices',
                                           cd_devices_list_key='MobileListObjects',
                                           outputs_prefix=f'{OUTPUT_PREFIX}.MobileDevices',
                                           )

ChromeOSDevicesConfig = DevicesCommandConfig(table_headers=['Serial Number', 'User Name', 'Model Name', 'OS', 'Status'],
                                             table_title=f'{INTEGRATION_NAME} - ChromeOS Devices List',
                                             response_devices_list_key='chromeosdevices',
                                             cd_devices_list_key='ChromeOSListObjects',
                                             outputs_prefix=f'{OUTPUT_PREFIX}.ChromeOSDevices',
                                             )


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, service_account_json: Dict[str, str]):
        self._headers = {'Content-Type': 'application/json'}
        self._service_account_json = service_account_json
        self._credentials = self._init_credentials()
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=self._headers)

    def _init_credentials(self) -> service_account.Credentials:
        """This function is in charge of initializing the service account credentials that
        will be used to retrieve OAuth tokens in order to use the API requests.

        Raises:
            DemistoException: If the content of the service account's json has invalid values.

        Returns:
            service_account.Credentials: The instance that will be used to access OAuth tokens and refresh them if they expire.
        """
        try:
            credentials = service_account.Credentials.from_service_account_info(
                self._service_account_json,
            )
            return credentials
        except ValueError:
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
            # We do requests on mobile devices and chrome os devices to also validate the authorizations.
            self.google_mobile_device_list_request()
            self.google_chromeos_device_list_request()
        except DemistoException as e:
            if(e.res is not None):
                error_res_to_json = e.res.json()
                error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
                if('Bad Request' in error_message):
                    raise DemistoException(INVALID_CUSTOMER_ID_ERROR)
                elif('Not Authorized to access this resource/api' in error_message):
                    raise DemistoException(UNAUTHORIZED_SERVICE_ACCOUNT_ERROR)
                else:
                    raise DemistoException(error_message)
            else:
                raise e

    def _get_oauth_token(self, scopes: Set[str]):
        """In charge or retrieving the OAuth token in order to make HTTP requests.
        OAuth tokens are correlated with scopes, so if a new HTTP request requires different scopes, a new token is required

        Args:
            scopes (Set[str]): A set that will hold the desired scopes in regard to the HTTP request.

        Returns:
            String: An OAuth token to be sent with the HTTP request.
        """

        #  Since OAuth tokens are correlated with scopes, that means we need to create a new credentials instance (that is
        # used to retrieve OAuth tokens) if the HTTP request desires different scopes than the one before.
        if(not self._credentials.scopes or scopes != set(self._credentials.scopes)):
            # If entered, that means either the scopes list was empty, or the previous scopes for the previous HTTP request
            # are different than the current ones.
            self._credentials = self._credentials.with_scopes(list(scopes))

        if(not self._credentials.valid):
            try:
                request = google.auth.transport.requests.Request()
                self._credentials.refresh(request)
                request.session.close()
            except google.auth.exceptions.TransportError:
                raise DemistoException(REQUEST_ADAPTER_ERROR)
            except google.auth.exceptions.RefreshError as e:
                if 'account not found' in str(e):
                    raise DemistoException(ACCOUNT_NOT_FOUND)
                raise DemistoException(str(e))

        if(not self._credentials.valid):
            raise DemistoException(REFRESH_TOKEN_ERROR)
        return self._credentials.token

    def google_mobile_device_action_request(self, customer_id: str, resource_id: str, action: str):
        json_body = {'action': action}
        scopes = {MOBILE_DEVICE_ACTION_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{customer_id}/devices/mobile/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_mobile_device_list_request(self, customer_id: str, query_params: dict = {}) -> dict:
        # TODO Don't forget to delete the following lines (these are for testing purposes)
        max_results = query_params.get('maxResults', 3)
        query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = {MOBILE_DEVICE_LIST_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{customer_id}/devices/mobile',
            params=query_params, headers=headers
        )
        return response

    def google_chromeos_device_action_request(self, customer_id: str, resource_id: str, action: str,
                                              deprovision_reason: str = ''):
        json_body = {'action': action}
        if action == 'deprovision':
            json_body['deprovisionReason'] = deprovision_reason

        scopes = {CHROMEOS_DEVICE_ACTION_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{customer_id}/devices/chromeos/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_chromeos_device_list_request(self, customer_id: str, query_params: dict = {}) -> dict:
        # TODO Don't forget to delete the following lines (these are for testing purposes)
        # max_results = query_params.get('maxResults', 3)
        # query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = {CHROMEOS_DEVICE_LIST_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{customer_id}/devices/chromeos',
            params=query_params, headers=headers
        )
        return response


def device_list_automatic_pagination(api_request: Callable, customer_id: str, query_params: dict,
                                     limit: int, response_devices_list_key: str) -> PaginationResult:
    """This function implements the automatic pagination mechanism for both commands: mobile-device-list, and chromos-device-list.
    Since the API does not support a `limit` argument, we have to do the automatic pagination manually. If the limit
    argument is smaller than or equal to the maximum page size allowed by the API, then we will only need one request call,
    else, we will make multiple requests by utilizing the `nextPageToken` argument supplied by the API.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        customer_id (str): The unique ID of the customer's Google Workspace Admin account.
        query_params (dict): The query parameters that will be sent with the API call.
        limit (int): The limit argument that will act as the maximum number of results to return from the API request.
        response_devices_list_key (str): The key that will point to the list of devices in the response body.

    Returns:
        PaginationResult: A PaginationResult instance that hold all the relevant data for creating a CommandResult.
    """
    results_limit = limit
    devices = []  # This will hold all aggregated mobile devices returned from the API requests
    responses = []  # This will hold all the responses from the API requests
    next_page_token = ''
    get_data_from_api = True  # This will decide if we should continue requesting from the API or that we should stop
    while get_data_from_api:
        query_params['maxResults'] = results_limit if results_limit <= MAX_PAGE_SIZE else MAX_PAGE_SIZE
        query_params['pageToken'] = next_page_token
        response = api_request(customer_id=customer_id, query_params=query_params)
        responses.append(response)
        response_mobile_devices = response.get(response_devices_list_key, [])
        next_page_token = response.get('nextPageToken', '')  # Get the token of the next page if needed

        devices.extend(response_mobile_devices)
        results_limit -= len(response_mobile_devices)
        if(results_limit <= 0 or not next_page_token):
            get_data_from_api = False
    return PaginationResult(data=devices, raw_response=responses)


def device_list_manual_pagination(api_request: Callable, customer_id: str, query_params: dict, page_token: str, page_size: int,
                                  response_devices_list_key: str) -> PaginationResult:
    """This function is in charge of retrieving the data of one page using the page_size and page_token arguments supported
    by the API.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        customer_id (str): The unique ID of the customer's Google Workspace Admin account.
        query_params (dict): The query parameters that will be sent with the API call.
        page_token (str): The token of the page from where to retrieve the devices.
        page_size (int): The size of the page, which cannot be bigger than the maximum page size (100).
        response_devices_list_key (str): The key that will point to the list of devices in the response body.

    Returns:
        PaginationResult: A PaginationResult instance that hold all the relevant data for creating a CommandResult.
    """
    query_params['maxResults'] = page_size
    query_params['pageToken'] = page_token
    response = api_request(customer_id=customer_id, query_params=query_params)
    devices = response.get(response_devices_list_key, [])
    return PaginationResult(data=devices, raw_response=[response], next_page_token=response.get('nextPageToken', ''))


def prepare_pagination_arguments(args: dict) -> dict:
    """ The function gets the arguments from the user and checks the content of the pagination arguments,
        and if everything is valid, it returns a dictionary that holds the pagination information.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that holds the pagination information.
    """
    if('page_token' in args or 'page_size' in args):
        if('limit' in args):
            raise DemistoException(INVALID_PAGINATION_ARGS_SUPPLIED)
        page_token = args.get('page_token', '')
        page_size = arg_to_number(args.get('page_size', None))
        page_size = page_size if page_size else DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise DemistoException(EXCEEDED_MAX_PAGE_SIZE_ERROR)
        return {'page_size': page_size, 'page_token': page_token}

    limit = arg_to_number(args.get('limit', None))
    limit = limit if (limit or limit == 0) else DEFAULT_LIMIT
    if(limit <= 0):
        raise DemistoException(message=LIMIT_ARG_INVALID_ERROR)
    return {'limit': limit}


def mobile_device_list_create_query_parameters(args: dict) -> dict:
    """This function takes in the arguments from the user and creates a dictionary that will hold
    the query arguments for the mobile-device-list request.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that will hold the query arguments of the request.
    """
    query_params = assign_params(projection=args.get('projection', 'full').lower(),
                                 query=args.get('query', ''),
                                 orderBy=args.get('order_by', 'status').lower(),
                                 sortOrder=args.get('sort_order', 'ascending').lower(),
                                 )
    return query_params


def devices_to_human_readable(devices_data: list[dict], keys: list, keys_mapping: dict[str, str]) -> List[dict]:
    human_readable: List[dict] = []
    for device in devices_data:
        human_readable_data = {}
        for key in keys:
            if key in keys_mapping:
                human_readable_data[keys_mapping.get(key)] = device.get(key)
            else:
                human_readable_data[pascalToSpace(key)] = device.get(key)
        human_readable.append(human_readable_data)

    return human_readable


def google_mobile_device_list_command(client: Client, **kwargs) -> List[CommandResults]:
    query_params = mobile_device_list_create_query_parameters(args=kwargs)
    pagination_args = prepare_pagination_arguments(args=kwargs)
    mutual_pagination_args = assign_params(
        api_request=client.google_mobile_device_list_request,
        customer_id=kwargs.get('customer_id', ''),
        response_devices_list_key=MobileDevicesConfig.response_devices_list_key,
        query_params=query_params,
    )
    try:
        markdown = ''
        if 'limit' in pagination_args:
            pagination_result = device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)
        else:
            pagination_result = device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
        if not pagination_result.data:
            markdown = 'No results were found with the respected arguments'

        else:
            human_readable = devices_to_human_readable(
                devices_data=pagination_result.data,
                keys=['serialNumber', 'name', 'model', 'os', 'type', 'status', 'resourceId'],
                keys_mapping={'name': 'User Names', 'model': 'Model Name', 'os': 'OS'})
            num_of_devices = len(pagination_result.data)
            markdown = tableToMarkdown(MobileDevicesConfig.table_title, human_readable,
                                       metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
        command_results = []
        command_results.append(
            CommandResults(outputs_prefix=f'{MobileDevicesConfig.outputs_prefix}.{MobileDevicesConfig.cd_devices_list_key}',
                           readable_output=markdown,
                           outputs_key_field='resourceId',
                           outputs=pagination_result.data,
                           raw_response=pagination_result.raw_response,
                           ))
        if(pagination_result.next_page_token):
            command_results.append(
                CommandResults(
                    outputs_prefix=f'{MobileDevicesConfig.outputs_prefix}.NextPageToken',
                    readable_output=f'### Next Page Token: {pagination_result.next_page_token}',
                    outputs_key_field='',
                    outputs=pagination_result.next_page_token,
                )
            )
        return command_results

    except DemistoException as e:
        error_to_return = str(e)
        demisto.debug(f'An error has occurred when running the command:\n{error_to_return}')
        if(e.res is not None):
            error_res_to_json = e.res.json()
            error_to_return = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
        raise DemistoException(error_to_return)


def chromeos_device_list_create_query_parameters(args: dict) -> dict:
    """This function takes in the arguments from the user and creates a dictionary that will hold
    the query arguments for the chromeos-device-list request.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that will hold the query arguments of the request.
    """
    include_child_org_units = argToBoolean(args.get('include_child_org_units', False))
    query_params = assign_params(projection=args.get('projection', 'full').lower(),
                                 query=args.get('query', None),
                                 orderBy=args.get('order_by', '').lower(),
                                 sortOrder=args.get('sort_order', '').lower(),
                                 orgUnitPath=args.get('org_unit_path', ''),
                                 includeChildOrgunits=str(include_child_org_units)
                                 )
    return query_params


def google_chromeos_device_list_command(client: Client, **kwargs) -> list[CommandResults]:
    query_params = chromeos_device_list_create_query_parameters(args=kwargs)
    pagination_args = prepare_pagination_arguments(args=kwargs)
    mutual_pagination_args = assign_params(
        api_request=client.google_chromeos_device_list_request,
        customer_id=kwargs.get('customer_id', ''),
        response_devices_list_key=ChromeOSDevicesConfig.response_devices_list_key,
        query_params=query_params,
    )
    try:
        markdown = ''
        if 'limit' in pagination_args:
            pagination_result = device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)
        else:
            pagination_result = device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
        if not pagination_result.data:
            markdown = 'No results were found with the respected arguments'

        else:
            human_readable = devices_to_human_readable(
                devices_data=pagination_result.data,
                keys=['serialNumber', 'annotatedUser', 'model', 'osVersion', 'status', 'deviceId'],
                keys_mapping={'annotatedUser': 'User Name', 'osVersion': 'OS'})
            num_of_devices = len(pagination_result.data)
            markdown = tableToMarkdown(ChromeOSDevicesConfig.table_title, human_readable,
                                       metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
        command_results = []
        command_results.append(
            CommandResults(outputs_prefix=f'{ChromeOSDevicesConfig.outputs_prefix}.{ChromeOSDevicesConfig.cd_devices_list_key}',
                           readable_output=markdown,
                           outputs_key_field='deviceId',
                           outputs=pagination_result.data,
                           raw_response=pagination_result.raw_response,
                           ))
        if(pagination_result.next_page_token):
            command_results.append(
                CommandResults(
                    outputs_prefix=f'{ChromeOSDevicesConfig.outputs_prefix}.NextPageToken',
                    readable_output=f'### Next Page Token: {pagination_result.next_page_token}',
                    outputs_key_field='',
                    outputs=pagination_result.next_page_token,
                )
            )
        return command_results
    except DemistoException as e:
        error_to_return = str(e)
        demisto.debug(f'An error has occurred when running the command:\n{error_to_return}')
        if(e.res is not None):
            error_res_to_json = e.res.json()
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            if 'INVALID_OU_ID' in error_message:
                error_to_return = INVALID_ORG_UNIT_PATH
            else:
                error_to_return = error_message
        raise DemistoException(error_to_return)


def google_mobile_device_action_command(client: Client, customer_id: str, resource_id: str, action: str) -> CommandResults:
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can map the
        # error message to a more human readable message
        client.google_mobile_device_action_request(customer_id=customer_id, resource_id=resource_id, action=action)

    except DemistoException as e:
        error_to_return = str(e)
        demisto.debug(f'An error has occurred when running the command:\n{error_to_return}')
        if(e.res is not None):
            error_res_to_json = e.res.json()
            # We want to print the error message to the UI
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            if('Internal error encountered' in error_message or 'Bad Request' in error_message):
                error_to_return = INVALID_RESOURCE_ID_ERROR
            else:
                error_to_return = error_message
        raise DemistoException(error_to_return)

    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.MobileAction',
        outputs_key_field='ResourceId',
        readable_output='Success',
        outputs={'Action': action, 'ResourceId': resource_id},
    )
    return command_results


def google_chromeos_device_action_command(client: Client, customer_id: str, resource_id: str, action: str,
                                          deprovision_reason: str = '') -> CommandResults:
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can map the
        # error message to a more human readable message
        client.google_chromeos_device_action_request(customer_id=customer_id, resource_id=resource_id, action=action,
                                                     deprovision_reason=deprovision_reason)

    except DemistoException as e:
        error_to_return = str(e)
        demisto.debug(f'An error has occurred when running the command:\n{error_to_return}')
        if(e.res is not None):
            error_res_to_json = e.res.json()
            # We want to print the error message to the UI
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            if('Delinquent account' in error_message):
                error_to_return = INVALID_RESOURCE_ID_ERROR
            else:
                error_to_return = error_message
        raise DemistoException(error_to_return)

    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.ChromeOSAction',
        outputs_key_field='ResourceId',
        readable_output='Success',
        outputs={'Action': action, 'ResourceId': resource_id},
    )
    return command_results


def test_module(client: Client) -> str:
    # Test functions here
    client.test_client_connection()
    return 'ok'


def load_service_account_json(service_account_json: str):
    try:
        return json.loads(service_account_json, strict=False)
    except json.decoder.JSONDecodeError:
        raise DemistoException(SERVICE_ACCOUNT_JSON_LOAD_ERROR)


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
    customer_id = params.get('customer_id')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    base_url = params.get('base_url', '')
    demisto.debug(f'Command being called is {command}')
    try:
        service_account_json = load_service_account_json(params.get('user_service_account_json'))
        client: Client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy,
                                service_account_json=service_account_json)

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
