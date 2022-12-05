from CommonServerPython import *
import demistomock as demisto


''' IMPORTS '''
from typing import Callable
from typing import NamedTuple
from google.oauth2 import service_account
import google.auth.transport.requests


''' CONSTANTS '''
OUTPUT_PREFIX = 'Google'
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
PAGE_NUMBER_INVALID_ERROR = 'Please insert a valid page number.'
LIMIT_ARG_INVALID_ERROR = 'Please insert a valid limit argument.'
INVALID_PAGINATION_ARGS_SUPPLIED = ('In order to use pagination, please supply either the argument limit,'
                                    ' or the argument page, or the arguments page and page_size together.')
ACCOUNT_NOT_FOUND = 'Please check if the account supplied in the service account exists.'
INVALID_ORG_UNIT_PATH = 'Please insert a valid organization unit path (org_unit_path)'
EXCEEDED_MAX_PAGE_SIZE_ERROR = f'The maximum page size is {MAX_PAGE_SIZE}'
DEPROVISION_REASON_EMPTY_ERROR = 'Deprovision reason cannot be empty'
SERVICE_ACCOUNT_JSON_LOAD_ERROR = 'Please validate the structure of the service account\'s json data'
# The following dictionary is used to map error messages returned from the API that don't
# share enough information to meaningful error messages.
ERROR_MESSAGES_MAPPING = {
    'Bad Request': 'Please check the customer ID parameter.',
    'Internal error encountered.': 'Please check the resource_id argument.',
    'Not Authorized to access this resource/api': 'Please check the authorizations of the configured service account.',
    'Delinquent account.': 'Please check the resource_id argument.'
}


class DeviceListConfig(NamedTuple):
    table_headers: list[str]
    table_title: str
    response_devices_list_key: str
    cd_devices_list_key: str
    outputs_prefix: str


class PaginationResult(NamedTuple):
    data: dict
    raw_response: list
    last_page_number: int = 0


MobileDeviceListConfig = DeviceListConfig(table_headers=['Serial Number', 'User Names', 'Model Name', 'OS', 'Type', 'Status'],
                                          table_title=f'{INTEGRATION_NAME} - Mobile Devices List',
                                          response_devices_list_key='mobiledevices',
                                          cd_devices_list_key='mobileListObjects',
                                          outputs_prefix=f'{OUTPUT_PREFIX}.mobileEvent',
                                          )

ChromeOSDeviceListConfig = DeviceListConfig(table_headers=['Serial Number', 'User Name', 'Model Name', 'OS', 'Status'],
                                            table_title=f'{INTEGRATION_NAME} - ChromeOs Devices List',
                                            response_devices_list_key='chromeosdevices',
                                            cd_devices_list_key='chromeosListObjects',
                                            outputs_prefix=f'{OUTPUT_PREFIX}.chromeosEvent',
                                            )


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, customer_id: str, service_account_json: Dict[str, str]):
        self._headers = {'Content-Type': 'application/json'}
        self._customer_id = customer_id
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

    def google_mobile_device_action_request(self, resource_id: str, action: str):
        json_body = {'action': action}
        scopes = {MOBILE_DEVICE_ACTION_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/mobile/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_mobile_device_list_request(self, query_params: dict = {}) -> dict:
        # TODO Don't forget to delete the following lines (these are for testing purposes)
        # max_results = query_params['maxResults']
        # query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = {MOBILE_DEVICE_LIST_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/mobile',
            params=query_params, headers=headers
        )
        return response

    def google_chromeos_device_action_request(self, resource_id: str, action: str, deprovision_reason: str = ''):
        json_body = {'action': action}
        if action == 'deprovision':
            if(not deprovision_reason):
                raise DemistoException(DEPROVISION_REASON_EMPTY_ERROR)
            json_body['deprovisionReason'] = deprovision_reason

        scopes = {CHROMEOS_DEVICE_ACTION_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='POST', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos/{resource_id}/action',
            json_data=json_body, headers=headers, resp_type='response')
        return response

    def google_chromeos_device_list_request(self, query_params: dict = {}) -> dict:
        # TODO Don't forget to delete the following lines (these are for testing purposes)
        # max_results = query_params['maxResults']
        # query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = {CHROMEOS_DEVICE_LIST_SCOPE}
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos',
            params=query_params, headers=headers
        )
        return response


def device_list_manual_pagination(api_request: Callable, query_params: dict, page: Optional[int],
                                  page_size: int, response_devices_list_key: str, cd_devices_list_key: str) -> PaginationResult:
    """This function implements the manual pagination mechanism for both commands: mobile-device-list, and chromos-device-list.
    Since the API does not support `page` and `page_size` arguments, we have to do the manual pagination manually. We do this by
    limiting the page size returned from the API, using the `page_size` argument, and iteratively doing API requests according to
    the value of the argument `page`.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        query_params (dict): The query parameters that will be sent with the API call.
        page (Optional[int]): The page number.
        page_size (int): The size of the page.
        response_devices_list_key (str): The key that will point to the list of devices in the response body.
        cd_devices_list_key (str): The key that will point to the list of devices in the context data.

    Returns:
        CommandResults: Command Results that hold all the relevant data to return to the engine.
    """
    query_params['maxResults'] = page_size
    relevant_response = {}  # This will hold the relevant response that holds the page that was requested
    context_data = {}  # This will hold the context data to return to the user
    next_page_token: str | None = None
    get_data_from_api = True  # This will decide if we should continue requesting from the API or that we should stop
    current_page_number = 0
    while get_data_from_api:
        query_params['pageToken'] = next_page_token
        response = api_request(query_params=query_params)
        next_page_token = response.get('nextPageToken')  # Get the token of the next page if needed
        current_page_number += 1
        devices_list = response.get(response_devices_list_key, [])
        if(current_page_number == page and devices_list):
            # If entered here, that means we found the required page
            get_data_from_api = False
            context_data['resourceKind'] = response.get('kind')
            context_data[cd_devices_list_key] = devices_list
            relevant_response = response
        elif(not next_page_token):
            # If entered here, that means we did not reach the required page, which means
            # the page was not found
            if(not devices_list and current_page_number == 1):
                # If entered here, that means we got no results from the first page, which implies that there
                # are no results at all, so we change the current_page_number to zero to emphasize that there
                # are no available pages.
                current_page_number = 0
            get_data_from_api = False

    return PaginationResult(data=context_data, raw_response=[relevant_response], last_page_number=current_page_number)


def device_list_automatic_pagination(api_request: Callable, query_params: dict,
                                     limit: int, response_devices_list_key: str, cd_devices_list_key) -> PaginationResult:
    """This function implements the automatic pagination mechanism for both commands: mobile-device-list, and chromos-device-list.
    Since the API does not support a `limit` argument, we have to do the automatic pagination manually. If the limit
    argument is smaller than or equal to the maximum page size allowed by the API, then we will only need one request call,
    else, we will make multiple requests by utilizing the `nextPageToken` argument supplied by the API.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        query_params (dict): The query parameters that will be sent with the API call.
        limit (int): The limit argument that will act as the maximum number of results to return from the API request.
        response_devices_list_key (str): The key that will point to the list of devices in the response body.
        cd_devices_list_key (_type_): The key that will point to the list of devices in the context data.

    Returns:
        CommandResults: Command Results that hold all the relevant data to return to the engine.
    """
    results_limit = limit
    context_data = {}  # This will hold the context data to return to the user
    mobile_devices = []  # This will hold all aggregated mobile devices returned from the API requests
    responses = []  # This will hold all the responses from the API requests
    next_page_token: str | None = None
    get_data_from_api = True  # This will decide if we should continue requesting from the API or that we should stop
    while get_data_from_api:
        query_params['maxResults'] = results_limit if results_limit <= MAX_PAGE_SIZE else MAX_PAGE_SIZE
        query_params['pageToken'] = next_page_token
        response = api_request(query_params=query_params)
        responses.append(response)
        response_mobile_devices = response.get(response_devices_list_key, [])
        next_page_token = response.get('nextPageToken')  # Get the token of the next page if needed

        mobile_devices.extend(response_mobile_devices)
        results_limit -= len(response_mobile_devices)
        if(results_limit <= 0 or not next_page_token):
            # If entered, that means we either reached the maximum results defined by the user,
            # or there is no more data from the API.
            context_data['resourceKind'] = response.get('kind')
            context_data[cd_devices_list_key] = mobile_devices
            get_data_from_api = False
    return PaginationResult(data=context_data, raw_response=responses)


def prepare_pagination_arguments(args: dict) -> dict:
    """ The function gets the arguments from the user and checks the content of the pagination arguments,
        and if everything is valid, it returns a dictionary that holds the pagination information.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that holds the pagination information.
    """
    if('page' in args or 'page_size' in args):
        if('limit' in args):
            raise DemistoException(INVALID_PAGINATION_ARGS_SUPPLIED)
        page = arg_to_number(args.get('page', None))
        if not page or page <= 0:
            raise DemistoException(message=PAGE_NUMBER_INVALID_ERROR)
        page_size = arg_to_number(args.get('page_size', None))
        page_size = page_size if page_size else DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise DemistoException(EXCEEDED_MAX_PAGE_SIZE_ERROR)
        return {'page_size': page_size, 'page': page}

    limit = arg_to_number(args.get('limit', None))
    limit = limit if limit else DEFAULT_LIMIT
    if(not limit or limit <= 0):
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


def device_list_to_human_readable(data: list, keys: list, keys_mapping: dict[str, str]) -> List[dict]:
    human_readable: List[dict] = []
    for mobile_device in data:
        human_readable_data = {}
        for key in keys:
            if key in keys_mapping:
                human_readable_data[keys_mapping.get(key)] = mobile_device.get(key)
            else:
                human_readable_data[pascalToSpace(key)] = mobile_device.get(key)
        human_readable.append(human_readable_data)

    return human_readable


# def mobile_device_list_to_human_readable(context_data: dict) -> List[dict]:
#     """This function will take a context data from the mobile-device-list command, and
#     return human readable data for the UI.

#     Args:
#         context_data (dict): Context Data returned from the mobile-device-list command.

#     Returns:
#         List[dict]: A list of human readable data to print to the user.
#     """
#     human_readable: List[dict] = []
#     for mobile_device in context_data.get('mobileListObjects', []):
#         human_readable.append({'Serial Number': mobile_device.get('serialNumber'),
#                                'User Names': mobile_device.get('name'),
#                                'Model Name': mobile_device.get('model'),
#                                'OS': mobile_device.get('os'),
#                                'Type': mobile_device.get('type'),
#                                'Status': mobile_device.get('status')
#                                })

#     return human_readable


def google_mobile_device_list_command(client: Client, **kwargs) -> CommandResults:
    query_params = mobile_device_list_create_query_parameters(kwargs)
    pagination_args = prepare_pagination_arguments(args=kwargs)
    mutual_pagination_args = assign_params(
        api_request=client.google_mobile_device_list_request,
        response_devices_list_key=MobileDeviceListConfig.response_devices_list_key,
        cd_devices_list_key=MobileDeviceListConfig.cd_devices_list_key,
        query_params=query_params,
    )
    try:
        markdown = ''
        if 'limit' in pagination_args:
            pagination_result = device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)
        else:
            pagination_result = device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
            if not pagination_result.data:
                if pagination_result.last_page_number == 0:
                    # If entered here, that means we got no results from the first page, which implies that there
                    # are no results at all.
                    markdown = 'No results were found with the respected arguments'
                else:
                    # If entered here, that means we got no results from the page the user asked,
                    # but there are results in the previous pages.
                    markdown = (f'No results were found. The maximum number of pages is {pagination_result.last_page_number}'
                                f' for page size of {pagination_args.get("page_size")} with the respected arguments')
        if not markdown:
            human_readable = device_list_to_human_readable(
                data=pagination_result.data.get(MobileDeviceListConfig.cd_devices_list_key, []),
                keys=['serialNumber', 'name', 'model', 'os', 'type', 'status'],
                keys_mapping={'name': 'User Names', 'model': 'Model Name', 'os': 'OS'})
            num_of_devices = len(pagination_result.data[MobileDeviceListConfig.cd_devices_list_key])
            markdown = tableToMarkdown(MobileDeviceListConfig.table_title, human_readable,
                                    #    headers=MobileDeviceListConfig.table_headers,
                                       metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
        command_results = CommandResults(
            outputs_prefix=MobileDeviceListConfig.outputs_prefix,
            readable_output=markdown,
            outputs=pagination_result.data,
            raw_response=pagination_result.raw_response,
        )
        return command_results
    except DemistoException as e:
        demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        if(e.res is not None):
            error_res_to_json = e.res.json()
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            raise DemistoException(error_message)
        else:
            raise e


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


# def chromeos_device_list_to_human_readable(context_data: dict) -> List[dict]:
#     """This function will take a context data from the chromeos-device-list command, and
#     return human readable data for the UI.

#     Args:
#         context_data (dict): Context Data returned from the chromeos-device-list command.

#     Returns:
#         List[dict]: A list of human readable data to print to the user.
#     """
#     human_readable: List[dict] = []
#     for mobile_device in context_data.get('chromeosListObjects', []):
#         human_readable.append({'Serial Number': mobile_device.get('serialNumber'),
#                                'User Name': mobile_device.get('annotatedUser'),
#                                'Model': mobile_device.get('model'),
#                                'OS': mobile_device.get('osVersion'),
#                                'Status': mobile_device.get('status')
#                                })

#     return human_readable


def google_chromeos_device_list_command(client: Client, **kwargs) -> CommandResults:
    query_params = chromeos_device_list_create_query_parameters(kwargs)
    pagination_args = prepare_pagination_arguments(args=kwargs)
    mutual_pagination_args = assign_params(
        api_request=client.google_chromeos_device_list_request,
        response_devices_list_key=ChromeOSDeviceListConfig.response_devices_list_key,
        cd_devices_list_key=ChromeOSDeviceListConfig.cd_devices_list_key,
        query_params=query_params,
    )
    try:
        markdown = ''
        if 'limit' in pagination_args:
            pagination_result = device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)
        else:
            pagination_result = device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
            if not pagination_result.data:
                if pagination_result.last_page_number == 0:
                    # If entered here, that means we got no results from the first page, which implies that there
                    # are no results at all.
                    markdown = 'No results were found with the respected arguments'
                else:
                    markdown = (f'No results were found. The maximum number of pages is {pagination_result.last_page_number}'
                                f' for page size of {pagination_args.get("page_size")} with the respected arguments')
        if not markdown:
            human_readable = device_list_to_human_readable(
                data=pagination_result.data.get(ChromeOSDeviceListConfig.cd_devices_list_key, []),
                keys=['serialNumber', 'annotatedUser', 'model', 'osVersion', 'status'],
                keys_mapping={'annotatedUser': 'User Name', 'osVersion': 'OS'})
            num_of_devices = len(pagination_result.data[ChromeOSDeviceListConfig.cd_devices_list_key])
            markdown = tableToMarkdown(ChromeOSDeviceListConfig.table_title, human_readable,
                                    #    headers=ChromeOSDeviceListConfig.table_headers,
                                       metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
        command_results = CommandResults(
            outputs_prefix=ChromeOSDeviceListConfig.outputs_prefix,
            readable_output=markdown,
            outputs=pagination_result.data,
            raw_response=pagination_result.raw_response,
        )
        return command_results
    except DemistoException as e:
        demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        if(e.res is not None):
            error_res_to_json = e.res.json()
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            if 'INVALID_OU_ID' in error_message:
                raise DemistoException(INVALID_ORG_UNIT_PATH)
            raise DemistoException(error_message)
        else:
            raise e


def google_mobile_device_action_command(client: Client, resource_id: str, action: str) -> CommandResults:
    status = 'Success'
    readable_output = status
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can mark this
        # request as failure
        client.google_mobile_device_action_request(resource_id, action)

    except DemistoException as e:
        demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        status = 'Failure'
        failure_reason = ''
        if(e.res is not None):
            error_res_to_json = e.res.json()
            # We want to print the error message to the UI
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            if('Internal error encountered' in error_message or 'Bad Request' in error_message):
                failure_reason = INVALID_RESOURCE_ID_ERROR
            else:
                failure_reason = error_message
        else:
            failure_reason = str(e)
        readable_output = f'{status}. An error has occurred when running the command:\n{failure_reason}'
    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}',
        outputs_key_field='mobileAction.Status',
        readable_output=readable_output,
        outputs={'mobileAction': {'Status': status}},
    )
    return command_results


def google_chromeos_device_action_command(client: Client, resource_id: str, action: str,
                                          deprovision_reason: str = '') -> CommandResults:
    status = 'Success'
    readable_output = status
    try:
        # We want to catch the exception that is thrown from a bad API call, so we can mark this
        # request as failure
        client.google_chromeos_device_action_request(resource_id, action, deprovision_reason=deprovision_reason)

    except DemistoException as e:
        demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        status = 'Failure'
        failure_reason = ''
        if(e.res is not None):
            error_res_to_json = e.res.json()
            # We want to print the error message to the UI
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            if('Delinquent account' in error_message):
                failure_reason = INVALID_RESOURCE_ID_ERROR
            else:
                failure_reason = error_message
        else:
            failure_reason = str(e)
        readable_output = f'{status}. An error has occurred when running the command:\n{failure_reason}'

    command_results = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}',
        outputs_key_field='chromeOSAction.Status',
        readable_output=readable_output,
        outputs={'chromeOSAction': {'Status': status}},
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
                                customer_id=customer_id, service_account_json=service_account_json)

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
