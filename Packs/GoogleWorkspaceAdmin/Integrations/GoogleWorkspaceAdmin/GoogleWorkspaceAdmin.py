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

# The following dictionary is used to map error messages returned from the API that don't
# share enough information to meaningful error messages.
ERROR_MESSAGES_MAPPING = {
    'Bad Request': 'Please check the customer ID parameter.',
    'Internal error encountered.': 'Please check the resource_id argument.',
    'Not Authorized to access this resource/api': 'Please check the authorizations of the configured service account.',
    'Delinquent account.': 'Please check the resource_id argument.'
}

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50


requests.packages.urllib3.disable_warnings()


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
            if(e.res is not None):
                error_res_to_json = e.res.json()
                error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
                raise DemistoException(ERROR_MESSAGES_MAPPING.get(error_message, error_message))
            else:
                raise e

    def _get_oauth_token(self, scopes: List[str]):
        """
        In charge or retrieving the OAuth token in order to make HTTP requests.
        OAuth tokens are correlated with scopes, so if a new HTTP request requires different scopes, a new token is required
        """

        #  Scopes are represented using a list, and it is enough to check the scopes' list using == operator since each HTTP
        # request requires at most one level of scope
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
        # max_results = query_params['maxResults']
        # query_params['maxResults'] = 3 if max_results > 3 else max_results

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
        if action == 'deprovision':
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
        # max_results = query_params['maxResults']
        # query_params['maxResults'] = 3 if max_results > 3 else max_results

        scopes = ['https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly']
        token = self._get_oauth_token(scopes=scopes)
        headers = self._headers | {'Authorization': f'Bearer {token}'}
        response = self.http_request(
            method='GET', url_suffix=f'admin/directory/v1/customer/{self._customer_id}/devices/chromeos',
            params=query_params, headers=headers
        )
        return response


def device_list_manual_pagination(api_request: Callable, to_human_readable: Callable, query_params: dict, page: Optional[int],
                                  page_size: int, table_headers: List[str], table_title: str, outputs_prefix: str,
                                  response_devices_list_key: str, cd_devices_list_key: str) -> CommandResults:
    """This function implements the manual pagination mechanism for both commands: mobile-device-list, and chromos-device-list.
    Since the API does not support `page` and `page_size` arguments, we have to do the manual pagination manually. We do this by
    limiting the page size returned from the API, using the `page_size` argument, and iteratively doing API requests according to
    the value of the argument `page`.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        to_human_readable (Callable): The function that will be used to create the human readable data from the context data.
        query_params (dict): The query parameters that will be sent with the API call.
        page (Optional[int]): The page number.
        page_size (int): The size of the page.
        table_headers (List[str]): The table headers that will be used in the human readable table.
        table_title (str): The tile of the human readable table.
        outputs_prefix (str): The outputs_prefix that will be used in the context data.
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
    page_found = True  # This will tell us if the required page was found or not
    while get_data_from_api:
        query_params['pageToken'] = next_page_token
        response = api_request(query_params=query_params)
        next_page_token = response.get('nextPageToken')  # Get the token of the next page if needed
        current_page_number += 1
        if(current_page_number == page):
            # If entered here, that means we found the required page
            get_data_from_api = False
            context_data['resourceKind'] = response.get('kind')
            context_data[cd_devices_list_key] = response.get(response_devices_list_key, [])
            relevant_response = response
        elif(not next_page_token):
            # If entered here, that means we did not reach the required page, which means
            # the page was not found
            get_data_from_api = False
            page_found = False

    markdown = ''
    if not page_found:
        markdown = (f'No results were found. The maximum number of pages is {current_page_number}'
                    f' for page size of {page_size}')
    else:
        num_of_devices = len(context_data[cd_devices_list_key])
        human_readable = to_human_readable(context_data=context_data)
        markdown = tableToMarkdown(table_title, human_readable, headers=table_headers,
                                   metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')

    command_results = CommandResults(
        outputs_prefix=outputs_prefix,
        readable_output=markdown,
        outputs=context_data,
        raw_response=relevant_response,
    )
    return command_results


def device_list_automatic_pagination(api_request: Callable, to_human_readable: Callable, query_params: dict,
                                     limit: int, table_headers: List[str], table_title: str, outputs_prefix: str,
                                     response_devices_list_key: str, cd_devices_list_key) -> CommandResults:
    """This function implements the automatic pagination mechanism for both commands: mobile-device-list, and chromos-device-list.
    Since the API does not support a `limit` argument, we have to do the automatic pagination manually. If the limit
    argument is smaller than or equal to the maximum page size allowed by the API, then we will only need one request call,
    else, we will make multiple requests by utilizing the `nextPageToken` argument supplied by the API.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        to_human_readable (Callable): The function that will be used to create the human readable data from the context data.
        query_params (dict): The query parameters that will be sent with the API call.
        limit (int): The limit argument that will act as the maximum number of results to return from the API request.
        table_headers (List[str]): The table headers that will be used in the human readable table.
        table_title (str): The tile of the human readable table.
        outputs_prefix (str): The outputs_prefix that will be used in the context data.
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
        query_params['maxResults'] = results_limit
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
    human_readable = to_human_readable(context_data=context_data)
    num_of_devices = len(context_data[cd_devices_list_key])
    markdown = tableToMarkdown(table_title, human_readable, headers=table_headers,
                               metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
    command_results = CommandResults(
        outputs_prefix=outputs_prefix,
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
        dict: A dictionary that holds the pagination information.
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
    """This function takes in the arguments from the user and creates a dictionary that will hold
    the query arguments for the mobile-device-list request.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that will hold the query arguments of the request.
    """
    query_params = assign_params(projection=args.get('projection', 'full').lower(),
                                 query=args.get('query', ''),
                                 orderBy=args.get('order_by', '').lower(),
                                 sortOrder=args.get('sort_order', '').lower(),
                                 )
    return query_params


def mobile_device_list_to_human_readable(context_data: dict) -> List[dict]:
    """This function will take a context data from the mobile-device-list command, and
    return human readable data for the UI.

    Args:
        context_data (dict): Context Data returned from the mobile-device-list command.

    Returns:
        List[dict]: A list of human readable data to print to the user.
    """
    human_readable: List[dict] = []
    for mobile_device in context_data.get('mobileListObjects', []):
        human_readable.append({'Serial Number': mobile_device.get('serialNumber'),
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
    outputs_prefix = f'{OUTPUT_PREFIX}.mobileEvent'
    pagination_args = prepare_pagination_arguments(args=kwargs)
    mutual_pagination_args = assign_params(
        api_request=client.google_mobile_device_list_request,
        to_human_readable=mobile_device_list_to_human_readable,
        table_headers=table_headers,
        table_title=table_title,
        response_devices_list_key=response_devices_list_key,
        cd_devices_list_key=cd_devices_list_key,
        outputs_prefix=outputs_prefix,
        query_params=query_params,
    )
    try:
        if 'limit' in pagination_args:
            return device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)

        return device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
    except DemistoException as e:
        if(e.res is not None):
            error_res_to_json = e.res.json()
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            raise DemistoException(ERROR_MESSAGES_MAPPING.get(error_message, error_message))
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


def chromeos_device_list_to_human_readable(context_data: dict) -> List[dict]:
    """This function will take a context data from the chromeos-device-list command, and
    return human readable data for the UI.

    Args:
        context_data (dict): Context Data returned from the chromeos-device-list command.

    Returns:
        List[dict]: A list of human readable data to print to the user.
    """
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
    outputs_prefix = f'{OUTPUT_PREFIX}.chromeosEvent'
    pagination_args = prepare_pagination_arguments(args=kwargs)
    mutual_pagination_args = assign_params(
        api_request=client.google_mobile_device_list_request,
        to_human_readable=mobile_device_list_to_human_readable,
        table_headers=table_headers,
        table_title=table_title,
        response_devices_list_key=response_devices_list_key,
        cd_devices_list_key=cd_devices_list_key,
        outputs_prefix=outputs_prefix,
        query_params=query_params
    )
    try:
        if 'limit' in pagination_args:
            return device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)

        return device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
    except DemistoException as e:
        if(e.res is not None):
            error_res_to_json = e.res.json()
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            raise DemistoException(ERROR_MESSAGES_MAPPING.get(error_message, error_message))
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
        # TODO Ask when it is a good idea to use demisto.debug
        # demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
        status = 'Failure'
        failure_reason = ''
        if(e.res is not None):
            error_res_to_json = e.res.json()
            # We want to print the error message to the UI
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            failure_reason = ERROR_MESSAGES_MAPPING.get(error_message, error_message)
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
        status = 'Failure'
        failure_reason = ''
        if(e.res is not None):
            error_res_to_json = e.res.json()
            # We want to print the error message to the UI
            error_message = demisto.get(obj=error_res_to_json, field='error.message', defaultParam=str(error_res_to_json))
            failure_reason = ERROR_MESSAGES_MAPPING.get(error_message, error_message)
        else:
            failure_reason = str(e)
        # TODO Ask when it is a good idea to use demisto.debug
        # demisto.debug(f'An error has occurred when running the command:\n{str(e)}')
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
        # print(str(e))
        return_error(f'Failed to execute {command} command.'
                     f'\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
