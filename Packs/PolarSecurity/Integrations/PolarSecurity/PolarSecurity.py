import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from urllib.parse import quote
import urllib3
import json
"""
Version: 1.0.0 - McGurk, release candidate.
Functional commands: polar-list-data-stores,
polar-get-data-store, polar-data-stores-summary,
polar-list-linked-vendors, polar-list-vendors-data-stores,
polar-list-vendor-accessible-data-stores
"""
# IMPORTS

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    # Client to use in the Polar Security integration.

    def __init__(self, server_url: str, auth_token: str,
                 proxy: bool, verify: bool):
        """
        Args:
            server_url: Polar API server url
            auth_token: authentication token pulled from Context
            proxy: use system proxy settings or not
            verify: verify server certificate or not
        """
        self._proxies = handle_proxy(proxy_param_name='proxy',
                                     checkbox_default_value=False)
        self._server_url = server_url
        self._verify = verify
        self._auth_token = auth_token
        self._headers = {
            'Authorization': self._auth_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def send_request(self, path: str, method: str, body: dict, params: dict):
        """
        Generic request to Polar Security.
        Args:
            path: API path
            method: request method
            body: request body
            params: request params
        Returns:
            response from API
        """
        body = body if body is not None else {}
        params = params if params is not None else {}
        url = f'{self._server_url}{path}'
        res = None
        max_retries = 3
        num_of_tries = 0
        while num_of_tries < max_retries:
            try:
                res = requests.request(method, url, headers=self._headers,
                                       data=json.dumps(body) if body else {},
                                       params=params, verify=self._verify,
                                       proxies=self._proxies
                                       )
            except Exception as error:
                if res and res.status_code == 401:
                    demisto.debug(f'Got status code 401 - {res}. Retrying ...')
                else:
                    raise Exception(f'Polar Error: {error}')

            if res and res.status_code != 200:
                if res.status_code != 401 or num_of_tries == (max_retries - 1):
                    raise Exception(
                        f'Got status code {str(res.status_code)} with url \
                        {url} with body {str(res.content)}'
                        f' with headers {str(res.headers)}'
                    )
            else:
                break
            num_of_tries += 1
        return res


def trim_args(args):
    """
    Trim the arguments for extra spaces.
    :type args: Dict
    :param args: it contains arguments of the command
    """
    for key, value in args.items():
        args[key] = value.strip()

    return args


def get_access_token(server_url, username, password):
    """
    Get an access token that was previously created if it is still valid,
    else, generate a new access token from
    the client id, client secret and refresh token.
    """
    previous_token = get_integration_context()
    # Check if there is an existing valid access token
    if previous_token.get('access_token') and previous_token.get(
            'expiry_time') > date_to_timestamp(datetime.now()):
        return previous_token.get('access_token')
    else:
        # Pull a new token and store it to the integration context
        try:
            try:
                res = polar_login(server_url, username, password)
            except ValueError as exception:
                raise DemistoException(
                    'Failed to parse json object from response', exception)
            if 'error' in res:
                return_error(
                    f'Error occurred while creating an access token. Please\n'
                    f'try to run the login command again \
                        to generate a new token.\n'
                    f'{res}')
            if res.json()['idToken']:
                expiry_time = date_to_timestamp(datetime.now(),
                                                date_format='%Y-%m-%dT%H:%M:%S')
                expiry_time += res.json()['expiresIn'] - 10
                new_token = {
                    'access_token': res.json()['idToken'],
                    'refresh_token': res.json()['refreshToken'],
                    'expiry_time': expiry_time
                }
                set_integration_context(new_token)
                return res.json()['idToken']
        except Exception as e:
            return_error(f'Error occurred while creating an access token. \
                         Please check the instance configuration.'
                         f'\n\n{e.args[0]}')


def polar_login(server_url, username, password):
    """
    Generate a refresh token using the given client credentials and save
    it in the integration context.
    """
    url = f'{server_url}/auth'
    data = {
        'username': username,
        'password': password
    }
    try:
        try:
            res = requests.post(url, data)
        except ValueError as exception:
            raise DemistoException(
                'Failed to parse json object from response', exception)
        if res.json()['idToken']:
            return res
    except Exception as e:
        return_error(f'Login failed. Please check the instance configuration \
                     and the given username and password.\n'
                     f'{e.args[0]}')


def test_module(server_url, username, password):
    """
    Test the instance configurations.
    """
    try:
        response = polar_login(server_url, username, password)
        if response.status_code != requests.codes.ok:
            return f'Unexpected result from the service, please check \
                configuration and try again. {response.status_code}'
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authorization Error: make sure username and password \
                are correctly set'
        else:
            raise e
    demisto.results('ok')


def polar_list_data_stores_command(polar_client, limit: int, page_size: int, next_token):
    """
    endpoint: {{baseUrl}}/dataStores/
    List all data stores currently observed by Polar-Security
    Returns a lot of data!
    """
    has_next_page = True
    found_items = []
    query_params = {'pageSize': page_size}

    try:
        while has_next_page and limit > 0:
            if next_token is not None:
                query_params['nextToken'] = next_token
            try:
                res = polar_client.send_request(method='GET', path='/dataStores',
                                                params=query_params, body={})
            except ValueError as exception:
                raise DemistoException(
                    'Unable to retrieve data store list', exception)
            if res.json()['results'] is not None:
                for item in res.json()['results']:
                    found_items.append(item)
            if res.json()['nextToken'] is not None:
                has_next_page = True
                next_token = res.json()['nextToken']
            else:
                has_next_page = False
            limit -= page_size
        if found_items is not None:
            outputs = found_items
            readable_output = tableToMarkdown(
                'Data Stores Observed by Polar Security',
                outputs,
                headers=['dataStoreId', 'dataStoreType', 'dataStoreName',
                         'vpcId', 'country', 'cloudRegion'])
            command_results = []
            command_results.append(CommandResults(
                outputs=outputs,
                readable_output=readable_output,
                outputs_prefix="PolarSecurity.DataStores.Stores",
                outputs_key_field="dataStoreId"
            ))
            if next_token is not None:
                human_readable = f'\nNext page token is {next_token}'
                command_results.append(CommandResults(
                    outputs={'PolarSecurity.DataStores(true)': {'NextToken': next_token}},
                    readable_output=human_readable
                ))
            return command_results
        else:
            return 'Found no results to return.'
    except Exception as e:
        return_error(f'Operation failed. Please check the instance configuration \
                     and the given username and password.\n'
                     f'{e.args[0]}')


def polar_get_data_store_command(polar_client, store_id):
    """
    endpoint: /dataStores/{dataStoreId}
    Retrieve details on 1 specific store
    Doesn't return anything above and beyond the polar_list_data_stores command,
    so no need to run it again
    """
    # URLencode the ID to make it safe to pass as a parameter
    safe_store_id = quote(store_id, safe='')
    try:
        try:
            res = polar_client.send_request(
                method='GET',
                path=f'/dataStores/{safe_store_id}',
                params={},
                body={})
        except ValueError as exception:
            raise DemistoException(
                'Unable to retrieve data store list', exception)
        if res.json() is not None:
            outputs = res.json()
            readable_output = tableToMarkdown(
                f'Data Store Details for {store_id}',
                outputs,
                headers=['dataStoreType', 'dataStoreName', 'dataStoreUrl',
                         'vpcId', 'country', 'cloudRegion'])
            results = CommandResults(
                outputs=outputs,
                readable_output=readable_output,
                outputs_prefix="PolarSecurity.DataStores.Stores",
                outputs_key_field="dataStoreId"
            )
            return results
    except Exception as e:
        return_error(f'Operation failed. Please check the instance configuration \
                     and the given username and password.\n'
                     f'{e.args[0]}')


def polar_data_stores_summary_command(polar_client):
    """
    endpoint: /dataStores/summary
    Summary statistics of all the known data stores
    """
    try:
        parameters = {
            'storeTypesFamily': 'SAAS,CLOUD',
            'serviceProviders': 'google-workspace,gcp',
            'classificationStatuses': 'CLASSIFIED,IN_PROGRESS',
            'encryptionStatuses': 'UNAVAILABLE_CUSTOM,AVAILABLE_CUSTOM'
        }
        try:
            res = polar_client.send_request(
                method='GET',
                path='/dataStores/summary?',
                params=parameters,
                body={})
        except ValueError as exception:
            raise DemistoException(
                'Unable to retrieve d list:', exception)
        if res.json() is not None:
            outputs = res.json()
            readable_output = tableToMarkdown(
                'Summary of Linked Data Stores',
                outputs,
                headers=['totalStores', 'totalSensitivities', 'totalPotentialFlows',
                         'totalActualFlows', 'totalSensitiveStores', 'serviceProviders'])
            results = CommandResults(
                outputs=outputs,
                readable_output=readable_output,
                outputs_prefix="PolarSecurity.DataStores.Summary"
            )
            return results
    except Exception as e:
        return_error(f'Operation failed. Please check the instance configuration \
                     and the given username and password.\n'
                     f'{e.args[0]}')


def polar_list_linked_vendors_command(polar_client):
    """
    endpoint: /linkedVendor
    Get a list of all 3rd party vendors connected to your cloud workloads (relevant
    for cloud workloads connected to Polar Security only).
    """
    try:
        try:
            res = polar_client.send_request(
                method='GET',
                path='/linkedVendor',
                params={},
                body={})
        except ValueError as exception:
            raise DemistoException(
                'Unable to retrieve vendor list', exception)
        if res:
            outputs: list = []
            for item in res.json():
                outputs.append(item['vendor'])
            readable_output = tableToMarkdown(
                'Linked Vendors Observed by Polar Security',
                outputs,
                headers=['vendorId', 'vendorName', 'vendorUrl',
                         'description', 'accounts'])
            command_results = CommandResults(
                outputs=outputs,
                readable_output=readable_output,
                outputs_prefix="PolarSecurity.Vendors",
                outputs_key_field='vendorId'
            )
            return command_results, outputs
    except Exception as e:
        return_error(f'Operation failed. Please check the instance configuration \
                     and the given username and password.\n'
                     f'{e.args[0]}')


def polar_list_vendors_data_stores_command(polar_client, vendor_id, limit: int, page_size: int, next_token):
    """
    endpoint: /linkedVendor/{vendorId}/dataStore
    Get a list of all data stores a specific 3rd party vendor can access.
    See whether they have sensitivities and with what role the access is made possible.
    """
    query_params = {'pageSize': page_size}
    has_next_page = True
    found_items: dict = {'dataStores': []}
    try:
        while has_next_page and limit > 0:
            if next_token is not None:
                query_params['nextToken'] = next_token
            try:
                res = polar_client.send_request(
                    method='GET',
                    path=f'/linkedVendor/{vendor_id}/dataStore',
                    params=query_params,
                    body={})
            except ValueError as exception:
                raise DemistoException(
                    'Unable to retrieve vendor data store list', exception)
            if res.json()['results'] is not None:
                found_items['vendorId'] = f'{vendor_id}'
                for item in res.json()['results']:
                    found_items['dataStores'].append(item)
            if res.json()['nextToken'] is not None:
                next_token = res.json()['nextToken']
                has_next_page = True
            else:
                has_next_page = False
            limit -= page_size
        if found_items['dataStores'] is not None:
            stores = found_items['dataStores']
            readable_output = tableToMarkdown(
                f'DataStores Accessible by Vendor {vendor_id}',
                stores,
                headers=['cloudProvider', 'cloudRegion', 'dataStoreId', 'dataStoreName',
                         'dataStoreType', 'sensitivitiesSummary'])
            command_results = []
            command_results.append(CommandResults(
                outputs=found_items,
                readable_output=readable_output,
                outputs_prefix='PolarSecurity.Vendors',
                outputs_key_field='vendorId'
            ))
            human_readable = f'\nCompleted listing data stores for vendor {vendor_id}'
            command_results.append(CommandResults(
                outputs={'PolarSecurity.Vendors(true)': {'vendorId': vendor_id}},
                readable_output=human_readable
            ))
            if next_token is not None:
                human_readable = f'\nNext page token is {next_token}'
                command_results.append(CommandResults(
                    outputs={'PolarSecurity(true)': {'NextToken': next_token}},
                    readable_output=human_readable
                ))
            return command_results, found_items
        else:
            return 'Found no results to return.'
    except Exception as e:
        return_error(f'Operation failed. Please check the instance configuration \
                     and the given username and password.\n'
                     f'{e.args[0]}')


def polar_list_vendor_accessible_data_stores(polar_client):
    """
    A combination command that will run polar_list_linked_vendors_command and
    polar_list_vendors_data_stores_command and then compile the results
    """
    vendors = polar_list_linked_vendors_command(polar_client)[1]
    pairs: dict = {}
    big_list: list = []
    stores_list: list = []
    for vendor in vendors:
        vendor_id = vendor['vendorId']
        # passing huge limit because to be useful we need all the results
        vendor_stores = polar_list_vendors_data_stores_command(
            polar_client, vendor_id, limit=9999999, page_size=50, next_token=None)[1]
        if len(vendor_stores['dataStores']):  # anything greater than 0 results
            for store in vendor_stores['dataStores']:
                store_id = store['dataStoreId']
                pairs.setdefault(store_id, []).append(vendor_id)
                big_list.append(store)

    for each_dict in big_list:
        if each_dict not in stores_list:
            # all other API results are camel case
            each_dict['3rdParties'] = []
            stores_list.append(each_dict)

    for key, value in pairs.items():
        for store in stores_list:
            if store['dataStoreId'] == key:
                for vendor_id in value:
                    for vendor in vendors:
                        if vendor['vendorId'] == vendor_id:
                            store['3rdParties'].append(vendor)

    readable_output = tableToMarkdown(
        'DataStores Accessible by all Vendors',
        stores_list,
        headers=['cloudProvider', 'cloudRegion', 'dataStoreId', 'dataStoreName',
                 'dataStoreType', 'sensitivitiesSummary', '3rdParties'])
    results = CommandResults(
        outputs=stores_list,
        readable_output=readable_output,
        outputs_prefix='PolarSecurity.DataStores.Stores',
        outputs_key_field='dataStoreId'
    )
    return results


def polar_apply_label_command(polar_client, store_id, mylabel):
    """
    endpoint: /dataStores/{dataStoreId}/labels
    Add or update a custom label to a data store
    """
    # URLencode the ID to make it safe to pass as a parameter
    safe_store_id = quote(store_id, safe='')
    try:
        polar_client.send_request(
            method='PUT',
            path=f'/dataStores/{safe_store_id}/labels',
            params={},
            body={"label": mylabel}
        )
    except ValueError as exception:
        raise DemistoException(exception)
    readable_output = 'Label Successfully Applied'
    results = CommandResults(readable_output=readable_output)
    return results


def main():

    # PARSE AND VALIDATE INTEGRATION PARAMS
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = str(params.get('credentials', {}).get('password'))
    server_url = params.get('url')
    verify: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    LOG(f'Executing command {command}')

    try:
        args = trim_args(demisto.args())
        auth_token = get_access_token(server_url, username, password)

        polar_client = Client(server_url=server_url, auth_token=auth_token,
                              proxy=proxy, verify=verify)
        if command == 'test-module':
            test_module(server_url, username, password)
            sys.exit(0)  # no results to return so exit gracefully
        elif command == 'polar-list-linked-vendors':
            results = polar_list_linked_vendors_command(polar_client)[0]
        elif command == 'polar-list-data-stores':
            next_token = args.get("next_token", "") or None
            limit = arg_to_number(args.get("limit", "50")) or 50
            page_size = arg_to_number(args.get("page_size", "50")) or 50
            if limit % page_size != 0:
                return_error('Value for limit must be divisible by page_size.')
            results = polar_list_data_stores_command(polar_client, limit, page_size, next_token)
        elif command == 'polar-data-stores-summary':
            results = polar_data_stores_summary_command(polar_client)
        elif command == 'polar-get-data-store':
            store_id = args.get('store_id')
            results = polar_get_data_store_command(polar_client, store_id)
        elif command == 'polar-list-vendors-data-stores':
            vendor_id = args.get('vendor_id')
            next_token = args.get("next_token", "") or None
            limit = arg_to_number(args.get("limit", "50")) or 50
            page_size = arg_to_number(args.get("page_size", "50")) or 50
            results = polar_list_vendors_data_stores_command(
                polar_client, vendor_id, limit, page_size, next_token)[0]
        elif command == 'polar-list-vendor-accessible-data-stores':
            results = polar_list_vendor_accessible_data_stores(polar_client)
        elif command == 'polar-apply-label':
            label = args.get('label')
            store_id = args.get('store_id')
            results = polar_apply_label_command(polar_client, store_id, label)
        else:
            raise NotImplementedError(
                f'Command not implemented: {demisto.command()}')
        return_results(results)

    except Exception as err:
        LOG(err)
        LOG.print_log()
        return_error(
            f'Unexpected error: {str(err)}', error=traceback.format_exc())
        raise


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
