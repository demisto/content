import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from MicrosoftApiModule import *  # noqa: E402

'''GLOBAL VARS'''
API_VERSION = '2022-10-01'
APP_NAME = 'azure-resource-graph'
MAX_PAGE_SIZE = 50


class AzureResourceGraphClient:
    """
      Azure Resource Graph Client enables authorized access to query for resource information.
      """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed, ok_codes, server,
                 certificate_thumbprint, private_key):

        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name, base_url=base_url, verify=verify,
            proxy=proxy, self_deployed=self_deployed, ok_codes=ok_codes, scope=Scopes.management_azure,
            certificate_thumbprint=certificate_thumbprint, private_key=private_key,
            command_prefix="azure-rg",
        )

        self.server = server
        self.default_params = {"api-version": API_VERSION}

    def list_operations(self):
        return self.ms_client.http_request(
            method='GET',
            full_url=f"{self.server}/providers/Microsoft.ResourceGraph/operations",
            params=self.default_params,
        )

    def query_resources(self, query, paging_options: dict[str, Any], subscriptions: list, management_groups: list):
        request_data = {"query": query, "options": paging_options}

        if subscriptions:
            request_data["subscriptions"] = subscriptions

        if management_groups:
            request_data["managementGroups"] = management_groups

        return self.ms_client.http_request(
            method='POST',
            full_url=f"{self.server}/providers/Microsoft.ResourceGraph/resources",
            params=self.default_params,
            json_data=request_data
        )


def query_resources_command(client: AzureResourceGraphClient, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get('limit'))
    page_size = arg_to_number(args.get('page_size'))
    page_number = arg_to_number(args.get('page'))
    management_groups = argToList(args.get('management_groups', None))
    subscriptions = argToList(args.get('subscriptions', None))

    query = args.get('query')

    list_of_query_results = []
    total_records = 0

    if page_number and not page_size:
        raise DemistoException("Please enter a value for \"page_size\" when using \"page\".")
    if page_size and not page_number:
        raise DemistoException("Please enter a value for \"page\" when using \"page_size\".")

    if page_number and page_size:
        skip = (page_number - 1) * page_size + 1
        params = {'$skip': skip, '$top': page_size}
        response = client.query_resources(query=query,
                                          paging_options=params,
                                          management_groups=management_groups,
                                          subscriptions=subscriptions)
        total_records = response.get('totalRecords')
        list_of_query_results = response.get('data')
    elif page_number:
        params = {'$top': page_size}  # type: ignore
        response = client.query_resources(query=query,
                                          paging_options=params,
                                          management_groups=management_groups,
                                          subscriptions=subscriptions)
        total_records = response.get('totalRecords')
        list_of_query_results = response.get('data')
    else:
        query_results = []
        skip_token = ""
        counter = 0

        while True:
            if skip_token:
                params = {'$skipToken': skip_token}  # type: ignore
            else:
                params = {}

            response = client.query_resources(query=query,
                                              paging_options=params,
                                              management_groups=management_groups,
                                              subscriptions=subscriptions)

            list_of_query_results = response.get('data')
            query_results.extend(list_of_query_results)
            counter += len(list_of_query_results)
            if limit and counter >= limit:
                break
            if '$skipToken' in response and (not limit or counter < limit):
                skip_token = response.get('$skipToken')
            else:
                break

        total_records = response.get('totalRecords')
        list_of_query_results = query_results

    if limit:
        list_of_query_results = list_of_query_results[:limit]

    title = f"Results of query:\n```{query}```\n\n Total Number of Possible Records:{total_records} \n"
    human_readable = tableToMarkdown(title, list_of_query_results, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureResourceGraph.Query',
        outputs_key_field='Query',
        outputs=list_of_query_results,
        raw_response=response
    )


def list_operations_command(client: AzureResourceGraphClient, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get('limit'))
    page_size = arg_to_number(args.get('page_size'))
    page = arg_to_number(args.get('page'))

    response = client.list_operations()
    operations_list = response.get('value')
    md_output_notes = ""

    if page and not page_size:
        raise DemistoException("Please enter a value for \"page_size\" when using \"page\".")
    if page_size and not page:
        raise DemistoException("Please enter a value for \"page\" when using \"page_size\".")
    if page and page_size:
        if limit:
            md_output_notes = "\"limit\" was ignored for paging parameters."
            demisto.debug("\"limit\" was ignored for paging parameters.")
        operations_list = pagination(operations_list, page_size, page)

    if page_size:
        limit = page_size

    operations = []
    for operation in operations_list[:limit]:
        operation_context = {
            'Name': operation.get('name'),
            'Display': operation.get('display')
        }
        operations.append(operation_context)

    title = 'List of Azure Resource Graph Operations\n\n' + md_output_notes
    human_readable = tableToMarkdown(title, operations, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureResourceGraph.Operations',
        outputs_key_field='Operations',
        outputs=operations,
        raw_response=response
    )


def test_module(client: AzureResourceGraphClient):
    # Implicitly will test tenant, enc_token and subscription_id
    try:
        result = client.list_operations()
        if result:
            return 'ok'
    except DemistoException as e:
        return_error(f"Test connection failed with message {e}")


# Helper Methods

def pagination(response, page_size, page_number):
    """Method to generate a page (slice) of data.
    Args:
        response: The response from the API.
        limit: Maximum number of objects to retrieve.
        page: Page number
    Returns:
        Return a list of objects from the response according to the page and limit per page.
    """
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    starting_index = (page_number - 1) * page_size
    ending_index = starting_index + page_size
    return response[starting_index:ending_index]


def validate_connection_params(tenant: str = None,
                               auth_and_token_url: str = None,
                               enc_key: str = None,
                               certificate_thumbprint: str = None,
                               private_key: str = None) -> None:
    if not tenant or not auth_and_token_url:
        raise DemistoException('Token and ID must be provided.')

    elif not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be providedFor further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')


def main():
    params: dict = demisto.params()
    args = demisto.args()
    server = params.get('host', 'https://management.azure.com').rstrip('/')
    tenant = params.get('cred_token', {}).get('password') or params.get('tenant_id')
    auth_and_token_url = params.get('cred_auth_id', {}).get('password') or params.get('auth_id')
    enc_key = params.get('cred_enc_key', {}).get('password') or params.get('enc_key')
    certificate_thumbprint = params.get('cred_certificate_thumbprint', {}).get(
        'password') or params.get('certificate_thumbprint')
    private_key = params.get('private_key')
    verify = not params.get('unsecure', False)
    proxy: bool = params.get('proxy', False)

    validate_connection_params(tenant, auth_and_token_url, enc_key,
                               certificate_thumbprint, private_key)

    ok_codes = (200, 201, 202, 204)

    commands_without_args: Dict[Any, Any] = {
        'test-module': test_module
    }

    commands_with_args: Dict[Any, Any] = {
        'azure-rg-query': query_resources_command,
        'azure-rg-list-operations': list_operations_command
    }

    '''EXECUTION'''
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        # Initial setup
        base_url = f"{server}/providers/Microsoft.ResourceGraph"

        client = AzureResourceGraphClient(
            base_url=base_url, tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key, app_name=APP_NAME,
            verify=verify, proxy=proxy, self_deployed=True, ok_codes=ok_codes, server=server,
            certificate_thumbprint=certificate_thumbprint, private_key=private_key)
        if command == 'azure-rg-auth-reset':
            return_results(reset_auth())
        elif command in commands_without_args:
            return_results(commands_without_args[command](client))
        elif command in commands_with_args:
            return_results(commands_with_args[command](client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
