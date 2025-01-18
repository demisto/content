from collections.abc import Callable

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from MicrosoftApiModule import *  # noqa: E402

''' CONSTANTS '''

APP_NAME = 'ms-azure-log-analytics'

API_VERSION = "2022-10-01"
ISO_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
TABLE_NAME_SUFFIX = "_SRCH"

SUBSCRIPTION_LIST_API_VERSION = '2020-01-01'
RESOURCE_GROUP_LIST_API_VERSION = '2021-04-01'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n'\
                          'The response from the server did not contain the expected content.'

SAVED_SEARCH_HEADERS = [
    'etag', 'id', 'category', 'displayName', 'functionAlias', 'functionParameters', 'query', 'tags', 'version', 'type'
]


class Client:
    def __init__(self, self_deployed, refresh_token, auth_and_token_url, enc_key, redirect_uri, auth_code,
                 subscription_id, resource_group_name, workspace_name, verify, proxy, certificate_thumbprint,
                 private_key, client_credentials, azure_cloud, managed_identities_client_id=None):

        tenant_id = refresh_token if self_deployed else ''
        refresh_token = get_integration_context().get('current_refresh_token') or refresh_token
        self.azure_cloud = azure_cloud or AZURE_WORLDWIDE_CLOUD
        suffix = (
            f"subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/"
            + f"providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        )
        auth_code_scope = (
            f"{urljoin(self.azure_cloud.endpoints.log_analytics_resource_id, 'Data.Read')} "
            f"{urljoin(self.azure_cloud.endpoints.resource_manager, 'user_impersonation')}"
        )
        resources_list = [self.azure_cloud.endpoints.resource_manager, self.azure_cloud.endpoints.log_analytics_resource_id]
        base_url = urljoin(url=self.azure_cloud.endpoints.resource_manager, suffix=suffix)

        demisto.debug(
            f"##### AzureLogAnalytics #####{self.azure_cloud.name=} \n{base_url=} \n{resources_list=} \n{auth_code_scope=}"
        )

        self.ms_client = MicrosoftClient(
            self_deployed=self_deployed,
            auth_id=auth_and_token_url,  # client_id for client credential
            refresh_token=refresh_token,
            enc_key=enc_key,  # client_secret for client credential
            redirect_uri=redirect_uri,
            token_retrieval_url=urljoin(self.azure_cloud.endpoints.active_directory, '/{tenant_id}/oauth2/token'),
            grant_type=CLIENT_CREDENTIALS if client_credentials else AUTHORIZATION_CODE,  # disable-secrets-detection
            app_name=APP_NAME,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            scope='' if client_credentials else auth_code_scope,
            tenant_id=tenant_id,
            auth_code=auth_code,
            ok_codes=(200, 202, 204, 400, 401, 403, 404, 409),
            multi_resource=True,
            resources=resources_list,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=self.azure_cloud.endpoints.resource_manager,
            command_prefix="azure-log-analytics",
            azure_cloud=azure_cloud
        )
        demisto.debug('##### AzureLogAnalytics ##### MicrosoftClient created successfully. Using {self.ms_client._base_url=}')
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name

    def resource_group_list_request(self, tag: str, limit: int, full_url: Optional[str] = None) -> dict:
        """
        List all resource groups.
        Args:
            tag str: Tag to filter by.
            limit (int): Maximum number of resource groups to retrieve. Default is 50.
            full_url (str): URL to retrieve the next set of results.
        Returns:
            List[dict]: API response from Azure.
        """
        filter_by_tag = azure_tag_formatter(tag) if tag else None
        params = {'$filter': filter_by_tag, '$top': limit, 'api-version': RESOURCE_GROUP_LIST_API_VERSION} if not full_url else {}
        default_url = f"{self.azure_cloud.endpoints.resource_manager}subscriptions/{self.subscription_id}/resourcegroups"
        full_url = full_url if full_url else default_url
        return self.http_request('GET', full_url=full_url, params=params, resource=self.azure_cloud.endpoints.resource_manager)

    def http_request(self, method, url_suffix=None, full_url=None, params=None,
                     data=None, resource=None, timeout=10):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        res = self.ms_client.http_request(method=method,  # disable-secrets-detection
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params,
                                          resp_type='response',
                                          resource=resource,
                                          timeout=timeout)

        if res.status_code in (200, 202, 204) and not res.text:
            return res

        res_json = res.json()

        if res.status_code in (400, 401, 403, 404, 409):
            code = res_json.get('error', {}).get('code', 'Error')
            error_msg = res_json.get('error', {}).get('message', res_json)
            raise ValueError(
                f'[{code} {res.status_code}] {error_msg}'
            )

        return res_json


''' INTEGRATION HELPER METHODS '''


def validate_params(refresh_token, managed_identities_client_id, client_credentials, enc_key, self_deployed,
                    certificate_thumbprint, private_key):
    if not refresh_token:
        raise DemistoException('Token / Tenant ID must be provided.')
    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided when not using self deployed flow. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')


def format_query_table(table: dict[str, Any]):
    name = table.get('name')
    columns = [column.get('name') for column in table.get('columns', [])]
    rows = table.get('rows', [])
    data = [
        dict(zip(columns, row)) for row in rows
    ]

    return name, columns, data


def flatten_saved_search_object(saved_search_obj: dict[str, Any]) -> dict[str, Any]:
    ret: dict = saved_search_obj.get('properties', {})
    ret['id'] = saved_search_obj.get('id', '').split('/')[-1]
    ret['etag'] = saved_search_obj.get('etag')
    ret['type'] = saved_search_obj.get('type')
    if ret.get('tags'):
        ret['tags'] = json.dumps(ret.get('tags'))

    return ret


def tags_arg_to_request_format(tags) -> list[dict[str, str]] | None:
    bad_arg_msg = 'The `tags` argument is malformed. ' \
                  'Value should be in the following format: `name=value;name=value`'
    if not tags:
        return None
    try:
        tags = tags.split(';')
        tags = [tag.split('=') for tag in tags]

        for tag in tags:
            if len(tag) != 2:
                raise DemistoException(bad_arg_msg)

        return [{
            'name': tag[0],
            'value': tag[1]
        } for tag in tags]
    except IndexError as e:
        raise DemistoException(bad_arg_msg) from e


''' INTEGRATION COMMANDS '''


def test_connection(client: Client, params: dict[str, Any]) -> str:
    if (
        not client.ms_client.managed_identities_client_id
        and params.get('self_deployed', False)
        and not params.get('client_credentials')
        and not params.get('credentials_auth_code', {}).get('password')
        and not params.get('auth_code')
    ):
        raise DemistoException('You must enter an authorization code in a self-deployed configuration.')

    # If fails, MicrosoftApiModule returns an error
    client.ms_client.get_access_token(client.azure_cloud.endpoints.resource_manager)
    try:
        execute_query_command(client, {'query': 'Usage | take 1'})
    except Exception as e:
        raise DemistoException(
            'Could not authorize to `api.loganalytics.io` resource. This could be due to one of the following:'
            '\n1. Workspace ID is wrong.'
            '\n2. Missing necessary grant IAM privileges in your workspace to the AAD Application.',
            e,
        ) from e
    return 'ok'


def execute_query_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = args['query']
    timeout = arg_to_number(args.get('timeout', 10)) or 10
    workspace_id = args.get('workspace_id') or demisto.params().get('workspaceID')

    full_url = f"{client.azure_cloud.endpoints.log_analytics_resource_id}/v1/workspaces/{workspace_id}/query"

    data = {
        "timespan": args.get('timespan'),
        "query": query,
        "workspaces": argToList(args.get('workspaces'))
    }

    remove_nulls_from_dictionary(data)

    response = client.http_request('POST', full_url=full_url, data=data,
                                   resource=client.azure_cloud.endpoints.log_analytics_resource_id, timeout=timeout)

    output = []

    readable_output = '## Query Results\n'
    for table in response.get('tables', []):
        name, columns, data = format_query_table(table)
        readable_output += tableToMarkdown(name=name,
                                           t=data,
                                           headers=columns,
                                           headerTransform=pascalToSpace,
                                           removeNull=True)
        output.append({
            'TableName': name,
            'Data': data,
            'Query': query
        })

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureLogAnalytics.Query',
        outputs_key_field='Query',
        outputs=output,
        raw_response=response
    )


def list_saved_searches_command(client: Client, args: dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get('page')) or 0
    limit = arg_to_number(args.get('limit')) or 50
    url_suffix = '/savedSearches'

    response = client.http_request('GET', url_suffix, resource=client.azure_cloud.endpoints.resource_manager)
    response = response.get('value')

    from_index = min(page * limit, len(response))
    to_index = min(from_index + limit, len(response))

    output = [
        flatten_saved_search_object(saved_search) for saved_search in response[from_index:to_index]
    ]

    readable_output = tableToMarkdown('Saved searches', output,
                                      headers=SAVED_SEARCH_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureLogAnalytics.SavedSearch',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def get_saved_search_by_id_command(client: Client, args: dict[str, Any]) -> CommandResults:
    saved_search_id = args['saved_search_id']
    url_suffix = f'/savedSearches/{saved_search_id}'
    response = client.http_request('GET', url_suffix, resource=client.azure_cloud.endpoints.resource_manager)
    output = flatten_saved_search_object(response)

    title = f'Saved search `{saved_search_id}` properties'
    readable_output = tableToMarkdown(title, output,
                                      headers=SAVED_SEARCH_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureLogAnalytics.SavedSearch',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def create_or_update_saved_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    saved_search_id = args['saved_search_id']
    display_name = args['display_name']
    category = args['category']
    query = args['query']
    etag = args.get('etag')

    if not etag and not (category and query and display_name):
        raise DemistoException('You must specify category, display_name and query arguments for creating a new saved search.')
    url_suffix = f'/savedSearches/{saved_search_id}'

    data = {
        'properties': {
            'category': category,
            'displayName': display_name,
            'functionAlias': args.get('function_alias'),
            'functionParameters': args.get('function_parameters'),
            'query': query,
            'tags': tags_arg_to_request_format(args.get('tags'))
        }
    }

    remove_nulls_from_dictionary(data.get('properties'))

    if etag:
        data['etag'] = etag

    response = client.http_request('PUT', url_suffix, data=data, resource=client.azure_cloud.endpoints.resource_manager)
    output = flatten_saved_search_object(response)

    title = f'Saved search `{saved_search_id}` properties'
    readable_output = tableToMarkdown(title, output,
                                      headers=SAVED_SEARCH_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureLogAnalytics.SavedSearch',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def delete_saved_search_command(client: Client, args: dict[str, Any]) -> str:
    saved_search_id = args['saved_search_id']
    url_suffix = f'/savedSearches/{saved_search_id}'

    client.http_request('DELETE', url_suffix, resource=client.azure_cloud.endpoints.resource_manager)

    return f'Successfully deleted the saved search {saved_search_id}.'


def subscriptions_list_command(client: Client) -> CommandResults:
    response = client.http_request(
        "GET",
        full_url=f"{client.azure_cloud.endpoints.resource_manager}subscriptions",
        params={"api-version": SUBSCRIPTION_LIST_API_VERSION},
        resource=client.azure_cloud.endpoints.resource_manager,
    )
    value = response.get('value', [])

    subscriptions = []
    for subscription in value:
        subscription_context = {
            'Subscription ID': subscription.get('subscriptionId'),
            'Tenant ID': subscription.get('tenantId'),
            'State': subscription.get('state'),
            'Display Name': subscription.get('displayName')
        }
        subscriptions.append(subscription_context)

    human_readable = tableToMarkdown('List of subscriptions', subscriptions, removeNull=True)

    return CommandResults(
        outputs_prefix='AzureLogAnalytics.Subscription',
        outputs_key_field='id',
        outputs=value,
        readable_output=human_readable,
        raw_response=value
    )


def workspace_list_command(client: Client) -> CommandResults:
    """
    Gets workspaces in a resource group.
    Returns:
        List[dict]: API response from Azure.
    """
    full_url = (
        f"{client.azure_cloud.endpoints.resource_manager}subscriptions/{client.subscription_id}/resourceGroups/"
        f"{client.resource_group_name}/providers/Microsoft.OperationalInsights/workspaces"
    )
    response = client.http_request('GET', full_url=full_url, params={
                                   'api-version': API_VERSION}, resource=client.azure_cloud.endpoints.resource_manager)
    value = response.get('value', [])

    workspaces = []
    for workspace in value:
        workspace_context = {
            'Name': workspace.get('name'),
            'Location': workspace.get('location'),
            'Tags': workspace.get('tags'),
            'Provisioning State': workspace.get('properties', {}).get('provisioningState')
        }
        workspaces.append(workspace_context)

    readable_output = tableToMarkdown('Workspaces List', workspaces, removeNull=True)

    return CommandResults(
        outputs_prefix='AzureLogAnalytics.workspace',
        outputs_key_field='id',
        outputs=value,
        raw_response=value,
        readable_output=readable_output
    )


def resource_group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List all resource groups.
    Args:
        tag (str): Tag to filter by.
        limit (int): Maximum number of resource groups to retrieve. Default is 50.
    Returns:
        List[dict]: API response from Azure.
    """
    limit = arg_to_number(args.get('limit')) or 50
    tag = args.get('tag', '')

    raw_responses = []
    resource_groups: list[dict] = []

    next_link = True
    while next_link and len(resource_groups) < limit:
        full_url = next_link if isinstance(next_link, str) else None
        response = client.resource_group_list_request(tag=tag, limit=limit, full_url=full_url)

        value = response.get('value', [])
        next_link = full_url = response.get('nextLink', '')

        raw_responses.extend(value)
        for resource_group in value:
            resource_group_context = {
                'Name': resource_group.get('name'),
                'Location': resource_group.get('location'),
                'Tags': resource_group.get('tags'),
                'Provisioning State': resource_group.get('properties', {}).get('provisioningState')
            }
            resource_groups.append(resource_group_context)

    raw_responses = raw_responses[:limit]
    resource_groups = resource_groups[:limit]
    readable_output = tableToMarkdown('Resource Groups List', resource_groups, removeNull=True)

    return CommandResults(
        outputs_prefix='AzureLogAnalytics.ResourceGroup',
        outputs_key_field='id',
        outputs=raw_responses,
        raw_response=raw_responses,
        readable_output=readable_output
    )


def get_search_job_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve information about a search job in Azure Log Analytics.

    Args:
        client (Client): An instance of the Azure Log Analytics client.
        args (dict): A dictionary containing the command arguments, including 'table_name'.

    Returns:
        CommandResults: A CommandResults object containing the retrieved search job information.
    """
    response = get_search_job(client, args['table_name'])

    properties: dict = response["properties"]
    schema: dict = properties["schema"]

    # Extract search results from schema or properties, the response sometimes returns it in schema sometimes in properties
    # https://github.com/MicrosoftDocs/azure-docs/issues/116671
    searchResults: dict = schema.get("searchResults", {}) or properties.get("searchResults", {})

    readable_output = {
        "Name": schema["name"],
        "Create Date": properties["createDate"],
        "Plan": properties["plan"],
        "Query": searchResults["query"],
        "Description": searchResults["description"],
        "startSearchTime": searchResults["startSearchTime"],
        "endSearchTime": searchResults["endSearchTime"],
        "provisioningState": properties["provisioningState"]
    }
    return CommandResults(
        readable_output=tableToMarkdown("Search Job", readable_output),
        outputs=response,
        outputs_prefix="AzureLogAnalytics.SearchJob",
        outputs_key_field="id"
    )


def get_search_job(client: Client, table_name: str) -> dict:
    url_suffix = f"/tables/{table_name}"
    response = client.http_request(
        'GET',
        url_suffix,
        resource=client.azure_cloud.endpoints.resource_manager
    )

    return response


@polling_function(
    name="azure-log-analytics-run-search-job",
    interval=arg_to_number(demisto.args().get("interval", 60)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    requires_polling_arg=False,  # means it will always default to poll
)
def run_search_job_command(args: dict[str, Any], client: Client) -> PollResult:
    """
    Run a search job command in Azure Log Analytics and handle polling for the job's status.
    Note: The argument `first_run` is `hidden: true` in the yml file,
            and is used to determine if this is the first time the function runs.

    Args:
        args (dict): A dictionary containing the command arguments, including 'table_name', 'query',
                     'limit', 'start_search_time', 'end_search_time', and 'first_run'.
        client (Client): An instance of the Azure Log Analytics client.

    Returns:
        PollResult: A PollResult object indicating whether the polling should continue and the response
                    to return.

    This function handles the execution of a search job command in Azure Log Analytics. It supports polling
    to check the status of the job. The behavior depends on whether it's the first run or a subsequent run:

    - First Run:
        - Validates the 'table_name' to ensure it ends with the appropriate suffix.
        - Sends a 'PUT' request to create the search job using the provided parameters.
        - Handles exceptions related to job existence.
        - Returns a PollResult indicating to continue polling for job status.

    - Subsequent Runs:
        - Checks the status of the previously created search job.
        - If the job is successful ('Succeeded'), it returns a PollResult to stop polling and provides
          a readable output for success.
        - If the job is still in progress, it returns a PollResult to continue polling.

    The polling interval and timeout are determined based on the command arguments.
    """
    table_name: str = args['table_name']
    if not table_name.endswith(TABLE_NAME_SUFFIX):
        raise DemistoException(f"The table_name should end with '{TABLE_NAME_SUFFIX}' suffix.")

    if argToBoolean(args["first_run"]):
        if start_search_time_datetime := arg_to_datetime(args.get('start_search_time', '1 day ago'), "start_search_time"):
            start_search_time_iso = start_search_time_datetime.isoformat()
        else:
            start_search_time_iso = None
            demisto.debug(f"{start_search_time_datetime=} -> {start_search_time_iso=}")
        if end_search_time_datetime := arg_to_datetime(args.get('end_search_time', 'now'), "end_search_time"):
            end_search_time_iso = end_search_time_datetime.isoformat()
        else:
            end_search_time_iso = None
            demisto.debug(f"{end_search_time_datetime=} -> {end_search_time_iso=}")
        url_suffix = f"/tables/{table_name}"
        data = {
            "properties": {
                "searchResults": {
                    "query": args['query'],
                    "limit": arg_to_number(args.get('limit')),
                    "startSearchTime": start_search_time_iso,
                    "endSearchTime": end_search_time_iso
                }
            }
        }
        try:
            client.http_request(
                'PUT',
                url_suffix,
                resource=client.azure_cloud.endpoints.resource_manager,
                data=data
            )  # the response contain only the status code [202]
        except Exception as e:
            if "[InvalidParameter 400] This operation is not permitted as properties.searchResult is immutable." in e.args[0]:
                raise DemistoException(
                    f"Search job {table_name} already exists - please choose another name."
                ) from e
            raise e
        args["first_run"] = False
        return PollResult(
            response=None,
            args_for_next_run=args,
            continue_to_poll=True,
            partial_result=CommandResults(
                readable_output=(
                    "The command was sent successfully. "
                    "You can check the status of the command by running !azure-log-analytics-get-search-job command or wait."
                )
            )
        )
    else:
        status = get_search_job(client, table_name)["properties"]["provisioningState"]
        if status != "Succeeded":
            return PollResult(
                continue_to_poll=True,
                args_for_next_run=args,
                response=None,
            )

        return PollResult(
            continue_to_poll=False,
            response=CommandResults(
                outputs_prefix="AzureLogAnalytics.RunSearchJob",
                outputs_key_field="TableName",
                outputs={"TableName": table_name, "Query": args["query"]},
                readable_output=(
                    f"The {table_name} table created successfully. "
                    f"The table can be queried by running the following command: "
                    f"!azure-log-analytics-execute-query query={table_name}"
                )
            )
        )


def delete_search_job_command(client: Client, args: dict[str, str]) -> CommandResults:
    table_name = args['table_name']
    if not table_name.endswith(TABLE_NAME_SUFFIX):
        raise DemistoException(f"Deleting tables without '{TABLE_NAME_SUFFIX}' suffix is not allowed.")
    url_suffix = f"/tables/{table_name}"

    client.http_request('DELETE', url_suffix, resource=client.azure_cloud.endpoints.resource_manager)

    return CommandResults(readable_output=f"Search job {table_name} deleted successfully.")


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    demisto.debug(f"##### AzureLogAnalytics ##### {params.get('azure_cloud')=}")

    try:
        self_deployed = params.get('self_deployed', False)
        client_credentials = params.get('client_credentials', False)
        auth_and_token_url = params.get('auth_id') or params.get('credentials', {}).get('identifier')  # client_id
        enc_key = params.get('enc_key') or params.get('credentials', {}).get('password')  # client_secret
        subscription_id = args.get('subscription_id') or params.get('subscriptionID')
        resource_group_name = args.get('resource_group_name') or params.get('resourceGroupName')
        workspace_name = args.get('workspace_name') or params.get('workspaceName')
        certificate_thumbprint = params.get('credentials_certificate_thumbprint', {}).get(
            'password') or params.get('certificate_thumbprint')
        private_key = params.get('private_key')
        managed_identities_client_id = get_azure_managed_identities_client_id(params)
        self_deployed = self_deployed or client_credentials or managed_identities_client_id is not None
        refresh_token = params.get('credentials_refresh_token', {}).get('password') or params.get('refresh_token')
        auth_code = params.get('credentials_auth_code', {}).get('password') or params.get('auth_code')
        validate_params(
            refresh_token,
            managed_identities_client_id,
            client_credentials,
            enc_key,
            self_deployed,
            certificate_thumbprint,
            private_key
        )

        client = Client(
            self_deployed=self_deployed,
            auth_and_token_url=auth_and_token_url,  # client_id or auth_id
            refresh_token=refresh_token,  # tenant_id or token
            enc_key=enc_key,  # client_secret or enc_key
            redirect_uri=params.get('redirect_uri', ''),
            auth_code=auth_code if not client_credentials else '',
            subscription_id=subscription_id,
            resource_group_name=resource_group_name,
            workspace_name=workspace_name,
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            client_credentials=client_credentials,
            azure_cloud=get_azure_cloud(params, 'Azure Log Analytics'),
            managed_identities_client_id=managed_identities_client_id,
        )

        commands: dict[str, Callable[[Client, dict], CommandResults | str]] = {
            'azure-log-analytics-execute-query': execute_query_command,
            'azure-log-analytics-list-saved-searches': list_saved_searches_command,
            'azure-log-analytics-get-saved-search-by-id': get_saved_search_by_id_command,
            'azure-log-analytics-create-or-update-saved-search': create_or_update_saved_search_command,
            'azure-log-analytics-delete-saved-search': delete_saved_search_command,
            'azure-log-analytics-get-search-job': get_search_job_command,
            'azure-log-analytics-delete-search-job': delete_search_job_command,
            'azure-log-analytics-resource-group-list': resource_group_list_command,
        }

        if command == 'test-module':
            if client_credentials or managed_identities_client_id:
                test_connection(client, params)
                return_results('ok')
            else:
                # In authorization code flow cannot use test module
                # due to the lack of ability to set refresh token to integration context
                raise Exception("Please use !azure-log-analytics-test instead")

        elif command == 'azure-log-analytics-generate-login-url':
            return_results(generate_login_url(client.ms_client))

        elif command == 'azure-log-analytics-test':
            test_connection(client, params)
            return_outputs('```✅ Success!```')

        elif command == 'azure-log-analytics-auth-reset':
            return_results(reset_auth())

        elif command == 'azure-log-analytics-subscriptions-list':
            return_results(subscriptions_list_command(client))

        elif command == 'azure-log-analytics-workspace-list':
            return_results(workspace_list_command(client))

        elif command == 'azure-log-analytics-run-search-job':
            return_results(run_search_job_command(args, client))

        elif command in commands:
            return_results(commands[command](client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
