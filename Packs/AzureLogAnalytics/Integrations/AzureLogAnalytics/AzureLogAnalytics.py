from collections.abc import Callable
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from MicrosoftApiModule import *  # noqa: E402
from json import JSONDecodeError

''' CONSTANTS '''

APP_NAME = 'ms-azure-log-analytics'

API_VERSION = "2021-12-01-preview" #'2021-06-01'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n'\
                          'The response from the server did not contain the expected content.'

SAVED_SEARCH_HEADERS = [
    'etag', 'id', 'category', 'displayName', 'functionAlias', 'functionParameters', 'query', 'tags', 'version', 'type'
]
PARAMS = demisto.params()
LOG_ANALYTICS_RESOURCE = 'https://api.loganalytics.io'
AZURE_MANAGEMENT_RESOURCE = 'https://management.azure.com'
AUTH_CODE_SCOPE = 'https://api.loganalytics.io/Data.Read%20https://management.azure.com/user_impersonation'


class Client:
    def __init__(self, self_deployed, refresh_token, auth_and_token_url, enc_key, redirect_uri, auth_code,
                 subscription_id, resource_group_name, workspace_name, verify, proxy, certificate_thumbprint,
                 private_key, client_credentials, managed_identities_client_id=None):

        tenant_id = refresh_token if self_deployed else ''
        refresh_token = get_integration_context().get('current_refresh_token') or refresh_token
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/' \
            f'{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}'
        self.ms_client = MicrosoftClient(
            self_deployed=self_deployed,
            auth_id=auth_and_token_url,  # client_id for client credential
            refresh_token=refresh_token,
            enc_key=enc_key,  # client_secret for client credential
            redirect_uri=redirect_uri,
            token_retrieval_url='https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            grant_type=CLIENT_CREDENTIALS if client_credentials else AUTHORIZATION_CODE,  # disable-secrets-detection
            app_name=APP_NAME,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            scope='' if client_credentials else AUTH_CODE_SCOPE,
            tenant_id=tenant_id,
            auth_code=auth_code,
            ok_codes=(200, 202, 204, 400, 401, 403, 404, 409),
            multi_resource=True,
            resources=[AZURE_MANAGEMENT_RESOURCE, LOG_ANALYTICS_RESOURCE],
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-log-analytics",
        )

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

        if res.status_code in (200, 204) and not res.text:
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


def format_query_table(table: dict[str, Any]):
    name = table.get('name')
    columns = [column.get('name') for column in table.get('columns', [])]
    rows = table.get('rows', [])
    data = [
        dict(zip(columns, row)) for row in rows
    ]

    return name, columns, data


def query_output_to_readable(tables):  #TODO no use
    tables_markdown = [tableToMarkdown(name=name,
                                       t=data,
                                       headers=columns,
                                       headerTransform=pascalToSpace,
                                       removeNull=True) for name, columns, data in tables]
    readable_output = '## Query Results\n' + '\n'.join(tables_markdown)
    return readable_output


def flatten_saved_search_object(saved_search_obj : dict[str, Any]) -> dict[str, Any]:
    ret: dict = saved_search_obj.get('properties', {})
    ret['id'] = saved_search_obj.get('id','').split('/')[-1]
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
                return_error(bad_arg_msg)

        return [{
            'name': tag[0],
            'value': tag[1]
        } for tag in tags]
    except IndexError:
        return_error(bad_arg_msg)
    return None

''' INTEGRATION COMMANDS '''


def test_connection(client: Client, params: dict[str, Any]) -> str:
    if (
        not client.ms_client.managed_identities_client_id
        and params.get('self_deployed', False)
        and not params.get('client_credentials')
        and not params.get('credentials_auth_code', {}).get('password')
        and not params.get('auth_code')
    ):
        return_error('You must enter an authorization code in a self-deployed configuration.')

    client.ms_client.get_access_token(AZURE_MANAGEMENT_RESOURCE)  # If fails, MicrosoftApiModule returns an error
    try:
        execute_query_command(client, {'query': 'Usage | take 1'})
    except Exception as e:
        return_error('Could not authorize to `api.loganalytics.io` resource. This could be due to one of the following:'
                     '\n1. Workspace ID is wrong.'
                     '\n2. Missing necessary grant IAM privileges in your workspace to the AAD Application.', e)
    return 'ok'


def execute_query_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = args['query']
    timeout = arg_to_number(args.get('timeout', 10))
    workspace_id = demisto.params().get('workspaceID')
    full_url = f'https://api.loganalytics.io/v1/workspaces/{workspace_id}/query'

    data = {
        "timespan": args.get('timespan'),
        "query": query,
        "workspaces": argToList(args.get('workspaces'))
    }

    remove_nulls_from_dictionary(data)

    response = client.http_request('POST', full_url=full_url, data=data,
                                   resource=LOG_ANALYTICS_RESOURCE, timeout=timeout)

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

    response = client.http_request('GET', url_suffix, resource=AZURE_MANAGEMENT_RESOURCE)
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

    response = client.http_request('GET', url_suffix, resource=AZURE_MANAGEMENT_RESOURCE)
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
        return_error('You must specify category, display_name and query arguments for creating a new saved search.')
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

    response = client.http_request('PUT', url_suffix, data=data, resource=AZURE_MANAGEMENT_RESOURCE)
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

    client.http_request('DELETE', url_suffix, resource=AZURE_MANAGEMENT_RESOURCE)

    return f'Successfully deleted the saved search {saved_search_id}.'


def get_search_job_status(client: Client, table_name: str) -> str:
    url_suffix = f"/tables/{table_name}_SRCH"
    response = client.http_request(
                'GET',
                url_suffix,
                resource=AZURE_MANAGEMENT_RESOURCE,
                timeout=60
            )

    return response["properties"]["provisioningState"]

@polling_function(
    name="azure-log-analytics-run-search-job",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", 60),),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    requires_polling_arg=False,  # means it will always default to poll
)
def run_search_job_command(args: dict[str, Any], client: Client) -> PollResult:
    table_name = args['table_name']
    if argToBoolean(args["first_run"]):
        query = args['query']
        limit = arg_to_number(args['limit'])
        start_search_time = args.get('start_search_time')
        end_search_time = args.get('end_search_time')
        timespan = args.get('timespan')
        url_suffix = f"/tables/{table_name}_SRCH"
        data = {
        "properties": { 
            "searchResults": {
                    "query": query,
                    "limit": limit,
                    "startSearchTime": start_search_time,
                    "endSearchTime": end_search_time
                }
        }
    }
        try:
            client.http_request(
                'PUT',
                url_suffix,
                resource=AZURE_MANAGEMENT_RESOURCE,
                data=data,
                timeout=60
            )
        except JSONDecodeError as e:
            print(e)
        except Exception as e:
            if "[InvalidParameter 400] This operation is not permitted as properties.searchResult is immutable." in  e.args[0]:
                return_warning(f"Search job {table_name}_SRCH already exists - please choose another name", exit=True)
            raise e
        args["first_run"] = False
        return PollResult(
            response=None,
            partial_result=CommandResults(readable_output="Command was sent successfully."),
            args_for_next_run=args,
            continue_to_poll=True
        )
    else:
        if get_search_job_status(client, table_name) not in ["Succeeded"]:
            return PollResult(
                continue_to_poll=True,
                args_for_next_run=args,
                response=None,
            )
        else:
            args["workspaces"] = demisto.params()['workspaceName']
            args["query"] = f'{table_name}_SRCH'
            
            return PollResult(
                continue_to_poll=False,
                response=execute_query_command(client, args)
            )
        

def validate_params(refresh_token, managed_identities_client_id, client_credentials, enc_key, self_deployed, certificate_thumbprint, private_key):
    if not refresh_token:
        raise DemistoException('Token / Tenant ID must be provided.')
    if not managed_identities_client_id:
        if client_credentials and not enc_key:
            raise DemistoException("Client Secret must be provided for client credentials flow.")
        elif not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                    'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')  # noqa: E501
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')
    

def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:
        self_deployed = params.get('self_deployed', False)
        client_credentials = params.get('client_credentials', False)
        auth_and_token_url = params.get('auth_id') or params.get('credentials', {}).get('identifier')  # client_id
        enc_key = params.get('enc_key') or params.get('credentials', {}).get('password')  # client_secret
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
            subscription_id=params['subscriptionID'],
            resource_group_name=params['resourceGroupName'],
            workspace_name=params['workspaceName'],
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            client_credentials=client_credentials,
            managed_identities_client_id=managed_identities_client_id,
        )

        commands: dict[str, Callable[[Client, dict], CommandResults | str]] = {
            'azure-log-analytics-execute-query': execute_query_command,
            'azure-log-analytics-list-saved-searches': list_saved_searches_command,
            'azure-log-analytics-get-saved-search-by-id': get_saved_search_by_id_command,
            'azure-log-analytics-create-or-update-saved-search': create_or_update_saved_search_command,
            'azure-log-analytics-delete-saved-search': delete_saved_search_command,
        }

        if command == 'test-module':
            if not managed_identities_client_id:
                # cannot use test module if not using Managed Identities
                # due to the lack of ability to set refresh token to integration context
                raise Exception("Please use !azure-log-analytics-test instead")

            test_connection(client, params)
            return_results('ok')

        elif command == 'azure-log-analytics-generate-login-url':
            return_results(generate_login_url(client.ms_client))

        elif command == 'azure-log-analytics-test':
            test_connection(client, params)
            return_outputs('```✅ Success!```')

        elif command == 'azure-log-analytics-auth-reset':
            return_results(reset_auth())
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
