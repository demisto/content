import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

APP_NAME = 'ms-azure-log-analytics'

API_VERSION = '2020-03-01-preview'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n'\
                          'The response from the server did not contain the expected content.'

SAVED_SEARCH_HEADERS = [
    'etag', 'id', 'category', 'displayName', 'functionAlias', 'functionParameters', 'query', 'tags', 'version', 'type'
]

LOG_ANALYTICS_RESOURCE = 'https://api.loganalytics.io'
AZURE_MANAGEMENT_RESOURCE = 'https://management.azure.com'


class Client:
    def __init__(self, self_deployed, refresh_token, auth_and_token_url, enc_key, redirect_uri, auth_code,
                 subscription_id, resource_group_name, workspace_name, verify, proxy):

        tenant_id = refresh_token if self_deployed else ''
        refresh_token = (demisto.getIntegrationContext().get('current_refresh_token') or refresh_token)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/' \
            f'{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}'
        self.ms_client = MicrosoftClient(
            self_deployed=self_deployed,
            auth_id=auth_and_token_url,
            refresh_token=refresh_token,
            enc_key=enc_key,
            redirect_uri=redirect_uri,
            token_retrieval_url='https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            grant_type=AUTHORIZATION_CODE,  # disable-secrets-detection
            app_name=APP_NAME,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            scope='',
            tenant_id=tenant_id,
            auth_code=auth_code,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404),
            multi_resource=True,
            resources=[AZURE_MANAGEMENT_RESOURCE, LOG_ANALYTICS_RESOURCE]
        )

    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None, resource=None):
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
                                          resource=resource)
        res_json = res.json()

        if res.status_code in (400, 401, 403, 404):
            code = res_json.get('error', {}).get('code', 'Error')
            error_msg = res_json.get('error', {}).get('message', res_json)
            raise ValueError(
                f'[{code} {res.status_code}] {error_msg}'
            )

        return res_json


''' INTEGRATION HELPER METHODS '''


def format_query_table(table):
    name = table.get('name')
    columns = [column.get('name') for column in table.get('columns')]
    rows = table.get('rows')
    data = [
        {k: v for k, v in zip(columns, row)} for row in rows
    ]

    return tableToMarkdown(name=name,
                           t=data,
                           headers=columns,
                           removeNull=True)


def query_output_to_readable(tables):
    readable_output = '## Query Results\n'
    readable_output += '\n'.join(tables)

    return readable_output


def flatten_saved_search_object(saved_search_obj):
    ret = saved_search_obj.get('properties')
    ret['id'] = saved_search_obj.get('id')
    ret['etag'] = saved_search_obj.get('etag')
    ret['type'] = saved_search_obj.get('type')

    return ret


def parse_tags(tags):
    if not tags:
        return None
    try:
        tags = tags.split(';')
        tags = [tag.split('=') for tag in tags]
        return [{
            tag[0]: tag[1]
        } for tag in tags]
    except IndexError:
        raise ValueError('The `tags` argument is malformed. '
                         'Value should be in the following format: `name=value;name=value`')


''' INTEGRATION COMMANDS '''


def test_connection(client, params):
    if params.get('self_deployed', False) and not params.get('auth_code'):
        return_error('You must enter an authorization code in a self-deployed configuration.')
    client.ms_client.get_access_token(AZURE_MANAGEMENT_RESOURCE)  # If fails, MicrosoftApiModule returns an error
    return_outputs('```✅ Success!```')


def execute_query_command(client, args):
    workspace_id = args.get('workspace_id')
    full_url = f'https://api.loganalytics.io/v1/workspaces/{workspace_id}/query'

    data = {
        "timespan": args.get('timespan'),
        "query": args.get('query'),
        "workspaces": argToList(args.get('workspaces'))
    }

    remove_nulls_from_dictionary(data)

    response = client.http_request('POST', full_url=full_url, data=data,
                                   resource=LOG_ANALYTICS_RESOURCE)

    output = [format_query_table(table) for table in response]

    return CommandResults(
        readable_output=query_output_to_readable(output),
        outputs_prefix='AzureLogAnalytics.Query',
        outputs=response,
        raw_response=response
    )


def list_saved_searches_command(client, args):
    page = int(args.get('page'))
    limit = min(50, int(args.get('limit')))
    url_suffix = '/savedSearches'

    response = client.http_request('GET', url_suffix, resource=AZURE_MANAGEMENT_RESOURCE)
    response = response.get('value')

    from_index = min(page, len(response))
    to_index = min(from_index + limit, len(response))

    output = [
        flatten_saved_search_object(saved_search) for saved_search in response
    ][from_index:to_index]

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


def get_saved_search_by_id_command(client, args):
    saved_search_id = args.get('saved_search_id')
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


def create_or_update_saved_search_command(client, args):
    saved_search_id = args.get('saved_search_id')
    url_suffix = f'/savedSearches/{saved_search_id}'

    data = {
      'properties': {
        'category': args.get('category'),
        'displayName': args.get('display_name'),
        'functionAlias': args.get('function_alias'),
        'functionParameters': args.get('function_parameters'),
        'query': args.get('query'),
        'tags': parse_tags(args.get('tags'))
      }
    }

    remove_nulls_from_dictionary(data)

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


def delete_saved_search_command(client, args):
    saved_search_id = args.get('saved_search_id')
    url_suffix = f'/savedSearches/{saved_search_id}'

    client.http_request('DELETE', url_suffix, resource=AZURE_MANAGEMENT_RESOURCE)

    return f'Successfully deleted the saved search `{saved_search_id}`.'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            self_deployed=params.get('self_deployed', False),
            auth_and_token_url=params.get('auth_id', ''),
            refresh_token=params.get('refresh_token', ''),
            enc_key=params.get('enc_key', ''),
            redirect_uri=params.get('redirect_uri', ''),
            auth_code=params.get('auth_code', ''),
            subscription_id=params.get('subscriptionID', ''),
            resource_group_name=params.get('resourceGroupName', ''),
            workspace_name=params.get('workspaceName', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False)
        )

        commands = {
            'azure-log-analytics-execute-query': execute_query_command,
            'azure-log-analytics-saved-search-list': list_saved_searches_command,
            'azure-log-analytics-get-saved-search-by-id': get_saved_search_by_id_command,
            'azure-log-analytics-saved-search-create-or-update': create_or_update_saved_search_command,
            'azure-log-analytics-saved-search-delete': delete_saved_search_command
        }

        if demisto.command() == 'test-module':
            # cannot use test module due to the lack of ability to set refresh token to integration context
            raise Exception("Please use !azure-log-analytics-test instead")

        elif demisto.command() == 'azure-log-analytics-test':
            test_connection(client, params)

        elif demisto.command() in commands:
            return_results(commands[demisto.command()](client, demisto.args()))  # type: ignore

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
