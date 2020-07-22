import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# IMPORTS

import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

APP_NAME = 'ms-azure-log-analytics'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

API_VERSION = '2020-03-01-preview'

AUTHORIZATION_ERROR_MSG = 'There was a problem in retrieving an updated access token.\n'\
                          'The response from the server did not contain the expected content.'


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
            resource='https://api.loganalytics.io',
            scope='',
            tenant_id=tenant_id,
            auth_code=auth_code,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404)
        )

    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        res = self.ms_client.http_request(method=method,  # disable-secrets-detection
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params,
                                          resp_type='response')
        res_json = res.json()

        if res.status_code in (400, 401, 403, 404):
            code = res_json.get('error', {}).get('code', 'Error')
            error_msg = res_json.get('error', {}).get('message', res_json)
            raise ValueError(
                f'[{code} {res.status_code}] {error_msg}'
            )

        return res_json


def test_connection(client, params):
    if params.get('self_deployed', False) and not params.get('auth_code'):
        return_error('You must enter an authorization code in a self-deployed configuration.')
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return_outputs('```✅ Success!```')


def get_saved_search_by_id_command(client, args):
    saved_search_id = args.get('saved_search_id')
    url_suffix = f'savedSearches/{saved_search_id}'

    result = client.http_request('GET', url_suffix)
    incident = incident_data_to_demisto_format(result)

    outputs = {'AzureSentinel.Incident(val.ID === obj.ID)': incident}

    readable_output = tableToMarkdown(f'Incident {inc_id} details', incident,
                                      headers=INCIDENT_HEADERS,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Domain',
        outputs_key_field='domain',
        outputs=domain_data_list,
        indicators=domain_standard_list
    )


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
            return_results(*commands[demisto.command()](client, demisto.args()))  # type: ignore

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
