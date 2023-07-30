import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from MicrosoftApiModule import *  # noqa: E402


''' IMPORTS '''
import urllib3


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''


''' HELPER FUNCTIONS '''


def create_search_request_body(query_string: str, entity_type: str):
    return {
        "requests": [
            {
                "entityTypes": [entity_type],
                "query": {
                    "queryString": query_string
                }
            }
        ]
    }


''' MICROSOFT GRAPH CLIENT '''


class MsGraphClient:
    def __init__(self, tenant_id, auth_and_token_url, enc_key, base_url, use_ssl, proxy,
                 ok_codes, refresh_token, auth_code, redirect_uri, certificate_thumbprint: Optional[str] = None,
                 private_key: Optional[str] = None):
        self.ms_client = MicrosoftClient(self_deployed=True, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                         enc_key=enc_key, base_url=base_url, verify=use_ssl,
                                         proxy=proxy, ok_codes=ok_codes, refresh_token=refresh_token,
                                         auth_code=auth_code, redirect_uri=redirect_uri,
                                         grant_type=AUTHORIZATION_CODE, certificate_thumbprint=certificate_thumbprint,
                                         private_key=private_key, retry_on_rate_limit=True,
                                         managed_identities_resource_uri=Resources.graph)

    def test_connection(self):
        """
        Basic connection test instead of test-module.

        :return: Returns markdown string representation of success or Exception in case of login failure.
        rtype: ``str`` or Exception
        """
        response = self.ms_client.http_request('POST', '/search/query', json_data=create_search_request_body('test', 'driveItem'))
        if response.get('@odata.context'):
            return '```✅ Success!```'
        else:
            raise Exception("Failed validating the user.")

    def search_content_command(self, args):
        response = self.ms_client.http_request(
            'POST', '/search/query', json_data=create_search_request_body(args['query_string'], args['entity_type']))
        table = []
        if response['value'][0]['hitsContainers'][0]['total'] > 0:
            for hit in response['value'][0]['hitsContainers'][0]['hits']:
                row = {
                    'Summary': hit['summary'],
                    'WebURL': hit['resource']['webUrl']
                }
                if args['entity_type'] != 'listItem':
                    row['Name'] = hit['resource']['name']
                    if args['entity_type'] == 'site':
                        row['DisplayName'] = hit['resource']['displayName']
                table.append(row)

        readable_output = tableToMarkdown(f'''Files within SharePoint sites containing string: "{args['query_string']}"''', table)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='SearchContent',
            outputs=response,
            raw_response=response
        )


def main():     # pragma: no cover
    """ COMMANDS MANAGER / SWITCH PANEL """
    params = demisto.params()
    # params related to common instance configuration
    base_url = 'https://graph.microsoft.com/v1.0/'
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    ok_codes = (200, 201, 202)
    refresh_token = params.get('creds_refresh_token', {}).get('password')
    auth_and_token_url = params.get('creds_auth_id', {}).get('password')
    enc_key = params.get('creds_enc_key', {}).get('password')
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier')
    private_key = replace_spaces_in_credential(params.get('creds_certificate', {}).get('password')) or params.get('private_key')
    auth_code = params.get('creds_auth_code', {}).get('password')

    if not enc_key:
        raise DemistoException('Key must be provided. For further information see '
                               'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
    elif not enc_key and not (certificate_thumbprint and private_key):
        raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')

    # params related to self deployed
    tenant_id = refresh_token

    # In case the script is running for the first time, refresh token is retrieved from integration parameters,
    # in other case it's retrieved from integration context.
    refresh_token = get_integration_context().get('current_refresh_token') or refresh_token

    client = MsGraphClient(tenant_id, auth_and_token_url, enc_key, base_url, use_ssl, proxy,
                           ok_codes, refresh_token, auth_code=auth_code, private_key=private_key,
                           redirect_uri=params.get('redirect_uri', ''), certificate_thumbprint=certificate_thumbprint)
    try:
        command = demisto.command()
        LOG(f'Command being called is {command}')
        if command == 'test-module':
            # cannot use test module due to the lack of ability to set refresh token to integration context
            raise Exception("Please use !msgraph-search-test instead")
        if command == 'msgraph-search-test':
            return_results(client.test_connection())
        elif command == 'msgraph-search-generate-login-url':
            return_results(generate_login_url(client.ms_client))
        elif command == 'msgraph-search-content':
            return_results(client.search_content_command(demisto.args()))
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
