import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from MicrosoftApiModule import *  # noqa: E402

import urllib3
from typing import Any

urllib3.disable_warnings()


class MsGraphClient:
    def __init__(self,
                 app_id: str,
                 scope: str,
                 app_secret: str,
                 tenant_id: str,
                 verify: bool,
                 proxy: bool,
                 azure_cloud: AzureCloud,
                 auth_code: str,
                 redirect_uri: str,
                 certificate_thumbprint: str | None = None,
                 private_key: str | None = None,
                 managed_identities_client_id: str | None = None,
                 ):
        client_args = {
            'base_url': azure_cloud.endpoints.microsoft_graph_resource_id.rstrip("/"),
            'auth_id': app_id,
            'scope': Scopes.graph,
            'enc_key': app_secret,
            'tenant_id': tenant_id,
            'verify': verify,
            'proxy': proxy,
            'self_deployed': True,
            'grant_type': AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS,
            'ok_codes': (200, 201, 204),
            'azure_ad_endpoint': azure_cloud.endpoints.active_directory,
            'private_key': private_key,
            'certificate_thumbprint': certificate_thumbprint,
            'managed_identities_client_id': managed_identities_client_id,
            'managed_identities_resource_uri': Resources.graph,
            'azure_cloud': azure_cloud,
            'auth_code': auth_code,
            'redirect_uri': redirect_uri,
            'command_prefix': "msgraph-api",
        }
        if not ((app_secret or (certificate_thumbprint and private_key)) and tenant_id):
            client_args['grant_type'] = DEVICE_CODE
            client_args['token_retrieval_url'] = urljoin(azure_cloud.endpoints.active_directory,
                                                         '/organizations/oauth2/v2.0/token')
            client_args['scope'] = scope
        self.ms_client = MicrosoftClient(**client_args)  # type: ignore[arg-type]

    def generic_request(
        self,
        resource: str,
        http_method: str = 'GET',
        api_version: str = 'v1.0',
        odata: str | None = None,
        request_body: dict | None = None,
        headers: dict | None = None
    ):
        url_suffix = urljoin(api_version, resource)
        if odata:
            url_suffix += f'?{odata}'
        res = self.ms_client.http_request(
            method=http_method,
            url_suffix=url_suffix,
            json_data=request_body,
            resp_type='resp',
            headers=headers
        )
        return res.json() if res.content else None


def start_auth(client: MsGraphClient) -> CommandResults:  # pragma: no cover
    result = client.ms_client.start_auth('!msgraph-api-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: MsGraphClient):  # pragma: no cover
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_module(client: MsGraphClient,
                managed_identities_client_id: str | None) -> str:  # pragma: no cover
    if client.ms_client.grant_type == CLIENT_CREDENTIALS or managed_identities_client_id:
        client.ms_client.get_access_token()
        return 'ok'
    else:
        raise DemistoException('The *Test* button is not available when using `Cortex XSOAR Azure app`, '
                               '`self-deployed - Device Code Flow` or '
                               ' `self-deployed - Authorization Code Flow`. '
                               'Use the !msgraph-api-test command instead once all relevant parameters have been entered.')


def test_command(client: MsGraphClient) -> CommandResults:  # pragma: no cover
    client.ms_client.get_access_token()
    return CommandResults(readable_output='```✅ Success!```')


def generic_command(client: MsGraphClient, args: dict[str, Any]) -> CommandResults:
    request_body = args.get('request_body')
    results: dict
    if request_body and isinstance(request_body, str):
        try:
            request_body = json.loads(request_body)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Invalid request body - {str(e)}')
    headers = args.get('headers')

    http_method = args.get('http_method', 'GET')

    response = client.generic_request(
        resource=args.get('resource', ''),
        http_method=http_method,
        api_version=args.get('api_version', 'v1.0'),
        odata=args.get('odata', ''),
        request_body=request_body,
        headers=dict(subString.split(":") for subString in headers.split(',')) if headers else None
    )

    if not response:
        results = {
            'readable_output': 'The API query ran successfully and returned no content.',
        }
    else:
        results = {'raw_response': response}

        if argToBoolean(args.get('populate_context', 'true')):
            outputs = get_response_outputs(response)
            if outputs is True:
                return CommandResults(readable_output='The API query ran successfully and returned no content.')
            results['outputs'] = outputs
            results['outputs_prefix'] = 'MicrosoftGraph'

    return CommandResults(**results)  # type: ignore[arg-type]


def get_response_outputs(response: dict) -> Union[dict, list]:
    if 'value' in response:
        return response['value']
    res = dict(response)
    res.pop('@odata.context', None)
    return res


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    scope = 'offline_access '
    if params.get('scope'):
        scope += params.get('scope')

    azure_cloud = get_azure_cloud(params, 'MicrosoftGraphAPI')
    app_secret = params.get('app_secret') or (params.get('credentials') or {}).get('password')
    app_secret = app_secret if isinstance(app_secret, str) else ''
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier') or params.get('certificate_thumbprint')
    private_key = replace_spaces_in_credential(params.get('creds_certificate', {}).get('password')) or params.get('private_key')
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    auth_code = params.get('auth_code', {}).get('password', '')
    redirect_uri = params.get('redirect_uri', '')

    try:
        client = MsGraphClient(
            app_id=params.get('app_id'),
            scope=scope,
            app_secret=app_secret,
            tenant_id=params.get('tenant_id'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_cloud=azure_cloud,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
        )

        if command == 'test-module':
            result = test_module(client, managed_identities_client_id)
            return_results(result)
        elif command == 'msgraph-api-request':
            return_results(generic_command(client, demisto.args()))
        elif command == 'msgraph-api-auth-start':
            return_results(start_auth(client))
        elif command == 'msgraph-api-auth-complete':
            return_results(complete_auth(client))
        elif command == 'msgraph-api-test':
            return_results(test_command(client))
        elif command == 'msgraph-api-auth-reset':
            return_results(reset_auth())
        elif command == 'msgraph-api-generate-login-url':
            return_results(generate_login_url(client.ms_client))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
