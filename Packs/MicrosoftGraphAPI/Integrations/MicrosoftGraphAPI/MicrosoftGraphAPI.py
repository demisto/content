import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
from typing import Any, Dict, Optional

urllib3.disable_warnings()


class MsGraphClient:
    def __init__(self,
                 app_id: str,
                 scope: str,
                 app_secret: str,
                 tenant_id: str,
                 verify: bool,
                 proxy: bool,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com'):
        client_args = {
            'base_url': 'https://graph.microsoft.com',
            'auth_id': app_id,
            'scope': Scopes.graph,
            'enc_key': app_secret,
            'tenant_id': tenant_id,
            'verify': verify,
            'proxy': proxy,
            'self_deployed': True,
            'grant_type': CLIENT_CREDENTIALS,
            'ok_codes': (200, 201, 204),
            'azure_ad_endpoint': azure_ad_endpoint
        }
        if not (app_secret and tenant_id):
            client_args['grant_type'] = DEVICE_CODE
            client_args['token_retrieval_url'] = f'{azure_ad_endpoint}/organizations/oauth2/v2.0/token'
            client_args['scope'] = scope
        self.ms_client = MicrosoftClient(**client_args)  # type: ignore[arg-type]

    def generic_request(
            self,
            resource: str,
            http_method: str = 'GET',
            api_version: str = 'v1.0',
            odata: Optional[str] = None,
            request_body: Optional[Dict] = None,
    ):
        url_suffix = urljoin(api_version, resource)
        if odata:
            url_suffix += '?' + odata
        res = self.ms_client.http_request(
            method=http_method,
            url_suffix=url_suffix,
            json_data=request_body,
            resp_type='resp',
        )
        if res.content:
            return res.json()


def start_auth(client: MsGraphClient) -> CommandResults:  # pragma: no cover
    result = client.ms_client.start_auth('!msgraph-api-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: MsGraphClient):  # pragma: no cover
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_module(client: MsGraphClient, params: Dict) -> str:  # pragma: no cover
    if params.get('app_secret') and params.get('tenant_id'):
        client.ms_client.get_access_token()
        return 'ok'
    else:
        raise ValueError('The test module is not functional when using Cortex XSOAR Azure app, '
                         'run the msgraph-test command instead.')


def test_command(client: MsGraphClient) -> CommandResults:  # pragma: no cover
    client.ms_client.get_access_token()
    return CommandResults(readable_output='```✅ Success!```')


def generic_command(client: MsGraphClient, args: Dict[str, Any]) -> CommandResults:
    request_body = args.get('request_body')
    results: dict
    if request_body and isinstance(request_body, str):
        try:
            request_body = json.loads(request_body)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Invalid request body - {str(e)}')
    http_method = args.get('http_method', 'GET')

    response = client.generic_request(
        resource=args.get('resource', ''),
        http_method=http_method,
        api_version=args.get('api_version', 'v1.0'),
        odata=args.get('odata', ''),
        request_body=request_body,
    )

    if not response:
        results = {
            'readable_output': 'The API query ran successfully and returned no content.',
        }
    else:
        results = {'raw_response': response}

        if argToBoolean(args.get('populate_context', 'true')):
            results['outputs'] = get_response_outputs(response)
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

    app_secret = params.get('app_secret') or (params.get('credentials') or {}).get('password')
    if not app_secret:
        raise Exception('Application Secret must be provided.')

    try:
        client = MsGraphClient(
            app_id=params.get('app_id'),
            scope=scope,
            app_secret=app_secret,
            tenant_id=params.get('tenant_id'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com'
        )

        if command == 'test-module':
            result = test_module(client, params)
            return_results(result)
        elif command == 'msgraph-api-request':
            return_results(generic_command(client, demisto.args()))
        elif command == 'msgraph-api-auth-start':
            return_results(start_auth(client))
        elif command == 'msgraph-api-auth-complete':
            return_results(complete_auth(client))
        elif command == 'msgraph-api-test':
            return_results(test_command(client))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
