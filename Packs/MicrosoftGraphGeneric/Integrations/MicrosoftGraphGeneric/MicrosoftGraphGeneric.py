import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
from typing import Any, Dict, Optional

urllib3.disable_warnings()


class MsGraphClient:
    def __init__(self,
                 app_id: str,
                 app_secret: str,
                 tenant_id: str,
                 verify: bool,
                 proxy: bool):
        self.ms_client = MicrosoftClient(
            base_url='https://graph.microsoft.com',
            auth_id=app_id,
            enc_key=app_secret,
            tenant_id=tenant_id,
            verify=verify,
            proxy=proxy,
            self_deployed=True,
            ok_codes=(200, 201, 204),
        )

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
        return self.ms_client.http_request(
            method=http_method,
            url_suffix=url_suffix,
            json_data=request_body,
            resp_type='content' if http_method == 'DELETE' else 'json',
        )


def test_module(client: MsGraphClient) -> str:
    client.ms_client.get_access_token()
    return 'ok'


def generic_command(client: MsGraphClient, args: Dict[str, Any]) -> CommandResults:
    request_body_str = args.get('request_body')
    request_body = None
    if request_body_str:
        try:
            request_body = json.loads(request_body_str)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Invalid request body - {str(e)}')

    response = client.generic_request(
        resource=args.get('resource', ''),
        http_method=args.get('http_method', 'GET'),
        api_version=args.get('api_version', 'v1.0'),
        odata=args.get('odata'),
        request_body=request_body,
    )

    return CommandResults(raw_response=response)


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = MsGraphClient(
            app_id=params.get('app_id'),
            app_secret=params.get('app_secret'),
            tenant_id=params.get('tenant_id'),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'msgraph-generic':
            return_results(generic_command(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
