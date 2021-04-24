import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
from typing import Any, Dict, Optional, Union

urllib3.disable_warnings()


class Client:
    def __init__(self, params: Dict):
        self.cs_client = CrowdStrikeClient(params)

    def api_request(
            self,
            endpoint: str,
            http_method: str = 'GET',
            request_body: Optional[Dict] = None,
            query_parameters: Optional[Dict] = None,
    ):
        return self.cs_client.http_request(
            method=http_method,
            url_suffix=endpoint,
            json_data=request_body,
            params=query_parameters,
        )


def test_module(client: Client) -> str:
    client.cs_client._generate_token()
    return 'ok'


def api_request(client: Client, args: Dict[str, Any]) -> CommandResults:
    request_body = args.get('request_body')
    if request_body and isinstance(request_body, str):
        try:
            request_body = json.loads(request_body)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Invalid request body - {str(e)}')

    query_parameters = args.get('query_parameters')
    if query_parameters and isinstance(query_parameters, str):
        try:
            query_parameters = json.loads(query_parameters)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Invalid query parameters - {str(e)}')

    endpoint = args.get('endpoint', '')

    response = client.api_request(
        endpoint=endpoint,
        http_method=args.get('http_method', 'GET'),
        request_body=request_body,
        query_parameters=query_parameters,
    )

    resources: List[Union[Dict, str]] = response.get('resources', [])

    if isinstance(resources, list) and len(resources) == 1 and isinstance(resources[0], dict):
        readable_output = resources[0]
    else:
        readable_output = {'resources': resources}

    results = {
        'raw_response': response,
        'readable_output': tableToMarkdown('Results', readable_output),
    }

    if argToBoolean(args.get('populate_context', True)):
        results['outputs'] = resources
        results['outputs_prefix'] = f'CrowdStrike.{endpoint}'

    return CommandResults(**results)


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        handle_proxy()
        client = Client(params)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'cs-api-request':
            return_results(api_request(client, demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


from CrowdStrikeApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
