import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def oauth_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'oauth2/token', headers=headers)

        return response


def oauth_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.oauth_request()
    command_results = CommandResults(
        outputs_prefix='Crowdstrike.Oauth',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    $BASEAUTHPARAMS$
    headers = {}
    $BEARERAUTHPARAMS$

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=$BASEAUTH$)
        $CLIENT_API_KEY$
        commands = {
            'CS-oauth': oauth_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
