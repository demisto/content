import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def anomalithreatstream1_request(self, username, api_key, count, reported_ts, org_id, attacker_address):
        params = assign_params(username=username, api_key=api_key)
        data = {"attacker_address": attacker_address, "count": count, "org_id": org_id, "reported_ts": reported_ts}
        headers = self._headers

        response = self._http_request('POST', 'api/v1/myattacks', params=params, json_data=data, headers=headers)

        return response

    def anomalithreatstream2_request(self, username, api_key):
        params = assign_params(username=username, api_key=api_key)
        headers = self._headers

        response = self._http_request('GET', 'api/v1/pdns/ip/194.68.44.19', params=params, headers=headers)

        return response


def anomalithreatstream1_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    username = args.get('username')
    api_key = args.get('api_key')
    count = args.get('count')
    reported_ts = args.get('reported_ts')
    org_id = args.get('org_id')
    attacker_address = args.get('attacker_address')

    response = client.anomalithreatstream1_request(username, api_key, count, reported_ts, org_id, attacker_address)
    command_results = CommandResults(
        outputs_prefix='AnomaliThreatstreamAshlesha.Anomalithreatstream1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def anomalithreatstream2_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    username = args.get('username')
    api_key = args.get('api_key')

    response = client.anomalithreatstream2_request(username, api_key)
    command_results = CommandResults(
        outputs_prefix='AnomaliThreatstreamAshlesha.Anomalithreatstream2',
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
            'AT-anomalithreatstream1': anomalithreatstream1_command,
            'AT-anomalithreatstream2': anomalithreatstream2_command,
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
