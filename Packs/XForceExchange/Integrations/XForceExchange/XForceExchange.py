from typing import Tuple
from typing import Dict
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

XFORCE_URL = 'https://exchange.xforce.ibmcloud.com'


class Client(BaseClient):
    def __init__(self, url: str, api_key: str, password: str, use_ssl: bool, use_proxy: bool):
        self.url = url
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json'},
                         auth=(api_key, password))

    def ip_report(self, ip: str) -> dict:
        return self._http_request('GET', f'/ipr/{ip}')


def calculate_score(score: int, threshold: int) -> int:
    if score > threshold:
        return 3
    elif score > threshold / 2:
        return 2
    return 1


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Args:
        client: X-Force client
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    return 'ok' if client.ip_report('8.8.8.8').get('ip') == '8.8.8.8' else 'Connection failed.'


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, dict]:
    """
    Executes IP enrichment against X-Force Exchange.
    Args:
        client: X-Force client.
        args: the arguments for the command.
    Returns:
    """

    threshold = demisto.params().get('threshold', 50)
    result = client.ip_report(args['ip'])

    outputs = {'Address': result['ip'],
               'Score': result.get('score'),
               'Country': result.get('geo', {'country': ''}).get('country'),
               'Reason': result.get('reason'),
               'Reason Description': result.get('reasonDescription'),
               'Subnets': result.get('subnets'),
               'Vendor': 'XFE',
               'History': result.get('history')}
    dbot_score = {'Indicator': result['ip'], 'Type': 'ip', 'Vendor': 'XFE',
                  'Score': calculate_score(result['score'], threshold)}

    context = {'IP(obj.Address==val.Address)': outputs, 'DBotScore': dbot_score}
    table = outputs.copy()
    table['Reason'] = f'{table["Reason"]}:\n{table["Reason Description"]}'
    table['Subnets'] = ', '.join(subnet.get('subnet') for subnet in table['Subnets'])
    mark_down = tableToMarkdown(f'X-Force IP Reputation for: {result.get("ip")}\n'
                                f'{XFORCE_URL}/ip/{result.get("ip")}', table, removeNull=True,
                                headers=['Reason', 'Subnets', 'Score', 'Country'])
    return mark_down, context, result


def main():
    params = demisto.params()
    credentials = params.get('credentials')

    LOG(f'Command being called is {demisto.command()}')
    client = Client(params.get('url'),
                    credentials.get('identifier'), credentials.get('password'),
                    use_ssl=not params.get('insecure', False),
                    use_proxy=params.get('proxy', False))
    commands = {
        'ip': ip_command
    }

    command = demisto.command()

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
