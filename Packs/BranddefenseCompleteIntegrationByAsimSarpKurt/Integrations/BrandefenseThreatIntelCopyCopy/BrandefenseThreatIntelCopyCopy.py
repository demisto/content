import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections import defaultdict
from typing import Callable, cast
import requests
from dateparser import parse


class Client(BaseClient):
    def __init__(self, params: dict):
        super().__init__(
            'https://api.brandefense.com',
            verify=not argToBoolean(params.get('insecure')),
            proxy=argToBoolean(params.get('proxy')),
            headers={
                'Authorization': 'Token ' + params['credentials'],
                'User-Agent': 'Mozilla/5.0 (compatible; BARIKAT/0.1; +https://www.barikat.com.tr)'
            }
        )

    def check_module(client: Client):
        return self._http_request('GET', client.get('server'), params=client.headers)


def main(params: dict, args: dict, command: str):
    client = Client(params)
    demisto.debug(f'Command called {command}')
    if command == 'test-module':
        results = check_module(client)
    elif command == 'ip':
        results = ip_command(client, score_calculator, args, ip_relationships)
    else:
        raise NotImplementedError(f'Command {command} not implemented')
    return_results(results)


if __name__ in ('builtins', '__builtin__', '__main__'):
    try:
        main(demisto.params(), demisto.args(), demisto.command())
    except Exception as exception:
        return_error(exception)
