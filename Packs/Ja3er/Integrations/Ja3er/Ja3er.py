import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):


def test_module(client: Client, **args) -> str:
    uri = f'/json'
    client._http_request('GET', uri)

    return "ok"


def ja3_search(client: Client, **args) -> CommandResults:
    ja3 = args.get('JA3')
    uri = f'search/{ja3}'
    r = client._http_request('GET', uri)

    results = CommandResults(
        outputs_prefix="JA3",
        outputs_key_field=f"JA3.hash",
        outputs={ja3: r},
        readable_output=tableToMarkdown(f'Search results for {ja3}', r)
    )

    return results


def main():
    # If an arg supplying an orgId is provided, will override the one found in params
    args = {**demisto.params(), **demisto.args()}

    base_url = 'https://ja3er.com/'
    verify = args.get('insecure')

    client = Client(
        base_url,
        verify=verify
    )

    commands = {
        'test-module': test_module,
        'ja3-search': ja3_search
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f'Command {command} is not available in this integration')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
