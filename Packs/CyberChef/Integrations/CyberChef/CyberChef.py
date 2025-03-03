import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from subprocess import run


def build_params(data: dict) -> list[str]:

    params: list[str] = []
    for value in data.values():
        params.append(f'{json.dumps(value)}')
    return params


def test_module(client: BaseClient | None, local_execution: bool):
    data = {'input': 'One, two, three, four.',
            'recipe': 'to decimal'}
    if not local_execution and client:
        result = client._http_request('POST', '/bake', json_data=data)
    else:
        params = build_params(data)

        cmd = ['node', '/bake.js']
        cmd.extend(params)
        process = run(cmd, capture_output=True, text=True)
        result = process.stdout
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def run_command(client: BaseClient | None, data: dict, endpoint: str, local_execution: bool):
    if not local_execution and client:
        response = client._http_request('POST', endpoint, json_data=data)
    else:
        params = build_params(data)
        cmd = ['node', '/bake.js']
        cmd.extend(params)
        process = run(cmd, capture_output=True, text=True)
        response = process.stdout
    return response


def create_output(results, endpoint: str):
    output = CommandResults(
        outputs_prefix=f'CyberChef.{endpoint}',
        outputs_key_field='',
        outputs=results
    )
    return output


def main():
    apikey = demisto.params().get('apikey')
    local_execution = argToBoolean(demisto.params().get('local_execution', 'false'))

    # get the service API url
    if not local_execution:
        base_url = urljoin(demisto.params()['url'], '/cyberchef')
        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)
        headers = {'Content-Type': 'application/json', 'x-api-key': apikey}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if not local_execution:
            client = BaseClient(
                base_url=base_url,
                verify=verify_certificate,
                headers=headers,
                proxy=proxy)
        else:
            client = None

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, local_execution)
            demisto.results(result)
        elif demisto.command() == 'cyberchef-bake':
            data = {'input': demisto.args().get('input'),
                    'recipe': json.loads(demisto.args().get('recipe')),
                    'outputType': demisto.args().get('outputType')}
            data = remove_empty_elements(data)
            results = run_command(client, data, '/bake', local_execution)
            return_results(create_output(results, 'Bake'))
        elif demisto.command() == 'cyberchef-magic':
            data = {'input': demisto.args().get('input'),
                    'args': demisto.args().get('args')}
            data = remove_empty_elements(data)
            results = run_command(client, data, '/magic', local_execution)
            return_results(create_output(results, 'Magic'))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
