import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_module(client):
    data = {'input': 'One, two, three, four.',
            'recipe': 'to decimal'}
    result = client._http_request('POST', '/bake', json_data=data)
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def run_command(client, data, endpoint):
    response = client._http_request('POST', endpoint, json_data=data)
    return response


def create_output(results, endpoint):
    output = CommandResults(
        outputs_prefix=f'CyberChef.{endpoint}',
        outputs_key_field='',
        outputs=results
    )
    return output


def main():
    apikey = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/cyberchef')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {'Content-Type': 'application/json',
               'x-api-key': apikey}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'cyberchef-bake':
            data = {'input': demisto.args().get('input'),
                    'recipe': json.loads(demisto.args().get('recipe')),
                    'outputType': demisto.args().get('outputType')}
            data = remove_empty_elements(data)
            results = run_command(client, data, '/bake')
            return_results(create_output(results, 'Bake'))
        elif demisto.command() == 'cyberchef-magic':
            data = {'input': demisto.args().get('input'),
                    'args': demisto.args().get('args')}
            data = remove_empty_elements(data)
            results = run_command(client, data, '/magic')
            return_results(create_output(results, 'Magic'))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
