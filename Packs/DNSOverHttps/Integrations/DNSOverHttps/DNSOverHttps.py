import ast

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_module(client, base_url):
    params = {'name': 'paloaltonetworks.com',
              'type': 'A'}
    result = client._http_request('GET', full_url=base_url, params=params)
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def run_command(client, params, base_url):
    response = client._http_request('GET', full_url=base_url, params=params)
    return response


def create_output(results, endpoint, only_answers):
    if only_answers:
        try:
            output = CommandResults(
                outputs_prefix=f'DNSOverHTTPS.{endpoint}',
                outputs_key_field='',
                outputs=results['Answer']
            )
            return output
        except LookupError:
            return 'No results found'
    else:
        output = CommandResults(
            outputs_prefix=f'DNSOverHTTPS.{endpoint}',
            outputs_key_field='',
            outputs=results
        )
        return output


def main():

    # get the service API url
    base_url = demisto.params().get('url')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {'accept': 'application/dns-json'}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, base_url)
            demisto.results(result)
        elif demisto.command() == 'doh-resolve':
            params = {'name': demisto.args().get('domain'),
                      'type': demisto.args().get('type')}
            only_answers = ast.literal_eval(demisto.args().get('only_answers'))
            results = run_command(client, params, base_url)
            return_results(create_output(results, 'Results', only_answers))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
