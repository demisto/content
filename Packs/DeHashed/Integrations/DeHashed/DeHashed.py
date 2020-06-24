from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
INTEGRATION_CONTEXT_BRAND = 'DeHashed'


class Client(BaseClient):
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=None, headers=None, auth=None,
                 email=None, api_key=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers, auth=auth)
        self.email = email
        self.api_key = api_key

    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def dehashed_search(self, asset_type: str, value: list, operation: str = None, results_page_number: str = None) -> dict:
        query_value = ''
        if operation == 'is':
            query_value = ' '.join((f'"{value}"' for value in value))
        elif operation == 'contains':
            query_value = ' OR '.join(value)
        elif operation == 'regex':
            query_value = ' '.join((f'/{value}/' for value in value))

        if asset_type == 'all_fields':
            query_string = f'{query_value}'
        else:
            query_string = f'{asset_type}:{query_value}'

        if results_page_number:
            return self._http_request('GET', 'search', params={'query': query_string, 'page': results_page_number},
                                        auth=(self.email, self.api_key))
        else:
            return self._http_request('GET', 'search', params={'query': query_string},
                                        auth=(self.email, self.api_key))


def test_module(client: object) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.dehashed_search('vin', 'test', 'is')
    if isinstance(result, dict):
        return 'ok'
    else:
        return f'Test failed because got unexpected response from api: {result}'


def dehashed_search_command(client: object, args: dict) -> [tuple, str]:
    """

    :param client:
    :param args:
    :return:
    """
    asset_type = args.get('asset_type')
    operation = args.get('operation')
    value = argToList(args.get('value'))
    results_page_number = args.get('page')

    result = client.dehashed_search(asset_type, value, operation, results_page_number)
    if not isinstance(result, dict):
        raise DemistoException(f'Got unexpected output from api: {result}')

    query_data = result.get('entries')
    if not query_data:
        return "No results match your're query"
    else:
        context_data = createContext(query_data, keyTransform=underscoreToCamelCase)
        return (
            tableToMarkdown('DeHashed Search', query_data, headers=[*query_data[0].keys()],
                            headerTransform=pascalToSpace),
            {
                f'{INTEGRATION_CONTEXT_BRAND}.search.{asset_type}(val.Id==obj.Id)': context_data
            },
            query_data
                )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    email = demisto.params().get('email')
    api_key = demisto.params().get('api_key')
    base_url = demisto.params().get('base_url')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url,
            verify=verify_certificate,
            email=email,
            api_key=api_key,
            proxy=proxy,
            headers={'accept': 'application/json'}
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'dehashed-search':
            return_outputs(*dehashed_search_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
