from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

INTEGRATION_CONTEXT_BRAND = 'DeHashed'
RESULTS_FROM = 0
RESULTS_TO = 49


class Client(BaseClient):
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=None, headers=None, auth=None,
                 email=None, api_key=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers, auth=auth)
        self.email = email
        self.api_key = api_key

    def dehashed_search(self, asset_type: str, value: list, operation: str = None, results_page_number: str = None)\
            -> dict:
        query_value = ''
        if operation == 'is':
            query_value = ' '.join((f'"{value}"' for value in value))
        elif operation == 'contains':
            query_value = ' OR '.join(value)
            if len(value) > 1:
                query_value = f'({query_value})'

        elif operation == 'regex':
            query_value = ' '.join((f'/{value}/' for value in value))
        if asset_type == 'all_fields':
            query_string = f'{query_value}'
        else:
            query_string = f'{asset_type}:{query_value}'

        if results_page_number:
            return self._http_request('GET', 'search', params={'query': query_string, 'page': results_page_number},
                                      auth=(self.email, self.api_key), timeout=15)
        else:
            return self._http_request('GET', 'search', params={'query': query_string},
                                      auth=(self.email, self.api_key))


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        result = client.dehashed_search(asset_type='vin', value=['test', 'test1'], operation='is')
    except Exception as e:
        raise DemistoException(
            f"Test failed. please check if Server Url, Email or Api key are correct. \n {e}"
        )
    else:
        if isinstance(result, dict):
            return 'ok'
        else:
            return f'Test failed because got unexpected response from api: {result}'


def convert_string_to_int(argument) -> int:
    try:
        input_as_int = int(argument)
    except ValueError as e:
        raise DemistoException(f'"results_from" and "results_to expected" to be integers/n {e}')
    else:
        return input_as_int


def filter_results(entries: list, results_from: any, results_to: any) -> tuple:
    if results_from:
        results_from_int = convert_string_to_int(results_from)
    else:
        results_from_int = RESULTS_FROM
    if results_to:
        results_to_int = convert_string_to_int(results_to)
    else:
        results_to_int = RESULTS_TO

    return entries[results_from_int:results_to_int], results_from_int, results_to_int


def dehashed_search_command(client: Client, args: dict) -> tuple:
    """

    :param client:
    :param args:
    :return:
    """
    asset_type = args.get('asset_type')
    operation = args.get('operation')
    value = argToList(args.get('value'))
    results_page_number = args.get('page')
    results_from = args.get('results_from')
    results_to = args.get('results_to')

    result = client.dehashed_search(asset_type, value, operation, results_page_number)
    if not isinstance(result, dict):
        raise DemistoException(f'Got unexpected output from api: {result}')

    query_data = result.get('entries')

    if not query_data:
        return 'No matching results found', None, None
    else:
        filtered_results, results_from, results_to = filter_results(query_data, results_from, results_to)
        if not results_page_number:
            results_page_number = "1"

        query_entries = createContext(filtered_results, keyTransform=underscoreToCamelCase)
        headers = [key.replace('_', ' ') for key in [*filtered_results[0].keys()]]
        last_query = {"ResultsFrom": results_from,
                      "ResultsTo": results_to,
                      "DisplayedResults": len(filtered_results),
                      "TotalResults": result.get("total"),
                      }
        return (
            tableToMarkdown(f'DeHashed Search - Got {result.get("total")} results. Display only:'
                            f' {len(filtered_results)} Page number:{results_page_number}.', filtered_results,
                            headers=headers, removeNull=True, headerTransform=pascalToSpace),
            {
                f'{INTEGRATION_CONTEXT_BRAND}.Search(val.Id==obj.Id)': query_entries,
                f'{INTEGRATION_CONTEXT_BRAND}.LastQuery(true)': last_query
            },
            filtered_results
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
