"""
AlphaVantage is a stock data API
"""

import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, params, base_url, verify):
        self.api_key = params.get('api_key')
        super().__init__(base_url, verify)

    def _http_request(  # type: ignore[override]
            self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
            params=None, data=None, files=None, timeout=10, resp_type='json', ok_codes=None,
            return_empty_response=False, retries=0, status_list_to_retry=None,
            backoff_factor=5, raise_on_redirect=False, raise_on_status=False,
            error_handler=None, empty_valid_codes=None, **kwargs
    ):
        """Adding API key and handling errors."""

        if not params:
            params = {}
        params['apikey'] = self.api_key
        response = super()._http_request(
            method, url_suffix=url_suffix, full_url=full_url, headers=headers, auth=auth,
            json_data=json_data, params=params, data=data, files=files,
            timeout=timeout, resp_type=resp_type, ok_codes=ok_codes,
            return_empty_response=return_empty_response, retries=retries,
            status_list_to_retry=status_list_to_retry, backoff_factor=backoff_factor,
            raise_on_redirect=raise_on_redirect, raise_on_status=raise_on_status,
            error_handler=error_handler, empty_valid_codes=empty_valid_codes, **kwargs
        )
        if error_message := response.get('Error Message'):
            raise DemistoException(error_message)
        return response

    def get_stock_history(
            self, symbol: str, interval: str, output_size: str = 'compact'
    ) -> dict:
        """Gets stock history data
        Documentation Link: https://www.alphavantage.co/documentation/#intraday
        https://www.alphavantage.co/query?function=TIME_SERIES_INTRADAY&symbol=IBM&interval=5min&outputsize=full&apikey=demo
        Args:
            symbol: the stock's ticker/symbol: MSFT, AAPL etc
            interval:  1min, 5min, 15min, 30min, 60min
            output_size: compact - latest 100 data points, full - full length array
        Returns:
            JSON Response
        """
        params = {
            'function': 'TIME_SERIES_INTRADAY',
            'symbol': symbol,
            'interval': interval,
            'outputsize': output_size,
        }
        return self._http_request(method='GET', params=params)

    def get_stock_data(self, symbol: str) -> dict:
        """Gets stock data about last trading day:
        Documentation Link: https://www.alphavantage.co/documentation/#latestprice
        Example: https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol=IBM&apikey=demo
        Args:
            symbol: The stock's symbol/ticker. Example: PANW, AAPL, MSFT etc
        Returns:
            JSON Response
        """

        params = {
            'function': 'GLOBAL_QUOTE',
            'symbol': symbol,
            'datatype': 'json',
        }
        return self._http_request(method='GET', params=params)


# region Helper Function

def remove_indexing_from_dictionary_keys(
        api_response: dict,
        regex: re.Pattern = re.compile(r'^[0-9][0-9]*\.\s*')
) -> dict:
    """Removes the running index from the keys in a json
    01.Key -> Key
    01. Key -> Key
    Args:
        regex: expression to filter out
        api_response: json response from api
    Returns:
        json response without the unnecessary indices at first
    """

    return {regex.sub('', key): value for key, value in api_response.items()}


# endregion

# region Commands
def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client: client to use
    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client.get_stock_data(symbol='PANW')
    return 'ok'


def get_stock_data(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    symbols = argToList(args.get('symbol'))
    if not symbols:
        raise ValueError('symbol not specified')

    # Call the Client function and get the raw response
    results = []
    for symbol in symbols:
        raw_api_response = client.get_stock_data(symbol)
        outputs = remove_indexing_from_dictionary_keys(raw_api_response.get('Global Quote', {}))
        results.append(
            CommandResults(
                outputs_prefix='AlphaVantage.StockData',
                outputs_key_field='symbol',
                outputs=outputs,
                raw_response=raw_api_response
            )
        )
    return results


def get_stock_history(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    symbols = argToList(args['symbol'])
    interval = args['interval']
    output_size = args['output_size']
    if not symbols:
        raise ValueError('symbol not specified')

    # Call the Client function and get the raw response
    results = []
    for symbol in symbols:
        raw_api_response = client.get_stock_history(symbol=symbol, interval=interval, output_size=output_size)
        outputs = {
            **remove_indexing_from_dictionary_keys(raw_api_response.get('Meta Data', {})),
            'Time Series':
                {key: remove_indexing_from_dictionary_keys(value)
                 for key, value in raw_api_response.get(f'Time Series ({interval})', {}).items()}
        }
        results.append(
            CommandResults(
                readable_output=tableToMarkdown(f'Stock History (Interval: {interval})',
                                                outputs.get('Time Series', {})),
                outputs_prefix='AlphaVantage.StockHistory',
                outputs_key_field=['Symbol', 'Last Refreshed', 'Interval'],
                outputs=outputs,
                raw_response=raw_api_response
            )
        )

    return results


# endregion

def main():
    """main function, parses params and runs command functions"""
    result: Union[CommandResults, List[CommandResults], str]
    params = demisto.params()
    args = demisto.args()
    base_url = 'https://www.alphavantage.co/query?'

    verify_certificate = not params.get('insecure', False)

    client = Client(
        base_url=base_url,
        params=params,
        verify=verify_certificate,
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
        elif command == 'alphavantage-stock-data-get':
            result = get_stock_data(client, args)
        elif command == 'alphavantage-stock-history-get':
            result = get_stock_history(client, args)
        else:
            raise NotImplementedError(f'{command} Not Implemented')
        return_results(result)
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
