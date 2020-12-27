import demistomock as demisto  # noqa: F401
from CSVFeedApiModule import *
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
SERVER_URL = 'https://www.bitcoinabuse.com/api/'
FEED_ENDPOINT_SUFFIX = 'download/'
FEED_ENDPOINT_DAILY_SUFFIX = 'download/1d'
REPORT_ADDRESS_SUFFIX = 'reports/create'
abuse_type_name_to_id: Dict[str, int] = {
    'ransomware': 1,
    'darknet market': 2,
    'bitcoin tumbler': 3,
    'blackmail scam': 4,
    'sextortio': 5,
    'other': 99
}
abuse_type_id_to_name: Dict[str, str] = {
    '1': 'ransomware',
    '2': 'darknet market',
    '3': 'bitcoin tumbler',
    '4': 'blackmail scam',
    '5': 'sextortio',
    '99': 'other'
}
first_fetch_interval_to_url_suffix: Dict[str, str] = {
    'Forever': 'forever',
    '30 Days': '30d'
}

READER_CONFIG = {
    'fieldnames': ['id', 'address', 'abuse_type_id', 'abuse_type_other', 'abuser',
                   'description', 'from_country', 'from_country_code', 'created_at'],
    'skip_first_line': True,
    'indicator_type': 'Cryptocurrency Address',
    'mapping': {
        'Value': ('address', None, 'bitcoin-{}'),
        'Raw Address': 'address',
        'Country Name': 'from_country',
        'Creation Date': 'created_at',
        'Description': 'description',
        'Abuse Type': ('abuse_type_id', lambda abuse_type_id: abuse_type_id_to_name.get(abuse_type_id))
    }
}


class BitcoinAbuseClient(BaseClient):

    def __init__(self, base_url, verify, proxy, api_key):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def report_address(self, address: str, abuse_type_id: int, abuse_type_other: Optional[str],
                       abuser: str, description: str) -> Dict:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            address (str): the address of the abuser
            abuse_type_id (int): an id which indicates which type of abuse was made
            abuse_type_other (Optional[str]): in case abuse_type_id was other, holds information describing the abuse type
            abuser (str): information about the abuser (email, name, ...)
            description (str): description of the abuse (may include email sent, etc)

        Returns:
            Returns if post request was successful.
        """
        return self._http_request(
            method='POST',
            url_suffix=REPORT_ADDRESS_SUFFIX,
            params={
                'api_token': self.api_key,
                'address': address,
                'abuse_type_id': abuse_type_id,
                'abuse_type_other': abuse_type_other,
                'abuser': abuser,
                'description': description
            }
        )


def build_fetch_indicators_url_suffixes(params: Dict, test_module: bool) -> set:
    """Builds the URL suffix fo the fetch. Default is 'FEED_ENDPOINT_DAILY_SUFFIX_SUFFIX' unless this is a first fetch
    which will be determined by the user parameter - initial_fetch_interval

    - If initial_fetch_interval is 'forever' - then suffixes will include 30d and forever, in order to extract
      the most updated data by the Bitcoin Abuse service, as 'forever' csv file only updates on 15 of each month
      (see Complete Download in https://www.bitcoinabuse.com/api-docs)
    - If initial_fetch_interval is '30d' - suffixes will only include '30d' suffix.

    Args:
        params (Dict): Demisto params
        test_module (bool): Indicates if command is test_module command

    Returns:
        - str: URL suffix to be used in the fetch process.
    """
    first_feed_interval_url_suffix = params.get('initial_fetch_interval', '30 Days')
    first_feed_interval_url_suffix = first_fetch_interval_to_url_suffix.get(first_feed_interval_url_suffix, '30d')

    have_fetched_first_time = argToBoolean(demisto.getIntegrationContext().get('have_fetched_first_time', False))

    if have_fetched_first_time:
        return {FEED_ENDPOINT_DAILY_SUFFIX}
    else:
        if not test_module:
            demisto.setIntegrationContext({'have_fetched_first_time': True})
        return {FEED_ENDPOINT_SUFFIX + first_feed_interval_url_suffix, FEED_ENDPOINT_SUFFIX + '30d'}


def _assure_valid_response(indicators: List[Dict]) -> None:
    """
    Receives the indicators fetched from Bitcoin Abuse service, and checks if
    the response received is valid.
    When an incorrect api key is inserted, Bitcoin Abuse returns response of
    their login page

    this function checks if the api key given is incorrect by checking if the received
    response was the login page.
    Throws DemistoException to inform the user of incorrect api key

    Args:
        indicators (List[Dict]): the array of indicators fetched

    Returns:
        - Throws DemistoException incase an incorrect api key was given
    """
    if indicators and '<html lang="en">' == indicators[0]['value']:
        raise DemistoException('api token inserted is not valid')


def report_address_command(params: Dict, args: Dict, api_key: str) -> CommandResults:
    """
    Reports a bitcoin abuse to Bitcoin Abuse service

    Args:
        params (Dict):  Demisto params.
        args (Dict): Demisto args for report address command.
        api_key (str): For Bitcoin Abuse service.

    Returns:
        str: 'bitcoin address (address reported) by abuser (abuser reported) was
        reported to BitcoinAbuse API' if http request was successful'
    """

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    bitcoin_client = BitcoinAbuseClient(
        base_url=SERVER_URL,
        verify=verify_certificate,
        proxy=proxy,
        api_key=api_key)

    abuse_type_id = abuse_type_name_to_id.get(args.get('abuse_type', ''))
    abuse_type_other = args.get('abuse_type_other')
    address = args.get('address', '')
    abuser = args.get('abuser', '')

    if abuse_type_id is None:
        raise DemistoException('Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type')

    if abuse_type_id == abuse_type_name_to_id['other'] and abuse_type_other is None:
        raise DemistoException('Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other')

    http_response = bitcoin_client.report_address(address=address,
                                                  abuse_type_id=abuse_type_id,
                                                  abuse_type_other=abuse_type_other,
                                                  abuser=args.get('abuser', ''),
                                                  description=args.get('description', ''))

    if argToBoolean(http_response.get('success')):
        return CommandResults(
            readable_output=f'Bitcoin address {address} by abuse bitcoin user {abuser}'
                            f' was reported to BitcoinAbuse service'
        )
    else:
        failure_message = http_response.get('response')
        raise DemistoException(f'bitcoin report address did not succeed: {failure_message}')


def _build_csv_client_params(params: Dict, test_module: bool, api_key: str):
    """
    Adds additional params needed for fetching indicators in order to build csv client properly
    and fetch csv from Bitcoin Abuse service

    Args:
        params (Dict): Demisto params
        test_module (bool): Indicates if command is test_module command
        api_key (str): For Bitcoin Abuse service

    Returns:
        - If command is bitcoin-report-address: returns the params enriched with url
        - If command is anything else - enriches params with more required params to
          CSVFeedApiModule fetch_indicators_command
    """
    urls_suffixes = build_fetch_indicators_url_suffixes(params, test_module)
    urls = [f'{SERVER_URL}{url_suffix}?api_token={api_key}' for url_suffix in urls_suffixes]
    feed_url_to_config = {url: READER_CONFIG for url in urls}

    params['url'] = urls
    params['feed_url_to_config'] = feed_url_to_config
    params['delimiter'] = ','

    return params


def fetch_indicators(params: Dict, api_key: str, test_module: bool):
    """
     Wrapper which calls to CSVFeedApiModule for fetching indicators from Bitcoin Abuse download csv feed.
    Args:
        params (Dict): Demisto params.
        api_key (str): For Bitcoin Abuse service.
        test_module (bool): Indicates if command is test_module command

    Returns:
        - Throws exception if an invalid api key was given or error occurred during the call to Bitcoin Abuse service
        - Fetches indicators if the call to Bitcoin Abuse service was successful and command is not test module
        - 'ok' if the call to Bitcoin Abuse service was successful and command is test_module
    """
    params = _build_csv_client_params(params, test_module, api_key)
    csv_module_client = Client(**params)

    highest_fetched_id = demisto.getIntegrationContext().get('highest_fetched_id', 0)
    indicators = fetch_indicators_command(
        client=csv_module_client,
        default_indicator_type='Cryptocurrency Address',
        auto_detect=False,
        limit=0
    )

    _assure_valid_response(indicators)

    if not test_module:
        indicators_without_duplicates = []
        indicators_ids = set()
        for indicator in indicators:
            try:
                indicator_id = int(indicator['rawJSON']['id'])
                if indicator_id not in indicators_ids and indicator_id > highest_fetched_id:
                    indicator['fields']['Cryptocurrency Address Type'] = 'bitcoin'
                    indicators_without_duplicates.append(indicator)
                    indicators_ids.add(indicator_id)
            except ValueError:
                pass

        highest_id_fetched_from_indicators = max(indicators_ids) if indicators_ids else 0
        highest_fetched_id = max(highest_fetched_id, highest_id_fetched_from_indicators)
        demisto.setIntegrationContext({'highest_fetched_id': highest_fetched_id})

        # we submit the indicators in batches
        for b in batch(indicators_without_duplicates, batch_size=2000):
            demisto.createIndicators(b)  # type: ignore

    else:
        demisto.results('ok')


def main() -> None:
    command = demisto.command()
    api_key = demisto.params().get('api_key', '')

    args = demisto.args()

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    try:

        if command == 'test-module':
            fetch_indicators(demisto.params(), api_key, test_module=True)

        elif command == 'fetch-indicators':
            fetch_indicators(demisto.params(), api_key, test_module=False)

        elif command == 'bitcoin-report-address':
            return_results(report_address_command(demisto.params(), args, api_key))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
