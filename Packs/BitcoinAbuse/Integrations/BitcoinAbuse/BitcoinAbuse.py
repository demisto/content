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


class BitcoinAbuseClient(Client):

    def __init__(self, params, api_key):
        super().__init__(**params)
        self.api_key = api_key

    def report_address(self, address: str, abuse_type_id: int, abuse_type_other: Optional[str],
                       abuser: str, description: str) -> Dict:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            address: the address of the abuser
            abuse_type_id: an id which indicates which type of abuse was made
            abuse_type_other: in case abuse_type_id was other, holds information describing the abuse type
            abuser: information about the abuser (email, name, ...)
            description: description of the abuse (may include email sent, etc)

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


def build_fetch_indicators_url_suffixes(have_fetched_first_time: bool, feed_interval_suffix_url: str) -> set:
    """Builds the URL suffix fo the fetch. Default is 'FEED_ENDPOINT_DAILY_SUFFIX_SUFFIX' unless this is a first fetch
    which will be determined by the user parameter - initial_fetch_interval

    - if initial_fetch_interval is 'forever' - then suffixes will include 30d and forever, in order to extract
      the most updated data by the Bitcoin Abuse service, as 'forever' csv file only updates on 15 of each month
      (see Complete Download in https://www.bitcoinabuse.com/api-docs)
    - if initial_fetch_interval is '30d' - suffixes will only include '30d' suffix.

    Args:
        have_fetched_first_time (bool) indicates if a fetch from BitcoinAbuse have been made
        feed_interval_suffix_url (str) the suffix for downloading csv from Bitcoin Abuse

    Returns:
        - str: URL suffix to be used in the fetch process.
    """
    if have_fetched_first_time:
        return {FEED_ENDPOINT_DAILY_SUFFIX}
    else:
        demisto.setIntegrationContext({'have_fetched_first_time': True})
        return {FEED_ENDPOINT_SUFFIX + feed_interval_suffix_url, FEED_ENDPOINT_SUFFIX + '30d'}


def fetch_indicators(client: BitcoinAbuseClient) -> None:
    """
    Wrapper which calls to CSVFeedApiModule for fetching indicators from Bitcoin Abuse download csv feed.
    Args:
        client: the client to be used for Bitcoin Abuse Api calls

    Returns:

    """
    highest_fetched_id = demisto.getIntegrationContext().get('highest_fetched_id', 0)
    indicators = fetch_indicators_command(
        client=client,
        default_indicator_type='Cryptocurrency Address',
        auto_detect=False,
        limit=0
    )

    indicators_without_duplicates = []
    indicators_ids = set()
    for indicator in indicators:
        indicator_id = int(indicator['rawJSON']['id'])
        if indicator_id not in indicators_ids and indicator_id > highest_fetched_id:
            indicator['fields']['Cryptocurrency Address Type'] = 'bitcoin'
            indicators_without_duplicates.append(indicator)
            indicators_ids.add(indicator_id)

    highest_id_fetched_from_indicators = int(indicators[-1]['rawJSON']['id']) if indicators else 0
    highest_fetched_id = max(highest_fetched_id, highest_id_fetched_from_indicators)
    demisto.setIntegrationContext({'highest_fetched_id': highest_fetched_id})

    # we submit the indicators in batches
    for b in batch(indicators_without_duplicates, batch_size=2000):
        demisto.createIndicators(b)  # type: ignore


def report_address_command(client: BitcoinAbuseClient, args: Dict) -> CommandResults:
    """
    Reports a bitcoin abuse to Bitcoin Abuse service

    Args:
        client: BitcoinAbuseClient  used to post abuse to the api
        args (Dict): Demisto args.

    Returns:
        str: 'bitcoin address (address reported) by abuser (abuser reported) was
        reported to BitcoinAbuse API' if http request was successful'
    """
    abuse_type_id = abuse_type_name_to_id.get(args.get('abuse_type', ''))
    abuse_type_other = args.get('abuse_type_other')
    address = args.get('address', '')
    abuser = args.get('abuser', '')

    if abuse_type_id is None:
        raise DemistoException('Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type')

    if abuse_type_id == abuse_type_name_to_id['other'] and abuse_type_other is None:
        raise DemistoException('Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other')

    http_response = client.report_address(address=address,
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


def _add_additional_params(command: str, params: Dict, api_key: str):
    """

    Args:
        command: demisto command requested
        params: demisto params
        api_key: for Bitcoin Abuse service

    Returns:
        - if command is bitcoin-report-address: returns the params enriched with url
        - if command is anything else - enriches params with more required params to CSVFeedApiModule
    """

    if command != 'bitcoin-report-address':
        first_feed_interval_url_suffix = params.get('initial_fetch_interval', '30d')
        first_feed_interval_url_suffix = first_fetch_interval_to_url_suffix.get(first_feed_interval_url_suffix)
        reader_config = {
            'fieldnames': ['id', 'address', 'abuse_type_id', 'abuse_type_other', 'abuser',
                           'description', 'from_country', 'from_country_code', 'created_at'],
            'skip_first_line': True,
            'indicator_type': 'Cryptocurrency Address',
            'mapping': {
                'Value': ('address', None, 'bitcoin-{}'),
                'Address': 'address',
                'Country Name': 'from_country',
                'Creation Date': 'created_at',
                'Description': 'description',
                'Abuse Type': ('abuse_type_id', lambda abuse_type_id: abuse_type_id_to_name.get(abuse_type_id))
            }
        }

        have_fetched_first_time = argToBoolean(demisto.getIntegrationContext().get('have_fetched_first_time', False))

        urls_suffixes = build_fetch_indicators_url_suffixes(have_fetched_first_time, first_feed_interval_url_suffix)
        urls = [f'{SERVER_URL}{url_suffix}?api_token={api_key}' for url_suffix in urls_suffixes]

        feed_url_to_config = {url: reader_config for url in urls}

        params['url'] = urls
        params['feed_url_to_config'] = feed_url_to_config
        params['delimiter'] = ','
    else:
        params['url'] = SERVER_URL

    return params


def main() -> None:
    command = demisto.command()
    api_key = demisto.params().get('api_key', '')
    params = _add_additional_params(command, demisto.params(), api_key)

    args = demisto.args()

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    client = BitcoinAbuseClient(params, api_key)
    try:

        if command == 'test-module':
            feed_main('Bitcoin Abuse Feed', params, 'bitcoin')

        elif command == 'fetch-indicators':
            fetch_indicators(client)

        elif command == 'bitcoin-report-address':
            return_results(report_address_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
