# import csv
# from io import StringIO

import demistomock as demisto  # noqa: F401
from CSVFeedApiModule import *
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
SERVER_URL = 'https://www.bitcoinabuse.com/api/'
FEED_ENDPOINT_PREFIX = 'download/'
FEED_ENDPOINT_DAILY = 'download/1d'
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
OTHER_ABUSE_TYPE_ID = 99
REPORT_ADDRESS_SUFFIX = '/reports/create'


class BitcoinAbuseClient(BaseClient):

    def __init__(self, api_key, verify, proxy):
        super().__init__(base_url=SERVER_URL, verify=verify, proxy=proxy)
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

    def download_csv(self) -> str:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:

        Returns:
            Returns response representing the csv file of text if get request was successful.
        """
        return self._http_request(
            method='GET',
            url_suffix=FEED_ENDPOINT_DAILY,
            params={
                'api_token': self.api_key
            },
            resp_type='text'
        )

    def download_csv_new(self, url_interval_suffix: str) -> str:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            download_params: _DownloadParams contains all the required parameters for download get http request
        Returns:
            Returns response representing the csv file of text if get request was successful.
        """
        params = {
            'api_token': self.api_key
        }
        return self._http_request(
            method='GET',
            url_suffix=FEED_ENDPOINT_PREFIX + url_interval_suffix,
            params=params,
            resp_type='text'
        )


def build_fetch_indicators_url_suffix(have_fetched_first_time: bool, feed_interval_suffix_url: str) -> str:
    """

    Args:
        have_fetched_first_time: bool indicates if a fetch from BitcoinAbuse have been made
        feed_interval_suffix_url: str the prefix for downloading csv from Bitcoin Abuse

    Returns:
        - if first fetch - returns the feed endpoint prefix concatenated with the first_fetch_interval requested
        - if first fetch was already done - returns the feed endpoint prefix concatenated with 1d fetch prefix
    """
    if have_fetched_first_time:
        return FEED_ENDPOINT_DAILY
    else:
        demisto.setIntegrationContext({'have_fetched_first_time': True})
        return FEED_ENDPOINT_PREFIX + feed_interval_suffix_url


def _build_fetch_indicators_params(demisto_params: Dict, feed_url_prefix: str) -> Dict:
    """
    helper function that builds the params for CSVFeedApiModule to fetch indicators

    Args:
        demisto_params: Dict

    Returns:
        csv_api_params: Dict

    """
    params = {k: v for k, v in demisto_params.items() if v is not None}

    api_key = demisto_params.get('api_key', '')
    url = f'{SERVER_URL}{feed_url_prefix}?api_token={api_key}'

    feed_url_to_config = {
        url: {
            'fieldnames': ['id', 'address', 'abuse_type_id', 'abuse_type_other', 'abuser',
                           'description', 'from_country', 'from_country_code', 'created_at'],
            'skip_first_line': True,
            'indicator_type': 'Cryptocurrency Address',
            'mapping': {
                'Value': ('address', None, 'bitcoin-{}'),
                'Country Name': 'from_country',
                'Creation Date': 'created_at',
                'Bitcoin Abuse Description': 'description',
                'Abuse Type': ('abuse_type_id', lambda abuse_type_id: abuse_type_id_to_name.get(abuse_type_id))
            }
        }
    }

    params['url'] = url
    params['feed_url_to_config'] = feed_url_to_config
    params['delimiter'] = ','

    return params


def fetch_indicators(demisto_params: Dict, feed_url_prefix: str) -> None:
    """
    Wrapper which calls to CSVFeedApiModule for fetching indicators from Bitcoin Abuse download csv feed.
    Args:
        demisto_params: Dict
        feed_url_prefix: str the prefix for download csv request

    Returns:

    """
    csv_api_params = _build_fetch_indicators_params(demisto_params, feed_url_prefix)
    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Bitcoin Abuse Feed', csv_api_params, 'bitcoin')


def report_address_command(client: BitcoinAbuseClient, args: Dict) -> CommandResults:
    """
    Reports a bitcoin abuse to Bitcoin Abuse integration

    Args:
        client: BitcoinAbuseClient  used to post abuse to the api
        args: Dict

    Returns:
        'bitcoin address (address reported) by abuser (abuser reported) was
        reported to BitcoinAbuse API' if http request was successful'
    """
    abuse_type_id = abuse_type_name_to_id.get(args.get('abuse_type', ''))
    abuse_type_other = args.get('abuse_type_other')
    address = args.get('address', '')
    abuser = args.get('abuser', '')

    if abuse_type_id is None:
        raise DemistoException('Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type')

    if abuse_type_id == OTHER_ABUSE_TYPE_ID and abuse_type_other is None:
        raise DemistoException('Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other')

    http_response = client.report_address(address=address,
                                          abuse_type_id=abuse_type_id,
                                          abuse_type_other=abuse_type_other,
                                          abuser=args.get('abuser', ''),
                                          description=args.get('description', ''))

    if http_response.get('success') is True:
        return CommandResults(
            readable_output=f'Bitcoin address {address} by abuse bitcoin user {abuser}'
                            f' was reported to BitcoinAbuse API'
        )
    else:
        failure_message = http_response.get('response')
        raise DemistoException(f'bitcoin report address did not succeed: {failure_message}')


def _create_indicator_obj(row: Dict[str, str]):
    return {
        'Value': row['address'],
        'Country Name': row['from_country'],
        'Creation Date': row['created_at'],
        'Description': row['description'],
        'Abuse Type': abuse_type_id_to_name.get(row['abuse_type_id'])
    }


# def _csv_to_indicators(csv_reader):
#     for fetch_url in first_fetch_urls:
#         response = client.download_csv_new(fetch_url)
#         csv_reader = csv.DictReader(StringIO(response))
#         for row in csv_reader:
#             indicator_obj = _create_indicator_obj(row)
#             indicators.append(indicator_obj)
#         max_id = row['id']
#         b = 2


# def _fetch_indicators_first_time(feed_interval_url_suffix: str, client: BitcoinAbuseClient):
#     indicators = []
#     first_fetch_urls = {feed_interval_url_suffix, '30d'}
#     for fetch_url in first_fetch_urls:
#         response = client.download_csv_new(fetch_url)
#         csv_reader = csv.DictReader(StringIO(response))
#         for row in csv_reader:
#             indicator_obj = _create_indicator_obj(row)
#             indicators.append(indicator_obj)
#         max_id = row['id']
#         b = 2
#
#     demisto.setIntegrationContext({'have_fetched_first_time': True})


def main() -> None:
    command = demisto.command()
    params = {k: v for k, v in demisto.params().items() if v is not None}
    args = demisto.args()

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('api_key', '')
    have_fetched_first_time = demisto.getIntegrationContext().get('have_fetched_first_time', False)
    # first_feed_interval_url_suffix = params.get('initial_fetch_interval', '30d')

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    client = BitcoinAbuseClient(
        verify=verify_certificate,
        proxy=proxy,
        api_key=api_key)
    try:

        if command == 'test-module':
            client.download_csv()

            return_results('ok')

        elif command == 'fetch-indicators':
            # _fetch_indicators_first_time(first_feed_interval_url_suffix, client)
            feed_url_prefix = build_fetch_indicators_url_suffix(have_fetched_first_time, first_feed_interval_url_prefix)
            fetch_indicators(params, feed_url_prefix)

        elif command == 'bitcoin-report-address':
            return_results(report_address_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
