from dataclasses import dataclass

import demistomock as demisto  # noqa: F401
from CSVFeedApiModule import *
from CommonServerPython import *  # noqa: F401

# disable insecure warningsø
urllib3.disable_warnings()

''' CONSTANTS '''
SERVER_URL = 'https://www.bitcoinabuse.com/api/'
API_KEY = demisto.params().get('api_key', '')
FEED_ENDPOINT_PREFIX = 'download/'
REPORT_ADDRESS_ENDPOINT_PREFIX = 'reports/create'
abuse_type_name_to_id: Dict[str, int] = {
    'ransomware': 1,
    'darknet market': 2,
    'bitcoin tumbler': 3,
    'blackmail scam': 4,
    'sextortio': 5,
    'other': 99
}
OTHER_ABUSE_TYPE_ID = 99
REPORT_ADDRESS_SUFFIX = '/reports/create'


@dataclass
class _ReportAddressParams:
    """
    contains all the parameters required for reporting address post http request
    Fields:
        api_token: the api token to connect to Bitcoin Abuse API
        address: the address of the abuser
        abuse_type_id: an id which indicates which type of abuse was made
        abuse_type_other: incase abuse_type_id was other, holds information describing the abuse type
        abuser: information about the abuser (email, name, ...)
        description: description of the abuse (may include email sent, etc)
    """
    api_token: str
    address: str
    abuse_type_id: int
    abuse_type_other: Optional[str]
    abuser: str
    description: str


@dataclass
class _DownloadParams:
    """
    contains all the parameters required for downloading csv get http request
    Fields:
        api_token: the api token to connect to Bitcoin Abuse API
    """
    api_token: str


class BitcoinAbuseClient(BaseClient):

    def report_address(self, report_address_params: _ReportAddressParams) -> Dict:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            report_address_params: _ReportAddressParams contains all the required parameters for report address http post request
        Returns:
            Returns if post request was successful.
        """
        return self._http_request(
            method='POST',
            url_suffix=REPORT_ADDRESS_SUFFIX,
            params=vars(report_address_params)
        )

    def download_csv(self, download_params: _DownloadParams, time_period: str) -> str:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            download_params: _DownloadParams contains all the required parameters for download get http request
            time_period: str the time period to receive in the csv from Bitcoin Abuse API.
                         Allowed options are 1d, 30d, or forever
        Returns:
            Returns response representing the csv file of text if get request was successful.
        """
        url_suffix = FEED_ENDPOINT_PREFIX + time_period
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=vars(download_params),
            resp_type='text'
        )


def test_module(client: BitcoinAbuseClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :param client: BitcoinAbuseClient the client to use for the api request

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    params = demisto.params()

    time_period = params.get('fetchInterval')

    download_params = _DownloadParams(API_KEY)
    client.download_csv(download_params, time_period)
    return "ok"


def _build_fetch_indicators_params() -> Dict:
    """
    helper function that builds the params for CSVFeedApiModule to fetch indicators
    Returns:
        params: Dict
    """
    params = {k: v for k, v in demisto.params().items() if v is not None}

    fetch_interval = params.get('fetchInterval')

    feed_url_to_config = {
        f'{SERVER_URL}{FEED_ENDPOINT_PREFIX}{fetch_interval}?api_token={API_KEY}': {
            'fieldnames': ['id', 'address', 'abuse_type_id', 'abuse_type_other', 'abuser',
                           'description', 'from_country', 'from_country_code', 'created_at'],
            'indicator_type': 'Cryptocurrency Address',
            'mapping': {
                'address': 'value',
                'from_country': 'Country Name',
                'created_at': 'Creation Date',
                'description': 'Bitcoin Abuse Description',
                'abuse_type': 'todo '  # TODO TOM
            }
        }
    }

    params['url'] = f'{SERVER_URL}{FEED_ENDPOINT_PREFIX}{fetch_interval}?api_token={API_KEY}'
    params['feed_url_to_config'] = feed_url_to_config
    params['delimiter'] = ','
    return params


def fetch_indicators() -> None:
    """
    Wrapper which calls to CSVFeedApiModule for fetching indicators from Bitcoin Abuse download csv feed.
    """

    params = _build_fetch_indicators_params()
    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Bitcoin Abuse Feed', params, 'bitcoin')


def _build_report_address_params() -> _ReportAddressParams:
    """
    Builds the params for reporting an address to Bitcoin Abuse
    after running some validation on the input

    Returns:
        report_address_params: _ReportAddressParams if validation succeeded
        raises DemistoException if validation failed

    """
    args = demisto.args()

    abuse_type_id = abuse_type_name_to_id.get(args.get('abuse_type', ''))
    abuse_type_other = args.get('abuse_type_other')

    if abuse_type_id is None:
        raise DemistoException("Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type")

    if abuse_type_id == OTHER_ABUSE_TYPE_ID and abuse_type_other is None:
        raise DemistoException("Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other")

    return _ReportAddressParams(
        api_token=API_KEY,
        address=args.get('address', ''),
        abuse_type_id=abuse_type_id,
        abuse_type_other=abuse_type_other,
        abuser=args.get('abuser', ''),
        description=args.get('description', '')
    )


def report_address_command(client: BitcoinAbuseClient) -> str:
    """
    Reports a bitcoin abuse to Bitcoin Abuse integration

    :param client: BitcoinAbuseClient  used to post abuse to the api
    :return: 'ok' if http request was successful
    """
    report_address_params: _ReportAddressParams = _build_report_address_params()
    response = client.report_address(report_address_params)
    if response.get('success') is True:
        return "ok"
    else:
        raise DemistoException(f"bitcoin report address did not succeed, response was {response}")


def main() -> None:
    command = demisto.command()

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    client = BitcoinAbuseClient(
        base_url=SERVER_URL,
        verify=verify_certificate,
        proxy=proxy)
    try:

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-indicators':
            fetch_indicators()

        elif command == 'bitcoin-report-address':
            return_results(report_address_command(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
