from dataclasses import dataclass

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

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
    api_token: str
    address: str
    abuse_type_id: int
    abuse_type_other: Optional[str]
    abuser: str
    description: str


@dataclass
class _DownloadParams:
    api_token: str


class Client(BaseClient):

    def report_address(self, report_address_params: _ReportAddressParams) -> str:
        return self._http_request(
            method='POST',
            url_suffix=REPORT_ADDRESS_SUFFIX,
            params=vars(report_address_params)
        )

    def download_csv(self, download_params: _DownloadParams, time_period: str) -> str:
        url_suffix = FEED_ENDPOINT_PREFIX + time_period
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=vars(download_params)
        )


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    Args:
        client: BitcoinAbuse client

    Returns:
        'ok' if test passed, anything else will fail the test
    """


def fetch_indicators(client: Client):
    params = demisto.params()
    time_period = params.get('fetchInterval')
    if time_period is None:
        raise DemistoException("TODO WRITE HERE")  # TODO TOM write here
    download_params = _DownloadParams(API_KEY)
    response = client.download_csv(download_params, time_period)

def report_address_command(client: Client) -> str:
    params = demisto.params()

    def is_valid_abuse_type(abuse_id, abuse_info):
        valid_other_abuse_id = abuse_id == OTHER_ABUSE_TYPE_ID and abuse_info is not None
        valid_rest_abuse_id = abuse_id is not None and abuse_id is not None
        return valid_rest_abuse_id or valid_other_abuse_id

    abuse_type_id = abuse_type_name_to_id.get(params.get('abuse_type', ''))
    abuse_type_other = params.get('abuse_type_other')  # TODO TOM VALIDATE NAME

    if not is_valid_abuse_type(abuse_type_id, abuse_type_other):
        raise DemistoException("TODO WHAT TO WRITE")  # TODO TOM WHICH ERROR TO RAISE?

    report_address_params = _ReportAddressParams(
        api_token=API_KEY,
        address=params.get('address', ''),
        abuse_type_id=abuse_type_id,
        abuse_type_other=abuse_type_other,
        abuser=params.get('abuser', ''),
        description=params.get('description', '')
    )
    return client.report_address(report_address_params)


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    command = demisto.command()

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    client = Client(
        base_url=SERVER_URL,
        verify=verify_certificate,
        proxy=proxy)
    try:

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-indicators':
            return_results(fetch_indicators(client))

        elif command == 'bitcoin-report-address':
            return_results(report_address_command(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
