from dataclasses import dataclass

import demistomock as demisto  # noqa: F401
from CSVFeedApiModule import *
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
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
    api_token: str
    address: str
    abuse_type_id: int
    abuse_type_other: Optional[str]
    abuser: str
    description: str


class BitcoinAbuseClient(BaseClient):

    def report_address(self, report_address_params: _ReportAddressParams) -> str:
        return self._http_request(
            method='POST',
            url_suffix=REPORT_ADDRESS_SUFFIX,
            params=vars(report_address_params)
        )


def test_module(client: BitcoinAbuseClient) -> str:
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    Args:
        client: BitcoinAbuse client

    Returns:
        'ok' if test passed, anything else will fail the test
    """


def fetch_indicators() -> None:
    params = {k: v for k, v in demisto.params().items() if v is not None}

    fetch_interval = params.get('fetchInterval')  # TODO TOM CHECK NAME And Validate?

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

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Bitcoin Abuse Feed', params, 'bitcoin_abuse')


def report_address_command(client: BitcoinAbuseClient) -> str:
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
