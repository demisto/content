import demistomock as demisto  # noqa: F401
from CSVFeedApiModule import *
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
SERVER_URL = 'https://www.bitcoinabuse.com/api/'
ABUSE_TYPE_ID_TO_NAME: Dict[str, str] = {
    '1': 'ransomware',
    '2': 'darknet market',
    '3': 'bitcoin tumbler',
    '4': 'blackmail scam',
    '5': 'sextortio',
    '99': 'other'
}

READER_CONFIG = {
    'fieldnames': ['id', 'address', 'abuse_type_id', 'abuse_type_other', 'abuser',
                   'description', 'from_country', 'from_country_code', 'created_at'],
    'skip_first_line': True,
    'indicator_type': 'Cryptocurrency Address',
    'mapping': {
        'Value': ('address', None, 'bitcoin:{}'),
        'rawaddress': 'address',
        'countryname': 'from_country',
        'creationdate': 'created_at',
        'description': 'description',
        'abusetype': ('abuse_type_id', lambda abuse_type_id: ABUSE_TYPE_ID_TO_NAME.get(abuse_type_id))
    }
}


class BitcoinAbuseClient(BaseClient):
    first_fetch_interval_to_url_suffix: Dict[str, str] = {
        'Forever': 'forever',
        '30 Days': '30d'
    }

    abuse_type_name_to_id = {
        'ransomware': 1,
        'darknet market': 2,
        'bitcoin tumbler': 3,
        'blackmail scam': 4,
        'sextortio': 5,
        'other': 99
    }

    def __init__(self, base_url, insecure, proxy, api_key, initial_fetch_interval, reader_config,
                 have_fetched_first_time):
        super().__init__(base_url=base_url, verify=not insecure, proxy=proxy)
        self.server_url = base_url
        self.api_key = api_key
        self.initial_fetch_interval = initial_fetch_interval
        self.reader_config = reader_config
        self.have_fetched_first_time = have_fetched_first_time
        self.insecure = insecure

    def report_address(self, address: str, abuse_type_id: int, abuse_type_other: Optional[str],
                       abuser: str, description: str) -> Dict:
        """
        Sends a post request to report an abuse to BitcoinAbuse servers.

        Args:
            address (str): The address of the abuser.
            abuse_type_id (int): An id which indicates which type of abuse was made.
            abuse_type_other (Optional[str]): In case abuse_type_id was other, holds information describing the
                                              abuse type.
            abuser (str): Information about the abuser (email, name, ...).
            description (str): Description of the abuse (may include email sent, etc).

        Returns:
            Returns if post request was successful.
        """
        return self._http_request(
            method='POST',
            url_suffix='reports/create',
            params=assign_params(
                api_token=self.api_key,
                address=address,
                abuse_type_id=abuse_type_id,
                abuser=abuser,
                description=description,
                abuse_type_other=abuse_type_other
            )
        )

    def get_indicators(self) -> List[Dict]:
        """
        Builds CSV module client and performs the API call to Bitcoin Abuse service.
        If the call was successful, returns list of indicators.
        Args:

        Returns:
            - Throws exception if an invalid api key was given or error occurred during the call to
              Bitcoin Abuse service.
            - Returns indicators list if the call to Bitcoin Abuse service was successful.
        """

        indicators_name_to_count_dict: Dict[str, int] = dict()

        params = self.build_params_for_csv_module()
        csv_module_client = Client(**params)

        indicators = fetch_indicators_command(
            client=csv_module_client,
            default_indicator_type='Cryptocurrency Address',
            auto_detect=False,
            limit=0
        )

        self.assure_valid_response(indicators)

        indicators_without_duplicates = []

        # in every fetch apart from first fetch, we are only fetching one csv file, so we know there aren't any
        # duplicates
        if self.have_fetched_first_time:
            for indicator in indicators:
                update_indicator_occurrences(indicator, indicators_name_to_count_dict)
            indicators_without_duplicates = indicators

        # in first fetch according to configurations, we might fetch more than one csv file, so we need to remove
        # duplicates
        else:
            indicators_ids = set()
            for indicator in indicators:
                try:
                    indicator_id = int(indicator['rawJSON']['id'])
                    if indicator_id not in indicators_ids:
                        update_indicator_occurrences(indicator, indicators_name_to_count_dict)
                        indicators_without_duplicates.append(indicator)
                        indicators_ids.add(indicator_id)
                except ValueError:
                    demisto.debug(f'The following indicator was found invalid and was skipped: {indicator}')

        for indicator in indicators_without_duplicates:
            indicator_count = indicators_name_to_count_dict.get(indicator['value'])
            indicator['fields']['reportscount'] = indicator_count
            indicator['fields']['cryptocurrencyaddresstype'] = 'bitcoin'

        return indicators_without_duplicates

    def build_fetch_indicators_url_suffixes(self) -> Set[str]:
        """
        Builds the URL suffix fo the fetch. Default is 'download/1d' unless this is a first fetch
        which will be determined by the user parameter - initial_fetch_interval.

        - If initial_fetch_interval is 'forever' - then suffixes will include 30d and forever, in order to extract
          the most updated data by the Bitcoin Abuse service, as 'forever' csv file only updates on 15 of each month
          (see Complete Download in https://www.bitcoinabuse.com/api-docs).
        - If initial_fetch_interval is '30d' - suffixes will only include '30d' suffix.

        Args:

        Returns:
            - Set of the url suffixes to be used in the fetch process.
        """
        feed_endpoint_suffix = 'download/'
        first_feed_interval_url_suffix = BitcoinAbuseClient.first_fetch_interval_to_url_suffix.get(
            self.initial_fetch_interval, '30d')

        if self.have_fetched_first_time:
            return {'download/1d'}
        else:
            return {feed_endpoint_suffix + first_feed_interval_url_suffix, feed_endpoint_suffix + '30d'}

    def build_params_for_csv_module(self):
        """
        Builds needed params for CSV Module client in order to fetch indicators from Bitcoin Abuse service.

        Args:

        Returns:
            - Params for building the CSVFeedApiModule client.
        """
        params: Dict[str, Any] = dict()
        urls_suffixes = self.build_fetch_indicators_url_suffixes()
        urls = [f'{self.server_url}{url_suffix}?api_token={self.api_key}' for url_suffix in urls_suffixes]
        feed_url_to_config = {url: self.reader_config for url in urls}

        params['url'] = urls
        params['feed_url_to_config'] = feed_url_to_config
        params['delimiter'] = ','

        params['encoding'] = 'utf-8'

        params['insecure'] = self.insecure

        return params

    @staticmethod
    def assure_valid_response(indicators: List[Dict]) -> None:
        """
        Receives the indicators fetched from Bitcoin Abuse service, and checks if
        the response received is valid.
        When an incorrect api key is inserted, Bitcoin Abuse returns response of
        their login page.

        This function checks if the api key given is incorrect by checking if the received
        response was the login page.
        Throws DemistoException to inform the user of incorrect api key.

        Args:
            indicators (List[Dict]): The array of indicators fetched.

        Returns:
            - Throws DemistoException in case an incorrect api key was given.
        """
        if indicators and '<html lang="en">' == indicators[0]['value']:
            raise DemistoException('api token inserted is not valid')


''' HELPER FUNCTIONS '''


def update_indicator_occurrences(indicator_obj: Dict, indicators_name_to_count_dict: Dict[str, int]) -> None:
    indicator_name = indicator_obj['value']
    updated_count = indicators_name_to_count_dict.get(indicator_name, 0) + 1
    indicators_name_to_count_dict[indicator_name] = updated_count


''' COMMAND FUNCTIONS '''


def bitcoin_abuse_report_address_command(bitcoin_client: BitcoinAbuseClient, args: Dict) -> CommandResults:
    """
    Reports a bitcoin abuse to Bitcoin Abuse service

    Args:
        bitcoin_client (BitcoinAbuseClient): Client object to perform request.
        args (Dict): Demisto args for report address command.

    Returns:
        str: 'bitcoin address (address reported) by abuser (abuser reported) was
        reported to BitcoinAbuse API' if http request was successful'
    """
    raise DemistoException('')
    abuse_type_id = BitcoinAbuseClient.abuse_type_name_to_id.get(args.get('abuse_type', ''))
    abuse_type_other = args.get('abuse_type_other')
    address = args.get('address', '')
    abuser = args.get('abuser', '')
    description = args.get('description', '')

    if abuse_type_id is None:
        raise DemistoException('Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type')
    if abuse_type_id == BitcoinAbuseClient.abuse_type_name_to_id['other'] and abuse_type_other is None:
        raise DemistoException('Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other')
    http_response = bitcoin_client.report_address(address=address,
                                                  abuse_type_id=abuse_type_id,
                                                  abuse_type_other=abuse_type_other,
                                                  abuser=abuser,
                                                  description=description)

    if argToBoolean(http_response.get('success')):
        return CommandResults(
            readable_output=f'Bitcoin address {address} by abuse bitcoin user {abuser}'
                            f' was reported to BitcoinAbuse service'
        )
    else:
        failure_message = http_response.get('response')
        raise DemistoException(f'bitcoin report address did not succeed: {failure_message}')


def test_module_command(bitcoin_client: BitcoinAbuseClient):
    """
    Performs a fetch indicators flow to validate the configuration params.

    Args:
        bitcoin_client (BitcoinAbuseClient): Client object.

    Returns:
        'ok' if the call to Bitcoin Abuse service was successful and command is test_module.
    """
    bitcoin_client.get_indicators()
    return 'ok'


def bitcoin_abuse_fetch_indicators_command(bitcoin_client: BitcoinAbuseClient) -> None:
    """
    Wrapper for fetching indicators from Bitcoin Abuse service.
    Args:
        bitcoin_client (BitcoinAbuseClient): Client object.

    Returns:

    """
    indicators = bitcoin_client.get_indicators()
    for b in batch(indicators, batch_size=2000):
        demisto.createIndicators(b)  # type: ignore
    demisto.setIntegrationContext({'have_fetched_first_time': True})


def bitcoin_abuse_get_indicators_command(bitcoin_client: BitcoinAbuseClient, args: Dict):
    """
    Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        bitcoin_client (BitcoinAbuseClient): Client object to perform request.
        args (Dict): Demsisto args.

    Returns:
        CommandResults.
    """
    indicators = bitcoin_client.get_indicators()
    limit = arg_to_number(args.get('limit', 50), 'limit')
    truncated_indicators_list = indicators[:limit]
    return CommandResults(
        readable_output=tableToMarkdown('Indicators', truncated_indicators_list,
                                        headers=['value', 'type', 'fields']),
        raw_response=truncated_indicators_list
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()

    demisto.debug(f'Bitcoin Abuse: Command being called is {demisto.command()}')

    api_key = params.get('api_key', '')
    insecure = params.get('insecure', False)
    proxy = params.get('proxy', False)
    initial_fetch_interval = params.get('initial_fetch_interval', '30 Days')

    have_fetched_first_time = argToBoolean(demisto.getIntegrationContext().get('have_fetched_first_time', False))

    try:
        bitcoin_client = BitcoinAbuseClient(
            base_url=SERVER_URL,
            insecure=insecure,
            proxy=proxy,
            api_key=api_key,
            initial_fetch_interval=initial_fetch_interval,
            reader_config=READER_CONFIG,
            have_fetched_first_time=have_fetched_first_time)
        return_results(bitcoin_abuse_get_indicators_command(bitcoin_client, demisto.args()))

        if command == 'test-module':
            return_results(test_module_command(bitcoin_client))

        elif command == 'fetch-indicators':
            bitcoin_abuse_fetch_indicators_command(bitcoin_client)

        elif command == 'bitcoinabuse-get-indicators':
            return_results(bitcoin_abuse_get_indicators_command(bitcoin_client, demisto.args()))

        elif command == 'bitcoinabuse-report-address':
            return_results(bitcoin_abuse_report_address_command(bitcoin_client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
