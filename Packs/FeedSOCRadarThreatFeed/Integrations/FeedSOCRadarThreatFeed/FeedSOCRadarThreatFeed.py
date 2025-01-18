import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from json.decoder import JSONDecodeError


import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

SOCRADAR_API_ENDPOINT = 'https://platform.socradar.com/api'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # XSOAR default in ISO8601 format
SOCRADAR_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
MAX_INDICATOR_FETCH_NUMBER = 1000
MESSAGES: dict[str, str] = {
    'BAD_REQUEST_ERROR': 'An error occurred while fetching the data.',
    'AUTHORIZATION_ERROR': 'Authorization Error: make sure API Key is correctly set.',
    'RATE_LIMIT_EXCEED_ERROR': 'Rate limit has been exceeded. Please make sure your your API key\'s rate limit is adequate.',
}

SOCRADAR_RECOMMENDED_COLLECTIONS = [
    "SOCRadar-Attackers-Recommended-Block-Hash",
    "SOCRadar-Attackers-Recommended-Block-IP",
    "SOCRadar-Attackers-Recommended-Block-Domain",
    "SOCRadar-Recommended-Ransomware-Hash",
    "SOCRadar-Recommended-Phishing-Global",
    "SOCRadar-Recommended-Block-Hash",
    "SOCRadar-Recommended-Phishing-Local",
    "SOCRadar-APT-Recommended-Block-IP",
    "SOCRadar-APT-Recommended-Block-Domain",
    "SOCRadar-APT-Recommended-Block-Hash",
    "SOCRadar-Botnet C&C - Block-Domain",
    "SOCRadar-Botnet C&C - Block-IP"
]
INTEGRATION_NAME = 'Feed SOCRadar ThreatFeed'

''' HELPER FUNCTIONS '''


def parse_int_or_raise(str_to_parse: Any, error_msg=None) -> int:
    """Parse a string to integer. Raise ValueError exception if fails with given error_msg
    """
    try:
        res = int(str_to_parse)
    except (TypeError, ValueError):
        if not error_msg:
            error_msg = f"Error while parsing integer! Provided string: {str_to_parse}"
        raise ValueError(error_msg)
    return res


def build_entry_context(indicators: Union[dict, List]) -> List[dict]:
    """Formatting indicators from SOCRadar Threat Feed/IOC API to Demisto Context

    :type indicators: ``Union[Dict, List]``
    :param indicators: Indicators obtained from SOCRadar Threat Feed/IOC API.

    :return: List of context entry dictionaries.
    :rtype: ``list``
    """

    return_context = []

    for indicator_dict in indicators:
        indicator = indicator_dict['value']
        indicator_type = indicator_dict['type']
        indicator_context_dict = {
            'Indicator': indicator,
            'Indicator Type': indicator_type,
            'rawJSON': indicator_dict['rawJSON'],
            'First Seen Date': indicator_dict['fields']['firstseenbysource'],
            'Last Seen Date': indicator_dict['fields']['lastseenbysource'],
            'Feed Maintainer Name': indicator_dict['fields']['collection_maintainer_name'],
            'Seen Count': indicator_dict['fields']['extra_info'].get('seen_count', 1),
        }

        if indicator_type == FeedIndicatorType.IP and indicator_dict['fields']['extra_info'].get('geo_location', []):
            geo_location_dict = indicator_dict['fields']['extra_info']['geo_location']
            asn_code = geo_location_dict.get('AsnCode', '')
            asn_description = geo_location_dict.get('AsnName', '')
            asn = f"[{asn_code}] {asn_description}"
            geo_location_dict['ASN'] = asn
            geo_location_dict = {key: value for key, value in geo_location_dict.items() if key.lower()
                                 not in ('ip', 'asncode', 'asnname')}
            indicator_context_dict['Geo Location'] = geo_location_dict

        return_context.append(indicator_context_dict)
    return return_context


def date_string_to_iso_format_parsing(date_str):
    """Formats a datestring to the ISO-8601 format which the server expects to receive

    :type date_str: ``str``
    :param date_str: String representation of the date.

    :return: ISO-8601 date string
    :rtype: ``str``
    """
    parsed_date_format = dateparser.parse(date_str, date_formats=[SOCRADAR_DATE_FORMAT], settings={'TIMEZONE': 'UTC'})
    assert parsed_date_format is not None, f'could not parse {date_str}'
    return parsed_date_format.strftime(DATE_FORMAT)


def convert_to_demisto_indicator_type(socradar_indicator_type: str, indicator_value: str = None) -> str:
    """Maps SOCRadar indicator type to Cortex XSOAR indicator type

    Converts the SOCRadar indicator types ('hostname', 'url', 'ip', 'hash') to Cortex XSOAR indicator type
    (Domain, URL, IP, File) for mapping.

    :type socradar_indicator_type: ``str``
    :param socradar_indicator_type: indicator type as returned from the SOCRadar API (str)

    :type indicator_value: ``str``
    :param indicator_value: indicator itself (default None)

    :return: Cortex XSOAR Indicator Type (Domain, URL, IP, IPv6 File)
    :rtype: ``str``
    """
    return {
        'hostname': FeedIndicatorType.Domain,
        'url': FeedIndicatorType.URL,
        'ip': FeedIndicatorType.ip_to_indicator_type(indicator_value) if indicator_value else FeedIndicatorType.IP,
        'hash': FeedIndicatorType.File,
    }[socradar_indicator_type]


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with SOCRadar Threat Intelligence API. Overrides BaseClient.
    """

    def __init__(self, base_url, api_key, tags, tlp_color, verify, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.tags = tags
        self.tlp_color = tlp_color

    def get_collection_indicators(self, collection_name, offset, limit):
        suffix = '/threat/intelligence/socradar_collections'
        api_params = {'key': self.api_key, 'collection_names': [collection_name], 'limit': limit, 'offset': offset}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params, timeout=60,
                                      error_handler=self.handle_error_response)
        return response

    def check_auth(self):
        suffix = '/threat/intelligence/check/auth'
        api_params = {'key': self.api_key}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params,
                                      error_handler=self.handle_error_response)

        return response

    def parse_raw_indicators(self, raw_indicators: list, collection_feed_type: str) -> list:
        """Creates a list of indicators from a given response

        :type raw_indicators: ``list``
        :param raw_indicators: List of dict that represent the response from the api

        :type collection_feed_type: ``str``
        :param collection_feed_type: Type of the indicators that exist in the collection

        :return: List of indicators with the correct indicator type.
        :rtype: ``list``
        """
        parsed_indicators = []

        collection_indicator_type = convert_to_demisto_indicator_type(collection_feed_type)

        for indicator_dict in raw_indicators:
            if indicator_dict:
                indicator = indicator_dict.get('feed', '')
                indicator_type = convert_to_demisto_indicator_type(
                    indicator_dict.get('feed_type', ''), indicator) or collection_indicator_type
                if not indicator_type:
                    indicator_type = auto_detect_indicator_type(indicator)

                first_seen_date = indicator_dict.get('first_seen_date', '')
                last_seen_date = indicator_dict.get('latest_seen_date', '')
                maintainer_name = indicator_dict.get('maintainer_name', '')
                extra_info = indicator_dict.get('extra_info', {})

                indicator_obj = {
                    "type": indicator_type,
                    "value": indicator,
                    "rawJSON": {
                        "value": indicator,
                        "type": indicator_type
                    },
                    "fields": {
                        "firstseenbysource": date_string_to_iso_format_parsing(first_seen_date),
                        "lastseenbysource": date_string_to_iso_format_parsing(last_seen_date),
                        "collection_maintainer_name": maintainer_name,
                        "extra_info": extra_info
                    }
                }
                if self.tags:
                    indicator_obj["fields"]["tags"] = self.tags

                if self.tlp_color:
                    indicator_obj["fields"]["trafficlightprotocol"] = self.tlp_color

                parsed_indicators.append(indicator_obj)

        return parsed_indicators

    def build_iterator(self, collection_name, limit=None, is_check_last_fetch=True) -> List:
        """Builds a list of indicators.

        :type collection_name: ``str``
        :param collection_name: The name of the collection to fetch indicators from SOCRadar.

        :type limit: ``int``
        :param limit: Maximum number of indicators to fetch.

        :type is_check_last_fetch: ``bool``
        :param is_check_last_fetch: Flag to decide whether the last fetch should be checked or not.

        :return: A list of JSON objects representing indicators fetched from a feed.
        :rtype: ``list``
        """
        parsed_indicators = []
        offset = 0
        error_count = 0
        batch_size = MAX_INDICATOR_FETCH_NUMBER
        last_fetch_dict = demisto.getIntegrationContext().get('last_fetch', {})
        while True:
            if limit is not None:
                if offset >= limit:
                    break
                batch_size = min(limit - offset, MAX_INDICATOR_FETCH_NUMBER)
            try:
                raw_response = self.get_collection_indicators(collection_name, offset, batch_size)
                if raw_response.get('is_success'):
                    collection_dict = raw_response.get('data', {}).get(collection_name, {})
                    raw_indicators_list = collection_dict.get('collection_data_list', [])
                    collection_date_str = collection_dict.get('collection_date')
                    collection_feed_type = collection_dict.get('collection_feed_type')
                    if not raw_indicators_list:
                        break
                    if is_check_last_fetch:
                        if last_fetch := last_fetch_dict.get(collection_name):
                            collection_date = datetime.strptime(collection_date_str, '%Y-%m-%d').date()
                            last_fetch = datetime.strptime(last_fetch, '%Y-%m-%d').date()
                            if last_fetch >= collection_date:
                                break
                        last_fetch_dict[collection_name] = collection_date_str
                        demisto.setIntegrationContext({'last_fetch': last_fetch_dict})  # type:ignore

                    parsed_indicators.extend(self.parse_raw_indicators(raw_indicators_list,
                                                                       collection_feed_type))  # list of dict of indicators
                    if len(raw_indicators_list) < batch_size:
                        break
                    offset += batch_size
                else:
                    error_count += 1
            except DemistoException as e:
                demisto.debug(f"Error while getting indicators. Skipping batch... Error: {str(e)}")
                offset += batch_size
                error_count += 1
            if error_count > 3:
                break
        return parsed_indicators

    @staticmethod
    def handle_error_response(response) -> None:
        """Handles API response to display descriptive error messages based on status code

        :param response: SOCRadar API response.
        :return: DemistoException for particular error code.
        """

        error_reason = ''
        try:
            json_resp = response.json()
            error_reason = json_resp.get('error') or json_resp.get('message')
        except JSONDecodeError:
            pass

        status_code_messages = {
            400: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            401: MESSAGES['AUTHORIZATION_ERROR'],
            404: f"{MESSAGES['BAD_REQUEST_ERROR']} Reason: {error_reason}",
            429: MESSAGES['RATE_LIMIT_EXCEED_ERROR']
        }

        if response.status_code in status_code_messages:
            demisto.debug(f'Response Code: {response.status_code}, Reason: {status_code_messages[response.status_code]}')
            raise DemistoException(status_code_messages[response.status_code])
        else:
            raise DemistoException(response.raise_for_status())


''' COMMAND FUNCTIONS '''


def test_module(client: Client, collections_to_fetch: List) -> str:
    """Tests by building the iterator to check that a proper connection can be established and the feed is
    accessible with the given parameters.

    :type client: ``Client``
    :param client: client to use

     :type collections_to_fetch: ``list``
    :param collections_to_fetch: Collection names list to fetch indicators from SOCRadar.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.check_auth()
    for collection in collections_to_fetch:
        client.build_iterator(collection, 1, is_check_last_fetch=False)
    return 'ok'


def get_indicators_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Retrieves indicators from the feed to the war-room.

    :type client: ``Client``
    :param client: Client object configured according to instance arguments.

    :type args: ``Dict[str, Any]``
    :param args: Contains all arguments for socradar-get-indicators command.

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    limit = parse_int_or_raise(args.get('limit', 10))
    collections_to_fetch = argToList(args.get('collections_to_fetch'))
    if 'ALL' in collections_to_fetch:
        collections_to_fetch = SOCRADAR_RECOMMENDED_COLLECTIONS

    indicators = fetch_indicators(client, collections_to_fetch, limit, is_check_last_fetch=False)
    context_entry = build_entry_context(indicators)

    human_readable = tableToMarkdown(f'Indicators from SOCRadar ThreatFeed Collections ({", ".join(collections_to_fetch)}):',
                                     context_entry, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='SOCRadarThreatFeed.Indicators',
        outputs_key_field='value',
        outputs=context_entry,
        readable_output=human_readable,
        raw_response=indicators
    )
    return command_results


def fetch_indicators(client: Client, collections_to_fetch: List, limit=None, is_check_last_fetch=True) -> List[dict]:
    """Retrieves indicators from the feed to the war-room.

    :type client: ``Client``
    :param client: Client object configured according to instance arguments.

    :type collections_to_fetch: ``list``
    :param collections_to_fetch: Collection names list to fetch indicators from SOCRadar.

    :type limit: ``int``
    :param limit: Maximum number of indicators to fetch.

    :type is_check_last_fetch: ``bool``
    :param is_check_last_fetch: Flag to decide whether the last fetch should be checked or not.

    :return: Fetched indicators list.
    :rtype: ``List[Dict]``
    """
    indicators = []
    for collection in collections_to_fetch:
        collection_indicators = client.build_iterator(collection, limit, is_check_last_fetch)
        indicators.extend(collection_indicators)

    return indicators


def reset_last_fetch_dict() -> CommandResults:
    """Reset the last fetch from the integration context

    :return: A ``CommandResults`` object that is then passed to ``return_results``.
    :rtype: ``CommandResults``
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history has been successfully deleted!')


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    api_key = params.get('apikey')
    base_url = SOCRADAR_API_ENDPOINT
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    collections_to_fetch = argToList(params.get('collections_to_fetch'))
    if 'ALL' in collections_to_fetch:
        collections_to_fetch = SOCRADAR_RECOMMENDED_COLLECTIONS

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            tags=feed_tags,
            tlp_color=tlp_color,
            verify=verify_certificate,
            proxy=proxy)
        if command == 'test-module':
            return_results(test_module(client, collections_to_fetch))
        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client, collections_to_fetch)
            # Submit indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)  # type: ignore
        elif command == 'socradar-get-indicators':
            return_results(get_indicators_command(client, args))
        elif command == "socradar-reset-fetch-indicators":
            return_results(reset_last_fetch_dict())

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
