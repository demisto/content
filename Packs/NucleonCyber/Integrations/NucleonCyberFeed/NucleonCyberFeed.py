import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3


# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld Feed implementation, no special attributes defined
    """

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        indicators = self._http_request('GET', full_url=self._base_url)

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if auto_detect_indicator_type(indicator):
                    result.append({
                        'value': indicator,
                        'type': auto_detect_indicator_type(indicator),
                        'FeedURL': self._base_url
                    })

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError massage: {err}') from err
        return result

    def get_hashes(self) -> List:
        json_payload = self._http_request('GET', full_url="http://api.cybercure.ai/feed/get_hash")
        result = []
        all_urls = json_payload.get("data").get("hash")
        for data in all_urls:
            result.append(
                {
                    'value': data,
                    "type": "File",
                }
            )
        return result

    def get_urls(self) -> List:
        json_payload = self._http_request('GET', full_url="http://api.cybercure.ai/feed/get_url")
        result = []
        response_data = json_payload.get("data")
        if response_data:
            all_urls = response_data.get("urls")
            for data in all_urls:
                result.append(
                    {
                        'value': data,
                        "type": "URL",
                    }
                )
        return result

    def get_ips(self, params: Dict[str, Any], limit: int) -> List:
        credentials: Dict = params.get('credentials', {})
        global_username = credentials.get('identifier')
        global_password = credentials.get('password')
        global_usrn = params.get('usrn')
        global_client_id = params.get('clientid')
        body = {'usrn': global_usrn, 'clientID': global_client_id, 'limit': limit}
        json_payload = self._http_request(
            'POST',
            full_url="https://api.nucleoncyber.com/feed/activethreats",
            auth=(global_username, global_password),
            data=body,
        )
        result = []
        all_data = json_payload.get("data")
        demisto.debug(all_data)
        for data in all_data:
            if not data.get("attackDetails"):
                continue
            if not data.get("attackDetails").get('remote'):
                continue
            if not data.get("attackMeta"):
                continue
            result.append(
                {
                    'value': data.get("ip"),
                    "exp": data.get("exp"),
                    'type': "IP",
                    'segment': data.get("attackDetails").get("segment", "other"),
                    'targetCountry': data.get("attackDetails").get("targetCountry", "unreconized"),
                    'os': data.get("attackDetails").get("remote").get("os", "unreconized"),
                    'osVersion': data.get("attackDetails").get("remote").get("osVersion", "unreconized"),
                    'governments': data.get("attackMeta").get("governments", False),
                    'port': data.get("attackMeta").get("port", False),
                    'darknet': data.get("attackMeta").get("darknet", False),
                    'bot': data.get("attackMeta").get("bot", False),
                    'cnc': data.get("attackMeta").get("cnc", False),
                    'proxy': data.get("attackMeta").get("proxy", False),
                    'automated': data.get("attackMeta").get("automated", False),
                    'bruteForce': data.get("attackMeta").get("bruteForce", False),
                    'sourceCountry': data.get("attackMeta").get("sourceCountry", False),
                }
            )
        return result


def fetch_indicators(client: Client, tlp_color: Optional[str], feed_tags: List, limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    params = demisto.params()
    iterator = client.get_ips(params, limit)

    indicators = []

    # extract values from iterator
    tags_ = []
    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        segment_ = item.get('segment')
        targetCountry_ = item.get('targetCountry')
        os_ = item.get('os')
        osVersion_ = item.get('osVersion')
        governments_ = item.get('governments')
        port_ = item.get('port')
        darknet_ = item.get('darknet')
        bot_ = item.get('bot')
        cnc_ = item.get('cnc')
        proxy_ = item.get('proxy')
        automated_ = item.get('automated')
        bruteForce_ = item.get('bruteForce')
        sourceCountry_ = item.get('sourceCountry')
        tags_name = {
            'botnet': bot_,
            'darknet': darknet_,
            'cnc': cnc_,
            'automated': automated_,
            'bruteForce': bruteForce_,
        }
        for tag_name, tag_value in tags_name.items():
            if (isinstance(tag_value, str) and tag_value == 'true') or (
                    isinstance(tag_value, bool) and tag_value is True):
                tags_.append(tag_name)

        if segment_:
            tags_.append(segment_)

        raw_data = {
            'value': value_,
            'type': type_,
            'segment': segment_,
            'targetCountry': targetCountry_,
            'os': os_,
            'osVersion': osVersion_,
            'governments': governments_,
            'port': port_,
            'darknet': darknet_,
            'botnet': bot_,
            'cnc': cnc_,
            'proxy': proxy_,
            'automated': automated_,
            'bruteForce': bruteForce_,
            'sourceCountry': sourceCountry_
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})

        indicator_obj = {
            # The indicator value.
            'value': value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'NucleonCyberFeed',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            # A dictionary of the raw data returned from the feed source about the indicator.
            'fields': {},
            'rawJSON': raw_data
        }

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        if feed_tags or tags_:
            indicator_obj['fields']['tags'] = feed_tags + tags_

        indicators.append(indicator_obj)

    return indicators


def fetch_hashes(client: Client, limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.get_hashes()

    indicators = []

    if limit > 0:
        iterator = iterator[:limit]
    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})

        indicator_obj = {
            # The indicator value.
            'value': value_,
            'type': type_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            # The name of the service supplying this feed.
            'service': 'NucleonCyberFeed',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }
        indicators.append(indicator_obj)

    return indicators


def fetch_urls(client: Client, limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.get_urls()

    indicators = []

    if limit > 0:
        iterator = iterator[:limit]
    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})

        indicator_obj = {
            # The indicator value.
            'value': value_,
            'type': type_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            # The name of the service supplying this feed.
            'service': 'NucleonCyberFeed',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }
        indicators.append(indicator_obj)

    return indicators


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        All indicators type (ip,url,hash(file)).
    """
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    ips = fetch_indicators(client, tlp_color, feed_tags)
    urls = fetch_urls(client)
    hashes = fetch_hashes(client)
    return [ips, urls, hashes]


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
        IP indicators
    """
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color') if params.get('tlp_color') else 'GREEN'
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown(
        'IP indicators from NucleonCyberFeed: ',
        indicators,
        headers=['value', 'type', 'exp'],
        headerTransform=string_to_table_header,
        removeNull=True
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='NucleonCyber.Indicators',
        outputs_key_field='value',
        raw_response=indicators,
        outputs=indicators,
    )


def get_hashes_command(client: Client,
                       args: Dict[str, Any]
                       ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        args: demisto.args()
    Returns:
        Outputs.
        Hash indicators
    """
    limit = int(args.get('limit', '10'))
    hashes = fetch_hashes(client, limit)
    human_readable = tableToMarkdown(
        'Hash indicators from NucleonCyberFeed: ',
        hashes,
        headers=['value', 'type'],
        headerTransform=string_to_table_header,
        removeNull=True
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='NucleonCyber.Indicators.hash',
        outputs_key_field='hash',
        raw_response=hashes,
        outputs=hashes,
    )


def get_urls_command(client: Client,
                     args: Dict[str, Any]
                     ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        args: demisto.args()
    Returns:
        Outputs.
        url indicators
    """
    limit = int(args.get('limit', '10'))
    urls = fetch_urls(client, limit)
    human_readable = tableToMarkdown(
        'URL indicators from NucleonCyberFeed:',
        urls,
        headers=['value', 'type'],
        headerTransform=string_to_table_header,
        removeNull=True
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='NucleonCyber.Indicators.url',
        outputs_key_field='url',
        raw_response=urls,
        outputs=urls,
    )


def main():
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    base_url = params.get('url')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )
        if command == 'test-module':
            client.get_ips(params, 10)
            demisto.results('ok')
        if command == 'nucleon-get-indicators':
            type_ = args.get('type')
            if type_ == 'hash':
                return_results(get_hashes_command(client, args))
            elif type_ == 'url':
                return_results(get_urls_command(client, args))
            else:
                return_results(get_indicators_command(client, params, args))
        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            ips, urls, hashes = fetch_indicators_command(client, params)
            for iter_ in batch(ips, batch_size=2000):
                demisto.createIndicators(iter_)
            for iter_ in batch(urls, batch_size=2000):
                demisto.createIndicators(iter_)
            for iter_ in batch(hashes, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        err_msg: str = str(e)
        if 'Error in API call [401]' in err_msg:
            err_msg = 'Unauthorized. Make sure your credentials are correct.'
        return_error(f'Failed to execute {command} command.\nError:\n{err_msg}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
