import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import bz2
import io
import json
import tarfile
import urllib3

# Disable insecure warnings.
urllib3.disable_warnings()


def _get_current_hour():
    """Gets current hour for Threat feeds."""
    time_obj = datetime.utcnow() - timedelta(hours=2)
    hour = time_obj.strftime('%Y%m%d%H')
    return hour


def _get_indicators(response):
    """Gets indicators from response."""
    indicators = []
    decompressed_data = bz2.decompress(response)
    tar_bytes = io.BytesIO(decompressed_data)
    with tarfile.open(fileobj=tar_bytes, mode='r:') as tar:
        for member in tar.getmembers():
            file_data = tar.extractfile(member)
            if file_data:
                while line := file_data.readline():
                    decoded_data = line.decode('utf-8')
                    indicator = json.loads(decoded_data)
                    indicators.append(indicator)
    return indicators


class Client(BaseClient):
    """Client for Google Threat Intelligence API."""

    def fetch_indicators(self, feed_type: str = 'apt', hour: str = None):
        """Fetches indicators given a feed type and an hour."""
        if not hour:
            hour = _get_current_hour()
        return self._http_request(
            'GET',
            f'threat_feeds/{feed_type}/hourly/{hour}',
            resp_type='content',
        )

    def get_threat_feed(self, feed_type: str) -> list:
        """Retrieves matches for a given feed type."""
        last_threat_feed = demisto.getIntegrationContext().get('last_threat_feed')

        hour = _get_current_hour()

        if last_threat_feed == hour:
            return []

        response = self.fetch_indicators(feed_type, hour)
        matches = _get_indicators(response)
        demisto.setIntegrationContext({'last_threat_feed': hour})
        return matches


def test_module(client: Client) -> str:
    client.fetch_indicators()
    return 'ok'


def fetch_indicators_command(client: Client,
                             feed_type: str,
                             tlp_color: str = None,
                             feed_tags: list = None,
                             limit: int = 40) -> list[dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): Tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.get_threat_feed(feed_type)
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        attributes = item.get('attributes', {})
        type_ = FeedIndicatorType.File
        raw_data = {
            'value': attributes,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        indicator_obj = {
            # The indicator value.
            'value': attributes['sha256'],
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'Google Threat Intelligence',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
                'md5': attributes.get('md5'),
                'sha1': attributes.get('sha1'),
                'sha256': attributes.get('sha256'),
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data,
            'sha256': attributes['sha256'],
            'fileType': attributes.get('type_description'),
        }

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    feed_type = params.get('feed_type', 'apt')
    limit = int(args.get('limit', params.get('limit', 40)))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators_command(client, feed_type, tlp_color, feed_tags, limit)

    human_readable = tableToMarkdown(
        'Indicators from Google Threat Intelligence Categorized Feeds:',
        indicators,
        headers=[
            'sha256',
            'fileType',
        ],
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def reset_last_threat_feed():
    """Reset last threat feed from the integration context"""
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def main():
    """main function, parses params and runs command functions"""
    params = demisto.params()

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url='https://www.virustotal.com/api/v3/',
            verify=insecure,
            proxy=proxy,
            headers={
                'x-apikey': params['credentials']['password'],
                'x-tool': 'CortexGTICategorizedFeeds',
            }
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'gti-feed-get-indicators':
            # This is the command that fetches a limited number of indicators
            # from the feed source and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == 'gti-feed-reset-fetch-indicators':
            return_results(reset_last_threat_feed())

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the commandthat will be executed at the specified feed fetch
            # interval.
            feed_type = params.get('feed_type', 'apt')
            tlp_color = params.get('tlp_color')
            feed_tags = argToList(params.get('feedTags'))
            limit = int(params.get('limit', 40))
            indicators = fetch_indicators_command(client, feed_type, tlp_color, feed_tags, limit)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
