import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


class DetectionRatio:
    malicious = 0
    total = 0

    def __init__(self, last_analysis_stats: dict):
        self.malicious = last_analysis_stats['malicious']
        self.total = last_analysis_stats['harmless'] + \
            last_analysis_stats['suspicious'] + \
            last_analysis_stats['undetected'] + \
            last_analysis_stats['malicious']

    def __repr__(self):
        return f'{self.malicious}/{self.total}'


class Client(BaseClient):
    def build_iterator(self, limit: Optional[int] = 10,
                       filter_: Optional[str] = None) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        response = self.list_notifications_files(limit, filter_)

        try:
            for indicator in response.get('data', []):
                result.append({
                    'data': indicator,
                    'type': 'file',
                    'FeedURL': self._base_url
                })
        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError message: {err}')
        return result

    def list_notifications_files(
            self,
            limit: Optional[int] = 10,
            filter_: Optional[str] = None
    ) -> dict:
        """Retrieve VT Hunting Livehunt notifications files.
        """
        return self._http_request(
            'GET',
            'intelligence/hunting_notification_files',
            params=assign_params(
                filter=filter_,
                limit=max(limit, 40),
            )
        )


def test_module(client: Client, args: dict) -> str:
    client.list_notifications_files()
    return 'ok'


def fetch_indicators_command(client: Client,
                             tlp_color: Optional[str] = None,
                             feed_tags: List = [],
                             limit: Optional[int] = 10,
                             filter_: Optional[str] = None) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
        filter_ (string): filter response by ruleset name
    Returns:
        Indicators.
    """
    iterator = client.build_iterator(limit, filter_)
    indicators = []
    if limit and limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get('data')
        type_ = FeedIndicatorType.File
        attributes = value_.get('attributes', {})
        context_attributes = value_.get('context_attributes', {})
        raw_data = {
            'value': value_,
            'type': type_,
        }

        detection_ratio = DetectionRatio(attributes.get('last_analysis_stats'))

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys
        # and values, as described blow.
        indicator_obj = {
            # The indicator value.
            'value': attributes['sha256'],
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython
            # to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'VirusTotal',
            # A dictionary that maps values to existing indicator fields defined
            # in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields
            # previously defined
            # in Cortex XSOAR to their values.
            'fields': {
                'md5': attributes.get('md5'),
                'sha1': attributes.get('sha1'),
                'sha256': attributes.get('sha256'),
                'ssdeep': attributes.get('ssdeep'),
                'fileextension': attributes.get('type_extension'),
                'filetype': attributes.get('type_tag'),
                'imphash': attributes.get('pe_info', {}).get('imphash'),
                'firstseenbysource': attributes.get('first_submission_date'),
                'lastseenbysource': attributes.get('last_submission_date'),
                'creationdate': attributes.get('creation_date'),
                'updateddate': attributes.get('last_modification_date'),
                'detectionengines': detection_ratio.total,
                'positivedetections': detection_ratio.malicious,
                'displayname': attributes.get('meaningful_name'),
                'name': attributes.get('meaningful_name'),
                'size': attributes.get('size'),
            },
            # A dictionary of the raw data returned from the feed source about
            # the indicator.
            'rawJSON': raw_data,
            'sha256': attributes['sha256'],
            'detections': str(detection_ratio),
            'fileType': attributes.get('type_description'),
            'rulesetName': context_attributes.get('ruleset_name'),
            'ruleName': context_attributes.get('rule_name'),
        }

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)

    return indicators


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
    """
    limit = int(args.get('limit', 10))
    filter_ = args.get('filter')
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators_command(client, tlp_color,
                                          feed_tags, limit, filter_)

    human_readable = tableToMarkdown('Indicators from VirusTotal Livehunt Feed:',
                                     indicators,
                                     headers=['sha256',
                                              'detections',
                                              'fileType',
                                              'rulesetName',
                                              'ruleName'],
                                     headerTransform=string_to_table_header,
                                     removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    limit = int(params.get('limit', 10))
    filter_ = params.get('filter')

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url='https://www.virustotal.com/api/v3/',
            verify=insecure,
            proxy=proxy,
            headers={
                'x-apikey': params['credentials']['password'],
                'x-tool': 'CortexVirusTotalLivehuntFeed',
            }
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, {}))

        elif command == 'vt-livehunt-get-indicators':
            # This is the command that fetches a limited number of indicators
            # from the feed source and displays them in the war room.
            return_results(get_indicators_command(client, params, demisto.args()))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the commandthat will be executed at the specified feed fetch
            # interval.
            indicators = fetch_indicators_command(client,
                                                  tlp_color,
                                                  feed_tags,
                                                  limit,
                                                  filter_)
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
