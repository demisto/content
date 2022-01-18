import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime

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
    def get_api_indicators(self,
                           query_filter: Optional[str] = None,
                           limit: Optional[int] = 10):
        return self._http_request(
            'GET',
            'intelligence/hunting_notification_files',
            params=assign_params(
                filter=query_filter,
                limit=min(limit, 40),
            )
        )

    def fetch_indicators(self,
                         limit: Optional[int] = 10,
                         filter_tag: Optional[str] = None,
                         fetch_command: bool = False) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        result = []
        query_filter = ''

        if isinstance(filter_tag, str):
            query_filter = f'tag:"{filter_tag}"'

        if fetch_command:
            if last_run := self.get_last_run():
                query_filter = f'{query_filter} {last_run}'

        response = self.get_api_indicators(query_filter.strip(), limit)

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

        if fetch_command:
            self.set_last_run()

        return result

    @staticmethod
    def set_last_run():
        """
        Returns: Current timestamp
        """
        current_time = datetime.now()
        current_timestamp = datetime.timestamp(current_time)
        timestamp = str(int(current_timestamp))
        demisto.setIntegrationContext({'last_run': timestamp})

    @staticmethod
    def get_last_run() -> str:
        """ Gets last run time in timestamp
        Returns:
            last run in timestamp, or '' if no last run
        """
        if last_run := demisto.getIntegrationContext().get('last_run'):
            demisto.info(f'get last_run: {last_run}')
            params = f'date:{last_run}+'
        else:
            params = ''
        return params


def test_module(client: Client, args: dict) -> str:
    try:
        client.fetch_indicators()
    except Exception:
        raise Exception("Could not fetch VT livehunt Feed\n"
                        "\nCheck your API key and your connection to VirusTotal.")
    return 'ok'


def fetch_indicators_command(client: Client,
                             tlp_color: Optional[str] = None,
                             feed_tags: List = [],
                             limit: Optional[int] = 10,
                             filter_tag: Optional[str] = None,
                             fetch_command: bool = False) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
        filter_tag (string): filter response by ruleset name
    Returns:
        Indicators.
    """
    indicators = []

    raw_indicators = client.fetch_indicators(limit, filter_tag,
                                             fetch_command=fetch_command)

    # extract values from iterator
    for item in raw_indicators:
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
    filter_tag = args.get('filter')
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators_command(client, tlp_color,
                                          feed_tags, limit, filter_tag)

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


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    limit = int(params.get('limit', 10))
    filter_tag = params.get('filter')

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

        elif command == "vt-reset-fetch-indicators":
            return_results(reset_last_run())

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the command that will be executed at the specified feed fetch
            # interval.
            indicators = fetch_indicators_command(client,
                                                  tlp_color,
                                                  feed_tags,
                                                  limit,
                                                  filter_tag,
                                                  fetch_command=True)
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
