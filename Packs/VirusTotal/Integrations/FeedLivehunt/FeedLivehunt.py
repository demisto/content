import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        response = self.list_notifications()

        try:
            for indicator in response.get('data'):
                result.append({
                    'value': indicator.get('attributes'),
                    'type': 'file',
                    'FeedURL': self._base_url
                })
        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError message: {err}')
        return result

    def list_notifications(
            self,
            from_time: Optional[datetime] = None,
            to_time: Optional[datetime] = None,
            tag: Optional[str] = None,
            cursor: Optional[str] = None,
            limit: Optional[int] = None
    ) -> dict:
        """Retrieve VT Hunting Livehunt notifications.

        See Also:
            https://developers.virustotal.com/v3.0/reference#list-hunting-notifications
        """
        time_format = "%Y-%m-%dT%H:%M:%S"
        filter_ = ''
        if tag:
            filter_ += f'{tag} '
        if from_time:
            filter_ += f'date:{from_time.strftime(time_format)}+ '
        if to_time:
            filter_ += f'date:{to_time.strftime(time_format)}- '
        return self._http_request(
            'GET',
            'intelligence/hunting_notifications',
            params=assign_params(
                filter=filter_,
                limit=limit,
                cursor=cursor
            )
        )

def test_module(client: Client, args: dict) -> str:
    client.list_notifications()
    return 'ok'

def fetch_indicators(client: Client,
                     tlp_color: Optional[str] = None,
                     feed_tags: List = [],
                     limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item
        type_ = FeedIndicatorType.File
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
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'VirusTotal',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {},
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
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
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)

    human_readable = tableToMarkdown('Indicators from VirusTotal Livehunt Feed:',
                                     indicators,
                                     headers=['value', 'type'],
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
            headers={'x-apikey': params['credentials']['password']}
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, {}))

        elif command == 'vt-livehunt-get-indicators':
            # This is the command that fetches a limited number of indicators
            # from the feed source and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the commandthat will be executed at the specified feed fetch
            # interval.
            indicators = fetch_indicators_command(client, params)
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
