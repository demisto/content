"""HelloWorld Feed Integration for Cortex XSOAR (aka Demisto)
"""

from typing import Dict, List, Optional

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


BASE_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0/'

MAP_TAG_CLASS = {'malware_family': ThreatIntel.ObjectsNames.MALWARE,
                 'actor': 'Threat Actor',
                 'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
                 'malicious_behavior': ThreatIntel.ObjectsNames.ATTACK_PATTERN
                 }


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with AutoFocus API
    """

    def __init__(self, api_key, verify, proxy):
        super().__init__(BASE_URL, verify, proxy)
        self.api_key = api_key

    def get_all_tags(self):
        return self._http_request('POST',
                                  url_suffix='tags',
                                  headers={
                                      'apiKey': self.api_key,
                                      'Content-Type': 'application/json'
                                  }
                                  )

    def get_tag_details(self, public_tag_name: str):
        return self._http_request('POST',
                                  url_suffix=f'tag/{public_tag_name}',
                                  headers={
                                      'apiKey': self.api_key,
                                      'Content-Type': 'application/json'
                                  }
                                  )

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        res = self.get_all_tags()
        if not res:
            raise Exception('no result')
        all_tags = res.get('tags', [])
        if not all_tags:
            raise Exception('no result')
        for tag in all_tags:
            public_tag_name = tag.get('public_tag_name', '')
            if public_tag_name:
                tag_details = self.get_tag_details(public_tag_name)
                result.append(tag_details)
        return result


''' HELPER FUNCTIONS '''


def get_tag_class(tag_class: Optional[str], source: Optional[str]) -> Optional[str]:
    """
    Returns the tag class as demisto indicator type.
    Args:
        tag_class: tag class name
        source: tag source

    Returns:
        The tag class as demisto indicator type, None if class is not specified.
    """

    if not tag_class:
        return None
    if (tag_class != 'malicious_behavior') or (tag_class == 'malicious_behavior' and source == 'Unit 42'):
        return MAP_TAG_CLASS.get(tag_class)
    return None


def get_fields(tag_details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns the indicator fields
    Args:
        tag_details:

    Returns:

    """
    fields: Dict[str, Any] = {}
    refs = tag_details.get('refs')
    fields['Publications.Link'] = refs.get('url')
    fields['Publications.Source'] = refs.get('source')
    fields['Publications.Timestamp'] = refs.get('created')
    fields['Aliases'] = tag_details.get('aliases')
    fields['Description'] = tag_details.get('description')
    # TODO new field
    fields['Last Seen'] = tag_details.get('lasthit')
    fields['Updated Date'] = tag_details.get('updated_at')
    fields['Threat Types.Threat Category'] = tag_details.get('tag_groups')
    # TODO new field
    fields['Source'] = tag_details.get('source')
    return fields


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """

    client.build_iterator()
    return 'ok'


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, feed_tags: List = [], limit: int = -1) \
        -> List[Dict]:
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
    for tag_details in iterator:
        value_ = tag_details.get('public_tag_name')
        tag_class = tag_details.get('tag_class')
        source = tag_details.get('source')
        type_ = get_tag_class(tag_class, source)
        if not type_:
            continue
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in tag_details.items():
            raw_data.update({key: value})
        indicator_obj = {
            'value': value_,
            'type': type_,
            'service': 'AutoFocus',
            'fields': get_fields(tag_details),
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
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown('Indicators from AutoFocus Tags Feed:', indicators,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    indicators = fetch_indicators(client, tlp_color, feed_tags)
    return indicators


''' MAIN FUNCTION '''


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('api_key', '')

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            api_key=api_key,
            verify=insecure,
            proxy=proxy,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'autofocus-tags-feed-get-indicators':
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
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
