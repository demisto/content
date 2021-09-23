"""HelloWorld Feed Integration for Cortex XSOAR (aka Demisto)
"""
import concurrent.futures
import threading
import time
from typing import Dict, List, Optional

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

BASE_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0/'

TAG_CLASS_TO_DEMISTO_TYPE = {'malware_family': ThreatIntel.ObjectsNames.MALWARE,
                             'actor': 'Threat Actor',
                             'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
                             'malicious_behavior': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                             }

MAP_RELATIONSHIPS = {
    ThreatIntel.ObjectsNames.MALWARE:
        {ThreatIntel.ObjectsNames.MALWARE: 'related-to',
         'Threat Actor': 'used-by',
         ThreatIntel.ObjectsNames.CAMPAIGN: 'used-by',
         ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'used-by'},
    'Threat Actor':
        {ThreatIntel.ObjectsNames.MALWARE: 'uses',
         'Threat Actor': 'related-to',
         ThreatIntel.ObjectsNames.CAMPAIGN: 'attributed-by',
         ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'uses'},
    ThreatIntel.ObjectsNames.CAMPAIGN:
        {ThreatIntel.ObjectsNames.MALWARE: 'uses',
         'Threat Actor': 'attributed-to',
         ThreatIntel.ObjectsNames.CAMPAIGN: 'related-to',
         ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'used-by'},
    ThreatIntel.ObjectsNames.ATTACK_PATTERN:
        {ThreatIntel.ObjectsNames.MALWARE: 'uses',
         'Threat Actor': 'used-by',
         ThreatIntel.ObjectsNames.CAMPAIGN: 'uses',
         ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'related-to'},

}

EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=59)
EXECUTOR1 = concurrent.futures.ThreadPoolExecutor(max_workers=59)
PAGE_SIZE = 59

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with AutoFocus API
    """

    def __init__(self, api_key, verify, proxy):
        super().__init__(BASE_URL, verify, proxy)
        self.api_key = api_key
        self.calls_count = 0
        self.test = 0
        self.page_num = -1
        self.thread_lock_for_calls_count = threading.Lock()
        self.thread_lock_for_page_num = threading.Lock()

    def get_all_tags(self):
        with self.thread_lock_for_calls_count:
            self.calls_count = (self.calls_count + 1)
            demisto.debug(f"in the first print , call count all tags {self.calls_count}")
            if self.calls_count >= 100:
                threading.Event.wait()
                self.calls_count = 0
        with self.thread_lock_for_page_num:
            self.page_num += 1
        res = self._http_request('POST',
                                 url_suffix='tags',
                                 headers={
                                     'apiKey': self.api_key,
                                     'Content-Type': 'application/json'
                                 },
                                 json_data={"pageSize": PAGE_SIZE, "pageNum": self.page_num},
                                 )
        with self.thread_lock_for_calls_count:
            demisto.debug(f"before exiting get all tags, call count all tags {self.calls_count}")
        return res

    def get_tag_details(self, public_tag_name: str):
        with self.thread_lock_for_calls_count:
            self.calls_count = (self.calls_count + 1)
            demisto.debug(f"get tag details,  {self.calls_count}")
            if self.calls_count >= 100:
                threading.Event.wait()
                self.calls_count = 0
        res = self._http_request('POST',
                                 url_suffix=f'tag/{public_tag_name}',
                                 headers={
                                     'apiKey': self.api_key,
                                     'Content-Type': 'application/json'
                                 },
                                 )
        return res

    def build_iterator(self) -> list:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        tag_details = []
        futures = []
        future_all_tags = []
        all_tags = []
        real_all_tags = []
        total_count_of_tags = 3625
        num_of_calls = total_count_of_tags // PAGE_SIZE + 1
        for i in range(num_of_calls):
            future_all_tags.append(
                EXECUTOR.submit(
                    self.get_all_tags
                )
            )

        for future in concurrent.futures.as_completed(future_all_tags):
            all_tags.append(future.result())


        demisto.debug("out from all tags")

        for tags_list in all_tags:
            tags = tags_list.get('tags', [])
            real_all_tags.extend(tags)
        demisto.debug("before the details")
        for tag in real_all_tags:
            public_tag_name = tag.get('public_tag_name', '')
            if public_tag_name:
                futures.append(
                    EXECUTOR1.submit(
                        self.get_tag_details,
                        public_tag_name=public_tag_name,
                    )
                )
        for future in concurrent.futures.as_completed(futures):
            tag_details.append(future.result())
        return tag_details


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
        return TAG_CLASS_TO_DEMISTO_TYPE.get(tag_class)
    return None


def get_fields(tag_details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns the indicator fields
    Args:
        tag_details:

    Returns:

    """
    fields: Dict[str, Any] = {}
    tag = tag_details.get('tag', {})
    refs = json.loads(tag.get('refs', '[]'))
    if len(refs) > 0:
        fields['publications'] = []
        for ref in refs:
            url = ref.get('url')
            source = ref.get('source')
            time_stamp = ref.get('created')
            title = ref.get('title')
            fields['publications'].append({'link': url, 'title': title, 'source': source, 'timestamp': time_stamp})
    fields['aliases'] = tag_details.get('aliases')
    fields['description'] = tag.get('description')
    fields['lastseenbysource'] = tag.get('lasthit')
    fields['updateddate'] = tag.get('updated_at')
    fields['threattypes'] = [{'threatcategory': tag_details.get('tag_groups')}]
    fields['reportedby'] = tag.get('source')
    return fields


def create_dict_of_all_tags(tags_list: list) -> Dict[str, Any]:
    """
    Creates a dict of all the tag_details, with tag name as key and tag details as value.
    Args:
        tags_list: list of all the tag details.

    Returns:
        Dictionary with tag name as key and tag details as value.
    """

    all_tags: Dict[str, Any] = {}
    for tag_details in tags_list:
        tag = tag_details.get('tag')
        public_tag_name = tag.get('public_tag_name')
        if public_tag_name:
            all_tags[public_tag_name] = tag_details
    return all_tags


def create_relationships_for_tag(name: str, tag_type: str, related_tags: List[str], all_tags: Dict[str, Any]):
    relationships: list = []
    for related_tag in related_tags:
        related_tag_details = all_tags.get(related_tag)
        if related_tag_details:
            tag = related_tag_details.get('tag')
            related_tag_name = tag.get('tag_name')
            tag_class = tag.get('tag_class')
            source = tag.get('source')
            related_tag_type = get_tag_class(tag_class, source)
            if related_tag_type:
                relationships.append(
                    create_relationship(name, tag_type, related_tag_name, related_tag_type).to_indicator())
    return relationships


def create_relationship(a_name: str, a_class: str, b_name: str, b_class: str):
    return EntityRelationship(
        name=MAP_RELATIONSHIPS.get(a_class, {}).get(b_class),
        entity_a=a_name,
        entity_a_type=a_class,
        entity_b=b_name,
        entity_b_type=b_class,
        reverse_name=MAP_RELATIONSHIPS.get(b_class, {}).get(a_class),
    )


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
    relationships = []
    all_tags = create_dict_of_all_tags(iterator)
    # extract values from iterator
    for tag_details in iterator:
        tag = tag_details.get('tag')
        value_ = tag.get('tag_name')
        print(value_)
        tag_class = tag.get('tag_class')
        source = tag.get('source')
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
            'rawJSON': raw_data,
        }
        related_tags = tag_details.get('related_tags', [])
        if related_tags:
            relationships.append(create_relationships_for_tag(value_,type_,related_tags,all_tags))
        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color
        indicators.append(indicator_obj)
    dummy_indicator = {
        "value": "$$DummyIndicator$$",
        "relationships": relationships
    }
    indicators.append(dummy_indicator)
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
            return_results(test_module(client))

        elif command == 'autofocus-tags-feed-get-indicators':
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
