"""HelloWorld Feed Integration for Cortex XSOAR (aka Demisto)
"""
import time
from concurrent.futures import wait
from typing import Dict, List, Optional

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

AF_TAGS_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

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

PAGE_SIZE = 50

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client class to interact with AutoFocus API
    """

    def __init__(self, api_key, verify, proxy):
        super().__init__(BASE_URL, verify, proxy)
        self.api_key = api_key

    def get_tags(self, data: Dict[str, Any], page_num: int = 0):
        res = self._http_request('POST',
                                 url_suffix='tags',
                                 headers={
                                     'apiKey': self.api_key,
                                     'Content-Type': 'application/json'
                                 },
                                 json_data=data,
                                 timeout=30,
                                 )
        return res

    def get_tag_details(self, public_tag_name: str):
        res = self._http_request('POST',
                                 url_suffix=f'tag/{public_tag_name}',
                                 headers={
                                     'apiKey': self.api_key,
                                     'Content-Type': 'application/json'
                                 },
                                 timeout=30,
                                 )
        return res

    def build_iterator(self, is_get_command: bool) -> list:
        """
        Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """
        results = []
        if is_get_command:
            page_num = 0
        else:
            integration_context = get_integration_context()
            demisto.debug(f"integration_context: {str(integration_context)}")

            if not integration_context:
                demisto.debug("if not integration context")
                page_num = 0
                time_of_first_fetch = datetime.now()
                set_integration_context({'time_of_first_fetch': time_of_first_fetch})
                demisto.debug(f"integration_context after set: {str(get_integration_context())}")
            else:
                page_num = arg_to_number(integration_context.get('page_num', 0))

        get_tags_response = self.get_tags({"pageNum": page_num,
                                           "pageSize": PAGE_SIZE,
                                           "sortBy": "created_at"})
        tags = get_tags_response.get('tags', [])

        # when finishing the "first level fetch" (getting all he tags from the feed), the next call to the api
        # will be with a page num greater than the total pages, and the api should return an empty tags list.
        if not tags:
            return only_updated_tags(self)
        # this is the "first level fetch" logic. Every fetch returns at most PAGE_SIZE indicators from the feed.
        for tag in tags:
            public_tag_name = tag.get('public_tag_name', '')
            tag_details_response = self.get_tag_details(public_tag_name)
            results.append(tag_details_response)
        if not is_get_command:
            page_num += 1
            demisto.debug("Im here before update")
            context = get_integration_context()
            context['page_num'] = page_num
            # context['most_updated_tag'] = get_update_time_most_updated_tag(tags)
            set_integration_context(context)
        return results


''' HELPER FUNCTIONS '''


def get_update_time_most_updated_tag(tags: list) -> str:
    # if the the order is desc than it is the first tag in the list
    if len(tags) > 0:
        return tags[0].get('updated_at', '').replace(' ', 'T')
    return ''


def only_updated_tags(client: Client) -> list:
    """

    Args:
        client:

    Returns:
    """

    results = []
    integration_context = get_integration_context()
    # This field saves tags that have been updated since the last time of fetch and need to be updated in demisto
    list_of_all_updated_tags = argToList(integration_context.get('tags_need_to_be_fetched', []))
    time_from_last_update = integration_context.get('time_of_first_fetch')
    if time_from_last_update:
        update_integration_context({'time_of_first_fetch': ''})
    else:
        time_from_last_update = integration_context.get('most_updated_tag')

    # if there are such tags, we first get all of them and upload to demisto
    for tag in list_of_all_updated_tags:
        if len(results) < PAGE_SIZE:
            results.append(client.get_tag_details(tag.get('public_tag_name')))
        else:
            tag.get('updated_at')
            update_integration_context({'time_of_first_fetch': ''})
            return results

    page_num = 0
    while True:
        response = client.get_tags({"pageNum": page_num,
                                    "pageSize": 200,
                                    "sortBy": "updated_at",
                                    "order": "desc"})
        tags = response.get('tags', [])
        # most_updated_tag = get_update_time_most_updated_tag(tags)
        for tag in tags:
            update_time = tag.get('updated_at')
            if update_time >= time_from_last_update:
                list_of_all_updated_tags.append(
                    {'public_tag_name': tag.get('public_tag_name'), 'updated_at': update_time})
            else:
                break
        if len(tags) < len(list_of_all_updated_tags):
            break
        page_num += 1

    # add only PAGE_SIZE get_tag_details to results, so we wont make to many calls to the api
    # we want to get the tags from the least updated to the most,
    # so next time we fetch we can take the tags that have been updated from that point
    list_index = 0
    for tag in reversed(list_of_all_updated_tags):
        if len(results) < PAGE_SIZE:
            public_tag_name = tag.get('public_tag_name')
            response = client.get_tag_details(public_tag_name)
            results.append(response)
            list_index += 1
        else:
            break
    # delete from the list all tags that we will return this fetch
    n = len(list_of_all_updated_tags)
    list_of_all_updated_tags = list_of_all_updated_tags[:n-list_index]
    # update integration context if needed
    if list_of_all_updated_tags:
        context = get_integration_context()
        context['tags_need_to_be_fetched'] = list_of_all_updated_tags
        context['time_of_first_fetch'] = datetime.now()
        set_integration_context(context)
    return results


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
    last_hit = tag.get('lasthit')
    fields['lastseenbysource'] = datetime.strptime(last_hit, AF_TAGS_DATE_FORMAT).strftime(
        DATE_FORMAT) if last_hit else None
    updated_at = tag.get('updated_at')
    fields['updateddate'] = datetime.strptime(updated_at, AF_TAGS_DATE_FORMAT).strftime(
        DATE_FORMAT) if updated_at else None
    fields['reportedby'] = tag.get('source')
    remove_nulls_from_dictionary(fields)
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


def create_relationships_for_tag(client: Client, name: str, tag_type: str, related_tags: List[str]):
    relationships: list = []
    for related_tag in related_tags:
        related_tag_details = client.get_tag_details(related_tag)
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

    client.build_iterator(True)
    return 'ok'


def fetch_indicators(client: Client,
                     is_get_command: bool,
                     tlp_color: Optional[str] = None,
                     feed_tags: List = [],
                     limit: int = -1) -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        is_get_command: is this method called from the get-indicators-command
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator(is_get_command)
    indicators = []
    for tag_details in iterator:
        tag = tag_details.get('tag')
        value_ = tag.get('tag_name')
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
            relationships = (create_relationships_for_tag(client, value_, type_, related_tags))
            if relationships:
                indicator_obj['relationships'] = relationships
        # TODO add group tags here
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
    indicators = fetch_indicators(client, True, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown('Indicators from AutoFocus Tags Feed:', indicators,
                                     headers=['value', 'type', 'fields'], headerTransform=string_to_table_header,
                                     removeNull=True)
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
    indicators = fetch_indicators(client, False, tlp_color, feed_tags)
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
            demisto.debug("before fetch")
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
