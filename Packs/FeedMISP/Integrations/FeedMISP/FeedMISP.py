import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()


"""
Constants
---------
"""

INDICATOR_TO_GALAXY_RELATION_DICT: Dict[str, Any] = {
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.USES,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.USES,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    },
    ThreatIntel.ObjectsNames.MALWARE: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.USES,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    },
    ThreatIntel.ObjectsNames.TOOL: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.USES,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    },
    ThreatIntel.ObjectsNames.INTRUSION_SET: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.RELATED_TO,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.ATTRIBUTED_TO,
    },
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: {
        FeedIndicatorType.File: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.IP: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.URL: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Email: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.RELATED_TO,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.MITIGATED_BY,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.RELATED_TO,
    }
}

ATTRIBUTE_TO_INDICATOR_MAP = {
    'sha256': FeedIndicatorType.File,
    'md5': FeedIndicatorType.File,
    'sha1': FeedIndicatorType.File,
    'filename|md5': FeedIndicatorType.File,
    'filename|sha1': FeedIndicatorType.File,
    'filename|sha256': FeedIndicatorType.File,
    'domain': FeedIndicatorType.Domain,
    'email': FeedIndicatorType.Email,
    'email-src': FeedIndicatorType.Email,
    'email-dst': FeedIndicatorType.Email,
    'url': FeedIndicatorType.URL,
    'regkey': FeedIndicatorType.Registry,
    'threat-actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
    'btc': DBotScoreType.CRYPTOCURRENCY,
    'campaign-name': ThreatIntel.ObjectsNames.CAMPAIGN,
    'campaign-id': ThreatIntel.ObjectsNames.CAMPAIGN,
    'malware-type': ThreatIntel.ObjectsNames.MALWARE,
}

GALAXY_MAP = {
    'misp-galaxy:mitre-attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'misp-galaxy:mitre-malware': ThreatIntel.ObjectsNames.MALWARE,
    'misp-galaxy:mitre-tool': ThreatIntel.ObjectsNames.TOOL,
    'misp-galaxy:mitre-intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
    'misp-galaxy:mitre-course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
}

""" Client Class """


class Client(BaseClient):

    def __init__(self, timeout, base_url, verify, proxy):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.timeout = timeout

    def search_query(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Creates a request to MISP to get all attributes filtered by query in the body argument
        Args:
            body: Dictionary containing query to filter MISP attributes.
        Returns: bytes representing the response from MISP API
        """
        headers = {
            'Authorization': demisto.get(demisto.params(), 'credentials.password'),
            "Accept": "application/json",
            'Content-Type': 'application/json'
        }
        response = self._http_request('POST',
                                      full_url=f'{self._base_url}attributes/restSearch',
                                      resp_type='json',
                                      headers=headers,
                                      data=json.dumps(body),
                                      timeout=self.timeout)
        return response


""" Helper Functions """


def build_indicators_iterator(attributes: Dict[str, Any], url: Optional[str]) -> List[Dict[str, Any]]:
    """
    Creates a list of valid indicators types to be created
    Args:
        attributes: List of attributes returned from MISP
        url: Feed URL
    Returns: List of indicators and their types
    """
    indicators_iterator = []
    try:
        attributes_list: List[Dict[str, Any]] = attributes['response']['Attribute']
        for attribute in attributes_list:
            if indicator_type := get_attribute_indicator_type(attribute):
                indicators_iterator.append({
                    'value': attribute,
                    'type': indicator_type,
                    'raw_type': attribute['type'],
                    'FeedURL': url,
                })
    except KeyError as err:
        demisto.debug(str(err))
        raise KeyError(f'Could not parse returned data as attributes list. \nError massage: {err}')
    return indicators_iterator


def handle_tags_fields(indicator_obj: Dict[str, Any], tags: List[Any], feed_tags: Optional[List]) -> None:
    """
    Adds tags to the indicator if they're a valid tag
    Args:
        indicator_obj: Indicator currently being built
        tags: List of tags of the attribute retrieved from MISP
        feed_tags: custom tags to be added to the created indicator
    Returns: None
    """
    indicator_obj['fields']['Tags'] = []
    for tag in tags:
        tag_name = tag.get('name', None)
        if tag_name and not get_galaxy_indicator_type(tag_name):
            indicator_obj['fields']['Tags'].append(tag_name)
    indicator_obj['fields']['Tags'].extend(feed_tags)


def handle_file_type_fields(raw_type: str, indicator_obj: Dict[str, Any]) -> None:
    """
    If the attribute is of type sha1,sha256 or MD5 - will add SHA1 or
    SHA256 or MD5 field and their value to the indicator.
    If the attribute type is 'filename|<sha1/sha256/md5>' will add the filename to Associated File Names field,
    will update the indicator value and will add the hash field.
    Args:
        raw_type: Type of the attribute
        indicator_obj: Indicator currently being built
    Returns: None
    """
    hash_value = indicator_obj['value']
    if 'filename|' in raw_type:
        pipe_index = hash_value.index("|")
        filename = hash_value[0:pipe_index]
        hash_value = hash_value[pipe_index + 1:]

        indicator_obj['fields']['Associated File Names'] = filename
        indicator_obj['value'] = hash_value
        raw_type = raw_type[raw_type.index("|") + 1:]

    indicator_obj['fields'][raw_type.upper()] = hash_value


def build_params_dict(tags: List[str], attribute_type: List[str]) -> Dict[str, Any]:
    """
    Creates a dictionary in the format required by MISP to be used as a query.
    Args:
        tags: List of tags to filter by
        attribute_type: List of types to filter by
    Returns: Dictionary used as a search query for MISP
    """
    params: Dict[str, Any] = {
        'returnFormat': 'json',
        'type': {
            'OR': attribute_type if attribute_type else [],
        },
        'tags': {
            'OR': tags if tags else [],
        },
    }
    return params


def clean_user_query(query: str) -> Dict[str, Any]:
    """
    Takes the query string created by the user, adds necessary argument and removes unnecessary arguments
    Args:
        query: User's query string
    Returns: Dict which has only needed arguments to be sent to MISP
    """
    try:
        params = json.loads(query)
        params["returnFormat"] = "json"
        params.pop("timestamp", None)
    except Exception as err:
        demisto.debug(str(err))
        raise DemistoException(f'Could not parse user query. \nError massage: {err}')
    return params


def get_ip_type(ip_attribute: Dict[str, Any]) -> str:
    """
    Returns the correct FeedIndicatorType for attributes of type ip
    Args:
        ip_attribute: the ip attribute
    Returns: FeedIndicatorType
    """
    if ':' in ip_attribute['value']:
        return FeedIndicatorType.IPv6
    else:
        return FeedIndicatorType.IP


def get_attribute_indicator_type(attribute: Dict[str, Any]) -> Optional[str]:
    """
    Gets the correct Indicator type that matches the attribute type, attribute type is not supported
    returns None
    Args:
        attribute: Dictionary containing information about the attribute
    Returns: The matching indicator type or None if the attribute type is not supported
    """
    attribute_type = attribute['type']
    if attribute_type == 'ip-src' or attribute_type == 'ip-dst':
        return get_ip_type(attribute)
    else:
        return ATTRIBUTE_TO_INDICATOR_MAP.get(attribute_type, None)


def get_galaxy_indicator_type(galaxy_tag_name: str) -> Optional[str]:
    """
    Returns an Indicator type matching to the galaxy type
    Args:
        galaxy_tag_name: name of the galaxy
    Returns: type of the indicator if there's one matching to the provided galaxy or None
    """
    if 'galaxy' in galaxy_tag_name:
        galaxy_name = galaxy_tag_name[0:galaxy_tag_name.index("=")]
        return GALAXY_MAP.get(galaxy_name, None)
    return None


def build_indicator(value_: str, type_: str, raw_data: Dict[str, Any], reputation: Optional[str]) -> Dict[str, Any]:
    """
    Creates an indicator object
    Args:
        value_: value of the indicator
        type_: type of the indicator
        raw_data: raw data of the indicator
        reputation: string representing reputation of the indicator
    Returns: Dictionray which is the indicator object
    """
    indicator_obj = {
        'value': value_,
        'type': type_,
        'service': 'MISP',
        'fields': {},
        'rawJSON': raw_data,
        'Reputation': reputation,
    }
    return indicator_obj


def update_indicators_iterator(indicators_iterator: List[Dict[str, Any]],
                               params_dict: Dict[str, Any],
                               is_fetch: bool) -> Optional[List[Dict[str, Any]]]:
    """
    sorts the indicators by their timestamp and returns a list of only new indicators received from MISP
    Args:
        params_dict: user's params sent to misp
        indicators_iterator: list of indicators
        is_fetch: flag for wether funciton was called for fetching command or a get
    Returns: Sorted list of new indicators
    """
    last_run = demisto.getLastRun()
    indicators_iterator.sort(key=lambda indicator: indicator['value']['timestamp'])

    if last_run is None:
        return indicators_iterator
    if params_dict != last_run.get('params'):
        if is_fetch:
            demisto.setLastRun(None)
        return indicators_iterator

    last_timestamp = int(last_run.get('timestamp'))

    for index in range(len(indicators_iterator)):
        if int(indicators_iterator[index]['value']['timestamp']) > last_timestamp:
            return indicators_iterator[index:]
    return []


def fetch_indicators(client: Client,
                     tags: List[str],
                     attribute_type: List[str],
                     query: Optional[str],
                     tlp_color: Optional[str],
                     url: Optional[str],
                     reputation: Optional[str],
                     feed_tags: Optional[List],
                     limit: int = -1,
                     is_fetch: bool = True) -> List[Dict]:
    if query:
        params_dict = clean_user_query(query)
    else:
        params_dict = build_params_dict(tags, attribute_type)

    response = client.search_query(params_dict)
    indicators_iterator = build_indicators_iterator(response, url)
    added_indicators_iterator = update_indicators_iterator(indicators_iterator, params_dict, is_fetch)
    indicators = []

    if not added_indicators_iterator:
        return []

    if limit > 0:
        added_indicators_iterator = added_indicators_iterator[:limit]

    if is_fetch:
        # fetching command, need to update last run dict
        demisto.setLastRun({
            'params': params_dict,
            'timestamp': added_indicators_iterator[len(added_indicators_iterator) - 1]['value']['timestamp']
        })

    for indicator in added_indicators_iterator:
        value_ = indicator['value']['value']
        type_ = indicator['type']
        raw_type = indicator.pop('raw_type')

        indicator_obj = build_indicator(value_, type_, indicator, reputation)

        update_indicator_fields(indicator_obj, tlp_color, raw_type, feed_tags)
        galaxy_indicators = build_indicators_from_galaxies(indicator_obj, reputation)
        create_and_add_relationships(indicator_obj, galaxy_indicators)

        indicators.append(indicator_obj)

    return indicators


def build_indicators_from_galaxies(indicator_obj: Dict[str, Any], reputation: Optional[str]) -> List[Dict[str, Any]]:
    """
    Builds indicators from the galaxy tags in the attribute
    Args:
        indicator_obj: Indicator being built
        reputation: string representing reputation of the indicator
    Returns: List of indicators created from the galaxies
    """
    tags = indicator_obj['rawJSON']['value'].get('Tag', [])
    galaxy_indicators = []
    for tag in tags:
        tag_name = tag.get('name', None)
        type_ = get_galaxy_indicator_type(tag_name)
        if tag_name and type_:
            value_ = tag_name[tag_name.index('=') + 2: tag_name.index(" -")]
            galaxy_indicators.append(build_indicator(value_, type_, tag, reputation))

    return galaxy_indicators


def create_and_add_relationships(indicator_obj: Dict[str, Any], galaxy_indicators: List[Dict[str, Any]]) -> None:
    """
    Creates relationships between the indicators created from the attributes and
    the indicators created from the galaxies
    Args:
        indicator_obj: Indicator being built
        galaxy_indicators: List of indicators created from the galaxies
    Returns: None
    """
    indicator_obj_type = indicator_obj['type']
    relationships_indicators = []
    for galaxy_indicator in galaxy_indicators:
        galaxy_indicator_type = galaxy_indicator['type']

        indicator_to_galaxy_relation = INDICATOR_TO_GALAXY_RELATION_DICT[galaxy_indicator_type][indicator_obj_type]
        galaxy_to_indicator_relation = EntityRelationship.Relationships.\
            RELATIONSHIPS_NAMES[indicator_to_galaxy_relation]

        indicator_relation = EntityRelationship(
            name=indicator_to_galaxy_relation,
            entity_a=indicator_obj['value'],
            entity_a_type=indicator_obj_type,
            entity_b=galaxy_indicator['value'],
            entity_b_type=galaxy_indicator_type,
        ).to_indicator()

        galaxy_relation = EntityRelationship(
            name=galaxy_to_indicator_relation,
            entity_a=galaxy_indicator['value'],
            entity_a_type=galaxy_indicator_type,
            entity_b=indicator_obj['value'],
            entity_b_type=indicator_obj_type,
        ).to_indicator()

        relationships_indicators.append(indicator_relation)
        galaxy_indicator['Relationships'] = [galaxy_relation]

    if relationships_indicators:
        indicator_obj['Relationships'] = relationships_indicators


def update_indicator_fields(indicator_obj: Dict[str, Any], tlp_color: Optional[str],
                            raw_type: str, feed_tags: Optional[List]) -> None:
    """
    Updating required fields of the indicator with values from the attribute
    Args:
        indicator_obj: Indicator being built
        tlp_color: Traffic Light Protocol color.
        raw_type: Type of the attribute
        feed_tags: Custom tags to be added to the created indicator
    Returns: None
    """
    raw_json_value = indicator_obj['rawJSON']['value']
    first_seen = raw_json_value.get('first_seen', None)
    last_seen = raw_json_value.get('last_seen', None)
    timestamp = raw_json_value.get('timestamp', None)
    category = raw_json_value.get('category', None)
    comment = raw_json_value.get('comment', None)
    tags = raw_json_value.get('Tag', None)

    if first_seen:
        indicator_obj['fields']['First Seen By Source'] = first_seen

    if last_seen:
        indicator_obj['fields']['Last Seen By Source'] = last_seen

    if timestamp:
        indicator_obj['fields']['Updated Date'] = timestamp

    if category:
        indicator_obj['fields']['Category'] = category

    if comment:
        indicator_obj['fields']['Description'] = comment

    if tlp_color:
        indicator_obj['fields']['trafficlightprotocol'] = tlp_color

    if tags:
        handle_tags_fields(indicator_obj, tags, feed_tags)

    if 'md5' in raw_type or 'sha1' in raw_type or 'sha256' in raw_type:
        handle_file_type_fields(raw_type, indicator_obj)


"""
Command Functions
"""


def test_module(client: Client, params: Dict[str, str]) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        ok if feed is accessible
    """
    tags = argToList(params.get('attribute_tags', ''))
    attribute_types = argToList(params.get('attribute_types', ''))
    query = params.get('query', None)

    if query:
        params_dict = clean_user_query(query)
    else:
        params_dict = build_params_dict(tags, attribute_types)

    client.search_query(params_dict)
    return 'ok'


def get_attributes_command(client: Client, args: Dict[str, str], params: Dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        args: demisto.args()
        params: demisto.params()
    Returns:
        CommandResults object containing the indicators retrieved
    """
    limit = arg_to_number(args.get('limit', '10')) or 10
    tlp_color = params.get('tlp_color')
    reputation = params.get('feedReputation')
    tags = argToList(args.get('tags', ''))
    feed_tags = argToList(params.get("feedTags", []))
    query = args.get('query', None)
    attribute_type = argToList(args.get('attribute_type', ''))

    indicators = fetch_indicators(client, tags, attribute_type,
                                  query, tlp_color, params.get('url'), reputation, feed_tags, limit, False)

    hr_indicators = []
    for indicator in indicators:
        hr_indicators.append({
            'Value': indicator.get('value'),
            'Type': indicator.get('type'),
            'rawJSON': indicator.get('rawJSON'),
            'fields': indicator.get('fields'),
        })

    human_readable = tableToMarkdown("Indicators from MISP:", hr_indicators,
                                     headers=['Value', 'Type', 'rawJSON', 'fields'], removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='MISPFeed.Indicators',
        outputs_key_field='value',
        raw_response=indicators,
    )


def fetch_attributes_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """
    Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns: List of indicators.
    """
    tlp_color = params.get('tlp_color')
    reputation = params.get('feedReputation')
    tags = argToList(params.get('attribute_tags', ''))
    feed_tags = argToList(params.get("feedTags", []))
    attribute_types = argToList(params.get('attribute_types', ''))
    query = params.get('query', None)

    indicators = fetch_indicators(client, tags, attribute_types, query, tlp_color,
                                  params.get('url'), reputation, feed_tags)
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    base_url = urljoin(params.get('url').rstrip('/'), '/')
    timeout = arg_to_number(params.get('timeout', 60))
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(base_url=base_url, verify=insecure, proxy=proxy, timeout=timeout)

        if command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'misp-feed-get-indicators':
            return_results(get_attributes_command(client, args, params))
        elif command == 'fetch-indicators':
            indicators = fetch_attributes_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:  # pragma: no cover
    main()
