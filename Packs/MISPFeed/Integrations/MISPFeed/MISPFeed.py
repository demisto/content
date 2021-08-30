import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()


"""
Constants
---------
"""

indicator_to_galaxy_relation_dict: Dict[str, Any] = {
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

"""
Client Class
------------
"""


class Client(BaseClient):
    def search_query(self, body: Dict[str, Any]) -> bytes:
        """
        Creates a request to MISP to get all attributes filtered by query in the body argument
        Args:
            body: Dictionary containing query to filter MISP attributes.
        Returns: bytes representing the response from MISP API
        """
        headers = {
            'Authorization': demisto.params().get('apikey'),
            "Accept": "application/json",
            'Content-Type': 'application/json'
        }
        # TODO: change to demisto handle_http and check for wrong apikey
        response = requests.request("POST",
                                    url=f'{self._base_url}attributes/restSearch',
                                    headers=headers,
                                    data=json.dumps(body),
                                    verify=False)
        return response.content


"""
Helper Functions
----------------
"""


def build_indicators_iterator(attributes_str: bytes, url: Optional[str]) -> List[Dict[str, Any]]:
    indicators_iterator = []
    try:
        attributes_list: List[Dict[str, Any]] = json.loads(attributes_str)['response']['Attribute']
        for attribute in attributes_list:
            if get_attribute_indicator_type(attribute):
                indicators_iterator.append({
                    'value': attribute,
                    'type': get_attribute_indicator_type(attribute),
                    'raw_type': attribute['type'],
                    'FeedURL': url,
                })
    except ValueError as err:
        demisto.debug(str(err))
        raise ValueError(f'Could not parse returned data as indicator. \n\nError massage: {err}')
    return indicators_iterator


def handle_tags_fields(indicator_obj: Dict[str, Any], tags: List[Any]) -> None:
    indicator_obj['fields']['Tags'] = []
    for tag in tags:
        tag_name = tag.get('name', None)
        if tag_name and not get_galaxy_indicator_type(tag_name):
            indicator_obj['fields']['Tags'].append(tag_name)


def handle_file_type_fields(raw_type: str, indicator_obj: Dict[str, Any]) -> None:
    hash_value = indicator_obj['value']
    if 'filename|' in raw_type:
        pipe_index = hash_value.index("|")
        filename = hash_value[0:pipe_index]
        hash_value = hash_value[pipe_index + 1:]

        indicator_obj['fields']['Associated File Names'] = filename
        indicator_obj['value'] = hash_value
        raw_type = raw_type[raw_type.index("|") + 1:]

    indicator_obj['fields'][raw_type.upper()] = hash_value


def build_params_dict(tags: List[str], attribute_type: List[str]) -> Dict[Any, str]:
    params = {
        'returnFormat': 'json',
        'type': {
                'OR': []
        },
        'tags': {
            'OR': []
        }
    }
    if attribute_type:
        params["type"]["OR"] = attribute_type
    if tags:
        params["tags"]["OR"] = tags
    return params


def clean_user_query(query: str):
    try:
        params = json.loads(query)
        params["returnFormat"] = "json"
        params.pop("timestamp", None)
    except Exception as err:
        demisto.debug(str(err))
        raise DemistoException(f'Could not parse user query. \n\nError massage: {err}')

    return params


def get_attribute_indicator_type(attribute: Dict[str, Any]) -> Optional[str]:
    attribute_type = attribute['type']
    indicator_map = {
        'sha256': FeedIndicatorType.File,
        'md5': FeedIndicatorType.File,
        'sha1': FeedIndicatorType.File,
        'filename|md5': FeedIndicatorType.File,
        'filename|sha1': FeedIndicatorType.File,
        'filename|sha256': FeedIndicatorType.File,
        'ip-src': FeedIndicatorType.IP,
        'ip-dst': FeedIndicatorType.IP,
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
        'malware-type': ThreatIntel.ObjectsNames.MALWARE

    }
    return indicator_map.get(attribute_type, None)


def get_galaxy_indicator_type(galaxy_tag_name: str) -> Optional[str]:
    if 'galaxy' in galaxy_tag_name:
        galaxy_name = galaxy_tag_name[0:galaxy_tag_name.index("=")]
        galaxy_map = {
            'misp-galaxy:mitre-attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            'misp-galaxy:mitre-malware': ThreatIntel.ObjectsNames.MALWARE,
            'misp-galaxy:mitre-tool': ThreatIntel.ObjectsNames.TOOL,
            'misp-galaxy:mitre-intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
            'misp-galaxy:mitre-course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
        }
        return galaxy_map.get(galaxy_name, None)
    return None


def build_indicator(value_: str, type_: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
    indicator_obj = {
        'value': value_,
        'type': type_,
        'service': 'MISP',
        'fields': {},
        'rawJSON': raw_data
    }
    return indicator_obj


def fetch_indicators(client: Client,
                     tags: List[str],
                     attribute_type: List[str],
                     query: Optional[str],
                     tlp_color: Optional[str],
                     url: Optional[str],
                     limit: int = -1) -> List[Dict]:
    if query:
        params_dict = clean_user_query(query)
    else:
        params_dict = build_params_dict(tags, attribute_type)

    response = client.search_query(params_dict)
    indicators_iterator = build_indicators_iterator(response, url)
    indicators = []

    if limit > 0:
        indicators_iterator = indicators_iterator[:limit]

    for indicator in indicators_iterator:
        value_ = indicator.get('value').get('value')
        type_ = indicator.get('type')
        raw_type = indicator.pop('raw_type')
        raw_data = {
            'value': value_,
            'type': type_,
        }
        for key, value in indicator.items():
            raw_data.update({key: value})

        indicator_obj = build_indicator(value_, type_, raw_data)

        update_indicator_fields(indicator_obj, tlp_color, raw_type)
        galaxy_indicators = build_indicators_from_galaxies(indicator_obj)
        indicators.extend(galaxy_indicators)
        create_and_add_relationships(indicator_obj, galaxy_indicators)

        indicators.append(indicator_obj)

    return indicators


def build_indicators_from_galaxies(indicator_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    tags = indicator_obj['rawJSON']['value'].get('Tag', [])
    galaxy_indicators = []
    for tag in tags:
        tag_name = tag.get('name', None)
        if tag_name and get_galaxy_indicator_type(tag_name):
            value_ = tag_name[tag_name.index('=') + 2: tag_name.index(" -")]
            type_ = get_galaxy_indicator_type(tag_name)
            raw_data = {
                'value': value_,
                'type': type_,
            }
            for key, value in tag.items():
                raw_data.update({key: value})

            galaxy_indicators.append(build_indicator(value_, type_, raw_data))

    return galaxy_indicators


def create_and_add_relationships(indicator_obj: Dict[str, Any], galaxy_indicators: List[Dict[str,Any]]) -> None:
    indicator_obj_type = indicator_obj['type']
    relationships_indicators = []
    for galaxy_indicator in galaxy_indicators:
        galaxy_indicator_type = galaxy_indicator['type']

        indicator_to_galaxy_relation = indicator_to_galaxy_relation_dict[galaxy_indicator_type][indicator_obj_type]
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


def update_indicator_fields(indicator_obj: Dict[str, Any], tlp_color: Optional[str], raw_type: str) -> None:
    first_seen = indicator_obj['rawJSON']['value'].get('first_seen', None)
    last_seen = indicator_obj['rawJSON']['value'].get('last_seen', None)
    timestamp = indicator_obj['rawJSON']['value'].get('timestamp', None)
    category = indicator_obj['rawJSON']['value'].get('category', None)
    comment = indicator_obj['rawJSON']['value'].get('comment', None)
    tags = indicator_obj['rawJSON']['value'].get('Tag', None)

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
        handle_tags_fields(indicator_obj, tags)

    if 'md5' in raw_type or 'sha1' in raw_type or 'sha256' in raw_type:
        handle_file_type_fields(raw_type, indicator_obj)


"""
Command Functions
"""


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        ok if feed is accessible
    """

    client.search_query(build_params_dict([], []))
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
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    tags = argToList(args.get('tags', ''))
    query = args.get('query', None)

    attribute_type = argToList(args.get('attribute_type', ''))
    indicators = fetch_indicators(client, tags, attribute_type, query, tlp_color, params.get('url'), limit)
    human_readable = f'Retrieved {str(len(indicators))} indicators.'
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Indicators',
        outputs_key_field='',
        raw_response=indicators,
        outputs=indicators,
    )


def fetch_attributes_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        A list of indiactors.
    """
    tlp_color = params.get('tlp_color')
    tags = argToList(params.get('attribute_tags', ''))
    attribute_types = argToList(params.get('attribute_types', ''))
    query = params.get('query', None)

    indicators = fetch_indicators(client, tags, attribute_types, query, tlp_color, params.get('url'))
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    base_url = params.get('url')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(base_url=base_url, verify=insecure, proxy=proxy,)

        if command == 'test-module':
            return_results(test_module(client))
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


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
