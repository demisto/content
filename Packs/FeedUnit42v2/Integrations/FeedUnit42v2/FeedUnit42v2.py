
from taxii2client.common import TokenAuth
from taxii2client.v20 import Server, as_pages

from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

UNIT42_TYPES_TO_DEMISTO_TYPES = {
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'domain': FeedIndicatorType.Domain,
    'domain-name': FeedIndicatorType.Domain,
    'url': FeedIndicatorType.URL,
    'md5': FeedIndicatorType.File,
    'sha-1': FeedIndicatorType.File,
    'sha-256': FeedIndicatorType.File,
    'file:hashes': FeedIndicatorType.File,
}

THREAT_INTEL_TYPE_TO_DEMISTO_TYPES = {
    'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
    'attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'report': ThreatIntel.ObjectsNames.REPORT,
    'malware': ThreatIntel.ObjectsNames.MALWARE,
    'course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    'intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET
}

MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS = {
    'build-capabilities': ThreatIntel.KillChainPhases.BUILD_CAPABILITIES,
    'privilege-escalation': ThreatIntel.KillChainPhases.PRIVILEGE_ESCALATION,
    'adversary-opsec': ThreatIntel.KillChainPhases.ADVERSARY_OPSEC,
    'credential-access': ThreatIntel.KillChainPhases.CREDENTIAL_ACCESS,
    'exfiltration': ThreatIntel.KillChainPhases.EXFILTRATION,
    'lateral-movement': ThreatIntel.KillChainPhases.LATERAL_MOVEMENT,
    'defense-evasion': ThreatIntel.KillChainPhases.DEFENSE_EVASION,
    'persistence': ThreatIntel.KillChainPhases.PERSISTENCE,
    'collection': ThreatIntel.KillChainPhases.COLLECTION,
    'impact': ThreatIntel.KillChainPhases.IMPACT,
    'initial-access': ThreatIntel.KillChainPhases.INITIAL_ACCESS,
    'discovery': ThreatIntel.KillChainPhases.DISCOVERY,
    'execution': ThreatIntel.KillChainPhases.EXECUTION,
    'installation': ThreatIntel.KillChainPhases.INSTALLATION,
    'delivery': ThreatIntel.KillChainPhases.DELIVERY,
    'weaponization': ThreatIntel.KillChainPhases.WEAPONIZATION,
    'act-on-objectives': ThreatIntel.KillChainPhases.ACT_ON_OBJECTIVES,
    'command-and-control': ThreatIntel.KillChainPhases.COMMAND_AND_CONTROL
}

RELATIONSHIP_TYPES = EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys()


class Client(BaseClient):

    def __init__(self, api_key, verify):
        """Implements class for Unit 42 feed.

        Args:
            api_key: unit42 API Key.
            verify: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        """
        super().__init__(base_url='https://stix2.unit42.org/taxii', verify=verify,
                         proxy=argToBoolean(demisto.params().get('proxy') or 'false'))
        self._api_key = api_key
        self._proxies = handle_proxy()
        self.objects_data = {}
        self.server = Server(
            url=self._base_url, auth=TokenAuth(key=self._api_key), verify=self._verify, proxies=self._proxies
        )

    def get_stix_objects(self, test: bool = False, items_types: Optional[list] = None):
        if not items_types:
            items_types = []
        for type_ in items_types:
            self.fetch_stix_objects_from_api(test, type=type_)

    def fetch_stix_objects_from_api(self, test: bool = False, limit: int = -1, **kwargs):
        """Retrieves all entries from the feed.

        Args:
            test: Whether it was called during clicking the test button or not - designed to save time.
            limit: number of indicators for get command
        """
        data: list = []
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                for bundle in as_pages(collection.get_objects, per_request=100, **kwargs):
                    data.extend(bundle.get('objects') or [])
                    if test and limit < len(data):
                        return data

        if test:
            return data
        self.objects_data[kwargs.get('type')] = data


def get_ioc_value_from_ioc_name(ioc_obj):
    """
    Extract SHA-256 from string:
    ([file:name = 'blabla' OR file:name = 'blabla'] AND [file:hashes.'SHA-256' = '1111'])" -> 1111
    """
    ioc_value = ioc_obj.get('name')
    try:
        ioc_value = re.search("(?<='SHA-256' = ').*?(?=')", ioc_value).group(0)  # type:ignore # guardrails-disable-line
    except AttributeError:
        ioc_value = None
    return ioc_value


def parse_indicators(indicator_objects: list, feed_tags: Optional[list] = None, tlp_color: Optional[str] = None) -> list:
    """Parse the IOC objects retrieved from the feed.
    Args:
      indicator_objects: a list of objects containing the indicators.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
    Returns:
        A list of processed indicators.
    """
    if not feed_tags:
        feed_tags = []

    indicators = []
    if indicator_objects:
        for indicator_object in indicator_objects:
            pattern = indicator_object.get('pattern') or ''
            for key in UNIT42_TYPES_TO_DEMISTO_TYPES.keys():
                if pattern.startswith(f'[{key}'):  # retrieve only Demisto indicator types
                    indicator_obj = {
                        "value": indicator_object.get('name'),
                        "type": UNIT42_TYPES_TO_DEMISTO_TYPES.get(key),
                        "score": ThreatIntel.ObjectsScore.MALWARE,
                        "rawJSON": indicator_object,
                        "fields": {
                            "firstseenbysource": indicator_object.get('created'),
                            "indicatoridentification": indicator_object.get('id'),
                            "tags": list((set(indicator_object.get('labels') or [])).union(set(feed_tags))),
                            "modified": indicator_object.get('modified'),
                            "reportedby": 'Unit42',
                        }
                    }

                    if "file:hashes.'SHA-256' = '" in indicator_obj['value']:
                        if get_ioc_value_from_ioc_name(indicator_object):
                            indicator_obj['value'] = get_ioc_value_from_ioc_name(indicator_object)

                    if tlp_color:
                        indicator_obj['fields']['trafficlightprotocol'] = tlp_color

                    indicators.append(indicator_obj)

    return indicators


def get_campaign_from_sub_reports(report_object, id_to_object):
    report_relationships = []
    object_refs = report_object.get('object_refs', [])
    for obj in object_refs:
        if obj.startswith('report--'):
            sub_report_obj = id_to_object.get(obj, {})
            for sub_report_obj_ref in sub_report_obj.get('object_refs', []):
                if sub_report_obj_ref.startswith('campaign--'):
                    related_campaign = id_to_object.get(sub_report_obj_ref)

                    if related_campaign:
                        entity_relation = EntityRelationship(name='related-to',
                                                             entity_a=f"[Unit42 ATOM] {report_object.get('name')}",
                                                             entity_a_type='Report',
                                                             entity_b=related_campaign.get('name'),
                                                             entity_b_type='Campaign')
                        report_relationships.append(entity_relation.to_indicator())
    return report_relationships


def is_sub_report(report_obj):
    obj_refs = report_obj.get('object_refs', [])
    for obj_ref in obj_refs:
        if obj_ref.startswith('report--'):
            return False
    return True


def parse_reports_and_report_relationships(report_objects: list, feed_tags: Optional[list] = None,
                                           tlp_color: Optional[str] = None, id_to_object: Optional[dict] = None):
    """Parse the Reports objects retrieved from the feed.

    Args:
      report_objects: a list of report objects containing the reports.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
      id_to_object: a dict in the form of - id: stix_object.

    Returns:
        A list of processed reports.
    """
    if not feed_tags:
        feed_tags = []

    if not id_to_object:
        id_to_object = {}

    reports = []

    for report_object in report_objects:
        if is_sub_report(report_object):
            continue

        report = dict()  # type: Dict[str, Any]

        report['type'] = ThreatIntel.ObjectsNames.REPORT
        report['value'] = f"[Unit42 ATOM] {report_object.get('name')}"
        report['score'] = ThreatIntel.ObjectsScore.REPORT
        report['fields'] = {
            'stixid': report_object.get('id'),
            "firstseenbysource": report_object.get('created'),
            'published': report_object.get('published'),
            'description': report_object.get('description', ''),
            "reportedby": 'Unit42',
            "tags": list((set(report_object.get('labels') or [])).union(set(feed_tags))),
        }
        if tlp_color:
            report['fields']['trafficlightprotocol'] = tlp_color

        report['rawJSON'] = {
            'unit42_id': report_object.get('id'),
            'unit42_labels': report_object.get('labels'),
            'unit42_published': report_object.get('published'),
            'unit42_created_date': report_object.get('created'),
            'unit42_modified_date': report_object.get('modified'),
            'unit42_description': report_object.get('description'),
            'unit42_object_refs': report_object.get('object_refs')
        }

        report['relationships'] = get_campaign_from_sub_reports(report_object, id_to_object)

        reports.append(report)

    return reports


def parse_campaigns(campaigns_obj, feed_tags, tlp_color):
    """Parse the Campaign objects retrieved from the feed.

    Args:
      campaigns_obj: a list of campaign objects containing the campaign.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.

    Returns:
        A list of processed campaign.
    """
    campaigns_indicators = []
    for campaign in campaigns_obj:
        indicator_obj = {
            "value": campaign.get('name'),
            "type": ThreatIntel.ObjectsNames.CAMPAIGN,
            "rawJSON": campaign,
            "score": ThreatIntel.ObjectsScore.CAMPAIGN,
            "fields": {
                'stixid': campaign.get('id'),
                "firstseenbysource": campaign.get('created'),
                "modified": campaign.get('modified'),
                'description': campaign.get('description'),
                "reportedby": 'Unit42',
                "tags": [tag for tag in feed_tags],
            }
        }

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        campaigns_indicators.append(indicator_obj)

    return campaigns_indicators


def handle_multiple_dates_in_one_field(field_name: str, field_value: str):
    """Parses datetime fields to handle one value or more

    Args:
        field_name (str): The field name that holds the data (created/modified).
        field_value (str): Raw value returned from feed.

    Returns:
        str. One datetime value (min/max) according to the field name.
    """
    dates_as_string = field_value.splitlines()
    dates_as_datetime = [datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ') for date in dates_as_string]

    if field_name == 'created':
        return f"{min(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"
    else:
        return f"{max(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"


def get_indicator_publication(indicator):
    """
    Build publications grid field from the indicator external_references field

    Args:
        indicator: The indicator with publication field

    Returns:
        list. publications grid field
    """
    publications = []
    for external_reference in indicator.get('external_references', []):
        if external_reference.get('external_id'):
            continue
        url = external_reference.get('url')
        description = external_reference.get('description')
        source_name = external_reference.get('source_name')
        publications.append({'link': url, 'title': description, 'source': source_name})
    return publications


def get_attack_id_and_value_from_name(attack_indicator):
    """
    Split indicator name into MITRE ID and indicator value: 'T1108: Redundant Access' -> MITRE ID = T1108,
    indicator value = 'Redundant Access'.
    """
    ind_name = attack_indicator.get('name')
    separator = ':'
    try:
        idx = ind_name.index(separator)
    except ValueError:
        raise DemistoException(f"Failed parsing attack indicator {ind_name}")
    ind_id = ind_name[:idx]
    value = ind_name[idx + 2:]

    if attack_indicator.get('x_mitre_is_subtechnique'):
        value = attack_indicator.get('x_panw_parent_technique_subtechnique')

    return ind_id, value


def change_attack_pattern_to_stix_attack_pattern(indicator: dict):
    kill_chain_phases = indicator['fields']['killchainphases']
    del indicator['fields']['killchainphases']
    description = indicator['fields']['description']
    del indicator['fields']['description']

    indicator_type = indicator['type']
    indicator['type'] = f'STIX {indicator_type}'
    indicator['fields']['stixkillchainphases'] = kill_chain_phases
    indicator['fields']['stixdescription'] = description

    return indicator


def create_attack_pattern_indicator(attack_indicator_objects, feed_tags, tlp_color, is_up_to_6_2) -> List:
    """Parse the Attack Pattern objects retrieved from the feed.

    Args:
      attack_indicator_objects: a list of Attack Pattern objects containing the Attack Pattern.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.
      is_up_to_6_2: is the server version is up to 6.2

    Returns:
        A list of processed Attack Pattern.
    """

    attack_pattern_indicators = []

    for attack_indicator in attack_indicator_objects:

        publications = get_indicator_publication(attack_indicator)
        mitre_id, value = get_attack_id_and_value_from_name(attack_indicator)

        kill_chain_mitre = [chain.get('phase_name', '') for chain in attack_indicator.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        indicator = {
            "value": value,
            "type": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
            "fields": {
                'stixid': attack_indicator.get('id'),
                "killchainphases": kill_chain_phases,
                "firstseenbysource": handle_multiple_dates_in_one_field('created', attack_indicator.get('created')),
                "modified": handle_multiple_dates_in_one_field('modified', attack_indicator.get('modified')),
                'description': attack_indicator.get('description'),
                'operatingsystemrefs': attack_indicator.get('x_mitre_platforms'),
                "publications": publications,
                "mitreid": mitre_id,
                "reportedby": 'Unit42',
                "tags": [tag for tag in feed_tags],
            }
        }
        indicator['fields']['tags'].extend([mitre_id])
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        if not is_up_to_6_2:
            # For versions less than 6.2 - that only support STIX and not the newer types - Malware, Tool, etc.
            indicator = change_attack_pattern_to_stix_attack_pattern(indicator)

        attack_pattern_indicators.append(indicator)
    return attack_pattern_indicators


def create_course_of_action_indicators(course_of_action_objects, feed_tags, tlp_color):
    """Parse the Course of Action objects retrieved from the feed.

    Args:
      course_of_action_objects: a list of Course of Action objects containing the Course of Action.
      feed_tags: feed tags.
      tlp_color: Traffic Light Protocol color.

    Returns:
        A list of processed campaign.
    """
    course_of_action_indicators = []

    for coa_indicator in course_of_action_objects:

        publications = get_indicator_publication(coa_indicator)

        indicator = {
            "value": coa_indicator.get('name'),
            "type": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
            "score": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
            "fields": {
                'stixid': coa_indicator.get('id'),
                "firstseenbysource": handle_multiple_dates_in_one_field('created', coa_indicator.get('created')),
                "modified": handle_multiple_dates_in_one_field('modified', coa_indicator.get('modified')),
                'description': coa_indicator.get('description', ''),
                "publications": publications,
                "reportedby": 'Unit42',
                "tags": [tag for tag in feed_tags],
            }
        }
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        course_of_action_indicators.append(indicator)

    return course_of_action_indicators


def create_intrusion_sets(intrusion_sets_objects, feed_tags, tlp_color):
    course_of_action_indicators = []

    for intrusion_set in intrusion_sets_objects:

        publications = get_indicator_publication(intrusion_set)

        indicator = {
            "value": intrusion_set.get('name'),
            "type": ThreatIntel.ObjectsNames.INTRUSION_SET,
            "score": ThreatIntel.ObjectsScore.INTRUSION_SET,
            "fields": {
                'stixid': intrusion_set.get('id'),
                "firstseenbysource": handle_multiple_dates_in_one_field('created', intrusion_set.get('created')),
                "modified": handle_multiple_dates_in_one_field('modified', intrusion_set.get('modified')),
                'description': intrusion_set.get('description', ''),
                "publications": publications,
                "reportedby": 'Unit42',
                "tags": [tag for tag in feed_tags],
            }
        }
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        course_of_action_indicators.append(indicator)

    return course_of_action_indicators


def get_ioc_type(indicator, id_to_object):
    """
    Get IOC type by extracting it from the pattern field.

    Args:
        indicator: the indicator to get information on.
        id_to_object: a dict in the form of - id: stix_object.

    Returns:
        str. the IOC type.
    """
    ioc_type = ''
    indicator_obj = id_to_object.get(indicator, {})
    pattern = indicator_obj.get('pattern', '')
    for unit42_type in UNIT42_TYPES_TO_DEMISTO_TYPES:
        if pattern.startswith(f'[{unit42_type}'):
            ioc_type = UNIT42_TYPES_TO_DEMISTO_TYPES.get(unit42_type)  # type: ignore
            break
    return ioc_type


def get_ioc_value(ioc, id_to_obj):
    """
    Get IOC value from the indicator name field.

    Args:
        ioc: the indicator to get information on.
        id_to_obj: a dict in the form of - id: stix_object.

    Returns:
        str. the IOC value. if its reports we add to it [Unit42 ATOM] prefix,
        if its attack pattern remove the id from the name.
    """
    ioc_obj = id_to_obj.get(ioc)
    if ioc_obj:
        if ioc_obj.get('type') == 'report':
            return f"[Unit42 ATOM] {ioc_obj.get('name')}"
        elif ioc_obj.get('type') == 'attack-pattern':
            _, value = get_attack_id_and_value_from_name(ioc_obj)
            return value
        elif "file:hashes.'SHA-256' = '" in ioc_obj.get('name'):
            return get_ioc_value_from_ioc_name(ioc_obj)
        else:
            return ioc_obj.get('name')


def create_list_relationships(relationships_objects, id_to_object):
    """Parse the Relationships objects retrieved from the feed.

    Args:
      relationships_objects: a list of relationships objects containing the relationships.
      id_to_object: a dict in the form of - id: stix_object.

    Returns:
        A list of processed relationships.
    """
    relationships_list = []

    for relationships_object in relationships_objects:

        relationship_type = relationships_object.get('relationship_type')
        if relationship_type not in RELATIONSHIP_TYPES:
            if relationship_type == 'indicates':
                relationship_type = 'indicated-by'
            else:
                demisto.debug(f"Invalid relation type: {relationship_type}")
                continue

        a_threat_intel_type = relationships_object.get('source_ref').split('--')[0]
        a_type = ''
        if a_threat_intel_type in THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.keys():
            a_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(a_threat_intel_type)  # type: ignore
        elif a_threat_intel_type == 'indicator':
            a_type = get_ioc_type(relationships_object.get('source_ref'), id_to_object)

        b_threat_intel_type = relationships_object.get('target_ref').split('--')[0]
        b_type = ''
        if b_threat_intel_type in THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.keys():
            b_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(b_threat_intel_type)  # type: ignore
        if b_threat_intel_type == 'indicator':
            b_type = get_ioc_type(relationships_object.get('target_ref'), id_to_object)

        if not a_type or not b_type:
            continue

        mapping_fields = {
            'lastseenbysource': relationships_object.get('modified'),
            'firstseenbysource': relationships_object.get('created')
        }

        entity_a = get_ioc_value(relationships_object.get('source_ref'), id_to_object)
        entity_b = get_ioc_value(relationships_object.get('target_ref'), id_to_object)

        entity_relation = EntityRelationship(name=relationship_type,
                                             entity_a=entity_a,
                                             entity_a_type=a_type,
                                             entity_b=entity_b,
                                             entity_b_type=b_type,
                                             fields=mapping_fields)
        relationships_list.append(entity_relation.to_indicator())
    return relationships_list


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    client.get_stix_objects(test=True, items_types=['indicator', 'report'])
    return 'ok'


def fetch_indicators(client: Client, feed_tags: Optional[list] = None, tlp_color: Optional[str] = None,
                     create_relationships=False) -> List[Dict]:
    """Retrieves indicators from the feed

    Args:
        client: Client object with request
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
        create_relationships: Create indicators relationships
    Returns:
        List. Processed indicators from feed.
    """
    if not feed_tags:
        feed_tags = []

    item_types_to_fetch_from_api = ['report', 'indicator', 'malware', 'campaign', 'attack-pattern', 'relationship',
                                    'course-of-action', 'intrusion-set']
    client.get_stix_objects(items_types=item_types_to_fetch_from_api)
    is_up_to_6_2 = is_demisto_version_ge('6.2.0')

    for type_, objects in client.objects_data.items():
        demisto.info(f'Fetched {len(objects)} Unit42 {type_} objects.')

    id_to_object = {
        obj.get('id'): obj for obj in
        client.objects_data['report'] + client.objects_data['indicator'] + client.objects_data['malware']
        + client.objects_data['campaign'] + client.objects_data['attack-pattern']
        + client.objects_data['course-of-action'] + client.objects_data['intrusion-set']
    }

    ioc_indicators = parse_indicators(client.objects_data['indicator'], feed_tags, tlp_color)
    reports = parse_reports_and_report_relationships(client.objects_data['report'], feed_tags, tlp_color, id_to_object)
    campaigns = parse_campaigns(client.objects_data['campaign'], feed_tags, tlp_color)
    attack_patterns = create_attack_pattern_indicator(client.objects_data['attack-pattern'],
                                                      feed_tags, tlp_color, is_up_to_6_2)
    intrusion_sets = create_intrusion_sets(client.objects_data['intrusion-set'], feed_tags, tlp_color)
    course_of_actions = create_course_of_action_indicators(client.objects_data['course-of-action'],
                                                           feed_tags, tlp_color)

    dummy_indicator = {}
    if create_relationships:
        list_relationships = create_list_relationships(client.objects_data['relationship'], id_to_object)

        dummy_indicator = {
            "value": "$$DummyIndicator$$",
            "relationships": list_relationships
        }

    if dummy_indicator:
        ioc_indicators.append(dummy_indicator)

    if ioc_indicators:
        demisto.debug(f'Feed Unit42 v2: {len(ioc_indicators)} XSOAR Indicators were created.')
    if reports:
        demisto.debug(f'Feed Unit42 v2: {len(reports)} XSOAR Reports Indicators were created.')
    if campaigns:
        demisto.debug(f'Feed Unit42 v2: {len(campaigns)} XSOAR campaigns Indicators were created.')
    if attack_patterns:
        demisto.debug(f'Feed Unit42 v2: {len(attack_patterns)} Attack Patterns Indicators were created.')
    if course_of_actions:
        demisto.debug(f'Feed Unit42 v2: {len(course_of_actions)} Course of Actions Indicators were created.')
    if intrusion_sets:
        demisto.debug(f'Feed Unit42 v2: {len(intrusion_sets)} Intrusion Sets Indicators were created.')

    return ioc_indicators + reports + campaigns + attack_patterns + course_of_actions + intrusion_sets


def get_indicators_command(client: Client, args: Dict[str, str], feed_tags: Optional[list] = None,
                           tlp_color: Optional[str] = None) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.

    Args:
        client: Client object with request
        args: demisto.args()
        feed_tags: feed tags.
        tlp_color: Traffic Light Protocol color.
    Returns:
        Demisto Outputs.
    """
    is_version_over_6_2 = is_demisto_version_ge('6.2.0')
    limit = arg_to_number(args.get('limit')) or 10
    if not feed_tags:
        feed_tags = []

    ind_type = args.get('indicators_type')

    indicators = client.fetch_stix_objects_from_api(test=True, type=ind_type, limit=limit)

    if ind_type == 'indicator':
        indicators = parse_indicators(indicators, feed_tags, tlp_color)
    else:
        indicators = create_attack_pattern_indicator(indicators, feed_tags, tlp_color, is_version_over_6_2)
    limited_indicators = indicators[:limit]

    readable_output = tableToMarkdown('Unit42 Indicators:', t=limited_indicators, headers=['type', 'value', 'fields'])

    command_results = CommandResults(
        outputs_prefix='',
        outputs_key_field='',
        outputs={},
        readable_output=readable_output,
        raw_response=limited_indicators
    )

    return command_results


def main():
    """
    PARSE AND VALIDATE FEED PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    api_key = str(params.get('api_key', ''))
    verify = not params.get('insecure', False)
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    create_relationships = argToBoolean(params.get('create_relationships'))

    command = demisto.command()
    demisto.debug(f'Command being called in Unit42 v2 feed is: {command}')

    try:
        client = Client(api_key, verify)

        if command == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client, feed_tags, tlp_color, create_relationships)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        elif command == 'unit42-get-indicators':
            return_results(get_indicators_command(client, args, feed_tags, tlp_color))

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
