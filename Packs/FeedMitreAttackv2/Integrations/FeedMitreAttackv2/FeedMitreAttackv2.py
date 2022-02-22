import demistomock as demisto
from CommonServerPython import *

from typing import List, Dict, Set, Optional
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Server, Collection, ApiRoot

''' CONSTANT VARIABLES '''

MITRE_TYPE_TO_DEMISTO_TYPE = {
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "relationship": "Relationship"
}

INDICATOR_TYPE_TO_SCORE = {
    "Intrusion Set": ThreatIntel.ObjectsScore.INTRUSION_SET,
    "Attack Pattern": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
    "Course of Action": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
    "Malware": ThreatIntel.ObjectsScore.MALWARE,
    "Tool": ThreatIntel.ObjectsScore.TOOL
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

FILTER_OBJS = {
    "Technique": {"name": "attack-pattern", "filter": Filter("type", "=", "attack-pattern")},
    "Mitigation": {"name": "course-of-action", "filter": Filter("type", "=", "course-of-action")},
    "Group": {"name": "intrusion-set", "filter": Filter("type", "=", "intrusion-set")},
    "Malware": {"name": "malware", "filter": Filter("type", "=", "malware")},
    "Tool": {"name": "tool", "filter": Filter("type", "=", "tool")},
    "relationships": {"name": "relationships", "filter": Filter("type", "=", "relationship")},
}

RELATIONSHIP_TYPES = EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys()
ENTERPRISE_COLLECTION_ID = '95ecc380-afe9-11e4-9b6c-751b66dd541e'

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:

    def __init__(self, url, proxies, verify, tags: list = None,
                 tlp_color: Optional[str] = None):
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.tags = [] if not tags else tags
        self.tlp_color = tlp_color
        self.server: Server
        self.api_root: List[ApiRoot]
        self.collections: List[Collection]

    def get_server(self):
        server_url = urljoin(self.base_url, '/taxii/')
        self.server = Server(server_url, verify=self.verify, proxies=self.proxies)

    def get_roots(self):
        self.api_root = self.server.api_roots[0]

    def get_collections(self):
        self.collections = [x for x in self.api_root.collections]  # type: ignore[attr-defined]

    def initialise(self):
        self.get_server()
        self.get_roots()
        self.get_collections()

    def create_indicator(self, item_type, value, mitre_item_json):
        indicator_score = INDICATOR_TYPE_TO_SCORE.get(item_type)  # type: ignore
        indicator_obj = {
            "value": value,
            "score": indicator_score,
            "type": item_type,
            "rawJSON": mitre_item_json,
            "fields": map_fields_by_type(item_type, mitre_item_json)  # type: ignore
        }

        indicator_obj['fields']['tags'].extend(self.tags)

        if self.tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

        return indicator_obj

    def build_iterator(self, create_relationships=False, is_up_to_6_2=True, limit: int = -1):
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        indicators: List[Dict] = list()
        mitre_id_list: Set[str] = set()
        mitre_relationships_list = []
        id_to_name: Dict = {}
        mitre_id_to_mitre_name: Dict = {}
        counter = 0

        # For each collection
        for collection in self.collections:

            # fetch only enterprise objects
            if collection.id != ENTERPRISE_COLLECTION_ID:
                continue

            # Stop when we have reached the limit defined
            if 0 < limit <= counter:
                break

            # Establish TAXII2 Collection instance
            collection_url = urljoin(self.base_url, f'stix/collections/{collection.id}/')
            collection_data = Collection(collection_url, verify=self.verify, proxies=self.proxies)

            # Supply the collection to TAXIICollection
            tc_source = TAXIICollectionSource(collection_data)

            for concept in FILTER_OBJS:
                if 0 < limit <= counter:
                    break

                input_filter = FILTER_OBJS[concept]['filter']
                try:
                    mitre_data = tc_source.query(input_filter)
                except Exception:
                    continue

                for mitre_item in mitre_data:
                    if 0 < limit <= counter:
                        break

                    mitre_item_json = json.loads(str(mitre_item))
                    if mitre_item_json.get('id') not in mitre_id_list:
                        value = mitre_item_json.get('name')
                        item_type = get_item_type(mitre_item_json.get('type'), is_up_to_6_2)

                        if item_type == 'Relationship' and create_relationships:
                            if mitre_item_json.get('relationship_type') == 'revoked-by':
                                continue
                            mitre_relationships_list.append(mitre_item_json)

                        else:
                            if is_indicator_deprecated_or_revoked(mitre_item_json):
                                continue
                            id_to_name[mitre_item_json.get('id')] = value
                            indicator_obj = self.create_indicator(item_type, value, mitre_item_json)
                            add_obj_to_mitre_id_to_mitre_name(mitre_id_to_mitre_name, mitre_item_json)
                            indicators.append(indicator_obj)
                            counter += 1
                        mitre_id_list.add(mitre_item_json.get('id'))

        return indicators, mitre_relationships_list, id_to_name, mitre_id_to_mitre_name


def add_obj_to_mitre_id_to_mitre_name(mitre_id_to_mitre_name, mitre_item_json):
    if mitre_item_json['type'] == 'attack-pattern':
        mitre_id = [external.get('external_id') for external in mitre_item_json.get('external_references', [])
                    if external.get('source_name', '') == 'mitre-attack']
        if mitre_id:
            mitre_id_to_mitre_name[mitre_id[0]] = mitre_item_json.get('name')


def add_technique_prefix_to_sub_technique(indicators, id_to_name, mitre_id_to_mitre_name):
    for indicator in indicators:
        if indicator['type'] in ['Attack Pattern', 'STIX Attack Pattern'] and \
                len(indicator['fields']['mitreid']) > 5:  # Txxxx.xxx is sub technique
            parent_mitre_id = indicator['fields']['mitreid'][:5]
            value = indicator['value']
            technique = mitre_id_to_mitre_name.get(parent_mitre_id)
            if technique:
                new_value = f'{technique}: {value}'
                indicator['value'] = new_value
                id_to_name[indicator['fields']['stixid']] = new_value
            else:
                demisto.debug(f'MITRE Attack Feed v2, There is no such Technique - {parent_mitre_id}')


def add_malware_prefix_to_dup_with_intrusion_set(indicators, id_to_name):
    """
    Some Malware have names like their Intrusion Set, in which case we add (Malware) as a suffix.
    """
    intrusion_sets = []
    for ind in indicators:
        if ind['type'] in ['STIX Intrusion Set', 'Intrusion Set']:
            intrusion_sets.append(ind['value'])

    for ind in indicators:
        if ind['type'] in ['STIX Malware', 'Malware'] and ind['value'] in intrusion_sets:
            ind_value = ind['value']
            ind['value'] = f'{ind_value} [Malware]'
            id_to_name[ind['fields']['stixid']] = ind['value']


def get_item_type(mitre_type, is_up_to_6_2):
    item_type = MITRE_TYPE_TO_DEMISTO_TYPE.get(mitre_type)

    # For versions less than 6.2 - that only support STIX and not the newer types - Malware, Tool, etc.
    if not is_up_to_6_2 and item_type in ['Malware', 'Tool', 'Attack Pattern']:
        return f'STIX {item_type}'
    return item_type


def is_indicator_deprecated_or_revoked(indicator_json):
    return True if indicator_json.get("x_mitre_deprecated") or indicator_json.get("revoked") else False


def map_fields_by_type(indicator_type: str, indicator_json: dict):
    created = handle_multiple_dates_in_one_field('created', indicator_json.get('created'))  # type: ignore
    modified = handle_multiple_dates_in_one_field('modified', indicator_json.get('modified'))  # type: ignore

    kill_chain_phases_mitre = [chain.get('phase_name', '') for chain in indicator_json.get('kill_chain_phases', [])]
    kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_phases_mitre]

    publications = []
    for external_reference in indicator_json.get('external_references', []):
        if external_reference.get('external_id'):
            continue
        url = external_reference.get('url', '')
        description = external_reference.get('description')
        source_name = external_reference.get('source_name')
        publications.append({'link': url, 'title': description, 'source': source_name})

    mitre_id = [external.get('external_id') for external in indicator_json.get('external_references', [])
                if external.get('source_name', '') == 'mitre-attack']
    mitre_id = mitre_id[0] if mitre_id else None

    tags = [mitre_id] if mitre_id else []
    if indicator_type in ['Tool', 'STIX Tool', 'Malware', 'STIX Malware']:
        tags.extend(indicator_json.get('labels', ''))

    generic_mapping_fields = {
        'stixid': indicator_json.get('id'),
        'firstseenbysource': created,
        'modified': modified,
        'publications': publications,
        'mitreid': mitre_id,
        'tags': tags
    }

    mapping_by_type = {
        "Attack Pattern": {
            'killchainphases': kill_chain_phases,
            'description': indicator_json.get('description'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "Intrusion Set": {
            'description': indicator_json.get('description'),
            'aliases': indicator_json.get('aliases')
        },
        "Malware": {
            'aliases': indicator_json.get('x_mitre_aliases'),
            'description': indicator_json.get('description'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')

        },
        "Tool": {
            'aliases': indicator_json.get('x_mitre_aliases'),
            'description': indicator_json.get('description'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "Course of Action": {
            'description': indicator_json.get('description')
        },

        "STIX Attack Pattern": {
            'stixkillchainphases': kill_chain_phases,
            'stixdescription': indicator_json.get('description'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "STIX Malware": {
            'stixaliases': indicator_json.get('x_mitre_aliases'),
            'stixdescription': indicator_json.get('description'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')

        },
        "STIX Tool": {
            'stixaliases': indicator_json.get('x_mitre_aliases'),
            'stixdescription': indicator_json.get('description'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        }
    }
    generic_mapping_fields.update(mapping_by_type.get(indicator_type, {}))
    return generic_mapping_fields


def create_relationship_list(mitre_relationships_list, id_to_name):
    relationships_list = []
    for mitre_relationship in mitre_relationships_list:
        relation_obj = create_relationship(mitre_relationship, id_to_name)
        relationships_list.append(relation_obj.to_indicator()) if relation_obj else None

    return relationships_list


def create_relationship(item_json, id_to_name):
    """
    Create a single relation with the given arguments.
    """
    a_type = item_json.get('source_ref').split('--')[0]
    a_type = MITRE_TYPE_TO_DEMISTO_TYPE.get(a_type)

    b_type = item_json.get('target_ref').split('--')[0]
    b_type = MITRE_TYPE_TO_DEMISTO_TYPE.get(b_type)

    mapping_fields = {
        'description': item_json.get('description'),
        'lastseenbysource': item_json.get('modified'),
        'firstseenbysource': item_json.get('created')
    }
    if item_json.get('relationship_type') not in RELATIONSHIP_TYPES:
        demisto.debug(f"Invalid relation type: {item_json.get('relationship_type')}")
        return

    entity_a = id_to_name.get(item_json.get('source_ref'))
    entity_b = id_to_name.get(item_json.get('target_ref'))

    if entity_b and entity_a:
        return EntityRelationship(name=item_json.get('relationship_type'),
                                  entity_a=entity_a,
                                  entity_a_type=a_type,
                                  entity_b=entity_b,
                                  entity_b_type=b_type,
                                  fields=mapping_fields)
    return None


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


def test_module(client):
    try:
        client.build_iterator(limit=1)
        demisto.results('ok')
    except DemistoException:
        return_error('Could not connect to server')


def fetch_indicators(client, create_relationships):
    is_up_to_6_2 = is_demisto_version_ge('6.2.0')
    indicators, mitre_relationships_list, id_to_name, mitre_id_to_mitre_name = client.build_iterator(
        create_relationships, is_up_to_6_2)
    add_malware_prefix_to_dup_with_intrusion_set(indicators, id_to_name)
    add_technique_prefix_to_sub_technique(indicators, id_to_name, mitre_id_to_mitre_name)
    relationships = create_relationship_list(mitre_relationships_list, id_to_name)

    if create_relationships and mitre_relationships_list:
        dummy_indicator_for_relations = {
            "value": "$$DummyIndicator$$",
            "relationships": relationships
        }

        indicators.append(dummy_indicator_for_relations)

    return indicators


def get_indicators_command(client, args):
    limit = int(args.get('limit', 10))
    raw = True if args.get('raw') == "True" else False

    indicators = client.build_iterator(limit=limit)

    if raw:
        demisto.results({
            "indicators": [x.get('rawJSON') for x in indicators]
        })
        return

    demisto.results(f"Found {len(indicators)} results:")
    demisto.results(
        {
            'Type': entryTypes['note'],
            'Contents': indicators,
            'ContentsFormat': formats['json'],
            'HumanReadable': tableToMarkdown('MITRE ATT&CK v2 Indicators:', indicators, ['value', 'score', 'type']),
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {'MITRE.ATT&CK(val.value && val.value == obj.value)': indicators}
        }
    )


def show_feeds_command(client):
    feeds = list()
    for collection in client.collections:
        feeds.append({"Name": collection.title, "ID": collection.id})
    md = tableToMarkdown('MITRE ATT&CK Feeds:', feeds, ['Name', 'ID'])
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': feeds,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown']
    })


def get_mitre_data_by_filter(client, mitre_filter):
    for collection in client.collections:

        collection_url = urljoin(client.base_url, f'stix/collections/{collection.id}/')
        collection_data = Collection(collection_url, verify=client.verify, proxies=client.proxies)

        tc_source = TAXIICollectionSource(collection_data)
        if tc_source.query(mitre_filter):
            mitre_data = tc_source.query(mitre_filter)[0]
            return mitre_data
    return {}


def build_command_result(value, score, md, attack_obj):
    dbot_score = Common.DBotScore(
        indicator=value,
        indicator_type=DBotScoreType.ATTACKPATTERN,
        score=score,
        integration_name="MITRE ATT&CK v2"
    )
    attack_context = Common.AttackPattern(
        stix_id=attack_obj.get('stixid'),
        kill_chain_phases=attack_obj.get('killchainphases'),
        first_seen_by_source=attack_obj.get('firstseenbysource'),
        description=attack_obj.get('description'),
        operating_system_refs=attack_obj.get('operatingsystemrefs'),
        publications=attack_obj.get('publications'),
        mitre_id=attack_obj.get('mitreid'),
        tags=attack_obj.get('tags'),
        dbot_score=dbot_score,
    )

    return CommandResults(
        outputs_prefix='MITREATTACK.AttackPattern',
        readable_output=md,
        outputs_key_field='name',
        indicator=attack_context,
    )


def attack_pattern_reputation_command(client, args):
    command_results: List[CommandResults] = []

    mitre_names = argToList(args.get('attack_pattern'))
    for name in mitre_names:
        if ':' not in name:  # not sub-technique
            filter_by_name = [Filter('type', '=', 'attack-pattern'), Filter('name', '=', name)]
            mitre_data = get_mitre_data_by_filter(client, filter_by_name)
            if not mitre_data:
                break

            attack_obj = map_fields_by_type('Attack Pattern', json.loads(str(mitre_data)))

            custom_fields = attack_obj or {}
            score = INDICATOR_TYPE_TO_SCORE.get('Attack Pattern')
            value = mitre_data.get('name')
            md = f"## {[value]}:\n {custom_fields.get('description', '')}"

            command_results.append(build_command_result(value, score, md, attack_obj))

        else:
            all_name = name.split(':')
            parent = all_name[0]
            sub = all_name[1][1:]
            mitre_id = ''

            # get parent MITRE ID
            filter_by_name = [Filter('type', '=', 'attack-pattern'), Filter('name', '=', parent)]
            mitre_data = get_mitre_data_by_filter(client, filter_by_name)
            if not mitre_data:
                break
            indicator_json = json.loads(str(mitre_data))
            parent_mitre_id = [external.get('external_id') for external in
                               indicator_json.get('external_references', [])
                               if external.get('source_name', '') == 'mitre-attack']
            parent_mitre_id = parent_mitre_id[0]
            parent_name = indicator_json['name']

            # get sub MITRE ID
            filter_by_name = [Filter('type', '=', 'attack-pattern'), Filter('name', '=', sub)]
            mitre_data = get_mitre_data_by_filter(client, filter_by_name)
            if not mitre_data:
                break
            indicator_json = json.loads(str(mitre_data))
            sub_mitre_id = [external.get('external_id') for external in
                            indicator_json.get('external_references', [])
                            if external.get('source_name', '') == 'mitre-attack']
            sub_mitre_id = sub_mitre_id[0]
            sub_mitre_id = sub_mitre_id[5:]

            mitre_id = f'{parent_mitre_id}{sub_mitre_id}'
            mitre_filter = [Filter("external_references.external_id", "=", mitre_id),
                            Filter("type", "=", "attack-pattern")]
            mitre_data = get_mitre_data_by_filter(client, mitre_filter)
            if not mitre_data:
                break

            attack_obj = map_fields_by_type('Attack Pattern', json.loads(str(mitre_data)))

            custom_fields = attack_obj or {}
            score = INDICATOR_TYPE_TO_SCORE.get('Attack Pattern')
            value_ = mitre_data.get('name')
            value = f'{parent_name}: {value_}'
            md = f"## {[value]}:\n {custom_fields.get('description', '')}"

            command_results.append(build_command_result(value, score, md, attack_obj))

    return command_results


def get_mitre_value_from_id(client, args):
    attack_ids = argToList(args.get('attack_ids', []))

    attack_values = []
    for attack_id in attack_ids:
        collection_id = f"stix/collections/{ENTERPRISE_COLLECTION_ID}/"
        collection_url = urljoin(client.base_url, collection_id)
        collection_data = Collection(collection_url, verify=client.verify, proxies=client.proxies)

        tc_source = TAXIICollectionSource(collection_data)
        attack_pattern_obj = tc_source.query([
            Filter("external_references.external_id", "=", attack_id),
            Filter("type", "=", "attack-pattern")
        ])
        attack_pattern_name = attack_pattern_obj[0]['name'] if attack_pattern_obj else None

        if attack_pattern_name and len(attack_id) > 5:  # sub-technique
            parent_name = tc_source.query([
                Filter("external_references.external_id", "=", attack_id[:5]),
                Filter("type", "=", "attack-pattern")
            ])[0]['name']
            attack_pattern_name = f'{parent_name}: {attack_pattern_name}'

        if attack_pattern_name:
            attack_values.append({'id': attack_id, 'value': attack_pattern_name})

    if attack_values:
        return CommandResults(
            outputs=attack_values,
            outputs_key_field='id',
            outputs_prefix='MITREATTACK',
            readable_output=tableToMarkdown('MITRE ATTACK Attack Patterns values:', attack_values)
        )

    return CommandResults(readable_output=f'MITRE ATTACK Attack Patterns values: '
                                          f'No Attack Patterns found for {attack_ids}.')


def main():
    params = demisto.params()
    args = demisto.args()
    url = 'https://cti-taxii.mitre.org'
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)
    tags = argToList(params.get('feedTags', []))
    tlp_color = params.get('tlp_color')
    create_relationships = argToBoolean(params.get('create_relationships'))
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url, proxies, verify_certificate, tags, tlp_color)
        client.initialise()

        if demisto.command() == 'mitre-get-indicators':
            get_indicators_command(client, args)

        elif demisto.command() == 'mitre-show-feeds':
            show_feeds_command(client)

        elif demisto.command() == 'mitre-get-indicator-name':
            return_results(get_mitre_value_from_id(client, args))

        elif demisto.command() == 'attack-pattern':
            return_results(attack_pattern_reputation_command(client, args))

        elif demisto.command() == 'test-module':
            test_module(client)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client, create_relationships)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

    # Log exceptions
    except Exception as e:
        return_error(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
