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
        counter = 0

        # For each collection
        for collection in self.collections:

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
                            indicators.append(indicator_obj)
                            counter += 1
                        mitre_id_list.add(mitre_item_json.get('id'))

        return indicators, mitre_relationships_list, id_to_name


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
        url = external_reference.get('url')
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

    return EntityRelationship(name=item_json.get('relationship_type'),
                              entity_a=id_to_name.get(item_json.get('source_ref')),
                              entity_a_type=a_type,
                              entity_b=id_to_name.get(item_json.get('target_ref')),
                              entity_b_type=b_type,
                              fields=mapping_fields)


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
    indicators, mitre_relationships_list, id_to_name = client.build_iterator(create_relationships, is_up_to_6_2)
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


# def build_attack_context():
#     command_results: List[CommandResults] = []
#     if entity_data and ("error" not in entity_data):
#         for ent in entity_data["data"]["results"]:
#             try:
#                 evidence = ent["risk"]["rule"]["evidence"]
#             except KeyError:
#                 evidence = {}
#             concat_rules = ','.join([e["rule"] for e in evidence.values()])
#             context = (
#                 {
#                     "riskScore": ent["risk"]["score"],
#                     "Evidence": [
#                         {
#                             "rule": dic["rule"],
#                             "mitigation": dic["mitigation"],
#                             "description": dic["description"],
#                             "timestamp": prettify_time(dic["timestamp"]),
#                             "level": dic["level"],
#                             "ruleid": key,
#                         }
#                         if dic.get("mitigation", None)
#                         else {
#                             "rule": dic["rule"],
#                             "description": dic["description"],
#                             "timestamp": prettify_time(dic["timestamp"]),
#                             "level": dic["level"],
#                             "ruleid": key,
#                         }
#                         for key, dic in evidence.items()
#                     ],
#                     "riskLevel": ent["risk"]["level"],
#                     "id": ent["entity"]["id"],
#                     "ruleCount": ent["risk"]["rule"]["count"],
#                     "rules": concat_rules,
#                     "maxRules": ent["risk"]["rule"]["maxCount"],
#                     "description": ent["entity"].get("description", ""),
#                     "name": ent["entity"]["name"],
#                 }
#             )
#             indicator = create_indicator(
#                 ent["entity"]["name"],
#                 entity_type,
#                 ent["risk"]["score"],
#                 ent["entity"].get("description", ""),
#             )
#             command_results.append(CommandResults(
#                 outputs_prefix=get_output_prefix(entity_type),
#                 outputs=context,
#                 raw_response=entity_data,
#                 readable_output=build_rep_markdown(ent, entity_type),
#                 outputs_key_field='name',
#                 indicator=indicator
#             ))
#         return command_results
#     else:
#         return [CommandResults(
#             readable_output="No records found"
#         )]


def attack_pattern_reputation_command(client, args):
    command_results: List[CommandResults] = []

    mitre_names = argToList(args.get('attack_pattern'))
    for name in mitre_names:
        filter_by_name = [Filter('type', '=', 'attack-pattern'), Filter('name', '=', name)]
        for collection in client.collections:

            collection_url = urljoin(client.base_url, f'stix/collections/{collection.id}/')
            collection_data = Collection(collection_url, verify=client.verify, proxies=client.proxies)

            tc_source = TAXIICollectionSource(collection_data)
            if tc_source.query(filter_by_name):
                mitre_data = tc_source.query(filter_by_name)[0]
            else:
                continue

            attack_obj = map_fields_by_type('Attack Pattern', json.loads(str(mitre_data)))

            custom_fields = attack_obj or {}
            score = INDICATOR_TYPE_TO_SCORE.get('Attack Pattern')
            value = mitre_data.get('name')
            md = f"## {[value]}:\n {custom_fields.get('mitredescription', '')}"

            attack_obj.update({
                "value": value,
                "score": score,
                "type": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
                "rawJSON": json.loads(str(mitre_data)),
            })
            command_results.append(CommandResults(
                outputs_prefix='MITRE ATT&CK.AttackPattern',
                outputs=attack_obj,
                readable_output=md,
                outputs_key_field='IndicatorValue',
                indicator=name
            ))
        return command_results
    else:
        return [CommandResults(
            readable_output="No records found"
        )]


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

        elif demisto.command() == 'attack-pattern':
            attack_pattern_reputation_command(client, args)

        elif demisto.command() == 'mitre-show-feeds':
            show_feeds_command(client)

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
