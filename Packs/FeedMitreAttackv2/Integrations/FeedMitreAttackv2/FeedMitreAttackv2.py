import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import logging


import json
import urllib3
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v21 import Server, Collection, ApiRoot

''' CONSTANT VARIABLES '''
MITRE_TYPE_TO_DEMISTO_TYPE = {  # pragma: no cover
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "relationship": "Relationship",
    "x-mitre-tactic": ThreatIntel.ObjectsNames.TACTIC
}
INDICATOR_TYPE_TO_SCORE = {  # pragma: no cover
    "Intrusion Set": ThreatIntel.ObjectsScore.INTRUSION_SET,
    "Attack Pattern": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
    "Course of Action": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
    "Malware": ThreatIntel.ObjectsScore.MALWARE,
    "Tool": ThreatIntel.ObjectsScore.TOOL,
    "Campaign": ThreatIntel.ObjectsScore.CAMPAIGN,
    "Tactic": ThreatIntel.ObjectsScore.TACTIC,
}
MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS = {  # pragma: no cover
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
FILTER_OBJS = {  # pragma: no cover
    "Tactic": {"name": "tactic", "filter": Filter("type", "=", "x-mitre-tactic")},
    "Technique": {"name": "attack-pattern", "filter": Filter("type", "=", "attack-pattern")},
    "Mitigation": {"name": "course-of-action", "filter": Filter("type", "=", "course-of-action")},
    "Group": {"name": "intrusion-set", "filter": Filter("type", "=", "intrusion-set")},
    "Malware": {"name": "malware", "filter": Filter("type", "=", "malware")},
    "Tool": {"name": "tool", "filter": Filter("type", "=", "tool")},
    "relationships": {"name": "relationships", "filter": Filter("type", "=", "relationship")},
    "Campaign": {"name": "campaign", "filter": Filter("type", "=", "campaign")},
}
RELATIONSHIP_TYPES = EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys()   # pragma: no cover
ENTERPRISE_COLLECTION_NAME = 'enterprise att&ck'                  # pragma: no cover
EXTRACT_TIMESTAMP_REGEX = r"\(([^()]+)\)"   # pragma: no cover
SERVER_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"    # pragma: no cover
DEFAULT_YEAR = datetime(1970, 1, 1)         # pragma: no cover

# disable warnings coming from taxii2client - https://github.com/OTRF/ATTACK-Python-Client/issues/43#issuecomment-1016581436
logging.getLogger("taxii2client.v21").setLevel(logging.ERROR)

# Disable insecure warnings
urllib3.disable_warnings()


class Client:

    def __init__(self, url, proxies, verify, tags: list | None = None,
                 tlp_color: str | None = None):
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.tags = tags if tags else []
        self.tlp_color = tlp_color
        self.server: Server
        self.api_root: list[ApiRoot]
        self.collections: list[Collection]
        self.tactic_name_to_mitre_id: dict[str, str] = {}

    def get_server(self):
        server_url = urljoin(self.base_url, '/taxii2/')
        self.server = Server(server_url, verify=self.verify, proxies=self.proxies)

    def get_roots(self):
        self.api_root = self.server.api_roots[0]

    def get_collections(self):
        self.collections = list(self.api_root.collections)  # type: ignore[attr-defined]
        demisto.debug(f'MA: found collections: {", ".join([collection.title for collection in self.collections])}')

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
        tlp = indicator_obj['fields']['tlp']
        if tlp != '':
            indicator_obj['fields']['trafficlightprotocol'] = tlp

        elif self.tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

        if item_type.lower() == "tactic":
            indicator_obj["value"] = f'{self.tactic_name_to_mitre_id[value]} - {value}'

        if item_type in ("Attack Pattern", "STIX Attack Pattern") and not mitre_item_json.get("x_mitre_is_subtechnique", None):
            tactics = []
            for tactic in mitre_item_json["kill_chain_phases"]:
                if tactic.get("kill_chain_name", "") != "mitre-attack":
                    continue

                else:
                    tactic_name = tactic["phase_name"].title().replace("-", " ").replace("And", "and")
                    tactic_mitre_id = self.tactic_name_to_mitre_id[tactic_name]
                    tactic = f'{tactic_mitre_id} - {tactic_name}'
                    tactics.append(
                        EntityRelationship(
                            name=EntityRelationship.Relationships.PART_OF,
                            entity_a=indicator_obj["value"],
                            entity_a_type=indicator_obj["type"],
                            entity_b=tactic,
                            entity_b_type="Tactic",
                        ).to_indicator()
                    )

            indicator_obj["relationships"] = tactics

        return indicator_obj

    def build_iterator(self,
                       create_relationships=False,
                       is_up_to_6_2=True,
                       limit: int = -1) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        """Retrieves indicators from the MITRE ATT&CK feed based on the filters defined in FILTER_OBJS.

        Returns:
            A tuple containing:
            - A list of objects, containing the indicators.
            - A list of relationship objects.
            - A dictionary mapping IDs to names.
            - A dictionary mapping MITRE IDs to MITRE names.
        """
        indicators: list[dict[str, Any]] = []
        mitre_id_list: set[str] = set()
        mitre_relationships_list: list[dict[str, Any]] = []
        id_to_name: dict[str, Any] = {}
        mitre_id_to_mitre_name: dict[str, Any] = {}
        counter = 0

        # For each collection
        for collection in self.collections:

            # fetch only enterprise objects
            if collection.title.lower() != ENTERPRISE_COLLECTION_NAME:
                continue

            # Stop when we have reached the limit defined
            if 0 < limit <= counter:
                break

            # Establish TAXII2 Collection instance
            collection_url = urljoin(self.base_url, f'api/v21/collections/{collection.id}/')
            collection_data = Collection(collection_url, verify=self.verify, proxies=self.proxies)

            # Supply the collection to TAXIICollection
            tc_source = TAXIICollectionSource(collection_data)

            for concept in FILTER_OBJS:
                if concept == "relationships" and not create_relationships:
                    demisto.debug('MA: Skipping relationships as create_relationships is False')
                    continue

                if 0 < limit <= counter:
                    break

                input_filter = FILTER_OBJS[concept]['filter']
                try:
                    demisto.debug(f'MA: Fetching data for {concept}')
                    mitre_data = tc_source.query(input_filter)

                except Exception as e:
                    demisto.debug(f'MA: Failed to fetch data for {concept} - {e}')
                    continue

                for mitre_item in mitre_data:
                    if 0 < limit <= counter:
                        break
                    if isinstance(mitre_item, dict):
                        # Extended STIX objects such as tactic are already in dict format
                        mitre_item_json = mitre_item

                    else:
                        mitre_item_json = json.loads(str(mitre_item))

                    if mitre_item_json.get('id') not in mitre_id_list:
                        value = str(mitre_item_json.get('name'))
                        item_type = get_item_type(mitre_item_json.get('type'), is_up_to_6_2)

                        if item_type.lower() == 'relationship':
                            if mitre_item_json.get('relationship_type') == 'revoked-by':
                                continue
                            mitre_relationships_list.append(mitre_item_json)

                        else:
                            if is_indicator_deprecated_or_revoked(mitre_item_json):
                                continue
                            id_to_name[mitre_item_json['id']] = value

                            if item_type == 'Tactic':
                                mitre_id = mitre_item_json['external_references'][0]['external_id']
                                self.tactic_name_to_mitre_id[value] = mitre_id

                            indicator_obj = self.create_indicator(item_type, value, mitre_item_json)
                            add_obj_to_mitre_id_to_mitre_name(mitre_id_to_mitre_name, mitre_item_json)
                            indicators.append(indicator_obj)
                            counter += 1
                        mitre_id_list.add(mitre_item_json['id'])

        return indicators, mitre_relationships_list, id_to_name, mitre_id_to_mitre_name


def add_obj_to_mitre_id_to_mitre_name(mitre_id_to_mitre_name, mitre_item_json) -> None:
    if mitre_item_json['type'] in ('attack-pattern', 'x-mitre-tactic'):
        mitre_id = [external.get('external_id') for external in mitre_item_json.get('external_references', [])
                    if external.get('source_name', '') == 'mitre-attack']
        if mitre_id:
            mitre_id_to_mitre_name[mitre_id[0]] = mitre_item_json.get('name')


def add_technique_prefix_to_sub_technique(indicators, id_to_name, mitre_id_to_mitre_name) -> None:
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
    return bool(indicator_json.get("x_mitre_deprecated") or indicator_json.get("revoked"))


def map_fields_by_type(indicator_type: str, indicator_json: dict) -> dict[str, Any]:
    """Maps indicator fields based on the indicator type.

    Args:
        indicator_type (str): The type of the indicator.
        indicator_json (dict): The JSON representation of the indicator.

    Returns:
        dict: A dictionary containing mapped fields for the indicator.
    """
    created = handle_multiple_dates_in_one_field('created', indicator_json.get('created'))  # type: ignore
    modified = handle_multiple_dates_in_one_field('modified', indicator_json.get('modified'))  # type: ignore

    kill_chain_phases_mitre = [chain.get('phase_name', '') for chain in indicator_json.get('kill_chain_phases', [])]
    kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) or phase for phase in kill_chain_phases_mitre]

    publications = []
    for external_reference in indicator_json.get('external_references', []):
        if external_reference.get('external_id'):
            continue
        url = external_reference.get('url', '')
        description = external_reference.get('description')
        time_stamp = extract_date_time_from_description(description)
        source_name = external_reference.get('source_name')
        publications.append({'link': url, 'title': description, 'source': source_name, 'timestamp': time_stamp})

    mitre_id = [external.get('external_id') for external in indicator_json.get('external_references', [])
                if external.get('source_name', '') == 'mitre-attack']
    mitre_id = mitre_id[0] if mitre_id else None

    tags = [mitre_id] if mitre_id else []
    if indicator_type in ['Tool', 'STIX Tool', 'Malware', 'STIX Malware']:
        tags.extend(indicator_json.get('labels', ''))

    tlp = STIX2XSOARParser.get_tlp(indicator_json)
    indicator_json['description'] = remove_citations(indicator_json.get('description', ''))

    generic_mapping_fields = {
        'stixid': indicator_json.get('id'),
        'firstseenbysource': created,
        'modified': modified,
        'publications': publications,
        'mitreid': mitre_id,
        'tags': tags,
        'tlp': tlp,
        'description': indicator_json['description'],
    }

    mapping_by_type = {
        "Attack Pattern": {
            'killchainphases': kill_chain_phases,
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "Intrusion Set": {
            'aliases': indicator_json.get('aliases')
        },
        "Threat Actor": {
            'aliases': indicator_json.get('aliases')
        },
        "Malware": {
            'aliases': indicator_json.get('x_mitre_aliases'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "Tool": {
            'aliases': indicator_json.get('x_mitre_aliases'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "Campaign": {
            'aliases': indicator_json.get('aliases')
        }
    }
    generic_mapping_fields.update(mapping_by_type.get(indicator_type, {}))  # type: ignore
    return generic_mapping_fields


def remove_citations(description: str) -> str:
    """
    Args:
        description (str): input description string can contain Citation parts.
        delimited by parenthesis.
        i.e (Citation ...)
    Returns:
        str: description string with no Citation parts.
    """
    return "".join(
        substring
        for substring in re.findall(r'\([^)]*\)|[^()]+', description)
        if 'Citation' not in substring
    )


def extract_date_time_from_description(description: str) -> str:
    """
    Extract the Datetime object from the description.
    In case of incomplete Datetime format, fill the missing component from the default format 1970-01-01T00:00:00.
    In any other case, return empty str.
    """
    date_time_result = ''
    if not description or 'Citation' in description or 'n.d' in description:
        return date_time_result
    matches = re.findall(EXTRACT_TIMESTAMP_REGEX, description)
    for match in matches:
        try:
            # In case there is only one of the Datetime component (day,month,year), return an empty str.
            int(match)
            continue
        except ValueError:
            pass
        if date_time_parsed := dateparser.parse(match, settings={'RELATIVE_BASE': DEFAULT_YEAR}):
            date_time_result = datetime.strftime(date_time_parsed, SERVER_DATE_FORMAT)
            break
    return date_time_result


def create_relationship_list(mitre_relationships_list, id_to_name) -> list[str]:
    """
    Create a list of relationship indicators from MITRE relationships.

    Args:
        mitre_relationships_list (list): A list of MITRE relationship objects.
        id_to_name (dict): A dictionary mapping MITRE IDs to their corresponding names.

    Returns:
        list: A list of relationship entities (in json format) created from the MITRE relationships.

    Note:
        This function filters out any relationships that couldn't be created
        (i.e., when create_relationship returns None).
    """
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
        demisto.debug(f"Unknown relationship name: {item_json.get('relationship_type')}")

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
    raw = args.get("raw") == "True"

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
            'HumanReadable': tableToMarkdown('MITRE ATT&CK v2 Indicators:', indicators[0], ['value', 'score', 'type']),
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {'MITRE.ATT&CK(val.value && val.value == obj.value)': indicators}
        }
    )


def show_feeds_command(client):
    feeds = []
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
    mitre_data = []
    for collection in client.collections:

        # fetch only enterprise data
        if collection.title.lower() != ENTERPRISE_COLLECTION_NAME:
            continue

        collection_url = urljoin(client.base_url, f'api/v21/collections/{collection.id}/')
        demisto.debug(f'MA: Trying to get mitre data from {collection_url} with filter {mitre_filter}')
        collection_data = Collection(collection_url, verify=client.verify, proxies=client.proxies)
        demisto.debug('MA: Getting collection source')
        tc_source = TAXIICollectionSource(collection_data)
        demisto.debug('MA: Querying the tc source')
        mitre_data += tc_source.query(mitre_filter)

    if mitre_data:
        demisto.debug('MA: Found mitre data')
        return mitre_data

    demisto.debug(f'MA: Did not found mitre data for {mitre_filter}')
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
        value=value,
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
    command_results: list[CommandResults] = []

    filter_by_type = [Filter('type', '=', 'attack-pattern')]
    mitre_data = get_mitre_data_by_filter(client, filter_by_type)

    mitre_names = argToList(args.get('attack_pattern'))
    for name in mitre_names:
        demisto.debug(f'MA: Getting info on {name}')
        if ':' not in name:  # not sub-technique
            attack_pattern = get_attack_pattern_by_name(mitre_data, name=name)
            demisto.debug(f'MA: Got {attack_pattern=}')
            if not attack_pattern:
                demisto.debug(f'MA: Did not found attack pattern value for name {name}')
                continue
            value = attack_pattern.get('name')

        else:
            all_name = name.split(':')
            parent = all_name[0]
            sub = all_name[1][1:]  # removes the space before the name of the sub-technique
            mitre_id = ''

            # get parent MITRE ID
            attack_pattern = get_attack_pattern_by_name(mitre_data, name=parent)
            demisto.debug(f'MA: Got {attack_pattern=}')
            if not attack_pattern:
                continue
            indicator_json = json.loads(str(attack_pattern))
            parent_mitre_id = [external.get('external_id') for external in
                               indicator_json.get('external_references', [])
                               if external.get('source_name', '') == 'mitre-attack']
            parent_mitre_id = parent_mitre_id[0]
            parent_name = indicator_json['name']

            # get sub MITRE ID
            attack_pattern = get_attack_pattern_by_name(mitre_data, name=sub)
            demisto.debug(f'MA: Got {attack_pattern=} for {sub=}')
            if not attack_pattern:
                continue
            indicator_json = json.loads(str(attack_pattern))
            sub_mitre_id = [external.get('external_id') for external in
                            indicator_json.get('external_references', [])
                            if external.get('source_name', '') == 'mitre-attack']
            sub_mitre_id = sub_mitre_id[0]
            sub_mitre_id = sub_mitre_id[5:]

            mitre_id = f'{parent_mitre_id}{sub_mitre_id}'
            attack_pattern = list(filter(lambda attack_pattern_obj:
                                         filter_attack_pattern_object_by_attack_id(mitre_id, attack_pattern_obj),
                                         mitre_data))
            demisto.debug(f'MA: Got {attack_pattern=} for {mitre_id=}')
            if not attack_pattern:
                continue

            attack_pattern = attack_pattern[0]
            value = f'{parent_name}: {attack_pattern.get("name")}'

        attack_obj = map_fields_by_type('Attack Pattern', json.loads(str(attack_pattern)))
        custom_fields = attack_obj or {}
        score = INDICATOR_TYPE_TO_SCORE.get('Attack Pattern')
        md = f"## MITRE ATTACK \n ## Name: {value} - ID: " \
             f"{attack_obj.get('mitreid')} \n {custom_fields.get('description', '')}"
        command_results.append(build_command_result(value, score, md, attack_obj))

    if not command_results:
        return CommandResults(readable_output=f'MITRE ATTACK Attack Patterns values: '
                                              f'No Attack Patterns found for {mitre_names} in the Enterprise collection.')

    return command_results


def get_attack_pattern_by_name(mitre_data, name):
    """
    Filter attack pattern objects by the attack name

    Returns:
        The attack pattern object with the name provided, if there is such one.
    """
    attack_pattern = [attack_pattern_obj
                      for attack_pattern_obj in mitre_data
                      if (attack_pattern_obj.get('name') == name)]
    return attack_pattern[0] if attack_pattern else {}


def filter_attack_pattern_object_by_attack_id(attack_id: str, attack_pattern_object):
    """Filter attach pattern objects by the attack id

    Returns:
        True if the external_id matches the attack_id, else False
    """
    external_references_list = attack_pattern_object.get('external_references', [])
    return any(external_reference.get("external_id", "") == attack_id for external_reference in external_references_list)


def get_mitre_value_from_id(client, args):
    attack_ids = argToList(args.get('attack_ids', []))

    attack_values = []
    filter_by_type = [Filter('type', '=', 'attack-pattern')]
    attack_pattern_objects = get_mitre_data_by_filter(client, filter_by_type)

    if attack_pattern_objects:
        for attack_id in attack_ids:
            attack_pattern = list(filter(lambda attack_pattern_obj:
                                         filter_attack_pattern_object_by_attack_id(attack_id,
                                                                                   attack_pattern_obj), attack_pattern_objects))
            if not attack_pattern:
                demisto.debug(f'MA: Did not found attack pattern value for ID {attack_id}')
                continue

            attack_pattern_name = attack_pattern[0]['name']

            if attack_pattern_name and len(attack_id) > 5:  # sub-technique
                sub_technique_attack_id = attack_id[:5]
                parent_object = list(filter(lambda attack_pattern_obj:
                                            filter_attack_pattern_object_by_attack_id(sub_technique_attack_id,
                                                                                      attack_pattern_obj),
                                            attack_pattern_objects))
                parent_name = parent_object[0]['name']

                attack_pattern_name = f'{parent_name}: {attack_pattern_name}'

            if attack_pattern_name:
                if not is_indicator_deprecated_or_revoked(attack_pattern[0]):
                    attack_values.append({'id': attack_id, 'value': attack_pattern_name})
                else:
                    attack_values.append({'id': attack_id, 'value': ''})

    if attack_values:
        return CommandResults(
            outputs=attack_values,
            outputs_key_field='id',
            outputs_prefix='MITREATTACK',
            readable_output=tableToMarkdown('MITRE ATTACK Attack Patterns values:', attack_values)
        )

    return CommandResults(readable_output=f'MITRE ATTACK Attack Patterns values: '
                                          f'No Attack Patterns found for {attack_ids} in the Enterprise collection.')


def main():
    params = demisto.params()
    args = demisto.args()
    url = 'https://attack-taxii.mitre.org'
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)
    tags = argToList(params.get('feedTags', []))
    tlp_color = params.get('tlp_color')
    create_relationships = argToBoolean(params.get('create_relationships', True))
    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    if params.get('switch_intrusion_set_to_threat_actor', False):
        MITRE_TYPE_TO_DEMISTO_TYPE['intrusion-set'] = ThreatIntel.ObjectsNames.THREAT_ACTOR

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
            for index, iter_ in enumerate(batch(indicators, batch_size=2000)):
                if len(indicators) < 2000:
                    demisto.debug(f'Uploading indicators {len(indicators)} / {len(indicators)}')
                else:
                    demisto.debug(f'Uploading indicators {index*2000} / {len(indicators)}')
                demisto.createIndicators(iter_)

    # Log exceptions
    except requests.exceptions.ConnectTimeout as exception:
        err_msg = 'Connection Timeout Error - potential reason might be that the server is not accessible from your host.'
        return_error(err_msg, exception)
    except requests.exceptions.SSLError as exception:
        # in case the "Trust any certificate" is already checked
        if not verify_certificate:
            return_error(str(exception), exception)
        err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                  ' the integration configuration.'
        return_error(err_msg, exception)
    except requests.exceptions.ProxyError as exception:
        err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                  ' selected, try clearing the checkbox.'
        return_error(err_msg, exception)
    except requests.exceptions.ConnectionError as exception:
        # Get originating Exception in Exception chain
        error_class = str(exception.__class__)
        err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
        err_msg = 'Verify that you have access to the server from your host.' \
                  f'\nError Type: {err_type}\nError Number: [{exception.errno}]\nMessage: {exception.strerror}\n' \

        return_error(err_msg, exception)
    except Exception as exception:
        return_error(str(exception), exception)


from TAXII2ApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
