import demistomock as demisto
from CommonServerPython import *

from typing import List, Dict, Set, Optional
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Server, Collection, ApiRoot

''' CONSTANT VARIABLES '''

# The field mapping here will determine how the fields
# are mapped into the indicator. Generally, fields of type
# "list" will be joined with a "\n". Types of "dict" and
# "str" will be mapped as is.
MITRE_FIELD_MAPPING = {
    "mitrealiases": {"name": "aliases", "type": "list"},
    "mitrecontributors": {"name": "x_mitre_contributors", "type": "list"},
    "mitredatasources": {"name": "x_mitre_data_sources", "type": "str"},
    "mitredefensebypassed": {"name": "x_mitre_defense_bypassed", "type": "list"},
    "mitredescription": {"name": "description", "type": "str"},
    "mitredetection": {"name": "x_mitre_detection", "type": "str"},
    "mitreextendedaliases": {"name": "x_mitre_aliases", "type": "list"},
    "mitreexternalreferences": {"name": "external_references", "type": "dict"},
    "mitreid": {"name": "id", "type": "str"},
    "mitreimpacttype": {"name": "x_mitre_impact_type", "type": "list"},
    "mitrekillchainphases": {"name": "kill_chain_phases", "type": "dict"},
    "mitrelabels": {"name": "labels", "type": "list"},
    "mitrename": {"name": "name", "type": "str"},
    "mitrepermissionsrequired": {"name": "x_mitre_permissions_required", "type": "list"},
    "mitreplatforms": {"name": "x_mitre_platforms", "type": "dict"},
    "mitresystemrequirements": {"name": "x_mitre_system_requirements", "type": "list"},
    "mitreversion": {"name": "x_mitre_version", "type": "str"},
    "mitretype": {"name": "type", "type": "str"},
    "mitrecreated": {"name": "created", "type": "str"},
    "mitremodified": {"name": "modified", "type": "str"}
}

MITRE_TYPE_TO_DEMISTO_TYPE = {
    "attack-pattern": "STIX Attack Pattern",
    "course-of-action": "Course of Action",
    "intrusion-set": "Intrusion Set",
    "malware": "STIX Malware",
    "tool": "STIX Tool",
    "relationship": "Relationship"
}

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:

    def __init__(self, url, proxies, verify, include_apt, reputation, tags: list = None,
                 tlp_color: Optional[str] = None):
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.include_apt = include_apt
        self.indicatorType = "MITRE ATT&CK"
        self.reputation = 0
        self.tags = [] if tags is None else tags
        self.tlp_color = tlp_color
        if reputation == 'Good':
            self.reputation = 0
        elif reputation == 'Suspicious':
            self.reputation = 2
        elif reputation == 'Malicious':
            self.reputation = 3
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

    def build_iterator(self, limit: int = -1) -> List:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        indicators: List[Dict] = list()
        mitre_id_list: Set[str] = set()
        relationships_list = []
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

            filter_objs = {
                "Technique": {"name": "attack-pattern", "filter": Filter("type", "=", "attack-pattern")},
                "Mitigation": {"name": "course-of-action", "filter": Filter("type", "=", "course-of-action")},
                "Group": {"name": "intrusion-set", "filter": Filter("type", "=", "intrusion-set")},
                "Malware": {"name": "malware", "filter": Filter("type", "=", "malware")},
                "Tool": {"name": "tool", "filter": Filter("type", "=", "tool")},
                "relationships": {"name": "relationships", "filter": Filter("type", "=", "relationship")},
            }

            for concept in filter_objs:
                if 0 < limit <= counter:
                    break

                input_filter = filter_objs[concept]['filter']
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
                        indicator_type = MITRE_TYPE_TO_DEMISTO_TYPE.get(mitre_item_json.get('type'))

                        if indicator_type == 'Relationship':
                            relationships_list.append(create_relationship(mitre_item_json))

                        else:
                            indicator_obj = {
                                "value": value,
                                "score": self.reputation,
                                "type": indicator_type,
                                "rawJSON": mitre_item_json,
                                "fields": map_fields_by_type(indicator_type, mitre_item_json)
                            }

                            indicator_obj['fields']['tags'] = self.tags
                            if self.tlp_color:
                                indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

                            indicators.append(indicator_obj)
                            counter += 1
                        mitre_id_list.add(mitre_item_json.get('id'))

        if indicators:
            indicators[0]['relationships'] = ['relationships_list']  # todo

        return indicators


def map_fields_by_type(indicator_type: str, indicator_json: dict):
    created = handle_multiple_dates_in_one_field('created', indicator_json.get('created'))
    modified = handle_multiple_dates_in_one_field('modified', indicator_json.get('modified'))
    tactics = [tactic.get('phase_name') for tactic in indicator_json.get('kill_chain_phases', {})]
    external_references_urls = [url.get('url') for url in indicator_json.get('external_references', {})]
    external_references_descriptions = [des.get('description') for des in indicator_json.get('external_references', {})]

    generic_mapping_fields = {
        'stixid': indicator_json.get('id'),
        'firstseenbysource': created,  # firstseenbysource?
        'modified': modified,
        'value': indicator_json.get('name'),  # already exist
        'description': indicator_json.get('description'),
        'communitynotes': external_references_urls,  # grid
        # 'communitynotes': external_references_descriptions, # duplicates
    }
    mapping_by_type = {
        "STIX Attack Pattern": {
            'mitretactics': tactics,  # string / list
            'operatingsystem': indicator_json.get('x_mitre_platforms')  # operatingsystemref ? list?
        },
        "Intrusion Set": {
            'stixaliases': indicator_json.get('aliases')  # stix?
        },
        "STIX Malware": {
            'tags': indicator_json.get('labels'),  # tags duplicate?
            'stixaliases': indicator_json.get('x_mitre_aliases'),  # stix?
            'operatingsystem': indicator_json.get('x_mitre_platforms')  # operatingsystemref ? list?

        },
        "STIX Tool": {
            'tags': indicator_json.get('labels'),  # tags duplicate?
            'stixaliases': indicator_json.get('x_mitre_aliases'),  # stix?
            'operatingsystem': indicator_json.get('x_mitre_platforms')  # operatingsystemref ? list?
        }
    }

    generic_mapping_fields.update(mapping_by_type.get(indicator_type))
    return generic_mapping_fields


def create_relationship(item_json):
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

    return EntityRelation(name=item_json.get('relationship_type'),
                          entity_a=item_json.get('source_ref'),
                          entity_a_type=a_type,
                          entity_b=item_json.get('target_ref'),
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
    if client.collections:
        demisto.results('ok')
    else:
        return_error('Could not connect to server')


def fetch_indicators(client):
    indicators = client.build_iterator()
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
            'HumanReadable': tableToMarkdown('MITRE ATT&CK Indicators:', indicators, ['value', 'score', 'type']),
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


def main():
    params = demisto.params()
    args = demisto.args()
    url = 'https://cti-taxii.mitre.org'
    include_apt = params.get('includeAPT')
    reputation = params.get('feedReputation', 'None')
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)
    tags = argToList(params.get('feedTags', []))
    tlp_color = params.get('tlp_color')
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url, proxies, verify_certificate, include_apt, reputation, tags, tlp_color)
        client.initialise()
        commands = {
            'mitre-get-indicators': get_indicators_command,
            'mitre-show-feeds': show_feeds_command,
        }

        if demisto.command() == 'test-module':
            test_module(client)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            commands[command](client, args)

    # Log exceptions
    except Exception as e:
        return_error(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
