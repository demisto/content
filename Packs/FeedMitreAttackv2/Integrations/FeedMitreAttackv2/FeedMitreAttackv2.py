import demistomock as demisto
from CommonServerPython import *

from typing import List, Dict, Set, Optional
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Server, Collection, ApiRoot

''' CONSTANT VARIABLES '''

MITRE_TYPE_TO_DEMISTO_TYPE = {
    "attack-pattern": "STIX Attack Pattern",
    "course-of-action": "Course of Action",
    "intrusion-set": "Intrusion Set",
    "malware": "STIX Malware",
    "tool": "STIX Tool",
    "relationship": "Relationship"
}

INDICATOR_TYPE_TO_SCORE = {
    "Intrusion Set": 3,
    "STIX Attack Pattern": 2,
    "Course of Action": 0,
    "Malware": 3,
    "Tool": 2
}

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

    def build_iterator(self, create_relationships=False, limit: int = -1) -> List:
        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        indicators: List[Dict] = list()
        mitre_id_list: Set[str] = set()
        relationships_list = []
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
                        indicator_type = MITRE_TYPE_TO_DEMISTO_TYPE.get(mitre_item_json.get('type'))  # type: ignore

                        if indicator_type == 'Relationship' and create_relationships:
                            if mitre_item_json.get('relationship_type') == 'revoked-by':
                                continue
                            relationships_list.append(create_relationship(mitre_item_json, id_to_name).to_indicator())

                        else:
                            if is_indicator_deprecated_or_revoked(mitre_item_json):
                                continue
                            id_to_name[mitre_item_json.get('id')] = value
                            indicator_score = INDICATOR_TYPE_TO_SCORE.get(indicator_type)  # type: ignore
                            indicator_obj = {
                                "value": value,
                                "score": indicator_score,
                                "type": indicator_type,
                                "rawJSON": mitre_item_json,
                                "fields": map_fields_by_type(indicator_type, mitre_item_json)  # type: ignore
                            }

                            if indicator_obj['fields'].get('tags'):
                                indicator_obj['fields']['tags'].append(self.tags) if self.tags else None
                            else:
                                indicator_obj['fields'].update({"tags": self.tags}) if self.tags else None

                            if self.tlp_color:
                                indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

                            indicators.append(indicator_obj)
                            counter += 1
                        mitre_id_list.add(mitre_item_json.get('id'))

        if create_relationships and limit > 0:
            dummy_indicator_for_relations = {
                "value": "$$DummyIndicator$$",
                "relationships": relationships_list
            }

            indicators.append(dummy_indicator_for_relations)

        return indicators


def is_indicator_deprecated_or_revoked(indicator_json):
    return True if indicator_json.get("x_mitre_deprecated") or indicator_json.get("revoked") else False


def map_fields_by_type(indicator_type: str, indicator_json: dict):
    created = handle_multiple_dates_in_one_field('created', indicator_json.get('created'))  # type: ignore
    modified = handle_multiple_dates_in_one_field('modified', indicator_json.get('modified'))  # type: ignore

    publications = []
    for external_reference in indicator_json.get('external_references', []):
        if external_reference.get('external_id'):
            continue
        url = external_reference.get('url')
        description = external_reference.get('description')
        publications.append({'Link': url, 'Title': description})

    mitre_id = [external.get('external_id') for external in indicator_json.get('external_references', [])
                if external.get('source_name', '') == 'mitre-attack']
    mitre_id = mitre_id[0] if mitre_id else None

    generic_mapping_fields = {
        'stixid': indicator_json.get('id'),
        'firstseenbysource': created,
        'modified': modified,
        'description': indicator_json.get('description'),
        'publications': publications,
    }

    mapping_by_type = {
        "STIX Attack Pattern": {
            'mitreid': mitre_id,
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        },
        "Intrusion Set": {
            'aliases': indicator_json.get('aliases')
        },
        "STIX Malware": {
            'tags': indicator_json.get('labels'),
            'aliases': indicator_json.get('x_mitre_aliases'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')

        },
        "STIX Tool": {
            'tags': indicator_json.get('labels'),
            'aliases': indicator_json.get('x_mitre_aliases'),
            'operatingsystemrefs': indicator_json.get('x_mitre_platforms')
        }
    }
    generic_mapping_fields.update(mapping_by_type.get(indicator_type, {}))
    return generic_mapping_fields


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

    return EntityRelation(name=item_json.get('relationship_type'),
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
    if client.collections:
        demisto.results('ok')
    else:
        return_error('Could not connect to server')


def fetch_indicators(client, create_relationships):
    indicators = client.build_iterator(create_relationships)
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
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)
    tags = argToList(params.get('feedTags', []))
    tlp_color = params.get('tlp_color')
    create_relationships = params.get('create_relationships')
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url, proxies, verify_certificate, tags, tlp_color)
        client.initialise()

        if demisto.command() == 'mitre-get-indicators':
            get_indicators_command(client, args)

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
