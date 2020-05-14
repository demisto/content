import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import List, Dict, Set
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection, ApiRoot

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:

    def __init__(self, url, collection, api_key, proxies, verify):#, include_apt, reputation):
        self.base_url = url
        self.collection = collection
        self.api_key = api_key
        self.proxies = proxies
        self.verify = verify

        # session = requests.Session()
        # session.verify = verify
        # session.headers = {
        #     'Authorization': f'Token {self.api_key}',
        #     'Accept': 'application/vnd.oasis.taxii+json; version=2.0'
        # }
        # r1 = session.get(self.base_url)
        # demisto.log(str(r1))
        # demisto.log(str(r1.headers))
        # demisto.log(str(r1.raw))
        # demisto.log(str(r1.text))
        # demisto.log(str(dir(r1)))

        self.collection_server = Collection(f'{url}collections/{self.collection}', verify=self.verify,
                                            proxies=self.proxies, password=self.api_key)
        demisto.log(str(self.server.api_roots))
        demisto.log(str(self.server.description))
        demisto.log(str(dir(self.server)))
        self.api_root: List[ApiRoot]
        self.collections: List[Collection]


        # self.server = Server(url, verify=self.verify, proxies=self.proxies,
        #                      password={'Authorization': f'Token {self.api_key}'})
        # demisto.log(str(self.server.api_roots))
        # demisto.log(str(self.server.description))
        # demisto.log(str(dir(self.server)))
        # self.api_root: List[ApiRoot]
        # self.collections: List[Collection]

    # def get_server(self):
    #     server_url = urljoin(self.base_url, '/taxii/')
    #     self.server = Server(server_url, verify=self.verify, proxies=self.proxies)
    #
    # def get_roots(self):
    #     self.api_root = self.server.api_roots[0]
    #
    # def get_collections(self):
    #     self.collections = [x for x in self.api_root.collections]  # type: ignore[attr-defined]
    #
    # def initialise(self):
    #     self.get_server()
    #     self.get_roots()
    #     self.get_collections()

    def build_iterator(self, limit: int = -1) -> List:

        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """

        indicators: List[Dict] = list()
        mitre_id_list: Set[str] = set()
        indicator_values_list: Set[str] = set()
        external_refs: Set[str] = set()
        counter = 0

        # For each collection
        for collection in self.collections:

            # Stop when we have reached the limit defined
            if 0 < limit <= counter:
                break

            # Establish TAXII2 Collection instance
            collection_url = urljoin(self.base_url, f'stix/collections/{collection.id}/')
            collection_data = Collection(collection_url)

            # Supply the collection to TAXIICollection
            tc_source = TAXIICollectionSource(collection_data)

            # Create filters to retrieve content
            filter_objs = {
                "Technique": {"name": "attack-pattern", "filter": Filter("type", "=", "attack-pattern")},
                "Mitigation": {"name": "course-of-action", "filter": Filter("type", "=", "course-of-action")},
                "Group": {"name": "intrusion-set", "filter": Filter("type", "=", "intrusion-set")},
                "Malware": {"name": "malware", "filter": Filter("type", "=", "malware")},
                "Tool": {"name": "tool", "filter": Filter("type", "=", "tool")},
            }

            # Retrieve content
            for concept in filter_objs:

                # Stop when we have reached the limit defined
                if 0 < limit <= counter:
                    break

                input_filter = filter_objs[concept]['filter']
                try:
                    mitre_data = tc_source.query(input_filter)
                except Exception:
                    continue

                # For each item in the MITRE list, add an indicator to the indicators list
                for mitreItem in mitre_data:

                    # Stop when we have reached the limit defined
                    if 0 < limit <= counter:
                        break

                    mitre_item_json = json.loads(str(mitreItem))
                    value = None

                    # Try and map a friendly name to the value before the real ID
                    try:
                        externals = [x['external_id'] for x in mitre_item_json.get('external_references', []) if
                                     x['source_name'] == 'mitre-attack' and x['external_id']]
                        value = externals[0]
                    except Exception:
                        value = None
                    if not value:
                        value = mitre_item_json.get('x_mitre_old_attack_id', None)
                    if not value:
                        value = mitre_item_json.get('id')

                    if mitre_item_json.get('id') not in mitre_id_list:

                        # If the indicator already exists, then append the new data
                        # to the existing indicator.
                        if value in indicator_values_list:

                            # Append data to the original item
                            original_item = [x for x in indicators if x.get('value') == value][0]
                            if original_item['rawJSON'].get('id', None):
                                try:
                                    original_item['rawJSON']['id'] += f"\n{mitre_item_json.get('id', '')}"
                                except Exception:
                                    pass
                            if original_item['rawJSON'].get('created', None):
                                try:
                                    original_item['rawJSON']['created'] += f"\n{mitre_item_json.get('created', '')}"
                                except Exception:
                                    pass
                            if original_item['rawJSON'].get('modified', None):
                                try:
                                    original_item['rawJSON']['modified'] += f"\n{mitre_item_json.get('modified', '')}"
                                except Exception:
                                    pass
                            if original_item['rawJSON'].get('description', None):
                                try:
                                    if not original_item['rawJSON'].get('description').startswith("###"):
                                        original_item['rawJSON']['description'] = \
                                            f"### {original_item['rawJSON'].get('type')}\n" \
                                            f"{original_item['rawJSON']['description']}"
                                    original_item['rawJSON']['description'] += \
                                        f"\n\n_____\n\n### {mitre_item_json.get('type')}\n" \
                                        f"{mitre_item_json.get('description', '')}"
                                except Exception:
                                    pass
                            if original_item['rawJSON'].get('external_references', None):
                                try:
                                    original_item['rawJSON']['external_references'].extend(
                                        mitre_item_json.get('external_references', [])
                                    )
                                except Exception:
                                    pass
                            if original_item['rawJSON'].get('kill_chain_phases', None):
                                try:
                                    original_item['rawJSON']['kill_chain_phases'].extend(
                                        mitre_item_json.get('kill_chain_phases', [])
                                    )
                                except Exception:
                                    pass
                            if original_item['rawJSON'].get('aliases', None):
                                try:
                                    original_item['rawJSON']['aliases'].extend(
                                        mitre_item_json.get('aliases', [])
                                    )
                                except Exception:
                                    pass

                        else:
                            indicators.append({
                                "value": value,
                                "score": self.reputation,
                                "type": "MITRE ATT&CK",
                                "rawJSON": mitre_item_json,
                            })
                            indicator_values_list.add(value)
                            counter += 1
                        mitre_id_list.add(mitre_item_json.get('id'))

                        # Create a duplicate indicator using the "external_id" from the
                        # original indicator, if the user has selected "includeAPT" as True
                        if self.include_apt:
                            ext_refs = [x.get('external_id') for x in mitre_item_json.get('external_references')
                                        if x.get('external_id') and x.get('source_name') != "mitre-attack"]
                            for x in ext_refs:
                                if x not in external_refs:
                                    indicators.append({
                                        "value": x,
                                        "score": self.reputation,
                                        "type": "MITRE ATT&CK",
                                        "rawJSON": mitre_item_json,
                                    })
                                    external_refs.add(x)

        # Finally, map all the fields from the indicator
        # rawjson to the fields in the indicator
        for indicator in indicators:
            indicator['fields'] = dict()
            for field, value in mitre_field_mapping.items():
                try:
                    # Try and map the field
                    value_type = value['type']
                    value_name = value['name']
                    if value_type == "list":
                        indicator['fields'][field] = "\n".join(indicator['rawJSON'][value_name])
                    else:
                        indicator['fields'][field] = indicator['rawJSON'][value_name]
                except KeyError:
                    # If the field does not exist in the indicator
                    # then move on
                    pass
                except Exception as err:
                    demisto.error(f"Error when mapping Mitre Fields - {err}")
        return indicators


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


def main():
    params = demisto.params()
    args = demisto.args()
    url = 'https://stix2.unit42.org/taxii/'
    collection = '5ac266d8-de48-3d6b-83f1-c4e4047d6e44'
    api_key = str(params.get('api_key', ''))
    # include_apt = params.get('includeAPT')
    # reputation = params.get('feedReputation', 'None')
    proxies = handle_proxy()
    verify = not params.get('insecure', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url, collection, api_key, proxies, verify)#, include_apt, reputation)
        # client.initialise()
        commands = {
            'unit42-get-indicators': get_indicators_command,
        }

        if demisto.command() == 'test-module':
            test_module(client)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            commands[command](client, args)

    except Exception as err:
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
