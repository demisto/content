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
mitre_field_mapping = {
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
            collection_data = Collection(collection_url, verify=self.verify, proxies=self.proxies)

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
                            indicator_obj = {
                                "value": value,
                                "score": self.reputation,
                                "type": "MITRE ATT&CK",
                                "rawJSON": mitre_item_json,
                                "fields": {
                                    "tags": self.tags,
                                }
                            }

                            if self.tlp_color:
                                indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

                            indicators.append(indicator_obj)
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
                                    indicator_obj = {
                                        "value": x,
                                        "score": self.reputation,
                                        "type": "MITRE ATT&CK",
                                        "rawJSON": mitre_item_json,
                                        "fields": {
                                            "tags": self.tags,
                                        }
                                    }

                                    if self.tlp_color:
                                        indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

                                    indicators.append(indicator_obj)
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
                        if value_name in ['created', 'modified']:
                            indicator['fields'][field] = handle_multiple_dates_in_one_field(
                                value_name, indicator['rawJSON'][value_name]
                            )

                        else:
                            indicator['fields'][field] = indicator['rawJSON'][value_name]

                except KeyError:
                    # If the field does not exist in the indicator
                    # then move on
                    pass
                except Exception as err:
                    demisto.error(f"Error when mapping Mitre Fields - {err}")
        return indicators


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


def show_feeds_command(client, args):
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


def search_command(client, args):
    search = args.get('search')
    demisto_urls = demisto.demistoUrls()
    indicator_url = demisto_urls.get('server') + "/#/indicator/"
    sensitive = True if args.get('casesensitive') == 'True' else False
    return_list_md: List[Dict] = list()
    entries = list()
    all_indicators: List[Dict] = list()
    page = 0
    size = 1000
    raw_data = demisto.searchIndicators(query=f'type:"{client.indicatorType}"', page=page, size=size)
    while len(raw_data.get('iocs', [])) > 0:
        all_indicators.extend(raw_data.get('iocs', []))
        page += 1
        raw_data = demisto.searchIndicators(query=f'type:"{client.indicatorType}"', page=page, size=size)

    for indicator in all_indicators:
        custom_fields = indicator.get('CustomFields', {})
        for v in custom_fields.values():
            if type(v) != str:
                continue
            if sensitive:
                if search in v and custom_fields.get('mitrename') not in [x.get('mitrename') for x in return_list_md]:
                    return_list_md.append({
                        'mitrename': custom_fields.get('mitrename'),
                        'Name': f"[{custom_fields.get('mitrename', '')}]({urljoin(indicator_url, indicator.get('id'))})",
                    })
                    entries.append({
                        "id": f"{indicator.get('id')}",
                        "value": f"{indicator.get('value')}"
                    })
                    break
            else:
                if search.lower() in v.lower() \
                        and custom_fields.get('mitrename') not in [x.get('mitrename') for x in return_list_md]:
                    return_list_md.append({
                        'mitrename': custom_fields.get('mitrename'),
                        'Name': f"[{custom_fields.get('mitrename', '')}]({urljoin(indicator_url, indicator.get('id'))})",
                    })
                    entries.append({
                        "id": f"{indicator.get('id')}",
                        "value": f"{indicator.get('value')}"
                    })
                    break
    return_list_md = sorted(return_list_md, key=lambda name: name['mitrename'])
    return_list_md = [{"Name": x.get('Name')} for x in return_list_md]

    md = tableToMarkdown('MITRE Indicator search:', return_list_md)
    ec = {'indicators(val.id && val.id == obj.id)': entries}
    return_outputs(md, ec, return_list_md)


def reputation_command(client, args):
    input_indicator = args.get('indicator')
    demisto_urls = demisto.demistoUrls()
    indicator_url = demisto_urls.get('server') + "/#/indicator/"
    all_indicators: List[Dict] = list()
    page = 0
    size = 1000
    raw_data: dict = demisto.searchIndicators(query=f'type:"{client.indicatorType}" value:{input_indicator}',
                                              page=page, size=size)
    if raw_data.get('total') == 0:
        md = 'No indicators found.'
        ec = {}
    else:
        while len(raw_data.get('iocs', [])) > 0:
            all_indicators.extend(raw_data.get('iocs', []))
            page += 1
            raw_data = demisto.searchIndicators(query=f'type:"{client.indicatorType}" value:{input_indicator}',
                                                page=page, size=size)
        for indicator in all_indicators:
            custom_fields = indicator.get('CustomFields', {})

            score = indicator.get('score')
            value = indicator.get('value')
            indicator_id = indicator.get('id')
            url = indicator_url + indicator_id
            md = f"## {[value]}({url}):\n {custom_fields.get('mitredescription', '')}"
            ec = {
                "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor && val.Vendor == obj.Vendor)": {
                    "Indicator": value,
                    "Type": client.indicatorType,
                    "Vendor": "MITRE ATT&CK",
                    "Score": score
                },
                "MITRE.ATT&CK(val.value && val.value = obj.value)": {
                    'value': value,
                    'indicatorid': indicator_id,
                    'customFields': custom_fields
                }
            }
        raw_data = {'indicators': all_indicators}

    return_outputs(md, ec, raw_data)


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
            'mitre-search-indicators': search_command,
            'mitre-reputation': reputation_command,
        }

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
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
