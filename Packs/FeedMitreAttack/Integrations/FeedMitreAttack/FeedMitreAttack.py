import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import List
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection

''' CONSTANT VARIABLES '''

# The field mapping here will determine how the fields
# are mapped into the indicator. Generally, fields of type
# "list" will be joined with a "\n". Types of "dict" and
# "str" will be mapped as is.
mitreFieldMapping = {
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
}


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:

    def __init__(self, url, proxies, verify, includeAPT):
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.server = None
        self.includeAPT = includeAPT
        self.indicatorType = "MITRE ATT&CK"
        self.reputation = 0
        self.api_root = None
        self.collections = None

    def getServer(self):
        serverURL = urljoin(self.base_url, '/taxii/')
        self.server = Server(serverURL, verify=self.verify, proxies=self.proxies)

    def getRoots(self):
        self.api_root = self.server.api_roots[0]

    def getCollections(self):
        self.collections = [x for x in self.api_root.collections]

    def initialise(self):
        self.getServer()
        self.getRoots()
        self.getCollections()

    def build_iterator(self, limit: int = -1) -> List:

        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """

        indicators = list()
        mitreIDList = set()
        indicatorValuesList = set()
        externalRefs = set()
        counter = 0

        # For each collection
        for collection in self.collections:

            # Stop when we have reached the limit defined
            if limit > 0 and counter >= limit:
                break

            # Establish TAXII2 Collection instance
            collectionURL = urljoin(self.base_url, f'stix/collections/{collection.id}/')
            collectionData = Collection(collectionURL)

            # Supply the collection to TAXIICollection
            tc_source = TAXIICollectionSource(collectionData)

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
                if limit > 0 and counter >= limit:
                    break

                inputFilter = filter_objs[concept]['filter']
                try:
                    mitreData = tc_source.query(inputFilter)
                except Exception:
                    continue

                # For each item in the MITRE list, add an indicator to the indicators list
                for mitreItem in mitreData:

                    # Stop when we have reached the limit defined
                    if limit > 0 and counter >= limit:
                        break

                    mitreItemJSON = json.loads(str(mitreItem))
                    value = None

                    # Try and map a friendly name to the value before the real ID
                    try:
                        externals = [x['external_id'] for x in mitreItemJSON.get('external_references', []) if
                                     x['source_name'] == 'mitre-attack' and x['external_id']]
                        value = externals[0]
                    except Exception:
                        value = None
                    if not value:
                        value = mitreItemJSON.get('x_mitre_old_attack_id', None)
                    if not value:
                        value = mitreItemJSON.get('id')

                    if mitreItemJSON.get('id') not in mitreIDList:

                        # If the indicator already exists, then append the new data
                        # to the existing indicator.
                        if value in indicatorValuesList:

                            # Append data to the original item
                            originalItem = [x for x in indicators if x.get('value') == value][0]
                            if originalItem['rawJSON'].get('id', None):
                                try:
                                    originalItem['rawJSON']['id'] += f"\n{mitreItemJSON.get('id', '')}"
                                except Exception:
                                    pass
                            if originalItem['rawJSON'].get('created', None):
                                try:
                                    originalItem['rawJSON']['created'] += f"\n{mitreItemJSON.get('created', '')}"
                                except Exception:
                                    pass
                            if originalItem['rawJSON'].get('modified', None):
                                try:
                                    originalItem['rawJSON']['modified'] += f"\n{mitreItemJSON.get('modified', '')}"
                                except Exception:
                                    pass
                            if originalItem['rawJSON'].get('description', None):
                                try:
                                    if not originalItem['rawJSON'].get('description').startswith("###"):
                                        originalItem['rawJSON']['description'] =\
                                            f"### {originalItem['rawJSON'].get('type')}\n{originalItem['rawJSON']['description']}"
                                    originalItem['rawJSON']['description'] +=\
                                        f"\n\n_____\n\n### {mitreItemJSON.get('type')}\n{mitreItemJSON.get('description', '')}"
                                except Exception:
                                    pass
                            if originalItem['rawJSON'].get('external_references', None):
                                try:
                                    originalItem['rawJSON']['external_references'].extend(
                                        mitreItemJSON.get('external_references', [])
                                    )
                                except Exception:
                                    pass
                            if originalItem['rawJSON'].get('kill_chain_phases', None):
                                try:
                                    originalItem['rawJSON']['kill_chain_phases'].extend(
                                        mitreItemJSON.get('kill_chain_phases', [])
                                    )
                                except Exception:
                                    pass
                            if originalItem['rawJSON'].get('aliases', None):
                                try:
                                    originalItem['rawJSON']['aliases'].extend(
                                        mitreItemJSON.get('aliases', [])
                                    )
                                except Exception:
                                    pass

                        else:
                            indicators.append({
                                "value": value,
                                "score": self.reputation,
                                "type": "MITRE ATT&CK",
                                "rawJSON": mitreItemJSON,
                            })
                            indicatorValuesList.add(value)
                            counter += 1
                        mitreIDList.add(mitreItemJSON.get('id'))

                        # Create a duplicate indicator using the "external_id" from the
                        # original indicator, if the user has selected "includeAPT" as True
                        if self.includeAPT:
                            extRefs = [x.get('external_id') for x in mitreItemJSON.get('external_references')
                                       if x.get('external_id') and x.get('source_name') != "mitre-attack"]
                            for x in extRefs:
                                if x not in externalRefs:
                                    indicators.append({
                                        "value": x,
                                        "score": self.reputation,
                                        "type": "MITRE ATT&CK",
                                        "rawJSON": mitreItemJSON,
                                    })
                                    externalRefs.add(x)

        # Finally, map all the fields from the indicator
        # rawjson to the fields in the indicator
        for indicator in indicators:
            indicator['fields'] = dict()
            for field, value in mitreFieldMapping.items():
                try:
                    # Try and map the field
                    valueType = value['type']
                    valueName = value['name']
                    if valueType == "list":
                        indicator['fields'][field] = "\n".join(indicator['rawJSON'][valueName])
                    else:
                        indicator['fields'][field] = indicator['rawJSON'][valueName]
                except KeyError as err:
                    # If the field does not exist in the indicator
                    # then move on
                    pass
                except Exception as err:
                    demisto.error(f"Error when mapping Mitre Fields - {err}")
        return(indicators)


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
    demistoURLs = demisto.demistoUrls()
    indicatorURL = demistoURLs.get('server') + "/#/indicator/"
    sensitive = True if args.get('casesensitive') == 'True' else False
    returnListMD = list()
    entries = list()
    allIndicators = list()
    page = 0
    size = 1000
    rawData = demisto.searchIndicators(query=f'type:"{client.indicatorType}"', page=page, size=size)
    while(len(rawData.get('iocs', [])) > 0):
        allIndicators.extend(rawData.get('iocs', []))
        page += 1
        rawData = demisto.searchIndicators(query=f'type:"{client.indicatorType}"', page=page, size=size)

    for indicator in allIndicators:
        customFields = indicator.get('CustomFields', {})
        for k, v in customFields.items():
            if type(v) != str:
                continue
            if sensitive:
                if search in v and customFields.get('mitrename') not in [x.get('mitrename') for x in returnListMD]:
                    returnListMD.append({
                        'mitrename': customFields.get('mitrename'),
                        'Name': f"[{customFields.get('mitrename', '')}]({urljoin(indicatorURL, indicator.get('id'))})",
                    })
                    entries.append({
                        "id": f"{indicator.get('id')}",
                        "value": f"{indicator.get('value')}"
                    })
                    break
            else:
                if search.lower() in v.lower()\
                   and customFields.get('mitrename') not in [x.get('mitrename') for x in returnListMD]:
                    returnListMD.append({
                        'mitrename': customFields.get('mitrename'),
                        'Name': f"[{customFields.get('mitrename', '')}]({urljoin(indicatorURL, indicator.get('id'))})",
                    })
                    entries.append({
                        "id": f"{indicator.get('id')}",
                        "value": f"{indicator.get('value')}"
                    })
                    break
    returnListMD = sorted(returnListMD, key=lambda name: name['mitrename'])
    returnListMD = [{"Name": x.get('Name')} for x in returnListMD]

    md = tableToMarkdown(f'MITRE Indicator search:', returnListMD)
    ec = {'indicators(val.id && val.id == obj.id)': entries}
    return_outputs(md, ec, returnListMD)


def reputation_command(client, args):
    indicator = args.get('indicator')
    allIndicators = list()
    page = 0
    size = 1000
    rawData = demisto.searchIndicators(query=f'type:"{client.indicatorType}" value:{indicator}', page=page, size=size)
    while(len(rawData.get('iocs', [])) > 0):
        allIndicators.extend(rawData.get('iocs', []))
        page += 1
        rawData = demisto.searchIndicators(query=f'type:"{client.indicatorType}" value:{indicator}', page=page, size=size)
    for indicator in allIndicators:
        customFields = indicator.get('CustomFields')

        # Build the markdown for the user
        md = customFields.get('mitredescriptionmarkdown')
        if customFields.get('mitreurls', None):
            md += "\n_____\n## MITRE URLs\n" + customFields.get('mitreurls')
        if customFields.get('mitrekillchainphases', None):
            md += "\n_____\n## Kill Chain Phases\n" + customFields.get('mitrekillchainphases')
        score = indicator.get('score')
        value = indicator.get('value')
        indicatorID = indicator.get('id')
        ec = {
            "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor && val.Vendor == obj.Vendor)": {
                "Indicator": value,
                "Type": client.indicatorType,
                "Vendor": "MITRE ATT&CK",
                "Score": score
            },
            "MITRE.ATT&CK(val.value && val.value = obj.value)": {
                'value': value,
                'indicatorid': indicatorID,
                'customFields': customFields
            }
        }

        return_outputs(md, ec, score)


def main():

    params = demisto.params()
    args = demisto.args()
    url = 'https://cti-taxii.mitre.org'
    includeAPT = params.get('includeAPT')
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url, proxies, verify_certificate, includeAPT)
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