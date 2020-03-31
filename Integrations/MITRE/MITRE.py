import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
from typing import List
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection

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

    def deduplicate_items(self, result):

        parsedResults = list()
        for res in result:

            rawJSON = res.get('rawJSON')
            name = rawJSON.get('name')
            value = res.get('value')

            # Find items that have the same ID
            totalItems = [x for x in result if x.get('value') == value]

            # If there is a duplicate external ID, merge them together
            if len(totalItems) > 1:

                # Ensure we don't already have a combined item for this
                if value in [x.get('value') for x in parsedResults]:
                    continue

                # Otherwise create a combined item
                else:

                    descriptionMarkdown = f"# {value}\n\n" + "\n\n".join(
                        [f"### {x.get('rawJSON').get('name')} ({x.get('rawJSON').get('type')})\n\n\
                        {x.get('rawJSON').get('description')}" for x in totalItems])

                    description = f"{value}\n" + "\n\n".join(
                        [f"{x.get('rawJSON').get('name')} ({x.get('rawJSON').get('type')})\n\n\
                        {x.get('rawJSON').get('description')}" for x in totalItems])

                    combinedReferences = list()
                    killChainsCombined = list()
                    platformsCombined = list()
                    mitreType = list()
                    subfeed = list()
                    mitreID = list()
                    aliases = list()
                    for item in totalItems:
                        mitreType.append(item.get('rawJSON').get('type'))
                        subfeed.append(item.get('rawJSON').get('type'))
                        mitreID.append(item.get('rawJSON').get('id'))
                        for alias in item.get('rawJSON').get('aliases', []):
                            aliases.append(alias) if alias not in aliases and alias != value else None
                        for alias in item.get('rawJSON').get('x_mitre_aliases', []):
                            aliases.append(alias) if alias not in aliases and alias != value else None
                        for reference in item.get('rawJSON').get('external_references', []):
                            reference['type'] = item.get('rawJSON').get('type')
                            combinedReferences.append(reference)
                        for killchain in item.get('rawJSON').get('kill_chain_phases', []):
                            killChainsCombined.append(killchain)
                        for platform in item.get('rawJSON').get('x_mitre_platforms', []):
                            if platform not in platformsCombined:
                                platformsCombined.append(platform)
                    associations = [x.get('external_id', '') for x in combinedReferences if
                                    x.get('external_id', None)
                                    and x.get('source_name', '') == 'mitre-attack'
                                    and x.get('external_id', '') != value]
                    mitreType = "\n".join(mitreType)
                    subfeed = "\n".join(subfeed)
                    mitreID = "\n".join(mitreID)
                    aliasesMarkdown = tableToMarkdown('', [{"Alias": x} for x in aliases])

                    referencesMarkdown = ""
                    urlMarkdown = ""
                    mitreURL = ''
                    if len(combinedReferences) > 0:
                        external_references = [
                            {
                                "Source Name": x.get('source_name'),
                                "ID": x.get('external_id'),
                                "URL": x.get('url')
                            } for x in combinedReferences]
                        referencesMarkdown = tableToMarkdown('', external_references, ['ID', 'Source Name', 'URL'])
                        URLsModified = [
                            {
                                "ID": f"{x.get('external_id', '')} \
                                ({x.get('type', '')})" if x.get('external_id', None)
                                and x.get('url', None) else '',
                                "Source": f"[{x.get('source_name', 'Link')}]\
                                ({x.get('url', None)})"
                            } for x in combinedReferences if x.get('url', None)]
                        mitreURL = [x['url'] for x in combinedReferences if x['source_name'] == 'mitre-attack']
                        mitreURL = mitreURL[0] if mitreURL else ''
                        urlMarkdown = tableToMarkdown('', URLsModified)

                    killchainMarkdown = ""
                    if len(killChainsCombined) > 0:
                        killchainModified = [
                            {
                                "Kill Chain Name": x.get('kill_chain_name', ''),
                                "Phase Name": x.get('phase_name', '')
                            } for x in killChainsCombined
                        ]
                        killchainMarkdown = tableToMarkdown('', killchainModified)

                    platformsMarkdown = ""
                    if platformsCombined:
                        platformsModified = [{"Platform": x} for x in platformsCombined]
                        platformsMarkdown = tableToMarkdown('', platformsModified)

            else:
                mitreType = rawJSON.get('type')
                subfeed = rawJSON.get('type', '')
                mitreID = rawJSON.get('id')
                description = rawJSON.get('description')
                aliases = rawJSON.get('aliases', [])
                aliases.extend(rawJSON.get('x_mitre-aliases', []))
                aliasesMarkdown = tableToMarkdown('', [{"Alias": x} for x in aliases])
                associations = [
                    x.get('external_id') for x in rawJSON.get('external_references', [])
                    if x.get('external_id', None) and x.get('source_name', '') == 'mitre-attack'
                    and x.get('external_id', '') != value
                ]
                descriptionMarkdown = f"# {value}\n\n## {rawJSON.get('name')} \
                ({rawJSON.get('type')})\n\n{rawJSON.get('description')}"

                referencesMarkdown = ''
                urlMarkdown = ""
                mitreURL = ''
                if rawJSON.get('external_references', None):
                    external_references = [
                        {
                            "Source Name": x.get('source_name'),
                            "ID": x.get('external_id'),
                            "URL": x.get('url')
                        }
                        for x in rawJSON.get('external_references')
                    ]
                    referencesMarkdown = tableToMarkdown('', external_references, ['ID', 'Source Name', 'URL'])
                    URLsModified = [
                        {
                            "ID": f"{x.get('external_id', '')} ({mitreType})"
                            if x.get('external_id', None) else '',
                            "Source": f"[{x.get('source_name', 'Link')}]({x.get('url', None)})"
                        }
                        for x in rawJSON.get('external_references') if x.get('url', None)
                    ]
                    mitreURL = [x['url'] for x in rawJSON.get('external_references') if x['source_name'] == 'mitre-attack']
                    mitreURL = mitreURL[0] if mitreURL else ''
                    urlMarkdown = tableToMarkdown('', URLsModified)

                killchainMarkdown = ""
                if rawJSON.get('kill_chain_phases', None):
                    killchainModified = [
                        {
                            "Kill Chain Name": x.get('kill_chain_name', ''),
                            "Phase Name": x.get('phase_name', '')
                        }
                        for x in rawJSON.get('kill_chain_phases')
                    ]
                    killchainMarkdown = tableToMarkdown('', killchainModified)

                platformsMarkdown = ""
                if rawJSON.get('x_mitre_platforms', None):
                    platformsModified = [{"Platform": x} for x in rawJSON.get('x_mitre_platforms', [])]
                    platformsMarkdown = tableToMarkdown('', platformsModified)

            indicator = {
                "value": value,
                "score": self.reputation,
                "type": self.indicatorType,
                "rawJSON": rawJSON,
                "fields": {
                    "subfeed": subfeed,
                    "associations": associations,
                    "mitrealiases": aliasesMarkdown,
                    "mitredescription": description,
                    "mitredescriptionmarkdown": descriptionMarkdown,
                    "mitreexternalreferences": referencesMarkdown,
                    "mitreid": mitreID,
                    "mitrekillchainphases": killchainMarkdown,
                    "mitrename": name,
                    "mitretype": mitreType,
                    "mitreurls": urlMarkdown,
                    "mitreurl": mitreURL,
                    "mitreplatforms": platformsMarkdown
                },
                "temp": {
                    "aliases": aliases
                }
            }
            parsedResults.append(indicator)
        return parsedResults

    def include_external_refs(self, result):
        external_refs = list()
        for indicator in result:
            for ref in indicator.get('temp', {}).get('aliases', []):
                if self.includeAPT:
                    newIndicator = dict()
                    for k, v in indicator.items():
                        newIndicator[k] = v
                    newIndicator['value'] = ref
                    del newIndicator['temp']
                    external_refs.append(newIndicator)
            del indicator['temp']
        result.extend(external_refs)
        return result

    def build_iterator(self, limit: int = -1) -> List:

        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """

        indicators = list()
        limit = limit
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
                        externals = [
                            x['external_id'] for x in mitreItemJSON.get('external_references', [])
                            if x['source_name'] == 'mitre-attack' and x['external_id']
                        ]
                        value = externals[0]
                    except Exception:
                        value = None
                    if not value:
                        value = mitreItemJSON.get('x_mitre_old_attack_id', None)
                    if not value:
                        value = mitreItemJSON.get('id')

                    if mitreItemJSON.get('id') not in [x.get('rawJSON').get('id') for x in indicators]:
                        indicators.append({
                            "value": value,
                            "rawJSON": mitreItemJSON,
                        })
                        counter += 1

        # De-duplicate the list for items with the same ID
        indicators = self.deduplicate_items(indicators)
        indicators = self.include_external_refs(indicators)
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

    indicators = list()
    limit = int(args.get('limit', 10))

    indicators = client.build_iterator(limit=limit)

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
                if search.lower() in v.lower() and customFields.get('mitrename') not in [
                    x.get('mitrename') for x in returnListMD
                ]:
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

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': returnListMD,
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown(f'MITRE Indicator search:', returnListMD),
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'indicators(val.id && val.id == obj.id)': entries
        }
    })


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
        entry = {
            'Type': entryTypes['note'],
            'Contents': score,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        }
        demisto.results(entry)


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
            test_module(client)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            commands[command](client, args)

    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {feed_name} Integration:\n{e}'
        return_error(err_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
