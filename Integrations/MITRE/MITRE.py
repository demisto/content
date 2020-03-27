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

''' CONSTANTS '''
mitreImage = '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'
mitreImageSize = '101x376'


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
    client.getServer()
    client.getRoots()
    client.getCollections()
    if client.collections:
        demisto.results('ok')
    else:
        return_error('Could not connect to server')


def fetch_indicators(client):

    client.initialise()
    indicators = client.build_iterator()
    return indicators


def get_indicators_command(client, args):

    indicators = list()
    limit = int(args.get('limit', 10))

    client.initialise()
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
    client.initialise()
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
        err_msg = f'Error in {feed_name} Integration - Encountered an issue with createIndicators' if \
            'failed to create' in str(e) else f'Error in {feed_name} Integration [{e}]'
        return_error(err_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
