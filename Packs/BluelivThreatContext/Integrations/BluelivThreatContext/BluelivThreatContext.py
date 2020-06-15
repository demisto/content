''' IMPORTS '''
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import urllib3

''' PARAM DEFINITION '''
SEARCHABLE_BY_NAME = 'threat-actor,campaign,attack-pattern,tool,signature'
SEARCHABLE_BY_HASH = 'sha256,sha1,md5'

urllib3.disable_warnings()


class Client(BaseClient):
    def authenticate(self, username: str, password: str):
        body = {
            'username': username,
            'password': password
        }
        res = self._http_request(method='POST', url_suffix='/auth', json_data=body)
        self._headers = {"Content-Type": "application/json", "x-cookie": str(res.get('token'))}
        return str(res.get('token'))

    def _query_gateway(self, url):
        body = {"apiId": "THIAPP", "url": "/api/v1/" + url, "requestType": "GET"}
        demisto.debug("Gateway call to " + json.dumps(body))
        res = self._http_request(method='POST', url_suffix='/gateway', json_data=body, headers=self._headers)
        return res

    def get_threat_actor_info(self, threat_actor_id):
        url = "threat-actor/{}".format(threat_actor_id)
        result = self._query_gateway(url)
        return result

    def get_campaign_info(self, campaign_id: str):
        url = "campaign/{}".format(campaign_id)
        result = self._query_gateway(url)
        return result

    def get_malware_hash_info(self, file_hash, hash_type="md5"):
        url = "malware/?dork={}%3A%22{}%22".format(hash_type, file_hash)
        result = self._query_gateway(url)
        return result

    def get_malware_info(self, malware_id):
        url = "malware/{}".format(malware_id)
        result = self._query_gateway(url)
        return result

    def get_ip_info(self, ip_id):
        url = "ip/{}".format(ip_id)
        result = self._query_gateway(url)
        return result

    def get_fqdn_info(self, fqdn_id):
        url = "fqdn/{}".format(fqdn_id)
        result = self._query_gateway(url)
        return result

    def get_crime_server_info(self, cs_id):
        url = "crime-server/{}".format(cs_id)
        result = self._query_gateway(url)
        return result

    def get_attack_pattern_info(self, attack_pattern_id):
        url = "attack-pattern/{}".format(attack_pattern_id)
        result = self._query_gateway(url)
        return result

    def get_tool_info(self, tool_id):
        url = "tool/{}".format(tool_id)
        result = self._query_gateway(url)
        return result

    def get_signature_info(self, signature_id):
        url = "signature/{}".format(signature_id)
        result = self._query_gateway(url)
        return result

    def get_cve_info(self, cve_id):
        url = "cve/{}".format(cve_id)
        result = self._query_gateway(url)
        return result

    def search_by_name(self, key, value):
        value = value.replace(' ', '+')
        if key in SEARCHABLE_BY_NAME:
            url = "{}/?fuzzy_filter%5Bname%5D={}".format(key, value)
        if key in SEARCHABLE_BY_HASH:
            url = "indicator/?fuzzy_filter%5Bvalue%5D={}".format(value)
        if key == 'crime-server':
            url = "crime-server/?fuzzy_filter%5Bcrime_server_url%5D={}".format(value)
        if key == 'fqdn':
            url = "fqdn/?fuzzy_filter%5Bdomain%5D={}".format(value)
        if key == 'ip':
            url = "ip/?fuzzy_filter%5Baddress%5D={}".format(value)

        result = self._query_gateway(url)
        return result.get("data", [])[0].get("id", "0")

    def get_relationships(self, object_name, value, of):
        url = "{}/{}/relationships/{}/".format(object_name, value, of)
        result = self._query_gateway(url)
        ids = ""
        if result != "error":
            for item in result['data']:
                ids = ids + str(item['id']) + ","

        '''except:
            url = "{}/{}/{}/".format(object_name, value, of)
            result = self._query_gateway(url)
            ids = ""
            if result != "error":
                for item in result['data']:
                    ids = ids + str(item['id']) + ","
        '''
        return ids


def getHuman(result):
    human = {"id": result.get("data").get("id"),
             "links": result.get("data").get("links"),
             "type": result.get("data").get("type")}
    human.update(result.get("data").get("attributes"))

    return human


# This function return false when there are no results to display
def notFound():
    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': False,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "No results found.",
        'EntryContext': {
            'threatContext.hasResults': False
        }
    })
    sys.exit(0)


# Get information about threat actors #
def blueliv_threatActor(client: Client, threatActorId, threatActorName):
    if threatActorId == '0':
        threatActorId = client.search_by_name('threat-actor', threatActorName)

    if threatActorId == '0':
        notFound()
    else:
        result = client.get_threat_actor_info(threatActorId)

        if result:
            name = str(result["data"]["attributes"]["name"])
            description = str(result['data']['attributes']['description'])
            objective = str(result['data']['attributes']['objective'])
            sophistication = str(result['data']['attributes']['sophistication'])
            lastSeen = str(result['data']['attributes']['last_seen'])
            active = str(result['data']['attributes']['active'])

            milestoneIds = ""
            milestones = result['data']['relationships']['milestones']['meta']['count']
            if milestones > 0:
                milestoneIds = client.get_relationships("threat-actor", threatActorId, "milestone")

            toolIds = ""
            tools = result['data']['relationships']['tools']['meta']['count']
            if tools > 0:
                toolIds = client.get_relationships("threat-actor", threatActorId, "tools")

            campaigns = result['data']['relationships']['campaigns']['meta']['count']
            campaignIds = ""
            if campaigns > 0:
                campaignIds = client.get_relationships("threat-actor", threatActorId, "campaign")

            signatures = result['data']['relationships']['signatures']['meta']['count']
            signatureIds = ""
            if signatures > 0:
                signatureIds = client.get_relationships("threat-actor", threatActorId, "signature")

            onlineServiceIds = ""
            onlineServices = result['data']['relationships']['online_services']['meta']['count']
            if onlineServices > 0:
                onlineServiceIds = client.get_relationships("threat-actor", threatActorId, "online-service")

            malwareIds = ""
            malware = result['data']['relationships']['malware']['meta']['count']
            if malware > 0:
                malwareIds = client.get_relationships("threat-actor", threatActorId, "malware")

            threatTypeIds = ""
            threatTypes = result['data']['relationships']['threat_types']['meta']['count']
            if threatTypes > 0:
                threatTypeIds = client.get_relationships("threat-actor", threatActorId, "threat-type")

            fqdnIds = ""
            fqdns = result['data']['relationships']['fqdns']['meta']['count']
            if fqdns > 0:
                fqdnIds = client.get_relationships("threat-actor", threatActorId, "fqdn")

            attackPatternIds = ""
            attackPatterns = result['data']['relationships']['attack_patterns']['meta']['count']
            if attackPatterns > 0:
                attackPatternIds = client.get_relationships("threat-actor", threatActorId, "attack-pattern")

            ipIds = ""
            ips = result['data']['relationships']['ips']['meta']['count']
            if ips > 0:
                ipIds = client.get_relationships("threat-actor", threatActorId, "ip")

            targetIds = ""
            targets = result['data']['relationships']['targets']['meta']['count']
            if targets > 0:
                targetIds = client.get_relationships("threat-actor", threatActorId, "target")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Threat Actor info", human),
                'EntryContext': {
                    'threatContext.hasResults': 'true',
                    'threatActor.name': name,
                    'threatActor.description': description,
                    'threatActor.objective': objective,
                    'threatActor.sophistication': sophistication,
                    'threatActor.lastSeen': lastSeen,
                    'threatActor.active': active,
                    'threatActor.milestones': milestones,
                    'threatActor.milestoneIds': milestoneIds,
                    'threatActor.tools': tools,
                    'threatActor.toolIds': toolIds,
                    'threatActor.campaigns': campaigns,
                    'threatActor.campaignIds': campaignIds,
                    'threatActor.signatures': signatures,
                    'threatActor.signatureIds': signatureIds,
                    'threatAactor.onlineServices': onlineServices,
                    'threatActor.onlineServiceIds': onlineServiceIds,
                    'threatActor.malware': malware,
                    'threatActor.malwareIds': malwareIds,
                    'threatAactor.threatTypes': threatTypes,
                    'threatActor.threatTypeIds': threatTypeIds,
                    'threatActor.fqdns': fqdns,
                    'threatActor.fqdnIds': fqdnIds,
                    'threatActor.attackPatterns': attackPatterns,
                    'threatActor.attackPatternIds': attackPatternIds,
                    'threatActor.ips': ips,
                    'threatActor,ipIds': ipIds,
                    'threatActor.targets': targets,
                    'threatActor.targetIds': targetIds
                }
            })
        else:
            notFound()


# Get campaign information
def blueliv_campaign(client: Client, campaignName, campaignId):
    if campaignId == '0':
        campaignId = client.search_by_name('campaign', campaignName)
    if campaignId == '0':
        notFound()
    else:
        result = client.get_campaign_info(campaignId)

        if result:
            lastSeen = result['data']['attributes']['last_seen']
            name = result['data']['attributes']['name']
            description = result['data']['attributes']['description']

            # BOTNETS #
            botnetIds = ""
            botnets = result['data']['relationships']['botnets']['meta']['count']
            if botnets > 0:
                botnetIds = client.get_relationships("campaign", campaignId, "botnet")

            # SIGNATURES #
            signatureIds = ""
            signatures = result['data']['relationships']['signatures']['meta']['count']
            if signatures > 0:
                signatureIds = client.get_relationships("campaign", campaignId, "signature")

            # IPs #
            ipIds = ""
            ips = result['data']['relationships']['ips']['meta']['count']
            if ips > 0:
                ipIds = client.get_relationships("campaign", campaignId, "ip")

            # MALWARE #
            malwareIds = ""
            malware = result['data']['relationships']['malware']['meta']['count']
            if malware > 0:
                malwareIds = client.get_relationships("campaign", campaignId, "malware")

            # ATTACK PATTERNS
            attackPatternIds = ""
            attackPatterns = result['data']['relationships']['attack_patterns']['meta']['count']
            if attackPatterns > 0:
                attackPatternIds = client.get_relationships("campaign", campaignId, "attack-pattern")

            # TOOLS #
            toolIds = ""
            tools = result['data']['relationships']['tools']['meta']['count']
            if tools > 0:
                toolIds = client.get_relationships("campaign", campaignId, "tool")

            # FQDNs #
            fqdnIds = ""
            fqdns = result['data']['relationships']['fqdns']['meta']['count']
            if fqdns > 0:
                fqdnIds = client.get_relationships("campaign", campaignId, "fqdn")

            # THREAT ACTORS #
            threatActorId = result['data']['relationships']['threat_actor']['data']['id']

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Campaign info", human),
                'EntryContext': {
                    'threatContext.hasResults': 'true',
                    'campaign.name': name,
                    'campaign.description': description,
                    'campaign.lastSeen': lastSeen,
                    'campaign.botnets': botnets,
                    'campaign.botnetIds': botnetIds,
                    'campaign.signatures': signatures,
                    'campaign.signatureIds': signatureIds,
                    'campaign.ips': ips,
                    'campaign,ipIds': ipIds,
                    'campaign.malware': malware,
                    'campaign.malwareIds': malwareIds,
                    'campaign.attackPatterns': attackPatterns,
                    'campaign.attackPatternIds': attackPatternIds,
                    'campaign.tools': tools,
                    'campaign.toolIds': toolIds,
                    'campaign.fqdns': fqdns,
                    'campaign.fqdnIds': fqdnIds,
                    'campaign.threatActorId': threatActorId
                }
            })
        else:
            notFound()


# Get detailed malware information #
def blueliv_malware(client: Client, hashValue, malwareId):
    if hashValue != '0':
        if len(hashValue) == 40:
            hash_type = 'sha1'
        elif len(hashValue) == 64:
            hash_type = 'sha256'
        elif len(hashValue) == 32:
            hash_type = 'md5'
        else:
            notFound()

    if malwareId == '0':
        result = client.get_malware_hash_info(hashValue, hash_type)

        if not result:
            notFound()
        malwareId = result['data'][0]['id']

    if malwareId != '0':
        result = client.get_malware_info(malwareId)

        if result:
            # lastSeen = result['data']['attributes']['last_seen']
            sha256 = result['data']['attributes']['sha256']
            sha1 = result['data']['attributes']['sha1']
            md5 = result['data']['attributes']['md5']
            fileType = result['data']['attributes']['file_type']
            hasCandC = result['data']['attributes']['has_c_and_c']
            memory = result['data']['attributes']['memory']
            procMemory = result['data']['attributes']['proc_memory']
            analysisStatus = result['data']['attributes']['analysis_status']
            dropped = result['data']['attributes']['dropped']
            buffers = result['data']['attributes']['buffers']
            hasNetwork = result['data']['attributes']['has_network']
            risk = result['data']['attributes']['risk']
            # Malware uses sha256 likes malwareId, so we need to use this field to call getIds function

            # CAMPAIGNS #
            campaigns = result['data']['relationships']['campaigns']['meta']['count']
            campaignIds = ""
            if campaigns > 0:
                campaignIds = client.get_relationships("malware", sha256, "campaign")

            # SIGNATURES #
            signatures = result['data']['relationships']['signatures']['meta']['count']
            signatureIds = ""
            if signatures > 0:
                signatureIds = client.get_relationships("malware", sha256, "signature")

            # THREAT ACTORS #
            threatActorIds = ""
            threatActors = result['data']['relationships']['threat_actors']['meta']['count']
            if threatActors > 0:
                threatActorIds = client.get_relationships("malware", sha256, "threat-actor")

            # SOURCES #
            sourceIds = ""
            sources = result['data']['relationships']['sources']['meta']['count']
            if sources > 0:
                sourceIds = client.get_relationships("malware", sha256, "source")

            # TAGS #
            tagIds = ""
            tags = result['data']['relationships']['tags']['meta']['count']
            if tags > 0:
                tagIds = client.get_relationships("malware", sha256, "tag")

            # CRIME SERVERS #
            crimeServerIds = ""
            crimeServers = result['data']['relationships']['crime_servers']['meta']['count']
            if crimeServers > 0:
                crimeServerIds = client.get_relationships("mwlware", sha256, "crime-server")

            # FQDNs #
            fqdnIds = ""
            fqdns = result['data']['relationships']['fqdns']['meta']['count']
            if fqdns > 0:
                fqdnIds = client.get_relationships("malware", sha256, "fqdn")

            # TYPES #
            typeIds = ""
            types = result['data']['relationships']['types']['meta']['count']
            if types > 0:
                typeIds = client.get_relationships("malware", sha256, "type")

            # SPARKS #
            sparkIds = ""
            sparks = result['data']['relationships']['sparks']['meta']['count']
            if sparks > 0:
                sparkIds = client.get_relationships("malware", sha256, "spark")

            # IPs #
            ipIds = ""
            ips = result['data']['relationships']['ips']['meta']['count']
            ipIds = client.get_relationships("malware", sha256, "ip")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Malware file info", human),
                'EntryContext': {
                    'threatContext.hasResults': 'true',
                    'malware.hash.sha256': sha256,
                    'malware.hash.sha1': sha1,
                    'malware.hash.md5': md5,
                    'malware.fileType': fileType,
                    'malware.hasCandC': hasCandC,
                    'malware.memory': memory,
                    'malware.procMemory': procMemory,
                    'malware.analysisStatus': analysisStatus,
                    'malware.dropped': dropped,
                    'malware.buffers': buffers,
                    'malware.hasNetwork': hasNetwork,
                    'malware.risk': risk,
                    'malware.campaigns': campaigns,
                    'malware.campaignIds': campaignIds,
                    'malware.signatures': signatures,
                    'malware.signatureIds': signatureIds,
                    'malware.threatActors': threatActors,
                    'malware.threatActorIds': threatActorIds,
                    'malware.sources': sources,
                    'malware.sourceIds': sourceIds,
                    'malware.tags': tags,
                    'malware.tagIds': tagIds,
                    'malware.crimeServers': crimeServers,
                    'malware.crimeserverIds': crimeServerIds,
                    'malware.fqdns': fqdns,
                    'malware.fqdnIds': fqdnIds,
                    'malware.types': types,
                    'malware.typeIds': typeIds,
                    'malware.sparks': sparks,
                    'malware.sparkIds': sparkIds,
                    'malware.ips': ips,
                    'malware.ipIds': ipIds
                }
            })
        else:
            notFound()
    else:
        notFound()


def blueliv_indicatorIp(client: Client, nameIP, valueIP):
    if valueIP == '0' and nameIP == '0':
        notFound()
    if valueIP == '0':
        valueIP = nameIP  # client.search_by_name('fqdn', nameIP)

    if valueIP == '0':
        notFound()

    result = client.get_ip_info(valueIP)

    if result:
        lastSeen = str(result['data']['attributes']['last_seen'])
        latitude = str(result['data']['attributes']['latitude'])
        longitude = str(result['data']['attributes']['longitude'])
        risk = str(result['data']['attributes']['risk'])
        countryId = str(result['data']['relationships']['country']['data']['id'])

        # CAMPAIGNS #
        campaigns = result['data']['relationships']['campaigns']['meta']['count']
        campaignIds = ""
        if campaigns > 0:
            campaignIds = client.get_relationships("ip", valueIP, "campaign")

        # SIGNATURES #
        signatures = result['data']['relationships']['signatures']['meta']['count']
        signatureIds = ""
        if signatures > 0:
            signatureIds = client.get_relationships("ip", valueIP, "signature")

        # THREAT ACTORS #
        threatActors = result['data']['relationships']['threat_actors']['meta']['count']
        threatActorIds = ""
        if threatActors > 0:
            client.get_relationships("ip", valueIP, "threat-actor")

        # TAGS #
        tags = result['data']['relationships']['tags']['meta']['count']
        tagIds = ""
        if tags > 0:
            tagIds = client.get_relationships("ip", valueIP, "tag")

        # FQDNs #
        fqdnIds = ""
        fqdns = result['data']['relationships']['fqdns']['meta']['count']
        if fqdns > 0:
            fqdnIds = client.get_relationships("ip", valueIP, "fqdn")

        # SPARKS #
        sparks = result['data']['relationships']['sparks']['meta']['count']
        sparkIds = ""
        if sparks > 0:
            sparkIds = client.get_relationships("ip", valueIP, "spark")

        # BOTS #
        bots = result['data']['relationships']['bots']['meta']['count']
        botIds = ""
        if bots > 0:
            botIds = client.get_relationships("ip", valueIP, "bot")

        human = getHuman(result)
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv IP info", human),
            'EntryContext': {
                'threatContext.hasResults': 'true',
                'indicator.lastSeen': lastSeen,
                'indicator.risk': risk,
                'indicator.latitude': latitude,
                'indicator.longitude': longitude,
                'indicator.countryId': countryId,
                'indicator.campaigns': campaigns,
                'indicator.campaignIds': campaignIds,
                'indicator.signatures': signatures,
                'indicator.signatureIds': signatureIds,
                'indicator.threatActors': threatActors,
                'indicator.threatActorIds': threatActorIds,
                'indicator.tags': tags,
                'indicator.tagIds': tagIds,
                'indicator.fqdns': fqdns,
                'indicator.fqdnIds': fqdnIds,
                'indicator.sparks': sparks,
                'indicator.sparkIds': sparkIds,
                'indicator.bots': bots,
                'indicator.botIds': botIds
            }
        })
    else:
        notFound()


def blueliv_indicatorFqdn(client: Client, nameFQDN, valueFQDN):
    if valueFQDN == '0' and nameFQDN == '0':
        notFound()
    if valueFQDN == '0' and nameFQDN != '0':
        valueFQDN = client.search_by_name('fqdn', nameFQDN)
    if valueFQDN == '0':
        notFound()
        sys.exit()

    result = client.get_fqdn_info(valueFQDN)
    if result:
        # PARAMETROS GENERALES #
        lastSeen = str(result['data']['attributes']['last_seen'])
        risk = str(result['data']['attributes']['risk'])

        # CAMPAIGNS #
        campaigns = result['data']['relationships']['campaigns']['meta']['count']
        campaignIds = ""
        if campaigns > 0:
            campaignIds = client.get_relationships("fqdn", valueFQDN, "campaign")

        # SIGNATURES #
        signatures = result['data']['relationships']['signatures']['meta']['count']
        signatureIds = ""
        if signatures > 0:
            signatureIds = client.get_relationships("fqdn", valueFQDN, "signature")

        # THREAT ACTORS #
        threatActors = result['data']['relationships']['threat_actors']['meta']['count']
        threatActorIds = ""
        if threatActors > 0:
            threatActorIds = client.get_relationships("fqdn", valueFQDN, "threat-actor")

        # TAGS #
        tags = result['data']['relationships']['tags']['meta']['count']
        tagIds = ""
        if tags > 0:
            tagIds = client.get_relationships("fqdn", valueFQDN, "tag")

        # CRIME SERVERS #
        crimeServers = result['data']['relationships']['crime_servers']['meta']['count']
        crimeServerIds = ""
        if crimeServers > 0:
            crimeServerIds = client.get_relationships("fqdn", valueFQDN, "crime-server")

        # SPARKS #
        sparks = result['data']['relationships']['sparks']['meta']['count']
        sparkIds = ""
        if sparks > 0:
            sparkIds = client.get_relationships("fqdn", valueFQDN, "spark")

        # IPs #
        ips = result['data']['relationships']['ips']['meta']['count']
        ipIds = ""
        if ips > 0:
            ipIds = client.get_relationships("fqdn", valueFQDN, "ip")

        human = getHuman(result)
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv FQDN info", human),
            'EntryContext': {
                'threatContext.hasResults': 'true',
                'indicator.lastSeen': lastSeen,
                'indicator.risk': risk,
                'indicator.campaigns': campaigns,
                'indicator.campaignIds': campaignIds,
                'indicator.signatures': signatures,
                'indicator.signatureIds': signatureIds,
                'indicator.threatActors': threatActors,
                'indicator.threatActorIds': threatActorIds,
                'indicator.tags': tags,
                'indicator.tagids': tagIds,
                'indicator.crimeServers': crimeServers,
                'indicator.crimeServerIds': crimeServerIds,
                'indicator.sparks': sparks,
                'indicator.sparkIds': sparkIds,
                'indicator.ips': ips,
                'indicator.ipIds': ipIds
            }
        })
    else:
        notFound()


# Get information about the crime server related with the provided URL
def blueliv_indicatorCs(client: Client, nameCS, valueCS):
    if valueCS == '0' and nameCS == '0':
        notFound()
    if valueCS == '0' and nameCS != '0':
        valueCS = client.search_by_name('crime-server', nameCS)
    if valueCS == '0':
        notFound()
        sys.exit()

    result = client.get_crime_server_info(valueCS)

    if result:
        lastSeen = str(result['data']['attributes']['last_seen'])
        status = str(result['data']['attributes']['status'])
        risk = str(result['data']['attributes']['risk'])
        isFalsePositive = str(result['data']['attributes']['is_false_positive'])
        crimeServerUrl = str(result['data']['attributes']['crime_server_url'])
        creditCardsCount = str(result['data']['attributes']['credit_cards_count'])
        credentialsCount = str(result['data']['attributes']['credentials_count'])
        botsCount = str(result['data']['attributes']['bots_count'])
        fqdnId = result['data']['relationships']['fqdn']['data']['id']

        # SOURCES #
        sourceIds = ""
        sources = result['data']['relationships']['sources']['meta']['count']
        if sources > 0:
            sourceIds = client.get_relationships("crime-server", valueCS, "source")

        # MALWARE #
        malwareIds = ""
        malware = result['data']['relationships']['malware']['meta']['count']
        if malware > 0:
            malwareIds = client.get_relationships("crime-server", valueCS, "malware")

        # TAGS #
        tags = result['data']['relationships']['tags']['meta']['count']
        tagIds = ""
        if tags > 0:
            tagIds = client.get_relationships("crime-server", valueCS, "tag")

        # SPARKS #
        sparks = result['data']['relationships']['sparks']['meta']['count']
        sparkIds = ""
        if sparks > 0:
            sparkIds = client.get_relationships("crime-server", valueCS, "spark")

        human = getHuman(result)
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv Crime Server info", human),
            'EntryContext': {
                'threatContext.hasResults': 'true',
                'indicator.lastSeen': lastSeen,
                'indicator.status': status,
                'indicator.risk': risk,
                'indicator.isFalsePositive': isFalsePositive,
                'indicator.crimeServerUrl': crimeServerUrl,
                'indicator.creditCardsCount': creditCardsCount,
                'indicator.credentialsCount': credentialsCount,
                'indicator.botsCount': botsCount,
                'indicator.fqdnId': fqdnId,
                'indicator.malware': malware,
                'indicator.malwareIds': malwareIds,
                'indicator.tags': tags,
                'indicator.tagIds': tagIds,
                'indicator.sparks': sparks,
                'indicator.sparkIds': sparkIds,
                'indicator.sources': sources,
                'indicator.sourceIds': sourceIds
            }
        })
    else:
        notFound()


# Get information about attack patterns
def blueliv_attackPattern(client: Client, attackPatternName, attackPatternId):
    attackPatternId = int(attackPatternId)
    if attackPatternId == 0:
        attackPatternId = client.search_by_name('attack-pattern', attackPatternName)

    if attackPatternId != 0:
        result = client.get_attack_pattern_info(attackPatternId)

        if result:
            updatedAt = result['data']['attributes']['updated_at']
            name = result['data']['attributes']['name']
            description = result['data']['attributes']['description']
            serverity = result['data']['attributes']['severity']

            # SIGNATURES #
            signatures = result['data']['relationships']['signatures']['meta']['count']
            signatureIds = ""
            if signatures > 0:
                signatureIds = client.get_relationships("attack-pattern", str(attackPatternId), "signature")

            # CAMPAIGNS #
            campaigns = result['data']['relationships']['campaigns']['meta']['count']
            campaignIds = ""
            if campaigns > 0:
                campaignIds = client.get_relationships("attack-pattern", str(attackPatternId), "campaign")

            # THREAT ACTORS #
            threatActorIds = ""
            threatActors = result['data']['relationships']['threat_actors']['meta']['count']
            if threatActors > 0:
                threatActorIds = client.get_relationships("attack-pattern", str(attackPatternId), "threat-actor")

            # CVEs #
            cveIds = ""
            cves = result['data']['relationships']['cves']['meta']['count']
            if cves > 0:
                cves = client.get_relationships("attack-pattern", str(attackPatternId), "cve")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Attack Pattern info", human),
                'EntryContext': {
                    'threatContext.hasResults': 'true',
                    'attackPattern.name': name,
                    'attackPattern.description': description,
                    'attackPattern.updatedAt': updatedAt,
                    'attackPattern.serverity': serverity,
                    'attackPattern.signatures': signatures,
                    'attackPattern.signatureIds': signatureIds,
                    'attackPattern.campaigns': campaigns,
                    'attackPattern.campaignIds': campaignIds,
                    'attackPattern.threatActors': threatActors,
                    'attackPattern.threatActorIds': threatActorIds,
                    'attackPattern.cves': cves,
                    'attackPattern.cveIds': cveIds
                }
            })
        else:
            notFound()
    else:
        notFound()


# Get information about tools
def blueliv_tool(client: Client, toolName, toolId):
    if toolId == '0':
        toolId = client.search_by_name('tool', toolName)

    if toolId != '0':
        result = client.get_tool_info(toolId)

        if result:
            name = result['data']['attributes']['name']
            description = result['data']['attributes']['description']
            lastSeen = result['data']['attributes']['last_seen']

            # CAMPAIGNS #
            campaigns = result['data']['relationships']['campaigns']['meta']['count']
            campaignIds = ""
            if campaigns > 0:
                campaignIds = client.get_relationships("tool", str(toolId), "campaign")

            # SIGNATURES #
            signatures = result['data']['relationships']['signatures']['meta']['count']
            signatureIds = ""
            if signatures > 0:
                signatureIds = client.get_relationships("tool", str(toolId), "signature")

            # THREAT ACTORS #
            threatActorIds = ""
            threatActors = result['data']['relationships']['threat_actors']['meta']['count']
            if threatActors > 0:
                threatActorIds = client.get_relationships("tool", str(toolId), "threat-actor")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Tool info", human),
                'EntryContext': {
                    'threatContext.hasResults': 'true',
                    'tool.name': name,
                    'tool.description': description,
                    'tool.lastSeen': lastSeen,
                    'tool.campaigns': campaigns,
                    'tool.campaignIds': campaignIds,
                    'tool.signatures': signatures,
                    'tool.signatureIds': signatureIds,
                    'tool.threatActors': threatActors,
                    'tool.threatActorIds': threatActorIds
                }
            })
        else:
            notFound()
    else:
        notFound()


def blueliv_signature(client: Client, signatureName, signatureId):
    if signatureId == '0':
        signatureId = client.search_by_name('signature', signatureName)

    if signatureId != '0':
        result = client.get_signature_info(signatureId)

        if result:
            name = result['data']['attributes']['name']
            signatureType = result['data']['attributes']['type']
            updatedAt = result['data']['attributes']['updated_at']

            # MALWARE #
            malwareIds = ""
            malware = result['data']['relationships']['malware']['meta']['count']
            if malware > 0:
                malwareIds = client.get_relationships("signature", str(signatureId), "malware")

            human = getHuman(result)
            demisto.results({
                "Type": entryTypes["note"],
                'Contents': result,
                "ContentsFormat": formats["json"],
                'HumanReadable': tableToMarkdown("Blueliv Signature info", human),
                'ReadableContentsFormat': formats['markdown'],
                'EntryContext': {
                    'threatContext.hasResults': 'true',
                    'signature.name': name,
                    'signature.type': signatureType,
                    'signature.updatedAt': updatedAt,
                    'signature.malware': malware,
                    'signature.malwareIds': malwareIds
                }
            })
        else:
            notFound()
    else:
        notFound()


# Get inforamtion abouth the provided CVE code
def blueliv_cve(client: Client, cveCode, vulnId):
    if vulnId == '0':
        vulnId = cveCode

    result = client.get_cve_info(vulnId)

    if result:
        name = result['data']['attributes']['name']
        description = result['data']['attributes']['description']
        updatedAt = result['data']['attributes']['updated_at']
        score = result['data']['attributes']['score']
        exploitsTableData = result['data']['attributes']['exploits']
        platformsTableData = result['data']['attributes']['platforms']

        # ATTACK PATTERNS
        attackPatternIds = ""
        attackPatterns = result['data']['relationships']['attack_patterns']['meta']['count']
        if attackPatterns > 0:
            attackPatternIds = client.get_relationships("cve", str(vulnId), "attack-pattern")

        # SIGNATURES #
        signatures = result['data']['relationships']['signatures']['meta']['count']
        signatureIds = ""
        if signatures > 0:
            signatureIds = client.get_relationships("cve", str(vulnId), "signature")

        # TAGS #
        tagIds = ""
        tags = result['data']['relationships']['tags']['meta']['count']
        if tags > 0:
            tagIds = client.get_relationships("cve", str(vulnId), "tag")

        # CRIME SERVERS #
        crimeServerIds = ""
        crimeServers = result['data']['relationships']['crime_servers']['meta']['count']
        if crimeServers > 0:
            crimeServerIds = client.get_relationships("cve", str(vulnId), "crime-server")

        # SPARKS #
        sparkIds = ""
        sparks = result['data']['relationships']['sparks']['meta']['count']
        if sparks > 0:
            sparkIds = client.get_relationships("cve", vulnId, "spark")

        # MALWARE #
        malwareIds = ""
        malware = result['data']['relationships']['malware']['meta']['count']
        if malware > 0:
            malwareIds = client.get_relationships("cve", vulnId, "malware")

        human = getHuman(result)

        human = getHuman(result)
        demisto.results({
            "Type": entryTypes["note"],
            'Contents': result,
            "ContentsFormat": formats["json"],
            'HumanReadable': tableToMarkdown("Blueliv CVE info", human),
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'threatContext.hasResults': True,
                'cve.name': name,
                'cve.description': description,
                'cve.updatedAt': updatedAt,
                'cve.score': score,
                'cve.attackPatterns': attackPatterns,
                'cve.attackPatternIds': attackPatternIds,
                'cve.signatures': signatures,
                'cve.signatureIds': signatureIds,
                'cve.tags': tags,
                'cve.tagIds': tagIds,
                'cve.crimeServers': crimeServers,
                'cve.crimeServerIds,': crimeServerIds,
                'cve.sparks': sparks,
                'cve.sparkIds': sparkIds,
                'cve.malware': malware,
                'cve.malwareIds': malwareIds,
                'cve.exploits': exploitsTableData,
                'cve.platforms': platformsTableData
            }
        })
    else:
        notFound()


# DEMISTO command evaluation
def main():
    params = demisto.params()
    server_url = params.get('url')
    verify_ssl = not params.get('unsecure', False)
    proxy = params.get('proxy')
    username = params['credentials']['identifier']
    password = params['credentials']['password']

    client = Client(server_url, verify_ssl, proxy, headers={'Accept': 'application/json'})
    token = client.authenticate(username, password)

    args = demisto.args()
    if demisto.command() == 'test-module':
        demisto.results("ok")

    if demisto.command() == 'blueliv-authenticate':
        demisto.results(token)

    elif demisto.command() == 'blueliv-tc-threat-actor':
        blueliv_threatActor(client, args['threatActor_id'], args['threatActor'])

    elif demisto.command() == 'blueliv-tc-campaign':
        blueliv_campaign(client, args['campaign'], args['campaign_id'])

    elif demisto.command() == 'blueliv-tc-malware':
        blueliv_malware(client, args['hash'], args['hash_id'])

    elif demisto.command() == 'blueliv-tc-indicator-ip':
        blueliv_indicatorIp(client, args['IP'], args['IP_id'])

    elif demisto.command() == 'blueliv-tc-indicator-fqdn':
        blueliv_indicatorFqdn(client, args['FQDN'], args['FQDN_id'])

    elif demisto.command() == 'blueliv-tc-indicator-cs':
        blueliv_indicatorCs(client, args['CS'], args['CS_id'])

    elif demisto.command() == 'blueliv-tc-attack-pattern':
        blueliv_attackPattern(client, args['attackPattern'], args['attackPattern_id'])

    elif demisto.command() == 'blueliv-tc-tool':
        blueliv_tool(client, args['tool'], args['tool_id'])

    elif demisto.command() == 'blueliv-tc-signature':
        blueliv_signature(client, args['signature'], args['signature_id'])

    elif demisto.command() == 'blueliv-tc-cve':
        blueliv_cve(client, args['CVE'], args["CVE_id"])


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
