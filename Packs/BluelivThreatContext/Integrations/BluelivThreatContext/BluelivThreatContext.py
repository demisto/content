import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
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
        url = f"threat-actor/{threat_actor_id}"
        result = self._query_gateway(url)
        return result

    def get_campaign_info(self, campaign_id: str):
        url = f"campaign/{campaign_id}"
        result = self._query_gateway(url)
        return result

    def get_malware_hash_info(self, file_hash, hash_type="md5"):
        url = f"malware/?dork={hash_type}%3A%22{file_hash}%22"
        result = self._query_gateway(url)
        return result

    def get_malware_info(self, malware_id):
        url = f"malware/{malware_id}"
        result = self._query_gateway(url)
        return result

    def get_ip_info(self, ip_id):
        url = f"ip/{ip_id}"
        result = self._query_gateway(url)
        return result

    def get_fqdn_info(self, fqdn_id):
        url = f"fqdn/{fqdn_id}"
        result = self._query_gateway(url)
        return result

    def get_crime_server_info(self, cs_id):
        url = f"crime-server/{cs_id}"
        result = self._query_gateway(url)
        return result

    def get_attack_pattern_info(self, attack_pattern_id):
        url = f"attack-pattern/{attack_pattern_id}"
        result = self._query_gateway(url)
        return result

    def get_tool_info(self, tool_id):
        url = f"tool/{tool_id}"
        result = self._query_gateway(url)
        return result

    def get_signature_info(self, signature_id):
        url = f"signature/{signature_id}"
        result = self._query_gateway(url)
        return result

    def get_cve_info(self, cve_id):
        url = f"cve/{cve_id}"
        result = self._query_gateway(url)
        return result

    def search_by_name(self, key, value):
        url = ""
        if value:
            value = value.replace(' ', '+')
        else:
            value = ""

        if key in SEARCHABLE_BY_NAME:
            url = f"{key}/?fuzzy_filter%5Bname%5D={value}"
        if key in SEARCHABLE_BY_HASH:
            url = f"indicator/?fuzzy_filter%5Bvalue%5D={value}"
        if key == 'crime-server':
            url = f"crime-server/?fuzzy_filter%5Bcrime_server_url%5D={value}"
        if key == 'fqdn':
            url = f"fqdn/?fuzzy_filter%5Bdomain%5D={value}"
        if key == 'ip':
            url = f"ip/?fuzzy_filter%5Baddress%5D={value}"

        result = self._query_gateway(url)
        return result.get("data", [])[0].get("id", "0")

    def get_relationships(self, object_name, value, of):
        url = f"{object_name}/{value}/relationships/{of}/"
        result = self._query_gateway(url)
        ids = ""
        if result != "error":
            ids = ','.join(str(item['id']) for item in result['data'])

        return ids


def getHuman(result):
    human = {"id": result.get("data", {}).get("id"),
             "links": result.get("data", {}).get("links"),
             "type": result.get("data", {}).get("type")}
    human.update(result.get("data", {}).get("attributes"))

    return human


# This function return false when there are no results to display
def notFound():
    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': "No results found.",
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "No results found.",
        'EntryContext': {
            'BluelivThreatContext': {}
        }
    })
    sys.exit(0)


# Get information about threat actors #
def blueliv_threatActor(client: Client, args):
    threatActorId = args.get('threatActor_id', '')
    threatActorName = args.get('threatActor', '')

    if not threatActorId and not threatActorName:
        notFound()

    if not threatActorId:
        threatActorId = client.search_by_name('threat-actor', threatActorName)

    if not threatActorId:
        notFound()
    else:
        result = client.get_threat_actor_info(threatActorId)

        if result:
            name = str(demisto.get(result, "data.attributes.name"))
            description = str(demisto.get(result, "data.attributes.description"))
            objective = str(demisto.get(result, "data.attributes.objective"))
            sophistication = str(demisto.get(result, "data.attributes.sophistication"))
            lastSeen = str(demisto.get(result, "data.attributes.last_seen"))
            active = str(demisto.get(result, "data.attributes.active"))

            milestoneIds = ""
            milestones = demisto.get(result, "data.relationships.milestones.meta.count")
            if milestones:
                milestoneIds = client.get_relationships("threat-actor", threatActorId, "milestone")

            toolIds = ""
            tools = demisto.get(result, "data.relationships.tools.meta.count")
            if tools:
                toolIds = client.get_relationships("threat-actor", threatActorId, "tools")

            campaigns = demisto.get(result, "data.relationships.campaigns.meta.count")
            campaignIds = ""
            if campaigns:
                campaignIds = client.get_relationships("threat-actor", threatActorId, "campaign")

            signatures = demisto.get(result, "data.relationships.signatures.meta.count")
            signatureIds = ""
            if signatures:
                signatureIds = client.get_relationships("threat-actor", threatActorId, "signature")

            onlineServiceIds = ""
            onlineServices = demisto.get(result, "data.relationships.online_services.meta.count")
            if onlineServices:
                onlineServiceIds = client.get_relationships("threat-actor", threatActorId, "online-service")

            malwareIds = ""
            malware = demisto.get(result, "data.relationships.malware.meta.count")
            if malware:
                malwareIds = client.get_relationships("threat-actor", threatActorId, "malware")

            threatTypeIds = ""
            threatTypes = demisto.get(result, "data.relationships.threat_types.meta.count")
            if threatTypes:
                threatTypeIds = client.get_relationships("threat-actor", threatActorId, "threat-type")

            fqdnIds = ""
            fqdns = demisto.get(result, "data.relationships.fqdns.meta.count")
            if fqdns:
                fqdnIds = client.get_relationships("threat-actor", threatActorId, "fqdn")

            attackPatternIds = ""
            attackPatterns = demisto.get(result, "data.relationships.attack_patterns.meta.count")
            if attackPatterns:
                attackPatternIds = client.get_relationships("threat-actor", threatActorId, "attack-pattern")

            ipIds = ""
            ips = demisto.get(result, "data.relationships.ips.meta.count")
            if ips:
                ipIds = client.get_relationships("threat-actor", threatActorId, "ip")

            targetIds = ""
            targets = demisto.get(result, "data.relationships.targets.meta.count")
            if targets:
                targetIds = client.get_relationships("threat-actor", threatActorId, "target")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Threat Actor info", human),
                'EntryContext': {
                    'BluelivThreatContext.threatActor(val.name && val.id == obj.id)': {
                        'id': threatActorId,
                        'name': name,
                        'description': description,
                        'objective': objective,
                        'sophistication': sophistication,
                        'lastSeen': lastSeen,
                        'active': active,
                        'milestones': milestones,
                        'milestoneIds': milestoneIds,
                        'tools': tools,
                        'toolIds': toolIds,
                        'campaigns': campaigns,
                        'campaignIds': campaignIds,
                        'signatures': signatures,
                        'signatureIds': signatureIds,
                        'onlineServices': onlineServices,
                        'onlineServiceIds': onlineServiceIds,
                        'malware': malware,
                        'malwareIds': malwareIds,
                        'threatTypes': threatTypes,
                        'threatTypeIds': threatTypeIds,
                        'fqdns': fqdns,
                        'fqdnIds': fqdnIds,
                        'attackPatterns': attackPatterns,
                        'attackPatternIds': attackPatternIds,
                        'ips': ips,
                        'ipIds': ipIds,
                        'targets': targets,
                        'targetIds': targetIds
                    }
                }
            })
        else:
            notFound()


# Get campaign information
def blueliv_campaign(client: Client, args):
    campaignName = args.get('campaign', '')
    campaignId = args.get('campaign_id', '')

    if not campaignId:
        campaignId = client.search_by_name('campaign', campaignName)
    if not campaignId:
        notFound()
    else:
        result = client.get_campaign_info(campaignId)

        if result:
            lastSeen = demisto.get(result, "data.attributes.last_seen")
            name = demisto.get(result, "data.attributes.name")
            description = demisto.get(result, "data.attributes.description")

            # BOTNETS #
            botnetIds = ""
            botnets = demisto.get(result, "data.relationships.botnets.meta.count")
            if botnets:
                botnetIds = client.get_relationships("campaign", campaignId, "botnet")

            # SIGNATURES #
            signatureIds = ""
            signatures = demisto.get(result, "data.relationships.signatures.meta.count")
            if signatures:
                signatureIds = client.get_relationships("campaign", campaignId, "signature")

            # IPs #
            ipIds = ""
            ips = demisto.get(result, "data.relationships.ips.meta.count")
            if ips:
                ipIds = client.get_relationships("campaign", campaignId, "ip")

            # MALWARE #
            malwareIds = ""
            malware = demisto.get(result, "data.relationships.malware.meta.count")
            if malware:
                malwareIds = client.get_relationships("campaign", campaignId, "malware")

            # ATTACK PATTERNS
            attackPatternIds = ""
            attackPatterns = demisto.get(result, "data.relationships.attack_patterns.meta.count")
            if attackPatterns:
                attackPatternIds = client.get_relationships("campaign", campaignId, "attack-pattern")

            # TOOLS #
            toolIds = ""
            tools = demisto.get(result, "data.relationships.tools.meta.count")
            if tools:
                toolIds = client.get_relationships("campaign", campaignId, "tool")

            # FQDNs #
            fqdnIds = ""
            fqdns = demisto.get(result, "data.relationships.fqdns.meta.count")
            if fqdns:
                fqdnIds = client.get_relationships("campaign", campaignId, "fqdn")

            # THREAT ACTORS #
            threatActorId = demisto.get(result, "data.relationships.threat_actor.data.id")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Campaign info", human),
                'EntryContext': {
                    'BluelivThreatContext.campaign(val.id && val.id == obj.id)': {
                        'id': campaignId,
                        'name': name,
                        'description': description,
                        'lastSeen': lastSeen,
                        'botnets': botnets,
                        'botnetIds': botnetIds,
                        'signatures': signatures,
                        'signatureIds': signatureIds,
                        'ips': ips,
                        'ipIds': ipIds,
                        'malware': malware,
                        'malwareIds': malwareIds,
                        'attackPatterns': attackPatterns,
                        'attackPatternIds': attackPatternIds,
                        'tools': tools,
                        'toolIds': toolIds,
                        'fqdns': fqdns,
                        'fqdnIds': fqdnIds,
                        'threatActorId': threatActorId
                    }
                }
            })
        else:
            notFound()


# Get detailed malware information #
def blueliv_malware(client: Client, args):
    hashValue = args.get('hash', '')
    malwareId = args.get('hash_id', '')

    if hashValue:
        if len(hashValue) == 40:
            hash_type = 'sha1'
        elif len(hashValue) == 64:
            hash_type = 'sha256'
        elif len(hashValue) == 32:
            hash_type = 'md5'
        else:
            hash_type = ""
            notFound()
    else:
        hash_type = ""
        demisto.debug(f"No hashValue -> {hash_type=}")

    if not malwareId:
        result = client.get_malware_hash_info(hashValue, hash_type)

        if not result:
            notFound()

        if result.get("data", []):
            malwareId = demisto.get(result.get("data")[0], "id")

    if malwareId:
        result = client.get_malware_info(malwareId)

        if result:
            # lastSeen = demisto.get(result, "data.attributes.last_seen")
            sha256 = demisto.get(result, "data.attributes.sha256")
            sha1 = demisto.get(result, "data.attributes.sha1")
            md5 = demisto.get(result, "data.attributes.md5")
            fileType = demisto.get(result, "data.attributes.file_type")
            hasCandC = demisto.get(result, "data.attributes.has_c_and_c")
            memory = demisto.get(result, "data.attributes.memory")
            procMemory = demisto.get(result, "data.attributes.proc_memory")
            analysisStatus = demisto.get(result, "data.attributes.analysis_status")
            dropped = demisto.get(result, "data.attributes.dropped")
            buffers = demisto.get(result, "data.attributes.buffers")
            hasNetwork = demisto.get(result, "data.attributes.has_network")
            risk = demisto.get(result, "data.attributes.risk")
            # Malware uses sha256 likes malwareId, so we need to use this field to call getIds function

            # CAMPAIGNS #
            campaigns = demisto.get(result, "data.relationships.campaigns.meta.count")
            campaignIds = ""
            if campaigns:
                campaignIds = client.get_relationships("malware", sha256, "campaign")

            # SIGNATURES #
            signatures = demisto.get(result, "data.relationships.signatures.meta.count")
            signatureIds = ""
            if signatures:
                signatureIds = client.get_relationships("malware", sha256, "signature")

            # THREAT ACTORS #
            threatActorIds = ""
            threatActors = demisto.get(result, "data.relationships.threat_actors.meta.count")
            if threatActors:
                threatActorIds = client.get_relationships("malware", sha256, "threat-actor")

            # SOURCES #
            sourceIds = ""
            sources = demisto.get(result, "data.relationships.sources.meta.count")
            if sources:
                sourceIds = client.get_relationships("malware", sha256, "source")

            # TAGS #
            tagIds = ""
            tags = demisto.get(result, "data.relationships.tags.meta.count")
            if tags:
                tagIds = client.get_relationships("malware", sha256, "tag")

            # CRIME SERVERS #
            crimeServerIds = ""
            crimeServers = demisto.get(result, "data.relationships.crime_servers.meta.count")
            if crimeServers:
                crimeServerIds = client.get_relationships("mwlware", sha256, "crime-server")

            # FQDNs #
            fqdnIds = ""
            fqdns = demisto.get(result, "data.relationships.fqdns.meta.count")
            if fqdns:
                fqdnIds = client.get_relationships("malware", sha256, "fqdn")

            # TYPES #
            typeIds = ""
            types = demisto.get(result, "data.relationships.types.meta.count")
            if types:
                typeIds = client.get_relationships("malware", sha256, "type")

            # SPARKS #
            sparkIds = ""
            sparks = demisto.get(result, "data.relationships.sparks.meta.count")
            if sparks:
                sparkIds = client.get_relationships("malware", sha256, "spark")

            # IPs #
            ipIds = ""
            ips = demisto.get(result, "data.relationships.ips.meta.count")
            if ips:
                ipIds = client.get_relationships("malware", sha256, "ip")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Malware file info", human),
                'EntryContext': {
                    'BluelivThreatContext.malware(val.id && val.id == obj.id)': {
                        'id': malwareId,
                        'hash.sha256': sha256,
                        'hash.sha1': sha1,
                        'hash.md5': md5,
                        'fileType': fileType,
                        'hasCandC': hasCandC,
                        'memory': memory,
                        'procMemory': procMemory,
                        'analysisStatus': analysisStatus,
                        'dropped': dropped,
                        'buffers': buffers,
                        'hasNetwork': hasNetwork,
                        'risk': risk,
                        'campaigns': campaigns,
                        'campaignIds': campaignIds,
                        'signatures': signatures,
                        'signatureIds': signatureIds,
                        'threatActors': threatActors,
                        'threatActorIds': threatActorIds,
                        'sources': sources,
                        'sourceIds': sourceIds,
                        'tags': tags,
                        'tagIds': tagIds,
                        'crimeServers': crimeServers,
                        'crimeserverIds': crimeServerIds,
                        'fqdns': fqdns,
                        'fqdnIds': fqdnIds,
                        'types': types,
                        'typeIds': typeIds,
                        'sparks': sparks,
                        'sparkIds': sparkIds,
                        'ips': ips,
                        'ipIds': ipIds
                    }
                }
            })
        else:
            notFound()
    else:
        notFound()


def blueliv_indicatorIp(client: Client, args):
    nameIP = args.get('IP', '')
    valueIP = args.get('IP_id', '')

    if not valueIP and not nameIP:
        notFound()
    if nameIP:
        valueIP = nameIP  # client.search_by_name('fqdn', nameIP)

    if not valueIP:
        notFound()

    result = client.get_ip_info(valueIP)

    if result:
        lastSeen = str(demisto.get(result, "data.attributes.last_seen"))
        latitude = str(demisto.get(result, "data.attributes.latitude"))
        longitude = str(demisto.get(result, "data.attributes.longitude"))
        risk = str(demisto.get(result, "data.attributes.risk"))
        countryId = str(demisto.get(result, "data.relationships.country.data.id"))

        # CAMPAIGNS #
        campaigns = demisto.get(result, "data.relationships.campaigns.meta.count")
        campaignIds = ""
        if campaigns:
            campaignIds = client.get_relationships("ip", valueIP, "campaign")

        # SIGNATURES #
        signatures = demisto.get(result, "data.relationships.signatures.meta.count")
        signatureIds = ""
        if signatures:
            signatureIds = client.get_relationships("ip", valueIP, "signature")

        # THREAT ACTORS #
        threatActors = demisto.get(result, "data.relationships.threat_actors.meta.count")
        threatActorIds = ""
        if threatActors:
            client.get_relationships("ip", valueIP, "threat-actor")

        # TAGS #
        tags = demisto.get(result, "data.relationships.tags.meta.count")
        tagIds = ""
        if tags:
            tagIds = client.get_relationships("ip", valueIP, "tag")

        # FQDNs #
        fqdnIds = ""
        fqdns = demisto.get(result, "data.relationships.fqdns.meta.count")
        if fqdns:
            fqdnIds = client.get_relationships("ip", valueIP, "fqdn")

        # SPARKS #
        sparks = demisto.get(result, "data.relationships.sparks.meta.count")
        sparkIds = ""
        if sparks:
            sparkIds = client.get_relationships("ip", valueIP, "spark")

        # BOTS #
        bots = demisto.get(result, "data.relationships.bots.meta.count")
        botIds = ""
        if bots:
            botIds = client.get_relationships("ip", valueIP, "bot")

        human = getHuman(result)
        ipName = valueIP.replace(".", "")
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv IP info", human),
            'EntryContext': {
                'BluelivThreatContext.indicator(val.ipName && val.ipName == obj.ipName)': {
                    "ipName": ipName,
                    'lastSeen': lastSeen,
                    'risk': risk,
                    'latitude': latitude,
                    'longitude': longitude,
                    'countryId': countryId,
                    'campaigns': campaigns,
                    'campaignIds': campaignIds,
                    'signatures': signatures,
                    'signatureIds': signatureIds,
                    'threatActors': threatActors,
                    'threatActorIds': threatActorIds,
                    'tags': tags,
                    'tagIds': tagIds,
                    'fqdns': fqdns,
                    'fqdnIds': fqdnIds,
                    'sparks': sparks,
                    'sparkIds': sparkIds,
                    'bots': bots,
                    'botIds': botIds
                }
            }
        })
    else:
        notFound()


def blueliv_indicatorFqdn(client: Client, args):
    nameFQDN = args.get('FQDN', '')
    valueFQDN = args.get('FQDN_id', '')

    if not valueFQDN and not nameFQDN:
        notFound()
    if not valueFQDN and nameFQDN:
        valueFQDN = client.search_by_name('fqdn', nameFQDN)
    if not valueFQDN:
        notFound()
        sys.exit()

    result = client.get_fqdn_info(valueFQDN)
    if result:
        # PARAMETROS GENERALES #
        lastSeen = str(demisto.get(result, "data.attributes.last_seen"))
        risk = str(demisto.get(result, "data.attributes.risk"))

        # CAMPAIGNS #
        campaigns = demisto.get(result, "data.relationships.campaigns.meta.count")
        campaignIds = ""
        if campaigns:
            campaignIds = client.get_relationships("fqdn", valueFQDN, "campaign")

        # SIGNATURES #
        signatures = demisto.get(result, "data.relationships.signatures.meta.count")
        signatureIds = ""
        if signatures:
            signatureIds = client.get_relationships("fqdn", valueFQDN, "signature")

        # THREAT ACTORS #
        threatActors = demisto.get(result, "data.relationships.threat_actors.meta.count")
        threatActorIds = ""
        if threatActors:
            threatActorIds = client.get_relationships("fqdn", valueFQDN, "threat-actor")

        # TAGS #
        tags = demisto.get(result, "data.relationships.tags.meta.count")
        tagIds = ""
        if tags:
            tagIds = client.get_relationships("fqdn", valueFQDN, "tag")

        # CRIME SERVERS #
        crimeServers = demisto.get(result, "data.relationships.crime_servers.meta.count")
        crimeServerIds = ""
        if crimeServers:
            crimeServerIds = client.get_relationships("fqdn", valueFQDN, "crime-server")

        # SPARKS #
        sparks = demisto.get(result, "data.relationships.sparks.meta.count")
        sparkIds = ""
        if sparks:
            sparkIds = client.get_relationships("fqdn", valueFQDN, "spark")

        # IPs #
        ips = demisto.get(result, "data.relationships.ips.meta.count")
        ipIds = ""
        if ips:
            ipIds = client.get_relationships("fqdn", valueFQDN, "ip")

        human = getHuman(result)
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv FQDN info", human),
            'EntryContext': {
                'BluelivThreatContext.indicator(val.id && val.id == obj.id)': {
                    'id': valueFQDN,
                    'lastSeen': lastSeen,
                    'risk': risk,
                    'campaigns': campaigns,
                    'campaignIds': campaignIds,
                    'signatures': signatures,
                    'signatureIds': signatureIds,
                    'threatActors': threatActors,
                    'threatActorIds': threatActorIds,
                    'tags': tags,
                    'tagids': tagIds,
                    'crimeServers': crimeServers,
                    'crimeServerIds': crimeServerIds,
                    'sparks': sparks,
                    'sparkIds': sparkIds,
                    'ips': ips,
                    'ipIds': ipIds
                }
            }
        })
    else:
        notFound()


# Get information about the crime server related with the provided URL
def blueliv_indicatorCs(client: Client, args):
    nameCS = args.get('CS', '')
    valueCS = args.get('CS_id', '')

    if not valueCS and not nameCS:
        notFound()
    if not valueCS and nameCS:
        valueCS = client.search_by_name('crime-server', nameCS)
    if not valueCS:
        notFound()
        sys.exit()

    result = client.get_crime_server_info(valueCS)

    if result:
        lastSeen = str(demisto.get(result, "data.attributes.last_seen"))
        status = str(demisto.get(result, "data.attributes.status"))
        risk = str(demisto.get(result, "data.attributes.risk"))
        isFalsePositive = str(demisto.get(result, "data.attributes.is_false_positive"))
        crimeServerUrl = str(demisto.get(result, "data.attributes.crime_server_url"))
        creditCardsCount = str(demisto.get(result, "data.attributes.credit_cards_count"))
        credentialsCount = str(demisto.get(result, "data.attributes.credentials_count"))
        botsCount = str(demisto.get(result, "data.attributes.bots_count"))
        fqdnId = demisto.get(result, "data.relationships.fqdn.data.id")

        # SOURCES #
        sourceIds = ""
        sources = demisto.get(result, "data.relationships.sources.meta.count")
        if sources:
            sourceIds = client.get_relationships("crime-server", valueCS, "source")

        # MALWARE #
        malwareIds = ""
        malware = demisto.get(result, "data.relationships.malware.meta.count")
        if malware:
            malwareIds = client.get_relationships("crime-server", valueCS, "malware")

        # TAGS #
        tags = demisto.get(result, "data.relationships.tags.meta.count")
        tagIds = ""
        if tags:
            tagIds = client.get_relationships("crime-server", valueCS, "tag")

        # SPARKS #
        sparks = demisto.get(result, "data.relationships.sparks.meta.count")
        sparkIds = ""
        if sparks:
            sparkIds = client.get_relationships("crime-server", valueCS, "spark")

        human = getHuman(result)
        demisto.results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': result,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv Crime Server info", human),
            'EntryContext': {
                'BluelivThreatContext.indicator(val.id && val.id == obj.id)': {
                    'id': valueCS,
                    'lastSeen': lastSeen,
                    'status': status,
                    'risk': risk,
                    'isFalsePositive': isFalsePositive,
                    'crimeServerUrl': crimeServerUrl,
                    'creditCardsCount': creditCardsCount,
                    'credentialsCount': credentialsCount,
                    'botsCount': botsCount,
                    'fqdnId': fqdnId,
                    'malware': malware,
                    'malwareIds': malwareIds,
                    'tags': tags,
                    'tagIds': tagIds,
                    'sparks': sparks,
                    'sparkIds': sparkIds,
                    'sources': sources,
                    'sourceIds': sourceIds
                }
            }
        })
    else:
        notFound()


# Get information about attack patterns
def blueliv_attackPattern(client: Client, args):
    attackPatternName = args.get('attackPattern', '')
    attackPatternId = args.get('attackPattern_id', '')

    if attackPatternId:
        attackPatternId = int(attackPatternId)

    if not attackPatternId:
        attackPatternId = client.search_by_name('attack-pattern', attackPatternName)

    if attackPatternId:
        result = client.get_attack_pattern_info(attackPatternId)

        if result:
            updatedAt = demisto.get(result, "data.attributes.updated_at")
            name = demisto.get(result, "data.attributes.name")
            description = demisto.get(result, "data.attributes.description")
            serverity = demisto.get(result, "data.attributes.severity")

            # SIGNATURES #
            signatures = demisto.get(result, "data.relationships.signatures.meta.count")
            signatureIds = ""
            if signatures:
                signatureIds = client.get_relationships("attack-pattern", str(attackPatternId), "signature")

            # CAMPAIGNS #
            campaigns = demisto.get(result, "data.relationships.campaigns.meta.count")
            campaignIds = ""
            if campaigns:
                campaignIds = client.get_relationships("attack-pattern", str(attackPatternId), "campaign")

            # THREAT ACTORS #
            threatActorIds = ""
            threatActors = demisto.get(result, "data.relationships.threat_actors.meta.count")
            if threatActors:
                threatActorIds = client.get_relationships("attack-pattern", str(attackPatternId), "threat-actor")

            # CVEs #
            cveIds = ""
            cves = demisto.get(result, "data.relationships.cves.meta.count")
            if cves:
                cves = client.get_relationships("attack-pattern", str(attackPatternId), "cve")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Attack Pattern info", human),
                'EntryContext': {
                    'BluelivThreatContext.attackPattern(val.id && val.id == obj.id)': {
                        'id': attackPatternId,
                        'name': name,
                        'description': description,
                        'updatedAt': updatedAt,
                        'serverity': serverity,
                        'signatures': signatures,
                        'signatureIds': signatureIds,
                        'campaigns': campaigns,
                        'campaignIds': campaignIds,
                        'threatActors': threatActors,
                        'threatActorIds': threatActorIds,
                        'cves': cves,
                        'cveIds': cveIds
                    }
                }
            })
        else:
            notFound()
    else:
        notFound()


# Get information about tools
def blueliv_tool(client: Client, args):
    toolName = args.get('tool', '')
    toolId = args.get('tool_id', '')

    if not toolId:
        toolId = client.search_by_name('tool', toolName)

    if toolId:
        result = client.get_tool_info(toolId)

        if result:
            name = demisto.get(result, "data.attributes.name")
            description = demisto.get(result, "data.attributes.description")
            lastSeen = demisto.get(result, "data.attributes.last_seen")

            # CAMPAIGNS #
            campaigns = demisto.get(result, "data.relationships.campaigns.meta.count")
            campaignIds = ""
            if campaigns:
                campaignIds = client.get_relationships("tool", str(toolId), "campaign")

            # SIGNATURES #
            signatures = demisto.get(result, "data.relationships.signatures.meta.count")
            signatureIds = ""
            if signatures:
                signatureIds = client.get_relationships("tool", str(toolId), "signature")

            # THREAT ACTORS #
            threatActorIds = ""
            threatActors = demisto.get(result, "data.relationships.threat_actors.meta.count")
            if threatActors:
                threatActorIds = client.get_relationships("tool", str(toolId), "threat-actor")

            human = getHuman(result)
            demisto.results({
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': result,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown("Blueliv Tool info", human),
                'EntryContext': {
                    'BluelivThreatContext.tool(val.id && val.id == obj.id)': {
                        'id': toolId,
                        'name': name,
                        'description': description,
                        'lastSeen': lastSeen,
                        'campaigns': campaigns,
                        'campaignIds': campaignIds,
                        'signatures': signatures,
                        'signatureIds': signatureIds,
                        'threatActors': threatActors,
                        'threatActorIds': threatActorIds
                    }
                }
            })
        else:
            notFound()
    else:
        notFound()


def blueliv_signature(client: Client, args):
    signatureName = args.get('signature', '')
    signatureId = args.get('signature_id', '')

    if not signatureId:
        signatureId = client.search_by_name('signature', signatureName)

    if signatureId:
        result = client.get_signature_info(signatureId)

        if result:
            name = demisto.get(result, "data.attributes.name")
            signatureType = demisto.get(result, "data.attributes.type")
            updatedAt = demisto.get(result, "data.attributes.updated_at")

            # MALWARE #
            malwareIds = ""
            malware = demisto.get(result, "data.relationships.malware.meta.count")
            if malware:
                malwareIds = client.get_relationships("signature", str(signatureId), "malware")

            human = getHuman(result)
            demisto.results({
                "Type": entryTypes["note"],
                'Contents': result,
                "ContentsFormat": formats["json"],
                'HumanReadable': tableToMarkdown("Blueliv Signature info", human),
                'ReadableContentsFormat': formats['markdown'],
                'EntryContext': {
                    'BluelivThreatContext.signature(val.id && val.id == obj.id)': {
                        'id': signatureId,
                        'name': name,
                        'type': signatureType,
                        'updatedAt': updatedAt,
                        'malware': malware,
                        'malwareIds': malwareIds
                    }
                }
            })
        else:
            notFound()
    else:
        notFound()


# Get inforamtion abouth the provided CVE code
def blueliv_cve(client: Client, args):
    cveCode = args.get('CVE', '')
    vulnId = args.get('CVE_id', '')

    if not vulnId:
        vulnId = cveCode

    result = client.get_cve_info(vulnId)

    if result:
        name = demisto.get(result, "data.attributes.name")
        description = demisto.get(result, "data.attributes.description")
        updatedAt = demisto.get(result, "data.attributes.updated_at")
        score = demisto.get(result, "data.attributes.score")
        exploitsTableData = demisto.get(result, "data.attributes.exploits")
        platformsTableData = demisto.get(result, "data.attributes.platforms")

        # ATTACK PATTERNS
        attackPatternIds = ""
        attackPatterns = demisto.get(result, "data.relationships.attack_patterns.meta.count")
        if attackPatterns:
            attackPatternIds = client.get_relationships("cve", str(vulnId), "attack-pattern")

        # SIGNATURES #
        signatures = demisto.get(result, "data.relationships.signatures.meta.count")
        signatureIds = ""
        if signatures:
            signatureIds = client.get_relationships("cve", str(vulnId), "signature")

        # TAGS #
        tagIds = ""
        tags = demisto.get(result, "data.relationships.tags.meta.count")
        if tags:
            tagIds = client.get_relationships("cve", str(vulnId), "tag")

        # CRIME SERVERS #
        crimeServerIds = ""
        crimeServers = demisto.get(result, "data.relationships.crime_servers.meta.count")
        if crimeServers:
            crimeServerIds = client.get_relationships("cve", str(vulnId), "crime-server")

        # SPARKS #
        sparkIds = ""
        sparks = demisto.get(result, "data.relationships.sparks.meta.count")
        if sparks:
            sparkIds = client.get_relationships("cve", vulnId, "spark")

        # MALWARE #
        malwareIds = ""
        malware = demisto.get(result, "data.relationships.malware.meta.count")
        if malware:
            malwareIds = client.get_relationships("cve", vulnId, "malware")

        human = getHuman(result)
        demisto.results({
            "Type": entryTypes["note"],
            'Contents': result,
            "ContentsFormat": formats["json"],
            'HumanReadable': tableToMarkdown("Blueliv CVE info", human),
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                'BluelivThreatContext.cve(val.id && val.id == obj.id)': {
                    'id': vulnId,
                    'name': name,
                    'description': description,
                    'updatedAt': updatedAt,
                    'score': score,
                    'attackPatterns': attackPatterns,
                    'attackPatternIds': attackPatternIds,
                    'signatures': signatures,
                    'signatureIds': signatureIds,
                    'tags': tags,
                    'tagIds': tagIds,
                    'crimeServers': crimeServers,
                    'crimeServerIds,': crimeServerIds,
                    'sparks': sparks,
                    'sparkIds': sparkIds,
                    'malware': malware,
                    'malwareIds': malwareIds,
                    'exploits': exploitsTableData,
                    'platforms': platformsTableData
                }
            }
        })
    else:
        notFound()


# DEMISTO command evaluation
def main():
    params = demisto.params()
    server_url = params.get('url')
    verify_ssl = not params.get('unsecure', '')
    proxy = params.get('proxy')
    username = params['credentials']['identifier']
    password = params['credentials']['password']

    client = Client(server_url, verify_ssl, proxy, headers={'Accept': 'application/json'})
    token = client.authenticate(username, password)

    args = demisto.args()
    if demisto.command() == 'test-module':
        # Checks if the user is correctly authenticated. If the execution gets here all is correct.
        demisto.results("ok")

    if demisto.command() == 'blueliv-authenticate':
        demisto.results({
            "Type": entryTypes["note"],
            'Contents': token,
            "ContentsFormat": formats["text"],
            'EntryContext': {'BluelivThreatContext.token': token}
        })

    elif demisto.command() == 'blueliv-tc-threat-actor':
        blueliv_threatActor(client, args)

    elif demisto.command() == 'blueliv-tc-campaign':
        blueliv_campaign(client, args)

    elif demisto.command() == 'blueliv-tc-malware':
        blueliv_malware(client, args)

    elif demisto.command() == 'blueliv-tc-indicator-ip':
        blueliv_indicatorIp(client, args)

    elif demisto.command() == 'blueliv-tc-indicator-fqdn':
        blueliv_indicatorFqdn(client, args)

    elif demisto.command() == 'blueliv-tc-indicator-cs':
        blueliv_indicatorCs(client, args)

    elif demisto.command() == 'blueliv-tc-attack-pattern':
        blueliv_attackPattern(client, args)

    elif demisto.command() == 'blueliv-tc-tool':
        blueliv_tool(client, args)

    elif demisto.command() == 'blueliv-tc-signature':
        blueliv_signature(client, args)

    elif demisto.command() == 'blueliv-tc-cve':
        blueliv_cve(client, args)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
