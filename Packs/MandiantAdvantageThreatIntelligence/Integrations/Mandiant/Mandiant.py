from collections.abc import Callable
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type:ignore


API_BASE_URL = "https://api.intelligence.mandiant.com"

MOCK_IP_INDICATOR = {
    "id": "ipv4--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "ipv4",
    "value": "1.2.3.4",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 100
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_DOMAIN_INDICATOR = {
    "id": "fqdn--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "fqdn",
    "value": "domain.test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_URL_INDICATOR = {
    "id": "url--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "url",
    "value": "https://domain.test/test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_FILE_INDICATOR = {
    "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "md5",
    "value": "ae1747c930e9e4f45fbc970a83b52284",
    "is_exclusive": True,
    "is_publishable": True,
    "associated_hashes": [
        {
            "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "md5",
            "value": "ae1747c930e9e4f45fbc970a83b52284"
        },
        {
            "id": "sha1--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha1",
            "value": "638cde28bbe3cfe7b53aa75a7cf6991baa692a4a"
        },
        {
            "id": "sha256--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha256",
            "value": "f68ec69a53130a24b0fe53d1d1fe70992d86a6d67006ae45f986f9ef4f450b6c"
        }
    ],
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}


class MandiantClient(BaseClient):
    def __init__(self, conf: Dict):
        verify = not conf.get("insecure", False)
        proxy = conf.get("proxy", False)
        super().__init__(base_url=API_BASE_URL, verify=verify, proxy=proxy, ok_codes=(200,))
        self.api_key = conf.get("api_key")
        self.secret_key = conf.get("secret_key")

        self.headers = {
            "X-App-Name": "content.xsoar.cortex.mandiant.enrichment.v1.1",
            "Accept": "application/json"
        }
        self.timeout = int(conf.get("timeout", 60))
        self.tlp_color = conf.get("tlp_color", "")
        self.tags = argToList(conf.get("tags", []))
        self.reliability = conf.get("reliability", "")

    def _get(self, url: str, params: Dict = {}) -> Dict:
        try:
            return self._http_request(method="GET", url_suffix=url, auth=(self.api_key, self.secret_key),
                                      headers=self.headers, timeout=self.timeout, params=params)
        except DemistoException as ex:
            raise DemistoException(str(ex))

    def _post(self, url: str, post_body: dict) -> Dict:
        try:
            return self._http_request(method="POST", url_suffix=url, auth=(self.api_key, self.secret_key),
                                      headers=self.headers, timeout=self.timeout, json_data=post_body)
        except DemistoException as ex:
            raise DemistoException(str(ex))

    def get_entitlements(self) -> Dict:
        return self._get("/v4/entitlements")

    def get_indicators_by_value(self, values_: List) -> List[Dict[str, Any]]:
        post_body = {
            "requests": [{"values": values_}],
            "include_campaigns": True,
            "include_threat_rating": True,
            "include_reports": True,
            "exclude_misp": True
        }
        url = "/v4/indicator"
        response = self._post(url, post_body)
        response = response.get("indicators", [])

        return response

    def get_actor(self, actor_name: str) -> Dict:
        return self._get(f"/v4/actor/{actor_name}")

    def get_malware(self, malware_name: str) -> Dict:
        return self._get(f"/v4/malware/{malware_name}")

    def get_associated_reports(self, intel_type: str, intel_id: str) -> Dict:
        return self._get(f"/v4/{intel_type}/{intel_id}/reports")

    def get_campaign(self, campaign_id: str) -> Dict:
        return self._get(f"/v4/campaign/{campaign_id}")

    def get_attack_patterns(self, intel_type: str, intel_id: str) -> Dict:
        return self._get(f"/v4/{intel_type}/{intel_id}/attack-pattern")

    def get_associated_campaigns(self, intel_type: str, intel_id: str) -> Dict:
        return self._get(f"v4/{intel_type}/{intel_id}/campaigns")

    def get_cve_by_cveid(self, cve_id: str) -> Dict:
        return self._get(f"/v4/vulnerability/{cve_id}?rating_types=analyst,predicted,unrated")


def calculate_dbot_score(threat_score: int):
    if not threat_score:
        return Common.DBotScore.NONE
    elif threat_score < 0 or threat_score == 0:
        return Common.DBotScore.NONE
    elif 0 <= threat_score <= 20:
        return Common.DBotScore.GOOD
    elif 21 <= threat_score <= 80:
        return Common.DBotScore.SUSPICIOUS
    elif 81 <= threat_score <= 100:
        return Common.DBotScore.BAD
    else:
        return Common.DBotScore.NONE


def create_dbot_score(indicator_value: str, indicator_type: str, reliability: str, threat_score: int) -> Common.DBotScore:
    return Common.DBotScore(
        indicator=indicator_value,
        indicator_type=indicator_type,
        integration_name="Mandiant",
        reliability=reliability,
        score=calculate_dbot_score(threat_score)
    )


def build_sources(indicator: Dict) -> List:
    return [s.get("source_name", "").lower() for s in indicator.get("sources", [])]


def get_indicator_campaigns(indicator: Dict) -> str:
    campaigns: List[str] = []

    if not indicator.get("campaigns"):
        return "-"

    for c in indicator.get("campaigns", []):
        title = c.get("title")
        campaign_id = c.get("name")
        if not title or not campaign_id:
            continue
        campaigns.append(f"{title} ({campaign_id})")

    return ", ".join(list(campaigns)) if campaigns else "-"


def get_indicator_malware_families(indicator: Dict) -> str:
    malware = []
    associations = indicator.get("attributed_associations", [])

    if not associations:
        return "-"

    for association in associations:
        association_type = association.get("type")
        association_name = association.get("name")
        if not association_type or not association_name:
            continue
        if association_type == "malware":
            malware.append(association_name)

    return ", ".join(malware) if malware else "-"


def get_indicator_reports(indicator: Dict):
    publications = []

    for r in indicator.get("reports", []):
        title = r.get("title")
        report_id = r.get("report_id")
        published = r.get("published_date")

        if not title or not report_id or not published:
            continue

        publications.append(Common.Publications(source="Mandiant", title=f"{title} ({report_id})",
                                                link=f"https://advantage.mandiant.com/reports/{report_id}",
                                                timestamp=published))
    return publications


def build_relationship(name: str, reverse_name: str, entity_a: str, entity_a_type: str,
                       entity_b: str, entity_b_type: str) -> EntityRelationship:
    return EntityRelationship(name=name, reverse_name=reverse_name, entity_a=entity_a,
                              entity_a_type=entity_a_type, entity_b=entity_b, entity_b_type=entity_b_type)


def build_indicator_relationships(indicator: Dict) -> List:
    indicator_ffed_type_map = {
        "ipv4": FeedIndicatorType.IP,
        "fqdn": FeedIndicatorType.Domain,
        "url": FeedIndicatorType.URL,
        "md5": FeedIndicatorType.File,
    }
    relationships: List = []
    associations = indicator.get("attributed_associations", [])
    entity_a = indicator.get("value", "")
    entity_a_type = indicator_ffed_type_map.get(indicator.get("type", ""), "")

    if not associations:
        return relationships

    for association in associations:
        association_type = association.get("type", "")
        entity_b = association.get("name", "")

        if association_type == "threat-actor":
            relationships.append(build_relationship("uses", "used-by", entity_a, entity_a_type,
                                                    entity_b, "Threat Actor"))
        elif association_type == "malware":
            relationships.append(build_relationship("indicates", "indicated-by", entity_a, entity_a_type,
                                                    entity_b, "Malware"))

    return relationships


def build_threat_types(indicator: Dict) -> List:
    threat_types = []
    for source in indicator.get("sources", []):
        for c in source.get("category", []):
            t = Common.ThreatTypes(threat_category=c,
                                   threat_category_confidence=str(indicator.get("mscore", 0)))
            threat_types.append(t)

    return threat_types


def build_indicator_markdown(value_: str, indicator: Dict) -> str:
    indicator_type = indicator.get("type")
    indicator_id = indicator.get("id")

    categories = set()
    for t in build_threat_types(indicator):
        categories.add(t.threat_category)

    reports_list: List = [r.title for r in get_indicator_reports(indicator)]

    table = {
        "Threat Score": indicator.get("threat_rating", {}).get("threat_score", 0),
        "Last Seen": indicator.get("last_seen"),
        "Malware": get_indicator_malware_families(indicator),
        "Campaigns": get_indicator_campaigns(indicator),
        "Categories": ", ".join(list(categories)) if categories else "-",
        "Reports": ", ".join(reports_list) if reports_list else "-"
    }

    return tableToMarkdown(f"Mandiant Advantage Threat Intelligence information for {value_}\n"
                           f"[View on Mandiant Advantage](https://advantage.mandiant.com/indicator/"
                           f"{indicator_type}/{indicator_id})", table)


def enrich_indicator(indicator_object: Common.IP | Common.Domain | Common.URL | Common.File, indicator: Dict,
                     relationships: List, tags: List, tlp_color: str) -> Common.IP | Common.Domain | Common.URL | Common.File:
    indicator_object.campaign = get_indicator_campaigns(indicator)
    indicator_object.malware_family = get_indicator_malware_families(indicator)
    indicator_object.publications = get_indicator_reports(indicator)
    indicator_object.relationships = relationships
    indicator_object.stix_id = indicator.get("id", "")
    indicator_tags = [t.threat_category for t in build_threat_types(indicator)]
    for t in tags:
        indicator_tags.append(t)
    indicator_object.tags = indicator_tags

    sources = build_sources(indicator)
    indicator_object.traffic_light_protocol = "GREEN" if "mandiant" not in sources else tlp_color

    return indicator_object


def get_hash_value(indicator: dict, hash_type: str) -> str:
    hash_value = ""
    for a in indicator.get("associated_hashes", []):
        hash_value = a.get("value", "") if a.get("type") == hash_type else ""
        if hash_value:
            break
    return hash_value


def ip_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("ip")))
    output = []

    for v in values_:
        # api_response = client.get_indicators_by_value([v])
        api_response: List[Dict[str, Any]] = [MOCK_IP_INDICATOR]
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            threat_score = i.get("threat_rating", {}).get("threat_score", 0)
            dbot_score = create_dbot_score(v, DBotScoreType.IP, client.reliability, threat_score)
            relationships = build_indicator_relationships(i)
            xsoar_indicator = Common.IP(ip=v, dbot_score=dbot_score)
            xsoar_indicator = enrich_indicator(xsoar_indicator, i, relationships, client.tags, client.tlp_color)
            markdown = build_indicator_markdown(v, i)

            output.append(CommandResults(readable_output=markdown, outputs=i, outputs_prefix="Mandiant.IP",
                                         indicator=xsoar_indicator, ignore_auto_extract=False,
                                         relationships=relationships))
    return output


def domain_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("domain")))
    output = []

    for v in values_:
        # api_response = client.get_indicators_by_value([v])
        api_response: List[Dict[str, Any]] = [MOCK_DOMAIN_INDICATOR]
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            threat_score = i.get("threat_rating", {}).get("threat_score", 0)
            dbot_score = create_dbot_score(v, DBotScoreType.DOMAIN, client.reliability, threat_score)
            relationships = build_indicator_relationships(i)
            xsoar_indicator = Common.Domain(domain=v, dbot_score=dbot_score)
            xsoar_indicator = enrich_indicator(xsoar_indicator, i, relationships, client.tags, client.tlp_color)
            markdown = build_indicator_markdown(v, i)

            output.append(CommandResults(readable_output=markdown, outputs=i, outputs_prefix="Mandiant.Domain",
                                         indicator=xsoar_indicator, ignore_auto_extract=False,
                                         relationships=relationships))
    return output


def url_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("url")))
    output = []

    for v in values_:
        # api_response = client.get_indicators_by_value([v])
        api_response: List[Dict[str, Any]] = [MOCK_URL_INDICATOR]
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            threat_score = i.get("threat_rating", {}).get("threat_score", 0)
            dbot_score = create_dbot_score(v, DBotScoreType.URL, client.reliability, threat_score)
            relationships = build_indicator_relationships(i)
            xsoar_indicator = Common.URL(url=v, dbot_score=dbot_score)
            xsoar_indicator = enrich_indicator(xsoar_indicator, i, relationships, client.tags, client.tlp_color)
            markdown = build_indicator_markdown(v, i)

            output.append(CommandResults(readable_output=markdown, outputs=i, outputs_prefix="Mandiant.URL",
                                         indicator=xsoar_indicator, ignore_auto_extract=False,
                                         relationships=relationships))
    return output


def file_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("file")))
    output = []

    for v in values_:
        # api_response = client.get_indicators_by_value([v])
        api_response: List[Dict[str, Any]] = [MOCK_FILE_INDICATOR]
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            threat_score = i.get("threat_rating", {}).get("threat_score", 0)
            dbot_score = create_dbot_score(v, DBotScoreType.FILE, client.reliability, threat_score)
            relationships = build_indicator_relationships(i)
            xsoar_indicator = Common.File(name=v, md5=i.get("value"), dbot_score=dbot_score)

            sha1 = get_hash_value(i, "sha1")
            sha256 = get_hash_value(i, "sha256")
            if sha1:
                xsoar_indicator.sha1 = sha1
            if sha256:
                xsoar_indicator.sha256 = sha256

            xsoar_indicator = enrich_indicator(xsoar_indicator, i, relationships, client.tags, client.tlp_color)
            markdown = build_indicator_markdown(v, i)

            output.append(CommandResults(readable_output=markdown, outputs=i, outputs_prefix="Mandiant.File",
                                         indicator=xsoar_indicator, ignore_auto_extract=False,
                                         relationships=relationships))
    return output


def cve_reputation_command(client: MandiantClient, args: Dict):
    pass


def fetch_threat_actor_command(client: MandiantClient, args: Dict):
    pass


def fetch_malware_family_command(client: MandiantClient, args: Dict):
    pass


def fetch_campaign_command(client: MandiantClient, args: Dict):
    pass


def module_test_command(client: MandiantClient) -> str:
    try:
        result = client.get_entitlements()
        if not result.get("entitlements"):
            raise Exception
        return "ok"
    except DemistoException as ex:
        raise DemistoException(str(ex))


def main() -> None:
    command = demisto.command()
    args = demisto.args()

    client = MandiantClient(demisto.params())

    try:
        command_map: dict[str, Callable] = {
            "ip": ip_reputation_command,
            "domain": domain_reputation_command,
            "url": url_reputation_command,
            "file": file_reputation_command,
            "cve": cve_reputation_command,
            "mati-get-actor": fetch_threat_actor_command,
            "mati-get-malware": fetch_malware_family_command,
            "mati-get-campaign": fetch_campaign_command
        }

        if command in command_map:
            return_results(command_map[command](client, args))
        elif command == "test-module":
            return_results(module_test_command(client))

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
