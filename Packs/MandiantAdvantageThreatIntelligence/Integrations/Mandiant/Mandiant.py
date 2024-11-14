from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from collections.abc import Callable, Generator


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type:ignore


API_BASE_URL = "https://api.intelligence.mandiant.com"
ADV_BASE_URL = "https://advantage.mandiant.com"


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
        self.map_to_mitre_attack = conf.get("map_to_mitre_attack", False)

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
        actor = self._get(f"/v4/actor/{actor_name}")
        return actor

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

    def get_mitre_attack_patterns(self) -> Dict:
        if not self.map_to_mitre_attack:
            return {}

        response = demisto.searchIndicators(**{"query": "type:\"Attack Pattern\" and sourceBrands:\"MITRE ATT&CK v2\"",
                                               "populateFields": "name, tags",
                                               "size": 1000})
        res_dict = {}

        for ioc in response.get("iocs", []):
            tags = ioc.get("CustomFields", {}).get("tags", "")
            name_ = ioc.get("CustomFields", {}).get("name", "")
            if not isinstance(tags, list):
                key_ = tags
                res_dict[key_] = name_
            else:
                for t in tags:
                    res_dict[t] = name_

        return res_dict


class MatiIndicator:
    def __init__(self, client: MandiantClient, ioc_data: Dict, ioc_type: str) -> None:
        self.client = client
        self.ioc_data = ioc_data
        self.ioc_type = ioc_type
        self.dbot_score_type: str
        self.indicator_object: Common.IP | Common.Domain | Common.URL | Common.File
        self.outputs_prefix: str
        self.ioc_value = self.ioc_data.get("value", "")
        self.threat_score = self.build_threat_score()
        self.sources = self.get_sources()
        self.relationships = self.build_relationships()

    def build_threat_score(self) -> int:
        return self.ioc_data.get("threat_rating", {}).get("threat_score", 0)

    def build_relationships(self) -> List:
        relationships: List = []

        for association in self.ioc_data.get("attributed_associations", []):
            association_type = association.get("type", "")
            entity_b = association.get("name", "")

            if association_type == "threat-actor":
                relationships.append(EntityRelationship(name="uses", reverse_name="used-by", entity_a=self.ioc_value,
                                                        entity_a_type=self.ioc_type, entity_b=entity_b,
                                                        entity_b_type="Threat Actor"))
            elif association_type == "malware":
                relationships.append(EntityRelationship(name="indicates", reverse_name="indicated-by",
                                                        entity_a=self.ioc_value, entity_a_type=self.ioc_type,
                                                        entity_b=entity_b, entity_b_type="Malware"))
        return relationships

    def calculate_dbot_score(self) -> int:
        if self.threat_score is None:
            return Common.DBotScore.NONE
        if 0 <= self.threat_score <= 20:
            return Common.DBotScore.GOOD
        elif 21 <= self.threat_score <= 80:
            return Common.DBotScore.SUSPICIOUS
        elif 81 <= self.threat_score <= 100:
            return Common.DBotScore.BAD
        else:
            return Common.DBotScore.NONE

    def create_dbot_score(self) -> Common.DBotScore:
        return Common.DBotScore(
            indicator=self.ioc_value,
            indicator_type=self.dbot_score_type,
            integration_name="Mandiant",
            reliability=self.client.reliability,
            score=self.calculate_dbot_score()
        )

    def build_campaigns(self) -> str:
        campaigns_list: List[str] = []

        for c in self.ioc_data.get("campaigns", []):
            title = c.get("title", "")
            campaign_id = c.get("name", "")
            if not title or not campaign_id:
                continue
            campaigns_list.append(f"{title} ({campaign_id})")

        return ", ".join(campaigns_list) if campaigns_list else "-"

    def build_malware_families(self) -> str:
        malware_list = []

        for association in self.ioc_data.get("attributed_associations", []):
            association_type = association.get("type", "")
            association_name = association.get("name", "")
            if not association_type or not association_name:
                continue
            if association_type == "malware":
                malware_list.append(association_name)

        return ", ".join(malware_list) if malware_list else "-"

    def build_publications(self):
        publications = []

        for r in self.ioc_data.get("reports", []):
            title = r.get("title", "")
            report_id = r.get("report_id", "")
            published = r.get("published_date")

            if not title or not report_id or not published:
                continue

            publications.append(Common.Publications(source="Mandiant", title=f"{title} ({report_id})",
                                                    link=f"{ADV_BASE_URL}/reports/{report_id}",
                                                    timestamp=published))
        return publications

    def get_stix_id(self) -> str:
        return self.ioc_data.get("id", "")

    def get_sources(self) -> List:
        return self.ioc_data.get("sources", [])

    def build_threat_types(self) -> List:
        threat_types = []
        for source in self.sources:
            for c in source.get("category", []):
                t = Common.ThreatTypes(threat_category=c,
                                       threat_category_confidence=str(self.ioc_data.get("mscore", 0)))
                threat_types.append(t)

        return threat_types

    def build_source_names(self) -> List:
        return [s.get("source_name", "").lower() for s in self.sources]

    def build_indicator(self, indicator_object: Common.IP | Common.Domain | Common.URL | Common.File):
        indicator_object.campaign = self.build_campaigns()
        indicator_object.malware_family = self.build_malware_families()
        indicator_object.publications = self.build_publications()
        indicator_object.relationships = self.relationships
        indicator_object.stix_id = self.get_stix_id()
        indicator_tags = [t.threat_category for t in self.build_threat_types()]
        for t in self.client.tags:
            indicator_tags.append(t)
        indicator_object.tags = indicator_tags
        sources = self.build_source_names()
        indicator_object.traffic_light_protocol = "GREEN" if "mandiant" not in sources else self.client.tlp_color

        return indicator_object

    def build_markdown(self) -> str:
        ioc_type = self.ioc_data.get("type", "")
        categories = set()
        for t in self.build_threat_types():
            categories.add(t.threat_category)

        reports_list: List = [r.title for r in self.build_publications()]

        table = {
            "Threat Score": self.threat_score,
            "Last Seen": self.ioc_data.get("last_seen"),
            "Malware": self.build_malware_families(),
            "Campaigns": self.build_campaigns(),
            "Categories": ", ".join(list(categories)) if categories else "-",
            "Reports": ", ".join(reports_list) if reports_list else "-"
        }

        return tableToMarkdown(f"Mandiant Advantage Threat Intelligence information for {self.ioc_value}\n"
                               f"[View on Mandiant Advantage]({ADV_BASE_URL}/indicator/"
                               f"{ioc_type}/{self.get_stix_id()})", table)

    def build_indicator_command_result(self) -> CommandResults:
        return CommandResults(
            readable_output=self.build_markdown(),
            ignore_auto_extract=False,
            outputs_prefix=self.outputs_prefix,
            relationships=self.relationships,
            outputs=self.ioc_data,
            indicator=self.indicator_object
        )


class MatiIpIndicator(MatiIndicator):
    def __init__(self, client: MandiantClient, ioc_data: Dict) -> None:
        super().__init__(client, ioc_data, FeedIndicatorType.IP)
        self.dbot_score_type = DBotScoreType.IP
        self.outputs_prefix = "Mandiant.IP"
        self.indicator_object = self.build_indicator(Common.IP(ip=self.ioc_value, dbot_score=self.create_dbot_score()))


class MatiDomainIndicator(MatiIndicator):
    def __init__(self, client: MandiantClient, ioc_data: Dict) -> None:
        super().__init__(client, ioc_data, FeedIndicatorType.Domain)
        self.dbot_score_type = DBotScoreType.DOMAIN
        self.outputs_prefix = "Mandiant.Domain"
        self.indicator_object = self.build_indicator(Common.Domain(domain=self.ioc_value, dbot_score=self.create_dbot_score()))


class MatiUrlIndicator(MatiIndicator):
    def __init__(self, client: MandiantClient, ioc_data: Dict) -> None:
        super().__init__(client, ioc_data, FeedIndicatorType.URL)
        self.dbot_score_type = DBotScoreType.URL
        self.outputs_prefix = "Mandiant.URL"
        self.indicator_object = self.build_indicator(Common.URL(url=self.ioc_value, dbot_score=self.create_dbot_score()))


class MatiFileIndicator(MatiIndicator):
    def __init__(self, client: MandiantClient, ioc_data: Dict, ioc_value: str) -> None:
        super().__init__(client, ioc_data, FeedIndicatorType.File)
        self.dbot_score_type = DBotScoreType.FILE
        self.outputs_prefix = "Mandiant.File"
        self.ioc_value = ioc_value
        self.indicator_object = Common.File(name=self.ioc_value, dbot_score=self.create_dbot_score())
        md5 = self.get_hash_value("md5")
        sha1 = self.get_hash_value("sha1")
        sha256 = self.get_hash_value("sha256")
        if md5:
            self.indicator_object.md5 = md5
        if sha1:
            self.indicator_object.sha1 = sha1
        if sha256:
            self.indicator_object.sha256 = sha256
        self.indicator_object = self.build_indicator(self.indicator_object)

    def get_hash_value(self, hash_type: str) -> str:
        hash_value = ""
        for a in self.ioc_data.get("associated_hashes", []):
            hash_value = a.get("value", "") if a.get("type") == hash_type else ""
            if hash_value:
                break
        return hash_value


class MatiThreatActor:
    def __init__(self, client: MandiantClient, actor_data: Dict) -> None:
        self.client = client
        self.actor_data = actor_data
        self.actor_name = self.actor_data.get("value", "")
        self.actor_id = self.actor_data.get("id", "")
        self.description = self.actor_data.get("description")
        self.target_industries = self.build_target_industries()
        self.reports_list = self.get_associated_reports()

    def get_associated_reports(self) -> List:
        reports = []

        for report in self.client.get_associated_reports("actor", self.actor_id).get("reports", []):
            reports.append({
                "source": "Mandiant",
                "title": report.get("title", "-"),
                "link": "{}/reports/{}".format(ADV_BASE_URL, report.get("report_id")),
                "timestamp": datetime.strptime(report.get("published_date"), "%B %d, %Y %I:%M:%S %p").timestamp()
            })

        return reports

    def build_target_industries(self) -> List:
        return [i.get("name", "") for i in self.actor_data.get("industries", [])]

    def build_target_industries_str(self) -> str:
        return ", ".join(list(self.target_industries))

    def build_motivations(self) -> str:
        return ", ".join([m.get("name") for m in self.actor_data.get("motivations", [])])

    def build_target_countries(self) -> str:
        return ", ".join([c.get("name") for c in self.actor_data.get("locations", {}).get("target", ["Unknown"])])

    def build_associated_malware(self) -> str:
        return ", ".join([m.get("name", "") for m in self.actor_data.get("malware", ["-"])])

    def build_associated_tools(self) -> str:
        return ", ".join([t.get("name", "") for t in self.actor_data.get("tools", ["-"])])

    def build_associated_vulnerabilities(self) -> str:
        return ", ".join([cve.get("cve_id", "") for cve in self.actor_data.get("cve", ["-"])])

    def build_aliases(self) -> str:
        return ", ".join([a.get("name") for a in self.actor_data.get("aliases", [])])

    def build_primary_motivation(self) -> str:
        motivation_map = {
            "Financial Gain": "Cyber Crime",
            "Surveillance": "Cyber Crime",
            "Attack / Destruction": "Cyber Crime",
            "Influence": "",
            "Espionage": "Cyber Espionage",
            "Hacktivism": "Hacktivism",
            "Unknown": ""
        }

        motivations = [m.get("name") for m in self.actor_data.get("motivations", [])]

        for m in motivations:
            if motivation_map.get(m):
                return motivation_map.get(m, "")
        return ""

    def get_source_country(self) -> str:
        return self.actor_data.get("locations", {}).get("source", [])[0].get("country", {}).get("name", "Unknown")

    def get_last_activity_time(self) -> str:
        return self.actor_data.get("last_activity_time", "Unknown")

    def get_last_updated(self) -> str:
        return self.actor_data.get("last_updated", "Unknown")

    def build_attribute_md(self) -> str:
        attribute_table = {
            "Link": f"{ADV_BASE_URL}/actors/{self.actor_id}",
            "Motivations": self.build_motivations(),
            "Target Industries": self.build_target_industries_str(),
            "Associated Malware": self.build_associated_malware(),
            "Associated Tools": self.build_associated_tools(),
            "Associated Vulnerabilities": self.build_associated_vulnerabilities(),
            "Last Activity Time": self.get_last_activity_time(),
            "Last Updated": self.get_last_updated()
        }
        return tableToMarkdown("Threat Actor Attributes", attribute_table, url_keys=["Link"])

    def build_report_md(self) -> str:
        earliest_report = time.time() - (86400 * 90)
        report_table = [{"Title": r.get("title", ""), "Link": r.get("link", "")}
                        for r in self.reports_list if int(r.get("timestamp", 1)) > earliest_report]
        return tableToMarkdown("Recent Associated Reports", report_table, url_keys=["Link"])

    def build_actor_markdown(self) -> str:
        return (f"## {self.actor_name}\n\n"
                + f"{self.description}\n\n"
                + f"{self.build_attribute_md()}\n\n"
                + self.build_report_md())

    def build_malware_relationships(self) -> Generator:
        for malware in self.actor_data.get("malware", []):
            yield EntityRelationship(name="uses", reverse_name="used-by", entity_a=self.actor_name,
                                     entity_a_type="Threat Actor", entity_b=malware.get("name", ""),
                                     entity_b_type="Malware").to_indicator()

    def build_vulnerbility_relationships(self) -> Generator:
        for vuln in self.actor_data.get("cve", []):
            yield EntityRelationship(name="exploits", reverse_name="exploited-by", entity_a=self.actor_name,
                                     entity_a_type="Threat Actor", entity_b=vuln.get("cve_id", ""),
                                     entity_b_type="CVE").to_indicator()

    def build_unc_relationships(self) -> Generator:
        for unc in self.actor_data.get("associated_uncs", []):
            yield EntityRelationship(name="related-to", reverse_name="related-to", entity_a=self.actor_name,
                                     entity_a_type="Threat Actor", entity_b=unc.get("name", ""),
                                     entity_b_type="Threat Actor").to_indicator()

    def build_attack_pattern_relationships(self) -> Generator:
        attack_patterns = self.client.get_attack_patterns("actor", self.actor_id).get("attack-patterns", {})
        mitre_attack_patterns: Dict = self.client.get_mitre_attack_patterns()
        for ap in attack_patterns:
            ap_id = attack_patterns.get(ap).get("attack_pattern_identifier", "")
            ap_title = attack_patterns.get(ap).get("name", "")
            mitre_ap = mitre_attack_patterns.get(ap_id, "")
            entity_b = mitre_ap if mitre_ap else f"{ap_id}: {ap_title}"
            yield EntityRelationship(name="uses", reverse_name="used-by", entity_a=self.actor_name,
                                     entity_a_type="Threat Actor", entity_b=entity_b,
                                     entity_b_type="Attack Pattern").to_indicator()

    def build_campaign_relationships(self) -> Generator:
        for c in self.client.get_associated_campaigns("actor", self.actor_id).get("campaigns", []):
            campaign_id = c.get("short_name", "")
            campaign_title = c.get("name", "")
            yield EntityRelationship(name="related-to", reverse_name="related-to", entity_a=self.actor_name,
                                     entity_a_type="Threat Actor", entity_b=f"{campaign_title} ({campaign_id})",
                                     entity_b_type="Campaign").to_indicator()

    def build_actor_relationships(self) -> List:
        relationships = []

        for malware in self.build_malware_relationships():
            relationships.append(malware)

        for vuln in self.build_vulnerbility_relationships():
            relationships.append(vuln)

        for unc in self.build_unc_relationships():
            relationships.append(unc)

        for ap in self.build_attack_pattern_relationships():
            relationships.append(ap)

        for campaign in self.build_campaign_relationships():
            relationships.append(campaign)

        return relationships

    def build_indicator(self) -> Dict:
        return {
            "value": self.actor_name,
            "type": "Threat Actor",
            "rawJSON": self.actor_data,
            "score": ThreatIntel.ObjectsScore.THREAT_ACTOR,
            "fields": {
                "Aliases": self.build_aliases(),
                "STIX ID": self.actor_id,
                "Description": self.description,
                "Geo Country": self.get_source_country(),
                "Primary Motivation": self.build_primary_motivation(),
                "Tags": self.build_target_industries_str(),
                "Publications": self.reports_list,
                "Industry sectors": self.target_industries
            },
            "relationships": self.build_actor_relationships()
        }

    def build_threat_actor_command_result(self):
        return CommandResults(outputs=self.actor_data, ignore_auto_extract=False, outputs_prefix="Mandiant.Actor",
                              readable_output=self.build_actor_markdown(), tags=self.target_industries)


class MatiMalware:
    def __init__(self, client: MandiantClient, malware_data: Dict) -> None:
        self.client = client
        self.malware_data = malware_data
        self.malware_name = self.malware_data.get("value", "")
        self.malware_id = self.malware_data.get("id", "")
        self.description = self.malware_data.get("description")
        self.target_industries = self.build_target_industries()
        self.reports_list = self.get_associated_reports()

    def build_target_industries(self) -> List:
        return [i.get("name", "") for i in self.malware_data.get("industries", [])]

    def get_associated_reports(self) -> List:
        reports = []

        for report in self.client.get_associated_reports("malware", self.malware_id).get("reports", []):
            reports.append({
                "source": "Mandiant",
                "title": report.get("title", "-"),
                "link": "{}/reports/{}".format(ADV_BASE_URL, report.get("report_id")),
                "timestamp": datetime.strptime(report.get("published_date"), "%B %d, %Y %I:%M:%S %p").timestamp()
            })

        return reports

    def build_actor_relationships(self) -> Generator:
        for actor in self.malware_data.get("actors", []):
            yield EntityRelationship(name="used-by", reverse_name="uses", entity_a=self.malware_name,
                                     entity_a_type="Malware", entity_b=actor.get("name", ""),
                                     entity_b_type="Threat Actor").to_indicator()

    def build_vulnerability_relationships(self) -> Generator:
        for vuln in self.malware_data.get("cve", []):
            yield EntityRelationship(name="exploits", reverse_name="exploited-by", entity_a=self.malware_name,
                                     entity_a_type="Malware", entity_b=vuln.get("cve_id", ""),
                                     entity_b_type="CVE").to_indicator()

    def build_attack_pattern_relationships(self) -> Generator:
        attack_patterns = self.client.get_attack_patterns("malware", self.malware_id).get("attack-patterns", {})
        mitre_attack_patterns: Dict = self.client.get_mitre_attack_patterns()
        for ap in attack_patterns:
            ap_id = attack_patterns.get(ap).get("attack_pattern_identifier", "")
            ap_title = attack_patterns.get(ap).get("name", "")
            mitre_ap = mitre_attack_patterns.get(ap_id, "")
            entity_b = mitre_ap if mitre_ap else f"{ap_id}: {ap_title}"
            yield EntityRelationship(name="uses", reverse_name="used-by", entity_a=self.malware_name,
                                     entity_a_type="Malware", entity_b=entity_b,
                                     entity_b_type="Attack Pattern").to_indicator()

    def build_campaign_relationships(self) -> Generator:
        for c in self.client.get_associated_campaigns("malware", self.malware_id).get("campaigns", []):
            campaign_id = c.get("short_name", "")
            campaign_title = c.get("name", "")
            yield EntityRelationship(name="related-to", reverse_name="related-to", entity_a=self.malware_name,
                                     entity_a_type="Malware", entity_b=f"{campaign_title} ({campaign_id})",
                                     entity_b_type="Campaign").to_indicator()

    def build_malware_relationships(self) -> List:
        relationships = []

        for actor in self.build_actor_relationships():
            relationships.append(actor)

        for vuln in self.build_vulnerability_relationships():
            relationships.append(vuln)

        for ap in self.build_attack_pattern_relationships():
            relationships.append(ap)

        for c in self.build_campaign_relationships():
            relationships.append(c)

        return relationships

    def build_indicator(self) -> Dict:
        return {
            "value": self.malware_name,
            "type": "Malware",
            "rawJSON": self.malware_data,
            "fields": {
                "Tags": self.build_target_industries(),
                "Publications": self.reports_list,
                "Industry sectors": self.target_industries
            },
            "score": ThreatIntel.ObjectsScore.MALWARE,
            "relationships": self.build_malware_relationships()
        }

    def build_roles(self) -> str:
        return ", ".join(self.malware_data.get("roles", []))

    def build_capabilities(self) -> str:
        return ", ".join([c.get("name", "") for c in self.malware_data.get("capabilities", [])])

    def build_detections(self) -> str:
        return ", ".join(self.malware_data.get("detections", []))

    def build_operating_systems(self) -> str:
        return ", ".join(self.malware_data.get("operating_systems", []))

    def build_target_indistries_str(self) -> str:
        return ", ".join(self.target_industries)

    def build_associated_actors(self) -> str:
        return ", ".join([a.get("name", "") for a in self.malware_data.get("actors", ["-"])])

    def build_associated_vulnerabilities(self) -> str:
        return ", ".join([v.get("cve_id", "") for v in self.malware_data.get("cve", ["-"])])

    def get_last_activity_time(self) -> str:
        return self.malware_data.get("last_activity_time", "Unknown")

    def get_last_updated(self) -> str:
        return self.malware_data.get("last_updated", "Unknown")

    def build_attribute_table_md(self) -> str:
        attribute_table = {
            "Link": f"{ADV_BASE_URL}/malware/{self.malware_id}",
            "Roles": self.build_roles(),
            "Capabilities": self.build_capabilities(),
            "Detections": self.build_detections(),
            "Operating Systems": self.build_operating_systems(),
            "Target Industries": self.build_target_indistries_str(),
            "Associated Threat Actors": self.build_associated_actors(),
            "Associated Vulnerabilities": self.build_associated_vulnerabilities(),
            "Last Activity Time": self.get_last_activity_time(),
            "Last Updated": self.get_last_updated()
        }

        return tableToMarkdown("Malware Family Attributes", attribute_table, url_keys=["Link"])

    def build_report_table_md(self) -> str:
        earliest_report = time.time() - (86400 * 90)
        report_table = [{"Title": r.get("title", ""), "Link": r.get("link", "")}
                        for r in self.reports_list
                        if int(r.get("timestamp", 1)) > earliest_report]
        return tableToMarkdown("Recent Associated Reports", report_table, url_keys=["Link"])

    def build_malware_markdown(self) -> str:
        return (
            f"## {self.malware_name}\n\n"
            + f"{self.description}\n\n"
            + f"{self.build_attribute_table_md()}\n\n"
            + self.build_report_table_md()
        )

    def build_malware_command_result(self):
        return CommandResults(outputs=self.malware_data, ignore_auto_extract=False, outputs_prefix="Mandiant.Malware",
                              readable_output=self.build_malware_markdown(), tags=self.target_industries)


class MatiCve:
    def __init__(self, cve_data: Dict, reliability: str, tlp_color: str, tags: List) -> None:
        self.cve_data = cve_data
        self.reliability = reliability
        self.tlp_color = tlp_color
        self.tags = tags
        self.cve_id = self.cve_data.get("cve_id", "")
        self.description = self.strip_html_tags(self.cve_data.get("description", ""), True, True)
        self.publish_date = self.cve_data.get("publish_date", "")
        self.last_modified_date = self.cve_data.get("last_modified_date", "")
        self.risk_rating = self.cve_data.get("risk_rating", "")
        self.vulnerable_products = self.strip_html_tags(self.cve_data.get("vulnerable_products", ""), True, True)
        self.executive_summary = self.strip_html_tags(self.cve_data.get("executive_summary", ""), True, True)
        self.cvss_data = self.cve_data.get("common_vulnerability_scores", {})
        self.cvss_version = self.calculate_cvss_version()
        self.cvss_score = self.get_cvss_score()
        self.cpe_objects = self.build_cpe_objects()
        self.relationships = self.build_relationships()

    @staticmethod
    def strip_html_tags(content: str, replace_line_breaks: bool, trim_result: bool) -> str:
        text = ""
        if content:
            text = re.sub(r'<\/?br\s?\/?>', '\n', content, flags=re.I) if replace_line_breaks else content

            text = re.sub(r'<.*?>', '', text)
            entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ',
                        'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
            for e in entities:
                text = text.replace(f'&{e};', entities[e])

            if trim_result:
                text = re.sub(r'[ \t]{2,}', ' ', text)
                text = re.sub(r'(\s*\r?\n){3,}', '\n\n', text)
                text = text.strip()
        return text

    def build_relationships(self) -> List:
        relationships = []

        for a in self.cve_data.get("associated_actors", []):
            relationships.append(EntityRelationship(name="exploited-by", reverse_name="exploits", entity_a=self.cve_id,
                                                    entity_a_type="Indicator", entity_b=a.get("name", ""),
                                                    entity_b_type="Threat Actor"))

        for m in self.cve_data.get("associated_malware", []):
            relationships.append(EntityRelationship(name="exploited-by", reverse_name="exploits", entity_a=self.cve_id,
                                                    entity_a_type="Indicator", entity_b=m.get("name", ""),
                                                    entity_b_type="Malware"))
        return relationships

    def build_cpe_objects(self):
        return [Common.CPE(cpe.get("cpe", "")) for cpe in self.cve_data.get("vulnerable_cpes", [])]

    def calculate_cvss_version(self) -> str:
        if "v3.1" in self.cvss_data:
            return "v3.1"
        elif "v2.0" in self.cvss_data:
            return "v2.0"
        else:
            return "0.0"

    def build_exploitation_vectors(self):
        return ", ".join(self.cve_data.get("exploitation_vectors", ""))

    def build_markdown(self) -> str:
        details_table_dict = {
            "Description": self.description,
            "Published": self.publish_date,
            "Last Modified": self.last_modified_date,
            "Risk Rating": self.risk_rating,
            "Exploitation Vectors": self.build_exploitation_vectors(),
            "Vulnerable Products": self.vulnerable_products
        }
        markdown_sections = [
            f"## {self.cve_id}",
            self.executive_summary,
            tableToMarkdown("Details", details_table_dict)
        ]

        return "\n\n".join(markdown_sections)

    def get_cvss_score(self):
        return str(self.cvss_data.get(self.cvss_version).get("base_score", "0.0"))

    def get_cvss_vector(self) -> str:
        return self.cvss_data.get(self.cvss_version).get("vector_string", "")

    def build_publications(self) -> List:
        publications = []
        for r in self.cve_data.get("associated_reports", []):
            publications.append(
                Common.Publications(source="Mandiant", title=r.get("title", ""),
                                    link="{}/reports/{}".format(ADV_BASE_URL, r.get("report_id", "")),
                                    timestamp=r.get("published_date", ""))
            )
        return publications

    def calculate_cve_dbot_score(self) -> int:
        try:
            score = float(self.cvss_score)
        except ValueError:
            return Common.DBotScore.NONE
        if not score:
            return Common.DBotScore.NONE
        elif score < 0 or score == 0.0:
            return Common.DBotScore.NONE
        elif 0.0 <= score <= 3.0:
            return Common.DBotScore.GOOD
        elif 4.0 <= score <= 7.0:
            return Common.DBotScore.SUSPICIOUS
        elif 8.0 <= score <= 10.0:
            return Common.DBotScore.BAD
        else:
            return Common.DBotScore.NONE

    def create_dbot_score(self) -> Common.DBotScore:
        return Common.DBotScore(
            indicator=self.cve_id,
            indicator_type=DBotScoreType.CVE,
            integration_name="Mandiant",
            reliability=self.reliability,
            score=self.calculate_cve_dbot_score()
        )

    def build_cve_object(self) -> Common.CVE:
        return Common.CVE(
            id=self.cve_id,
            cvss=self.cvss_score,
            published=self.publish_date,
            modified=self.last_modified_date,
            description=self.description,
            relationships=self.relationships,
            stix_id=self.cve_data.get("id", ""),
            cvss_version=self.cvss_version.replace("v", ""),
            cvss_vector=self.get_cvss_vector(),
            cvss_score=self.cvss_score,
            tags=", ".join(self.tags),
            traffic_light_protocol=self.tlp_color,
            publications=self.build_publications(),
            dbot_score=self.create_dbot_score(),
            vulnerable_products=self.cpe_objects,
            vulnerable_configurations=self.cpe_objects
        )

    def build_cve_command_result(self) -> CommandResults:
        return CommandResults(
            readable_output=self.build_markdown(),
            ignore_auto_extract=False,
            outputs_prefix="Mandiant.CVE",
            relationships=self.relationships,
            outputs=self.cve_data,
            indicator=self.build_cve_object()
        )


class MatiCampaign:
    def __init__(self, client: MandiantClient, campaign_data: Dict) -> None:
        self.client = client
        self.campaign_data = campaign_data
        self.short_name = self.campaign_data.get("short_name", "")
        self.campaign_title = self.campaign_data.get("name", "")
        self.campaign_name = f"{self.campaign_title} ({self.short_name})"
        self.target_industries = self.build_target_industries()
        self.description = self.campaign_data.get("description", "")
        self.campaign_id = self.campaign_data.get("id", "")
        self.last_active = self.campaign_data.get("last_activity_time", "")

    def build_target_industries(self) -> List:
        return [i.get("name", "") for i in self.campaign_data.get("industries", [])]

    def build_markdown(self) -> str:
        return (f"## {self.campaign_name}\n\n"
                + f"**Short Name:** {self.short_name} | **Last Active:** {self.last_active}\n\n"
                + f"{self.description}\n\n"
                + f"**Link:** {ADV_BASE_URL}/campaigns/{self.campaign_id}")

    def build_publications(self):
        publications = []

        for r in self.client.get_associated_reports("campaign", self.campaign_id).get("reports", []):
            title = r.get("title", "")
            report_id = r.get("report_id", "")
            published = r.get("published_date")

            if not title or not report_id or not published:
                continue

            publications.append(Common.Publications(source="Mandiant", title=f"{title} ({report_id})",
                                                    link=f"{ADV_BASE_URL}/reports/{report_id}",
                                                    timestamp=published).to_context())
        return publications

    def build_relationships(self) -> List:
        relationships = []

        for actor in self.campaign_data.get("actors", []):
            relationships.append(EntityRelationship(name="related-to", reverse_name="related-to",
                                                    entity_a=self.campaign_name, entity_a_type="Campaign",
                                                    entity_b=actor.get("name"),
                                                    entity_b_type="Campaign").to_indicator())

        for malware in self.campaign_data.get("malware", []):
            relationships.append(EntityRelationship(name="related-to", reverse_name="related-to",
                                                    entity_a=self.campaign_name, entity_a_type="Campaign",
                                                    entity_b=malware.get("name"),
                                                    entity_b_type="Campaign").to_indicator())

        return relationships

    def build_indicator(self) -> Dict:
        return {
            "value": self.campaign_name,
            "type": "Campaign",
            "rawJSON": self.campaign_data,
            "fields": {
                "Tags": self.target_industries,
                "Publications": self.build_publications(),
                "STIX ID": self.campaign_id,
                "Traffic Light Protocol": self.client.tlp_color,
                "Industry sectors": self.target_industries
            },
            "score": ThreatIntel.ObjectsScore.CAMPAIGN,
            "relationships": self.build_relationships()
        }

    def build_campaign_command_result(self):
        return CommandResults(outputs=self.campaign_data, ignore_auto_extract=False, outputs_prefix="Mandiant.Campaign",
                              readable_output=self.build_markdown(), tags=self.target_industries)


def ip_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("ip")))
    output = []

    for v in values_:
        api_response = client.get_indicators_by_value([v])
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            output.append(MatiIpIndicator(client, i).build_indicator_command_result())

    return output


def domain_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("domain")))
    output = []

    for v in values_:
        api_response = client.get_indicators_by_value([v])
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            output.append(MatiDomainIndicator(client, i).build_indicator_command_result())

    return output


def url_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("url")))
    output = []

    for v in values_:
        api_response = client.get_indicators_by_value([v])
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            output.append(MatiUrlIndicator(client, i).build_indicator_command_result())

    return output


def file_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("file")))
    output = []

    for v in values_:
        api_response = client.get_indicators_by_value([v])
        if not api_response:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        for i in api_response:
            output.append(MatiFileIndicator(client, i, v).build_indicator_command_result())

    return output


def cve_reputation_command(client: MandiantClient, args: Dict) -> List:
    args = args if args else {}
    values_: list[str] = argToList(str(args.get("cve")))
    output = []

    for v in values_:
        cve = client.get_cve_by_cveid(v)
        if not cve:
            output.append(CommandResults(readable_output=f"{v} not found"))
            continue
        output.append(MatiCve(cve, client.reliability, client.tlp_color, client.tags).build_cve_command_result())
    return output


def fetch_threat_actor_command(client: MandiantClient, args: Dict) -> CommandResults:
    args = args if args else {}
    actor_name: str = args["actor_name"]

    actor_from_api = client.get_actor(actor_name)
    actor_from_api["value"] = actor_name
    actor_from_api["type"] = "Threat Actor"

    if not actor_from_api:
        return CommandResults(readable_output=f"{actor_name} not found")

    actor_client = MatiThreatActor(client, actor_from_api)
    demisto.createIndicators([actor_client.build_indicator()])

    return actor_client.build_threat_actor_command_result()


def fetch_malware_family_command(client: MandiantClient, args: Dict):
    args = args if args else {}
    malware_name: str = args["malware_name"]

    malware_from_api = client.get_malware(malware_name)
    malware_from_api["value"] = malware_name
    malware_from_api["type"] = "Malware"

    if not malware_from_api:
        return CommandResults(readable_output=f"{malware_name} not found")

    malware_client = MatiMalware(client, malware_from_api)
    demisto.createIndicators([malware_client.build_indicator()])

    return malware_client.build_malware_command_result()


def fetch_campaign_command(client: MandiantClient, args: Dict):
    args = args if args else {}
    campaign_id: str = args["campaign_id"]

    campaign_from_api = client.get_campaign(campaign_id)
    campaign_from_api["value"] = campaign_id
    campaign_from_api["type"] = "Campaign"

    if not campaign_from_api:
        return CommandResults(readable_output=f"{campaign_id} not found")

    campaign_client = MatiCampaign(client, campaign_from_api)
    demisto.createIndicators([campaign_client.build_indicator()])

    return campaign_client.build_campaign_command_result()


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
