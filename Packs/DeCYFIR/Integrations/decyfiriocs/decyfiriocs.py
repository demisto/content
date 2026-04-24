import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

urllib3.disable_warnings()

""" CONSTANTS """
API_TEST_PATH_SUFFIX = "/core/api-ua/v2/data/ping?key={0}"
IOC_API_STIX_2_1_PATH_SUFFIX = "/core/api-ua/stix-v2.1/v2/ioc?key={0}&delta=false&all=false&product-name=PALO_ALTO_XSOAR"
API_IOC_By_TYPE_PATH_SUFFIX = IOC_API_STIX_2_1_PATH_SUFFIX + "&types={1}"

IOC_API_STIX_2_1_SEARCH_PATH_SUFFIX = "/core/api-ua/threatioc/stix/v2.1/search?key={0}&indicatorType={1}&value={2}"

TA_API_STIX_2_1_PATH_SUFFIX = "/core/api-ua/threatactor/ctc/stix/v2.1?key={0}&product-name=PALO_ALTO_XSOAR"
TA_API_STIX_2_1_SEARCH_PATH_SUFFIX = "/core/api-ua/threatactor/stix/v2.1?key={0}&name={1}&mitre-required=false"


LABEL_DECYFIR = "DeCYFIR"
LABEL_INDICATOR = "indicator"
LABEL_THREAT_ACTOR = "threat-actor"
LABEL_INTRUSION_SET = "intrusion-set"
LABEL_CAMPAIGN = "campaign"
LABEL_MALWARE = "malware"
LABEL_VULNERABILITY = "vulnerability"
LABEL_RELATIONSHIP = "relationship"
LABEL_RELATIONSHIPS = "relationships"
LABEL_ATTACK_PATTERN = "attack-pattern"
LABEL_TYPE = "type"
LABEL_ID = "id"
LABEL_VALUE = "value"
LABEL_SOURCE_REF = "source_ref"
LABEL_TARGET_REF = "target_ref"

CVSS_COMMON_METRICS = [
    "availability_impact",
    "integrity_impact",
    "impact_score",
    "exploitability_score",
    "confidentiality_impact",
]

CVSS_VERSION_METRICS_2 = ["access_vector", "access_complexity", "authentication"]

CVSS_VERSION_METRICS_3 = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope"]

THREAT_INTEL_SCORES = {
    ThreatIntel.ObjectsNames.CAMPAIGN: ThreatIntel.ObjectsScore.CAMPAIGN,
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: ThreatIntel.ObjectsScore.ATTACK_PATTERN,
    ThreatIntel.ObjectsNames.REPORT: ThreatIntel.ObjectsScore.REPORT,
    ThreatIntel.ObjectsNames.MALWARE: ThreatIntel.ObjectsScore.MALWARE,
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
    ThreatIntel.ObjectsNames.INTRUSION_SET: ThreatIntel.ObjectsScore.INTRUSION_SET,
    ThreatIntel.ObjectsNames.THREAT_ACTOR: ThreatIntel.ObjectsScore.THREAT_ACTOR,
    ThreatIntel.ObjectsNames.TOOL: ThreatIntel.ObjectsScore.TOOL,
}

INDICATOR_AND_TI_TYPES = {
    "[domain-name:value": FeedIndicatorType.Domain,
    "[email:value": FeedIndicatorType.Email,
    "[ipv4-addr:value": FeedIndicatorType.IP,
    "[ipv6-addr:value": FeedIndicatorType.IPv6,
    "[url:value": FeedIndicatorType.URL,
    "[file:name": FeedIndicatorType.File,
    "[file:hashes.md5": FeedIndicatorType.File,
    "[file:hashes.'SHA-1'": FeedIndicatorType.File,
    "[file:hashes.'SHA-256'": FeedIndicatorType.File,
    "[mutex:value": FeedIndicatorType.MUTEX,
    "[host": FeedIndicatorType.Host,
    "[cve:value": FeedIndicatorType.CVE,
    "vulnerability": FeedIndicatorType.CVE,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "tool": ThreatIntel.ObjectsNames.TOOL,
}

RELATIONSHIPS_MAPPING_TYPES = {
    ThreatIntel.ObjectsNames.INTRUSION_SET: EntityRelationship.Relationships.ATTRIBUTED_TO,
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: EntityRelationship.Relationships.USES,
    ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.USES,
    FeedIndicatorType.CVE: EntityRelationship.Relationships.TARGETS,
    ThreatIntel.ObjectsNames.TOOL: EntityRelationship.Relationships.USES,
}


class Client(BaseClient):
    def get_indicator_or_threatintel_type(self, data) -> str:
        if data is None:
            return ""

        for key, value in INDICATOR_AND_TI_TYPES.items():
            if key in data:
                return value

        return ""

    def get_decyfir_api_ti_data(self, decyfir_api_path: str) -> List[Dict]:
        response = self._http_request(url_suffix=decyfir_api_path, method="GET", resp_type="response")
        if response.status_code == 200 and response.content:
            return response.json()

        return []

    def build_relationships(self, relation_type, source_value, source_type, target_value, target_type):
        return EntityRelationship(
            name=relation_type, entity_a=source_value, entity_a_type=source_type, entity_b=target_value, entity_b_type=target_type
        ).to_indicator()

    def build_threat_actor_relationship_obj(self, source_data: Dict[str, str], target_data: Dict[str, str])-> Dict|None:
        target_type = target_data.get(LABEL_TYPE)
        target_value = target_data.get(LABEL_VALUE)
        source_type = source_data.get(LABEL_TYPE)
        source_value = source_data.get(LABEL_VALUE)

        relationship = RELATIONSHIPS_MAPPING_TYPES.get(str(target_type))
        if relationship:
            return self.build_relationships(relationship, source_value, source_type, target_value, target_type)
        else:
            relationship = RELATIONSHIPS_MAPPING_TYPES.get(str(source_type))
            if relationship:
                return self.build_relationships(relationship, source_value, source_type, target_value, target_type)

        return None

    def build_ioc_relationship_obj(self, ioc_data: Dict, target_data: Dict):
        return self.build_relationships(
            EntityRelationship.Relationships.INDICATOR_OF,
            ioc_data.get(LABEL_VALUE),
            ioc_data.get(LABEL_TYPE),
            target_data.get(LABEL_VALUE),
            target_data.get(LABEL_TYPE),
        )

    def add_tags(self, in_ti: Dict, data: Optional[List | str]):
        if not data:
            return

        if isinstance(data, str):
            data = [data]

        data = [item for item in data if item not in {"unknown", "Unknown"}]
        in_ti["fields"]["tags"].extend(data)

    def add_aliases(self, in_ti: Dict, data: Optional[List[str] | str]):
        if not data:
            return

        if isinstance(data, str):
            data = [data]

        data = [item for item in data if item not in {"unknown", "Unknown"}]
        in_ti["fields"]["aliases"].extend(data)

    def build_threat_intel_indicator_obj(self, data: Dict, tlp_color: Optional[str], feed_tags: Optional[List]):

        try:
            intel_type: str = self.get_indicator_or_threatintel_type(data.get(LABEL_TYPE))
            confidence: int = data.get("confidence", 0)

            verdict: str = "Unknown"
            cve_score: int = 0
            if (confidence >= 80):
                verdict = "Malicious"
                cve_score = 3
            elif (confidence >= 50):
                verdict = "Suspicious"
                cve_score = 2
            else:
                verdict = "Benign"
                cve_score = 1

            ti_data_obj: Dict = {
                "value": data.get("name", ""),
                "name": data.get("name", ""),
                "type": intel_type,
                "score": THREAT_INTEL_SCORES.get(intel_type, cve_score),
                "service": LABEL_DECYFIR,
                "rawJSON": data,
                "relationships": [],
                "fields": {
                    "confidence": confidence,
                    "stixid": data.get(LABEL_ID),
                    "description": data.get("description", ""),
                    "firstseenbysource": data.get("created"),
                    "modified": data.get("modified"),
                    "trafficlightprotocol": tlp_color if tlp_color else "",
                    "aliases": [],
                    "tags": [],
                    "primary_motivation": "Cyber Crime",
                    "secondary_motivations": data.get("primary_motivation", ""),
                    "sophistication": "advanced",
                    "resource_level": "team",
                    "threatactortypes": data.get("threat_actor_types", ""),
                },
            }

            ti_fields = ti_data_obj["fields"]

            if intel_type == FeedIndicatorType.CVE:
                ti_data_obj["fields"]["verdict"] = verdict
                ti_data_obj["fields"]["score"] = cve_score
                ti_fields["cvedescription"] = data.get("description", "")
                ti_fields["cvemodified"] = data.get("modified")

            if intel_type is ThreatIntel.ObjectsNames.MALWARE:
                ti_data_obj["fields"].update({"ismalwarefamily": data.get("is_family"),
                                             "malwaretypes": data.get("malware_types")})

            ti_properties = next(iter(data.get("extensions", {}).values()), {}).get("properties", {})

            if ti_properties:
                ta_origin = ti_properties.get("origin-of-country", "")
                if ta_origin:
                    ti_fields["geocountry"] = ta_origin

                ta_target_countries = ti_properties.get("target-countries", ti_properties.get("geographies"))
                if ta_target_countries:
                    ti_fields["targetcountries"] = ta_target_countries

                ta_target_industries = ti_properties.get("target-industries", ti_properties.get("industries", ""))
                if ta_target_industries:
                    ti_fields["targetindustries"] = ta_target_industries

                technologies = ti_properties.get("technologies")
                if technologies:
                    ti_fields["technologies"] = technologies

                if intel_type == FeedIndicatorType.CVE:

                    ti_fields["cvssscore"] = ti_properties.get("cvss_score", "")
                    ti_fields["cvssvector"] = ti_properties.get("cvss_vector", "")
                    ti_fields["cvssversion"] = ti_properties.get("cvss_version", "")
                    ti_data_obj["score"] = 0

                    if ti_properties.get("cvss_metrics_data"):
                        metrics = []
                        cvss_metrics_data = ti_properties["cvss_metrics_data"]

                        for metric in CVSS_COMMON_METRICS:
                            key = str(metric).replace("_", " ").capitalize()
                            metrics.append({"metrics": key, "value": cvss_metrics_data.get(metric)})

                        cvss_version = ti_properties.get("cvss_version", "")
                        if cvss_version and cvss_version[0] == "2":
                            cvss_version_metrics = CVSS_VERSION_METRICS_2
                        elif cvss_version and cvss_version[0] == "3":
                            cvss_version_metrics = CVSS_VERSION_METRICS_3
                        else:
                            cvss_version_metrics = []

                        for metric in cvss_version_metrics:
                            key = str(metric).replace("_", " ").capitalize()
                            metrics.append({"metrics": key, "value": cvss_metrics_data.get(metric)})

                        if cvss_metrics_data.get("vendors"):
                            vendors = ", ".join(cvss_metrics_data["vendors"])
                            metrics.append({"metrics": "Vendors", "value": vendors})

                        if cvss_metrics_data.get("products"):
                            products = ", ".join(cvss_metrics_data["products"])
                            metrics.append({"metrics": "Products", "value": products})

                        if cvss_metrics_data.get("technologies"):
                            technologies = ", ".join(cvss_metrics_data["technologies"])
                            metrics.append({"metrics": "Technologies", "value": technologies})

                        ti_fields["cvsstable"] = metrics

            return ti_data_obj
        except Exception as e:
            val=data.get("name","")
            demisto.debug(f"Error occurred while building the threat intelligence data object ({val}). Error: {e}")
            return {}

    def build_ta_relationships_data(
        self, ta_rel_data_coll: list, ta_source_obj: dict, return_data: list, tlp_color: Optional[str], feed_tags: Optional[List]
    ):
        src_ti_relationships_data = []
        raw_ta_rels: List = []
        raw_ta_data: Dict = {}
        raw_ta_obj: Dict = {}

        # Only source object getting from the iterating
        # Threat actor relationships data getting from the API and mapping.
        for ta_rel_data in ta_rel_data_coll:
            if ta_rel_data.get(LABEL_TYPE) == LABEL_THREAT_ACTOR:
                raw_ta_obj = ta_rel_data
                ta_source_obj = self.build_threat_intel_indicator_obj(ta_rel_data, tlp_color, feed_tags)

            elif ta_rel_data.get(LABEL_TYPE) == LABEL_RELATIONSHIP:
                raw_ta_rels.append(ta_rel_data)
            else:
                is_types_in = ta_rel_data.get(LABEL_TYPE) in [LABEL_INTRUSION_SET, LABEL_CAMPAIGN, LABEL_MALWARE]
                if raw_ta_obj.get(LABEL_ID) != ta_rel_data.get(LABEL_ID) and is_types_in:
                    ta_rel_data["labels"] = raw_ta_obj.get("labels", [])

            raw_ta_data[ta_rel_data.get(LABEL_ID)] = ta_rel_data

        # Mapping the relations with source and target objects
        if raw_ta_rels is not None and raw_ta_rels:
            for raw_ta_rel_ in raw_ta_rels:

                # Source ref obj from relationship obj
                if raw_ta_rel_.get(LABEL_SOURCE_REF) in raw_ta_data:
                    source_ref_obj: Dict = raw_ta_data.get(raw_ta_rel_.get(LABEL_SOURCE_REF, ""), {})
                else:
                    source_ref_obj = raw_ta_data.get(raw_ta_rel_.get("sourceRef", ""), {})

                # Target ref obj from relationship obj
                if raw_ta_rel_.get(LABEL_TARGET_REF) in raw_ta_data:
                    target_ref_obj: Dict = raw_ta_data.get(raw_ta_rel_.get(LABEL_TARGET_REF, ""), {})
                else:
                    target_ref_obj = raw_ta_data.get(raw_ta_rel_.get("targetRef", ""), {})

                if source_ref_obj is not None and target_ref_obj is not None:
                    if raw_ta_obj.get(LABEL_ID) != source_ref_obj.get(LABEL_ID):
                        source_ti_data_obj = self.build_threat_intel_indicator_obj(source_ref_obj, tlp_color, feed_tags)
                        if source_ti_data_obj is not None and source_ti_data_obj:
                            src_exists_in = False
                            for re_data1 in return_data:
                                try:
                                    if re_data1["value"] == source_ti_data_obj["value"]:
                                        src_exists_in = True
                                except Exception as e:
                                    demisto.debug(
                                        f"Error occurred while checking for existing source relationship-re_data1 ({str(re_data1)} <> {str(source_ti_data_obj)}). Error: {e}")
                                    break
                            if not src_exists_in:
                                return_data.append(source_ti_data_obj)
                    else:
                        source_ti_data_obj = ta_source_obj

                    src_tar_flag = source_ti_data_obj is not None and source_ti_data_obj.get(LABEL_ID) != target_ref_obj.get(
                        LABEL_ID
                    )

                    if raw_ta_obj.get(LABEL_ID) != target_ref_obj.get(LABEL_ID) and src_tar_flag:
                        target_ti_data_obj = self.build_threat_intel_indicator_obj(target_ref_obj, tlp_color, feed_tags)
                        if target_ti_data_obj is not None and target_ti_data_obj:
                            tar_exists_in = False
                            for re_data2 in return_data:
                                try:
                                    if re_data2["value"] == target_ti_data_obj["value"]:
                                        tar_exists_in = True
                                        break
                                except Exception as e:
                                    demisto.debug(
                                        f"Error occurred while checking for existing target relationship-re_data2 ({str(re_data2)} <> {str(target_ti_data_obj)}). Error: {e}")
                                    break
                            if not tar_exists_in:
                                return_data.append(target_ti_data_obj)
                    else:
                        target_ti_data_obj = ta_source_obj

                    if source_ti_data_obj and target_ti_data_obj:
                        ti_relationships = self.build_threat_actor_relationship_obj(source_ti_data_obj, target_ti_data_obj)

                        if ti_relationships:
                            is_scr_rel = raw_ta_obj.get(LABEL_ID) == source_ref_obj.get(LABEL_ID) or raw_ta_obj.get(
                                LABEL_ID
                            ) == target_ti_data_obj.get(LABEL_ID)

                            if raw_ta_obj.get(LABEL_ID) != source_ref_obj.get(LABEL_ID):
                                source_ti_data_obj[LABEL_RELATIONSHIPS].append(ti_relationships)

                            if raw_ta_obj.get(LABEL_ID) != target_ti_data_obj.get(LABEL_ID):
                                target_ti_data_obj[LABEL_RELATIONSHIPS].append(ti_relationships)

                            if is_scr_rel:
                                src_ti_relationships_data.append(ti_relationships)

        return ta_source_obj, src_ti_relationships_data, return_data

    def convert_decyfir_ioc_to_indicators_formats(
        self,
        decyfir_api_key: str,
        decyfir_iocs: List[Dict],
        reputation: Optional[str],
        tlp_color: Optional[str],
        feed_tags: Optional[List],
        is_data_save: bool,
    ) -> List[Dict]:

        return_data = []
        threat_actors_cache: Dict[str, List[Dict]] = {}

        for ioc in decyfir_iocs:
            try:
                ioc_type: str = self.get_indicator_or_threatintel_type(ioc.get("pattern"))
                value: str = str(ioc.get("name", ""))
                file_hash_values = {}

                if "File SHA-1 hash" in value:
                    value = value.replace("File SHA-1 hash '", "").replace("'", "")
                elif "File SHA-256 hash" in value:
                    value = value.replace("File SHA-256 hash '", "").replace("'", "")
                elif "File MD5 hash" in value:
                    value = value.replace("File MD5 hash '", "").replace("'", "")

                pattern_val: str = str(ioc.get("pattern"))

                if pattern_val != "None" and pattern_val is not None:
                    pattern_val = pattern_val.replace("[", "").replace("]", "").replace("file:hashes.", "")
                    pattern_vals: list = pattern_val.split("OR")

                    for p_v in pattern_vals:
                        p = p_v.split(" = ")
                        key_ = p[0].replace("'", "").replace(" ", "")
                        val_ = p[1].replace("'", "").replace(" ", "")
                        file_hash_values[key_] = val_
                        value = val_

                verdict: str = "Unknown"
                confidence: int = ioc.get("confidence", 0)
                score: int = 0

                if (confidence >= 80):
                    verdict = "Malicious"
                    score = 3
                elif (confidence >= 50):
                    verdict = "Suspicious"
                    score = 2
                else:
                    verdict = "Benign"
                    score = 1

                ioc_properties = next(iter(ioc.get("extensions", {}).values()), {}).get("properties", {})
                threat_actors = ioc_properties.get("threat_actors", "")
                recomendation_actions = ioc_properties.get("recommended_actions", "")
                recomended_action =True if recomendation_actions and recomendation_actions.lower() == "block" else False

                ioc_data = {
                    "value": value,
                    "type": ioc_type or "Unknown",
                    "rawJSON": ioc,
                    "service": LABEL_DECYFIR,
                    "score": score,
                    "fields": {
                        "reputation": reputation,
                        "verdict": verdict,
                        "confidence": confidence,
                        "aliases": [],
                        "tags": [],
                        "stixid": ioc.get("id"),
                        "description": ioc.get("description", ""),
                        "firstseenbysource": ioc.get("created"),
                        "lastseenbysource": ioc.get("modified"),
                        "modified": ioc.get("modified"),
                        "created": ioc.get("created"),
                        "threat_actor": threat_actors,
                        "malware_type": ioc_properties.get("roles"),
                        "remediation": recomendation_actions,
                        "asn": ioc_properties.get("asn", ""),
                        "geocountry": ioc_properties.get("country_code", ""),
                        "blocked": recomended_action,
                        "trafficlightprotocol": tlp_color if tlp_color else "",
                    },
                }

                if file_hash_values:
                    for key_ in file_hash_values:
                        ioc_data["fields"][key_] = file_hash_values.get(key_)

                if feed_tags:
                    self.add_tags(ioc_data, feed_tags)

                ioc_labels = ioc.get("labels", [])

                if ioc_labels:
                    self.add_tags(ioc_data, ioc_labels)

                if is_data_save:

                    tas = [ta.strip() for ta in threat_actors.split(",")
                           if ta.strip() and ta.strip() not in ["Unknown", "unknown", "UNKNOW"]]

                    if tas:
                        relationships_data = []
                        for ta in tas:
                            ta_source_obj: dict = {}
                            src_ti_relationships_data: list = []

                            # populating the threat actor data.
                            if ta in threat_actors_cache:
                                in_rel_ti_data_ = threat_actors_cache.get(ta)
                                is_ta_exits_in_cache = True
                            else:
                                ta_api_path = TA_API_STIX_2_1_SEARCH_PATH_SUFFIX.format(decyfir_api_key, ta)
                                in_rel_ti_data_ = self.get_decyfir_api_ti_data(ta_api_path)
                                threat_actors_cache[ta] = in_rel_ti_data_
                                is_ta_exits_in_cache = False

                            if in_rel_ti_data_:
                                if not is_ta_exits_in_cache:
                                    ta_source_obj, src_ti_relationships_data, return_data = self.build_ta_relationships_data(
                                        in_rel_ti_data_, ta_source_obj, return_data, tlp_color, feed_tags
                                    )
                                    ta_source_obj[LABEL_RELATIONSHIPS] = src_ti_relationships_data
                                    return_data.append(ta_source_obj)

                                for ta_da in in_rel_ti_data_:
                                    if ta_da.get(LABEL_TYPE) == LABEL_THREAT_ACTOR:
                                        ta_obj = self.build_threat_intel_indicator_obj(ta_da, tlp_color, feed_tags)
                                        in_rel_data = self.build_ioc_relationship_obj(ioc_data, ta_obj)
                                        if in_rel_data:
                                            relationships_data.append(in_rel_data)

                        ioc_data[LABEL_RELATIONSHIPS] = relationships_data

                return_data.append(ioc_data)
            except Exception as e:
                demisto.debug(f"Error occurred while processing the IOC: {ioc.get('id', 'Unknown ID')}. Error: {e}")
        return return_data

    def fetch_indicators(
        self,
        decyfir_api_key: str,
        reputation: Optional[str],
        tlp_color: Optional[str],
        feed_tags: Optional[List],
        is_data_save: bool,
    ) -> List[Dict]:

        return_data = []
        try:
            # Indicators from DeCYFIR
            iocs_data = self.get_decyfir_api_ti_data(IOC_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key))
            demisto.debug(f"API fetched from DeCYFIR feed: {len(iocs_data)}")

            if not is_data_save and iocs_data:
                iocs_data = iocs_data[:2]

            # Converting indicators data to XSOAR indicators format
            ioc_indicators = self.convert_decyfir_ioc_to_indicators_formats(
                decyfir_api_key, iocs_data, reputation, tlp_color, feed_tags, is_data_save
            )

            return_data.extend(ioc_indicators)

            demisto.debug(f"Total indicators with relationships fetched from DeCYFIR feed: {len(ioc_indicators)}")

            if not is_data_save:
                return return_data

            return return_data

        except Exception as e:
            err = f"Failed to fetch the feed data. DeCYFIR error: {e}"
            demisto.debug(err)

        return return_data

    def fetch_indicators_by_type(self, decyfir_api_key: str, indicator_type: str) -> List[Dict]:
        try:
            api_path = API_IOC_By_TYPE_PATH_SUFFIX.format(decyfir_api_key, indicator_type)
            return self.get_decyfir_api_ti_data(api_path)
        except Exception as e:
            demisto.debug(f"Error occurred while fetching the indicator details for ({indicator_type}). Error: {e}")
            return []


# The below function is used to test the connectivity with DeCYFIR API using the ping API.
def test_module_command(client, decyfir_api_key):
    url = API_TEST_PATH_SUFFIX.format(decyfir_api_key)
    response = client._http_request(url_suffix=url, method="GET", resp_type="response")
    if response.status_code == 200:
        return "ok"
    elif response.status_code in [401, 403]:
        return "Not Authorized"
    else:
        return f"Error_code: {response.status_code}, Please contact the DeCYFIR team to assist you further on this."


def extract_value(pattern: str) -> str:
    match = re.search(r"'([^']+)'", pattern or "")
    return match.group(1) if match else ""


def get_type(pattern: str) -> str:
    if "ipv4-addr" in pattern:
        return "IP"
    elif "domain-name" in pattern:
        return "Domain"
    elif "url" in pattern:
        return "URL"
    elif "file:hashes" in pattern:
        return "File"
    return "Unknown"


def calculate_score(vendors: Dict, confidence: int) -> int:
    malicious = sum(1 for v in vendors.values() if v in ["malicious", "phishing", "malware"])

    if malicious > 5:
        return 3
    elif malicious > 0:
        return 2
    elif confidence > 80:
        return 2
    return 1


def command_results(indicators: List[Dict], title: str) -> CommandResults:
    if not indicators:
        return CommandResults(readable_output="For current request no indicators found.")

    table_data = []
    outputs = []

    for ind in indicators:
        pattern = ind.get("pattern", "")
        value = extract_value(pattern)
        ioc_type = get_type(pattern)

        ext = next(iter(ind.get("extensions", {}).values()), {}).get("properties", {})
        vendors = ext.get("security_vendors", {})

        confidence = ind.get("confidence", 0)
        score = calculate_score(vendors, confidence)

        # -------- Human Readable Row --------
        row = {
            "Value": value,
            "Type": ioc_type,
            "Score": score,
            "Country": ext.get("country", ""),
            "Threat Actor": ext.get("threat_actors", ""),
            "Action": ext.get("recommended_actions"),
            "Role": ext.get("roles"),
            "Confidence": confidence,
            "Description": ind.get("description"),
        }

        table_data.append(row)

        # -------- Context Output --------
        outputs.append({
            "value": value,
            "type": ioc_type,
            "score": score,
            "country": ext.get("country", ""),
            "threat_actor": ext.get("threat_actors", ""),
        })

    human_readable = tableToMarkdown(title, table_data, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="CYFIRMA.Indicators",
        outputs_key_field="value",
        outputs=outputs,
        raw_response=indicators
    )


# The below function is used to fetch the IP type indicators from DeCYFIR feed.
def decyfir_ip_indicator_command(client: Client, decyfir_api_key: str):
    ip_indicators = client.fetch_indicators_by_type(decyfir_api_key, "ip")
    return command_results(ip_indicators, "IP Indicators from DeCYFIR Feed:")


# The below function is used to fetch the domain type indicators from DeCYFIR feed.
def decyfir_domain_indicator_command(client: Client, decyfir_api_key: str):

    domain_indicators = client.fetch_indicators_by_type(decyfir_api_key, "domain")
    return command_results(domain_indicators, "Domain Indicators from DeCYFIR Feed:")


# The below function is used to fetch the URL type indicators from DeCYFIR feed.
def decyfir_url_indicator_command(client: Client, decyfir_api_key: str):

    url_indicators = client.fetch_indicators_by_type(decyfir_api_key, "url")
    return command_results(url_indicators, "URL Indicators from DeCYFIR Feed:")


# The below function is used to fetch the hash type indicators (MD5, SHA-1 and SHA-256) from DeCYFIR feed.
def decyfir_hash_indicator_command(client: Client, decyfir_api_key: str):

    hashIndicators = client.fetch_indicators_by_type(decyfir_api_key, "hashes")
    return command_results(hashIndicators, "File Hash Indicators from DeCYFIR Feed:")


def fetch_indicators_command(
    client: Client, decyfir_api_key: str, tlp_color: Optional[str], reputation: Optional[str], feed_tags: Optional[List]
) -> List[Dict]:
    return client.fetch_indicators(decyfir_api_key, reputation, tlp_color, feed_tags, True)


def decyfir_get_indicators_command(
    client: Client, decyfir_api_key: str, tlp_color: Optional[str], reputation: Optional[str], feed_tags: Optional[List]
):
    indicators = client.fetch_indicators(decyfir_api_key, reputation, tlp_color, feed_tags, False)
    return command_results(indicators, "Indicators from DeCYFIR Feeds")


def main():  # pragma: no cover
    try:
        params = demisto.params()
        decyfir_url = params["url"].rstrip("/")
        decyfir_api_key = params.get("api_key").get("password")
        use_ssl = params.get("insecure", False)
        proxy = params.get("proxy", False)
        feed_tags = argToList(params.get("feedTags"))
        tlp_color = params.get("tlp_color")
        feed_reputation = params.get("feedReputation")

        demisto.info(f"Command being called is {demisto.command()}")

        client = Client(base_url=decyfir_url, verify=use_ssl, proxy=proxy)

        if demisto.command() == "test-module":
            result = test_module_command(client, decyfir_api_key)
            demisto.results(result)
        
        elif demisto.command() == "fetch-indicators":
            indicators = fetch_indicators_command(client, decyfir_api_key, tlp_color, feed_reputation, feed_tags)
            for ioc in batch(indicators, batch_size=2500):
                demisto.createIndicators(ioc)
        
        elif demisto.command() == "decyfir-get-indicators":
            return_results(decyfir_get_indicators_command(client, decyfir_api_key, tlp_color, feed_reputation, feed_tags))

        elif demisto.command() == "ip":
            return_results(decyfir_ip_indicator_command(client, decyfir_api_key))

        elif demisto.command() == "domain":
            return_results(decyfir_domain_indicator_command(client, decyfir_api_key))

        elif demisto.command() == "url":
            return_results(decyfir_url_indicator_command(client, decyfir_api_key))

        elif demisto.command() == "file":
            return_results(decyfir_hash_indicator_command(client, decyfir_api_key))

        else:
            raise NotImplementedError("DeCYFIR error: " + f"command {demisto.command()} is not implemented")

    except Exception as e:
        err = f"Failed to execute {demisto.command()} command. DeCYFIR error: {e}"
        return_error(err)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
