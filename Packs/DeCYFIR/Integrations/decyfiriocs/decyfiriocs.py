import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''
IOC_API_STIX_2_1_PATH_SUFFIX = '/core/api-ua/threatioc/stix/v2.1?key={0}&delta=false&all=false'
IOC_API_STIX_2_1_SEARCH_PATH_SUFFIX = '/core/api-ua/threatioc/stix/v2.1/search?key={0}&&indicatorType={1}&value={2}'

TA_API_STIX_2_1_PATH_SUFFIX = '/core/api-ua/threatactor/ctc/stix/v2.1?key={0}'
TA_API_STIX_2_1_SEARCH_PATH_SUFFIX = '/core/api-ua/threatactor/stix/v2.1?key={0}&name={1}'

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

CVSS_COMMON_METRICS = ['availability_impact', 'integrity_impact', 'impact_score', 'exploitability_score',
                       'confidentiality_impact']

CVSS_VERSION_METRICS_2 = ['access_vector', 'access_complexity', 'authentication']

CVSS_VERSION_METRICS_3 = ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 'scope']

THREAT_INTEL_SCORES = {
    ThreatIntel.ObjectsNames.CAMPAIGN: ThreatIntel.ObjectsScore.CAMPAIGN,
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: ThreatIntel.ObjectsScore.ATTACK_PATTERN,
    ThreatIntel.ObjectsNames.REPORT: ThreatIntel.ObjectsScore.REPORT,
    ThreatIntel.ObjectsNames.MALWARE: ThreatIntel.ObjectsScore.MALWARE,
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
    ThreatIntel.ObjectsNames.INTRUSION_SET: ThreatIntel.ObjectsScore.INTRUSION_SET,
    ThreatIntel.ObjectsNames.THREAT_ACTOR: ThreatIntel.ObjectsScore.THREAT_ACTOR,
    ThreatIntel.ObjectsNames.TOOL: ThreatIntel.ObjectsScore.TOOL
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
    "tool": ThreatIntel.ObjectsNames.TOOL
}

RELATIONSHIPS_MAPPING_TYPES = {
    ThreatIntel.ObjectsNames.INTRUSION_SET: EntityRelationship.Relationships.ATTRIBUTED_TO,
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: EntityRelationship.Relationships.USES,
    ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.USES,
    FeedIndicatorType.CVE: EntityRelationship.Relationships.TARGETS,
    ThreatIntel.ObjectsNames.TOOL: EntityRelationship.Relationships.USES
}


class Client(BaseClient):

    def get_indicator_or_threatintel_type(self, data):
        if data is None:
            return None

        for key, value in INDICATOR_AND_TI_TYPES.items():
            if key in data:
                return value

        return None

    def get_decyfir_api_iocs_ti_data(self, decyfir_api_path: str) -> List[Dict]:
        response = self._http_request(url_suffix=decyfir_api_path, method='GET', resp_type='response')

        if response.status_code == 200 and response.content:
            return response.json()

        return []

    def build_relationships(self, relation_type, source_value, source_type, target_value, target_type):

        return EntityRelationship(name=relation_type,
                                  entity_a=source_value, entity_a_type=source_type,
                                  entity_b=target_value, entity_b_type=target_type
                                  ).to_indicator()

    def build_threat_actor_relationship_obj(self, source_data: Dict[str, str], target_data: Dict[str, str]):

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

        return self.build_relationships(EntityRelationship.Relationships.INDICATOR_OF,
                                        ioc_data.get(LABEL_VALUE), ioc_data.get(LABEL_TYPE),
                                        target_data.get(LABEL_VALUE), target_data.get(LABEL_TYPE))

    def add_tags(self, in_ti: Dict, data: Optional[List | str]):
        if not data:
            return

        if isinstance(data, str):
            data = [data]

        data = [item for item in data if item not in {'unknown', 'Unknown'}]
        in_ti["fields"]["tags"].extend(data)

    def add_aliases(self, in_ti: Dict, data: Optional[List[str] | str]):
        if not data:
            return

        if isinstance(data, str):
            data = [data]

        data = [item for item in data if item not in {'unknown', 'Unknown'}]
        in_ti["fields"]["aliases"].extend(data)

    def build_threat_intel_indicator_obj(self, data: Dict, tlp_color: Optional[str], feed_tags: Optional[List]):

        intel_type: str = self.get_indicator_or_threatintel_type(data.get(LABEL_TYPE))

        ti_data_obj: Dict = {
            "value": data.get("name"),
            "name": data.get("name"),
            "type": intel_type,
            "score": THREAT_INTEL_SCORES.get(intel_type),
            "service": LABEL_DECYFIR,
            "rawJSON": data,
            "relationships": [],
            "fields": {
                "stixid": data.get(LABEL_ID),
                "description": data.get("description", ''),
                "firstseenbysource": data.get("created"),
                "modified": data.get("modified"),
                "trafficlightprotocol": tlp_color if tlp_color else "",
                "aliases": [],
                "tags": [],
                "primary_motivation": "Cyber Crime",
                "secondary_motivations": data.get('primary_motivation', ''),
                "sophistication": "advanced",
                "resource_level": "team",
                "threatactortypes": data.get('threat_actor_types', ''),
            }
        }
        ti_fields = ti_data_obj["fields"]

        if intel_type == FeedIndicatorType.CVE:
            ti_fields["cvedescription"] = data.get("description", "")
            ti_fields["cvemodified"] = data.get("modified")

        if data.get("xMitreAliases"):
            self.add_aliases(ti_data_obj, data.get("xMitreAliases"))

        if data.get("aliases"):
            self.add_aliases(ti_data_obj, data.get("aliases"))

        if data.get('xMitrePlatforms'):
            ti_fields["operatingsystemrefs"] = data.get('xMitrePlatforms')

        if isinstance(data.get("xMitreDataSources"), List):
            self.add_tags(ti_data_obj, data.get("xMitreDataSources"))

        if isinstance(data.get('external_references'), list):
            for ex_ref in data['external_references']:
                if ttps_id := ex_ref.get('external_id'):
                    self.add_tags(ti_data_obj, ttps_id)

        if intel_type is ThreatIntel.ObjectsNames.MALWARE:
            ti_data_obj['fields'].update({
                'ismalwarefamily': data.get('is_family'),
                'malwaretypes': data.get('malware_types')
            })

        kill_chain_phases = [phase.get("phase_name") for phase in data.get("kill_chain_phases", [])]
        ti_fields["killchainphases"] = kill_chain_phases

        labels = data.get("labels", [])
        for label in labels:
            if isinstance(label, Dict):
                if label.get("origin-of-country"):
                    ti_fields["geocountry"] = label.get("origin-of-country")

                if label.get("target-countries"):
                    ti_fields["targetcountries"] = label.get("target-countries")

                if label.get("target-industries"):
                    ti_fields["targetindustries"] = label.get("target-industries")

                if label.get("geographies"):
                    ti_fields["targetcountries"] = label.get("geographies")

                if label.get("industries"):
                    ti_fields["targetindustries"] = label.get("industries")

                if label.get("technologies"):
                    ti_fields["technologies"] = label.get("technologies")

                if intel_type == FeedIndicatorType.CVE:
                    ti_fields["cvssscore"] = label.get("cvss_score", "")
                    ti_fields["cvssvector"] = label.get("cvss_vector", "")
                    ti_fields["cvssversion"] = label.get("cvss_version", "")
                    ti_data_obj["score"] = 0

                    if label.get("cvss_metrics_data"):
                        metrics = []
                        cvss_metrics_data = label["cvss_metrics_data"]

                        for metric in CVSS_COMMON_METRICS:
                            key = str(metric).replace("_", " ").capitalize()
                            metrics.append({"metrics": key, "value": cvss_metrics_data.get(metric)})

                        cvss_version = label.get("cvss_version", "")
                        if cvss_version and cvss_version[0] == "2":
                            cvss_version_metrics = CVSS_VERSION_METRICS_2
                        elif cvss_version and cvss_version[0] == "3":
                            cvss_version_metrics = CVSS_VERSION_METRICS_3
                        else:
                            cvss_version_metrics = []

                        for metric in cvss_version_metrics:
                            key = str(metric).replace("_", " ").capitalize()
                            metrics.append({"metrics": key, "value": cvss_metrics_data.get(metric)})

                        if cvss_metrics_data.get('vendors'):
                            vendors = ', '.join(cvss_metrics_data['vendors'])
                            metrics.append({"metrics": 'Vendors', "value": vendors})

                        if cvss_metrics_data.get('products'):
                            products = ', '.join(cvss_metrics_data['products'])
                            metrics.append({"metrics": 'Products', "value": products})

                        if cvss_metrics_data.get('technologies'):
                            technologies = ', '.join(cvss_metrics_data['technologies'])
                            metrics.append({"metrics": 'Technologies', "value": technologies})

                        ti_fields["cvsstable"] = metrics

        if feed_tags:
            self.add_tags(ti_data_obj, feed_tags)

        return ti_data_obj

    def build_ta_relationships_data(self, ta_rel_data_coll: list, ta_source_obj: dict, return_data: list,
                                    tlp_color: Optional[str],
                                    feed_tags: Optional[List]):
        src_ti_relationships_data = []
        raw_ta_rels: List = []
        raw_ta_data: Dict = {}
        raw_ta_obj: Dict = {}

        # Only source object getting from the iterating
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
                    source_ref_obj: Dict = raw_ta_data.get(raw_ta_rel_.get(LABEL_SOURCE_REF, ''), {})
                else:
                    source_ref_obj = raw_ta_data.get(raw_ta_rel_.get('sourceRef', ''), {})
                # Target ref obj from relationship obj
                if raw_ta_rel_.get(LABEL_TARGET_REF) in raw_ta_data:
                    target_ref_obj: Dict = raw_ta_data.get(raw_ta_rel_.get(LABEL_TARGET_REF, ''), {})
                else:
                    target_ref_obj = raw_ta_data.get(raw_ta_rel_.get('targetRef', ''), {})

                if source_ref_obj is not None and target_ref_obj is not None:
                    if raw_ta_obj.get(LABEL_ID) != source_ref_obj.get(LABEL_ID):
                        source_ti_data_obj = self.build_threat_intel_indicator_obj(source_ref_obj, tlp_color,
                                                                                   feed_tags)
                        if source_ti_data_obj is not None and source_ti_data_obj:
                            src_exists_in = False
                            for re_data1 in return_data:
                                if re_data1["name"] == source_ti_data_obj["name"]:
                                    src_exists_in = True
                                    break
                            if not src_exists_in:
                                return_data.append(source_ti_data_obj)
                    else:
                        source_ti_data_obj = ta_source_obj

                    src_tar_flag = source_ti_data_obj is not None and source_ti_data_obj.get(
                        LABEL_ID) != target_ref_obj.get(LABEL_ID)

                    if raw_ta_obj.get(LABEL_ID) != target_ref_obj.get(LABEL_ID) and src_tar_flag:

                        target_ti_data_obj = self.build_threat_intel_indicator_obj(target_ref_obj, tlp_color,
                                                                                   feed_tags)
                        if target_ti_data_obj is not None and target_ti_data_obj:
                            tar_exists_in = False
                            for re_data2 in return_data:
                                if re_data2["name"] == target_ti_data_obj["name"]:
                                    tar_exists_in = True
                                    break
                            if not tar_exists_in:
                                return_data.append(target_ti_data_obj)
                    else:
                        target_ti_data_obj = ta_source_obj

                    if source_ti_data_obj and target_ti_data_obj:
                        ti_relationships: dict = self.build_threat_actor_relationship_obj(source_ti_data_obj,
                                                                                          target_ti_data_obj)

                        if ti_relationships:
                            is_scr_rel = raw_ta_obj.get(LABEL_ID) == source_ref_obj.get(LABEL_ID) or raw_ta_obj.get(
                                LABEL_ID) == target_ti_data_obj.get(LABEL_ID)

                            if raw_ta_obj.get(LABEL_ID) != source_ref_obj.get(LABEL_ID):
                                source_ti_data_obj[LABEL_RELATIONSHIPS].append(ti_relationships)

                            if raw_ta_obj.get(LABEL_ID) != target_ti_data_obj.get(LABEL_ID):
                                target_ti_data_obj[LABEL_RELATIONSHIPS].append(ti_relationships)

                            if is_scr_rel:
                                src_ti_relationships_data.append(ti_relationships)

        return ta_source_obj, src_ti_relationships_data, return_data

    def convert_decyfir_ti_to_indicator_format(self, decyfir_api_key: str, data: Dict, tlp_color: Optional[str],
                                               feed_tags: Optional[List], threat_intel_type: str,
                                               is_data_save: bool) -> List[Dict]:

        return_data: list[dict] = []
        ta_source_obj: dict = {}
        src_ti_relationships_data: list = []

        if data:
            # Threat actors Data
            if threat_intel_type is ThreatIntel.ObjectsNames.THREAT_ACTOR:
                ta_name = data.get("name")
                if is_data_save:
                    # Threat actor details search API
                    # Threat actors relationships
                    if ta_rel_data_coll := self.get_decyfir_api_iocs_ti_data(
                        TA_API_STIX_2_1_SEARCH_PATH_SUFFIX.format(decyfir_api_key, ta_name)
                    ):
                        ta_source_obj, src_ti_relationships_data, return_data = self.build_ta_relationships_data(ta_rel_data_coll,
                                                                                                                 ta_source_obj,
                                                                                                                 return_data,
                                                                                                                 tlp_color,
                                                                                                                 feed_tags)
                    ta_source_obj[LABEL_RELATIONSHIPS] = src_ti_relationships_data
                    return_data.append(ta_source_obj)
                else:
                    ns_ti_data_obj1 = self.build_threat_intel_indicator_obj(data, tlp_color, feed_tags)
                    return_data.append(ns_ti_data_obj1)
            else:
                ti_data_obj = self.build_threat_intel_indicator_obj(data, tlp_color, feed_tags)
                return_data.append(ti_data_obj)

        return return_data

    def convert_decyfir_ti_to_indicators_formats(self, decyfir_api_key: str, ti_data: List[Dict], tlp_color: Optional[str],
                                                 feed_tags: Optional[List], threat_intel_type: str,
                                                 is_data_save: bool) -> List[Dict]:

        return_data = []
        for data in ti_data:
            tis_data = self.convert_decyfir_ti_to_indicator_format(decyfir_api_key, data, tlp_color, feed_tags, threat_intel_type,
                                                                   is_data_save)
            return_data.extend(tis_data)

        return return_data

    def convert_decyfir_ioc_to_indicators_formats(self, decyfir_api_key: str, decyfir_iocs: List[Dict], reputation: Optional[str],
                                                  tlp_color: Optional[str], feed_tags: Optional[List],
                                                  is_data_save: bool) -> List[Dict]:

        return_data = []

        for ioc in decyfir_iocs:
            ioc_type = self.get_indicator_or_threatintel_type(ioc.get("pattern"))
            value: str = str(ioc.get("name"))
            file_hash_values = {}
            decyfir_ioc_type: str = ioc_type

            if 'File SHA-1 hash' in value:
                decyfir_ioc_type = "SHA"
            elif 'File SHA-256 hash' in value:
                decyfir_ioc_type = "SHA"
            elif 'File MD5 hash' in value:
                decyfir_ioc_type = "MD5"

            pattern_val: str = str(ioc.get("pattern"))

            if pattern_val != "None" and pattern_val is not None:
                pattern_val = pattern_val.replace("[", "").replace("]", "").replace("file:hashes.", "")
                pattern_vals: list = pattern_val.split("OR")

                for p_v in pattern_vals:
                    p = p_v.split(" = ")
                    key_ = p[0].replace("'", '').replace(" ", '')
                    val_ = p[1].replace("'", '').replace(" ", '')
                    file_hash_values[key_] = val_

            if ioc_type is FeedIndicatorType.IPv6:
                decyfir_ioc_type = FeedIndicatorType.IP
            elif ioc_type is FeedIndicatorType.Host:
                decyfir_ioc_type = "HOSTNAME"

            ioc_data = {
                "value": value,
                "type": ioc_type,
                "rawJSON": ioc,
                'service': LABEL_DECYFIR,
                'Reputation': reputation,
                "fields": {
                    "aliases": [],
                    "tags": [],
                    "stixid": ioc.get('id'),
                    "description": ioc.get("description", ''),
                    "firstseenbysource": ioc.get("created"),
                    "modified": ioc.get('modified'),
                    "trafficlightprotocol": tlp_color if tlp_color else "",
                }
            }
            if file_hash_values:
                for key_ in file_hash_values:
                    ioc_data['fields'][key_] = file_hash_values.get(key_)

            if feed_tags:
                self.add_tags(ioc_data, feed_tags)

            ioc_labels = ioc.get("labels")
            if ioc_labels is not None:
                for label in ioc_labels:
                    if isinstance(label, dict):
                        if label.get("geographies"):
                            ioc_data['fields']['geocountry'] = label.get("geographies")
                        if label.get("tags"):
                            self.add_tags(ioc_data, label.get("tags"))

            if isinstance(ioc.get("kill_chain_phases"), List):
                self.add_tags(ioc_data, ioc.get("kill_chain_phases"))

            if is_data_save:
                ioc_rel_data: List[Dict] = self.get_decyfir_api_iocs_ti_data(
                    IOC_API_STIX_2_1_SEARCH_PATH_SUFFIX.format(decyfir_api_key, decyfir_ioc_type, ioc_data.get(LABEL_VALUE)))

                if ioc_rel_data:
                    relationships_data = []
                    for ioc_rel in ioc_rel_data:
                        if ioc_rel.get(LABEL_TYPE) != LABEL_INDICATOR and ioc_rel.get(LABEL_TYPE) != LABEL_RELATIONSHIP:
                            in_rel_ti_data_ = self.build_threat_intel_indicator_obj(ioc_rel, tlp_color, feed_tags)
                            if in_rel_ti_data_.get(LABEL_TYPE) == ThreatIntel.ObjectsNames.THREAT_ACTOR:
                                tis_data = self.convert_decyfir_ti_to_indicator_format(decyfir_api_key, in_rel_ti_data_,
                                                                                       tlp_color,
                                                                                       feed_tags,
                                                                                       ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                                                       is_data_save)
                                for t_rel_d in tis_data:
                                    return_data.append(t_rel_d)
                                    if t_rel_d.get(LABEL_TYPE) == ThreatIntel.ObjectsNames.THREAT_ACTOR:
                                        in_rel_data = self.build_ioc_relationship_obj(ioc_data, t_rel_d)
                                        if in_rel_data:
                                            relationships_data.append(in_rel_data)
                            else:
                                return_data.append(in_rel_ti_data_)
                                in_rel_data = self.build_ioc_relationship_obj(ioc_data, in_rel_ti_data_)
                                if in_rel_data:
                                    relationships_data.append(in_rel_data)
                    ioc_data[LABEL_RELATIONSHIPS] = relationships_data

            return_data.append(ioc_data)
        return return_data

    def fetch_indicators(self, decyfir_api_key: str, reputation: Optional[str], tlp_color: Optional[str],
                         feed_tags: Optional[List], is_data_save: bool) -> List[Dict]:
        return_data = []
        try:
            # Indicators from DeCYFIR
            iocs_data = self.get_decyfir_api_iocs_ti_data(IOC_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key))

            # Threat Intel Data from DeCYFIR
            tas_data = self.get_decyfir_api_iocs_ti_data(TA_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key))

            if not is_data_save and iocs_data:
                iocs_data = iocs_data[:2]

            # Converting indicators data to XSOAR indicators format
            ioc_indicators = self.convert_decyfir_ioc_to_indicators_formats(decyfir_api_key, iocs_data, reputation, tlp_color,
                                                                            feed_tags, is_data_save)
            return_data.extend(ioc_indicators)

            if not is_data_save:
                return return_data

            # Converting threat intel data to XSOAR indicators format
            ta_indicators = self.convert_decyfir_ti_to_indicators_formats(decyfir_api_key, tas_data, tlp_color, feed_tags,
                                                                          ThreatIntel.ObjectsNames.THREAT_ACTOR, is_data_save)
            return_data.extend(ta_indicators)
            return return_data

        except Exception as e:
            err = f'Failed to fetch the feed data. DeCYFIR error: {e}'
            demisto.debug(err)

        return return_data


def test_module_command(client, decyfir_api_key):
    url = IOC_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key)
    response = client._http_request(url_suffix=url, method='GET', resp_type='response')
    if response.status_code == 200:
        return 'ok'
    elif response.status_code in [401, 403]:
        return 'Not Authorized'
    else:
        return f"Error_code: {response.status_code}, Please contact the DeCYFIR team to assist you further on this."


def fetch_indicators_command(client: Client, decyfir_api_key: str, tlp_color: Optional[str], reputation: Optional[str],
                             feed_tags: Optional[List]) -> List[Dict]:
    return client.fetch_indicators(decyfir_api_key, reputation, tlp_color, feed_tags, True)


def decyfir_get_indicators_command(client: Client, decyfir_api_key: str, tlp_color: Optional[str], reputation: Optional[str],
                                   feed_tags: Optional[List]):
    indicators = client.fetch_indicators(decyfir_api_key, reputation, tlp_color, feed_tags, False)
    human_readable = tableToMarkdown('Indicators from DeCYFIR Feed:', indicators,
                                     headers=['value', 'type', 'rawJSON'], headerTransform=string_to_table_header,
                                     removeNull=True,
                                     is_auto_json_transform=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def main():  # pragma: no cover
    try:
        params = demisto.params()
        decyfir_url = params['url'].rstrip('/')
        decyfir_api_key = params.get('api_key').get("password")
        use_ssl = params.get('insecure', False)
        proxy = params.get('proxy', False)
        feed_tags = argToList(params.get('feedTags'))
        tlp_color = params.get('tlp_color')
        feed_reputation = params.get('feedReputation')

        demisto.info(f'Command being called is {demisto.command()}')

        client = Client(
            base_url=decyfir_url,
            verify=use_ssl,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_module_command(client, decyfir_api_key)
            demisto.results(result)
        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client, decyfir_api_key, tlp_color, feed_reputation, feed_tags)
            for ioc in batch(indicators, batch_size=2500):
                demisto.createIndicators(ioc)
        elif demisto.command() == "decyfir-get-indicators":
            return_results(decyfir_get_indicators_command(client, decyfir_api_key, tlp_color, feed_reputation, feed_tags))
        else:
            raise NotImplementedError('DeCYFIR error: ' + f'command {demisto.command()} is not implemented')

    except Exception as e:
        err = f'Failed to execute {demisto.command()} command. DeCYFIR error: {e}'
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
