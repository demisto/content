import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

IOC_API_STIX_2_1_PATH_SUFFIX = '/core/api-ua/threatioc/stix/v2.1?key={0}&delta=false&all=false'
IOC_API_STIX_2_1_SEARCH_PATH_SUFFIX = '/core/api-ua/threatioc/stix/v2.1/search?key={0}&&indicatorType={1}&value={2}'

TA_API_STIX_2_1_PATH_SUFFIX = '/core/api-ua/threatactor/ctc/stix/v2.1?key={0}'
TA_API_STIX_2_1_SEARCH_PATH_SUFFIX = '/core/api-ua/threatactor/stix/v2.1?key={0}&name={1}'
TA_MITRE_API_STIX_2_1_PATH_SUFFIX = '/core/api-ua/threatactor/mitre/stix/v2.1?key={0}&threat-actor={1}'

LABEL_DECYFIR = "DeCYFIR"
LABEL_INDICATOR = "indicator"
LABEL_THREAT_ACTOR = "threat-actor"
LABEL_INTRUSION_SET = "intrusion-set"
LABEL_RELATIONSHIP = "relationship"
LABEL_RELATIONSHIPS = "relationships"
LABEL_ATTACK_PATTERN = "attack-pattern"
LABEL_TYPE = "type"
LABEL_ID = "id"
LABEL_VALUE = "value"
LABEL_SOURCE_REF = "source_ref"
LABEL_TARGET_REF = "target_ref"

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


class Client(BaseClient):
    def get_indicator_or_threatintel_type(self, data):
        indicator_mapping = {
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

        for key, value in indicator_mapping.items():
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
        relationship_mapping = {
            ThreatIntel.ObjectsNames.INTRUSION_SET: EntityRelationship.Relationships.ATTRIBUTED_TO,
            ThreatIntel.ObjectsNames.ATTACK_PATTERN: EntityRelationship.Relationships.USES,
            ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
            ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.USES,
            FeedIndicatorType.CVE: EntityRelationship.Relationships.TARGETS,
            ThreatIntel.ObjectsNames.TOOL: EntityRelationship.Relationships.USES
        }

        target_type: str = str(target_data.get(LABEL_TYPE))
        target_value: str = str(target_data.get(LABEL_VALUE))
        source_type: str = str(source_data.get(LABEL_TYPE))
        source_value: str = str(source_data.get(LABEL_VALUE))

        relationship = relationship_mapping.get(target_type)
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

        if 'Unknown' in data:
            data.remove('Unknown')
        elif 'unknown' in data:
            data.remove('unknown')

        in_ti["fields"]["tags"].extend(data)

    def add_aliases(self, in_ti: Dict, data: Optional[List[str] | str]):
        if not data:
            return

        if isinstance(data, str):
            data = [data]

        if 'Unknown' in data:
            data.remove('Unknown')
        elif 'unknown' in data:
            data.remove('unknown')

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

                # "ismalwarefamily": data.get('is_family', ''),
                # "malwaretypes": data.get('malware_types', ''),
                # "operatingsystemrefs": data.get('xMitrePlatforms', '')
            }
        }
        ti_fields = ti_data_obj["fields"]

        if FeedIndicatorType.CVE == intel_type:
            ti_fields["cvedescription"] = data.get("description", "")

        if data.get("xMitreAliases"):
            self.add_aliases(ti_data_obj, data.get("xMitreAliases"))

        if data.get("aliases"):
            self.add_aliases(ti_data_obj, data.get("aliases"))

        if data.get('xMitrePlatforms'):
            ti_fields["operatingsystemrefs"] = data.get('xMitrePlatforms')

        if isinstance(data.get("xMitreDataSources"), List):
            self.add_tags(ti_data_obj, data.get("xMitreDataSources"))

        external_ref = data.get("external_references")

        if external_ref is not None and isinstance(external_ref, List):
            for ex_ref in list(external_ref):
                ttps_id: str = str(ex_ref.get("external_id"))
                if ttps_id:
                    self.add_tags(ti_data_obj, ttps_id)

        # if intel_type is ThreatIntel.ObjectsNames.THREAT_ACTOR:
        #     ti_data_obj['fields'].update({
        #         'primary_motivation': "Cyber Crime",
        #         'secondary_motivations': data.get('primary_motivation'),
        #         'sophistication': "advanced",
        #         'resource_level': "team",
        #         'threatactortypes': data.get('threat_actor_types')
        #     })

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
                    self.add_tags(ti_data_obj, label.get("target-countries"))
                    ti_fields["targetcountries"] = label.get("target-countries")

                if label.get("target-industries"):
                    self.add_tags(ti_data_obj, label.get("target-industries"))
                    ti_fields["targetindustries"] = label.get("target-industries")

                if label.get("geographies"):
                    self.add_tags(ti_data_obj, label.get("geographies"))
                    ti_fields["targetcountries"] = label.get("geographies")

                if label.get("industries"):
                    self.add_tags(ti_data_obj, label.get("industries"))
                    ti_fields["targetindustries"] = label.get("industries")

                if label.get("technologies"):
                    self.add_tags(ti_data_obj, label.get("technologies"))
                    ti_fields["technologies"] = label.get("technologies")

        if feed_tags:
            self.add_tags(ti_data_obj, feed_tags)

        return ti_data_obj

    def convert_decyfir_ti_to_indicator_format(self, decyfir_api_key: str, data: Dict, tlp_color: Optional[str],
                                               feed_tags: Optional[List], threat_intel_type: str) -> List[Dict]:

        return_data = []
        ta_source_obj = {}
        src_ti_relationships_data = []

        if data:
            # Threat actors Data
            if threat_intel_type is ThreatIntel.ObjectsNames.THREAT_ACTOR:
                ta_name = data.get("name")
                # Threat actor details search API
                ta_rel_data: List[Dict] = self.get_decyfir_api_iocs_ti_data(
                    TA_API_STIX_2_1_SEARCH_PATH_SUFFIX.format(decyfir_api_key, ta_name))

                # Threat actors relationships
                if ta_rel_data:
                    raw_ta_rels: List = [Dict]
                    raw_ta_data: Dict = {}
                    raw_ta_obj: Dict = {}
                    # Only source object getting from the iterating
                    for data1 in ta_rel_data:
                        if LABEL_THREAT_ACTOR == data1.get(LABEL_TYPE):
                            raw_ta_obj = data1
                            ta_source_obj = self.build_threat_intel_indicator_obj(data1, tlp_color, feed_tags)

                        if LABEL_RELATIONSHIP == data1.get(LABEL_TYPE):
                            raw_ta_rels.append(data1)
                        else:
                            raw_ta_data[data1.get(LABEL_ID)] = data1

                    for raw_ta_rel_ in raw_ta_rels:
                        if str(raw_ta_rel_.get(LABEL_SOURCE_REF)) in raw_ta_data:
                            source_ref = str(raw_ta_rel_.get(LABEL_SOURCE_REF))
                        else:
                            source_ref = str(raw_ta_rel_.get('sourceRef'))

                        source_ref_val_ = raw_ta_data.get(source_ref)
                        source_ref_obj: Dict = source_ref_val_ if source_ref_val_ is not None else {}

                        if str(raw_ta_rel_.get(LABEL_TARGET_REF)) in raw_ta_data:
                            target_ref = str(raw_ta_rel_.get(LABEL_TARGET_REF))
                        else:
                            target_ref = str(raw_ta_rel_.get('targetRef'))

                        target_ref_val_ = raw_ta_data.get(target_ref)
                        target_ref_obj: Dict = target_ref_val_ if target_ref_val_ is not None else {}

                        if str(raw_ta_obj.get(LABEL_ID)) != str(source_ref_obj.get(LABEL_ID)):
                            source_ti_data_obj = self.build_threat_intel_indicator_obj(source_ref_obj, tlp_color, feed_tags)
                            return_data.append(source_ti_data_obj)
                        else:
                            source_ti_data_obj = ta_source_obj

                        if str(raw_ta_obj.get(LABEL_ID)) != str(target_ref_obj.get(LABEL_ID)) and str(source_ti_data_obj.get(
                            LABEL_ID)) != str(target_ref_obj.get(LABEL_ID)):
                            target_ti_data_obj = self.build_threat_intel_indicator_obj(target_ref_obj, tlp_color, feed_tags)
                            return_data.append(target_ti_data_obj)
                        else:
                            target_ti_data_obj = ta_source_obj

                        if source_ti_data_obj and target_ti_data_obj:
                            if raw_ta_obj.get(LABEL_ID) != source_ref_obj.get(LABEL_ID):
                                ti_relationships: dict = self.build_threat_actor_relationship_obj(source_ti_data_obj,
                                                                                                  target_ti_data_obj)
                                source_ti_data_obj[LABEL_RELATIONSHIPS] = []
                                if ti_relationships:
                                    if source_ti_data_obj[LABEL_RELATIONSHIPS]:
                                        source_ti_data_obj[LABEL_RELATIONSHIPS].append(ti_relationships)
                                    else:
                                        source_ti_data_obj[LABEL_RELATIONSHIPS] = [ti_relationships]
                            else:
                                ti_relationships = self.build_threat_actor_relationship_obj(source_ti_data_obj,
                                                                                            target_ti_data_obj)
                                if ti_relationships:
                                    src_ti_relationships_data.append(ti_relationships)

            ta_source_obj[LABEL_RELATIONSHIPS] = src_ti_relationships_data
            return_data.append(ta_source_obj)
        else:
            ti_data_obj = self.build_threat_intel_indicator_obj(data, tlp_color, feed_tags)
            return_data.append(ti_data_obj)

        return return_data

    def convert_decyfir_ti_to_indicators_formats(self, decyfir_api_key: str, ti_data: List[Dict], tlp_color: Optional[str],
                                                 feed_tags: Optional[List], threat_intel_type: str) -> List[Dict]:

        return_data = []
        for data in ti_data:
            tis_data = self.convert_decyfir_ti_to_indicator_format(decyfir_api_key, data, tlp_color, feed_tags, threat_intel_type)
            return_data.extend(tis_data)

        return return_data

    def convert_decyfir_ioc_to_indicators_formats(self, decyfir_api_key: str, decyfir_iocs: List[Dict], reputation: Optional[str],
                                                  tlp_color: Optional[str], feed_tags: Optional[List]) -> List[Dict]:

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
                for key_ in file_hash_values.keys():
                    ioc_data['fields'][key_] = file_hash_values.get(key_)

            if feed_tags:
                self.add_tags(ioc_data, feed_tags)

            ioc_labels = ioc.get("labels")
            if ioc_labels is not None:
                for label in list(ioc_labels):
                    if label.get("geographies"):
                        ioc_data['fields']['geocountry'] = label.get("geographies")
                    if label.get("tags"):
                        self.add_tags(ioc_data, label.get("tags"))

            if isinstance(ioc.get("kill_chain_phases"), List):
                self.add_tags(ioc_data, ioc.get("kill_chain_phases"))

            ioc_rel_data: List[Dict] = self.get_decyfir_api_iocs_ti_data(
                IOC_API_STIX_2_1_SEARCH_PATH_SUFFIX.format(decyfir_api_key, decyfir_ioc_type, ioc_data.get(LABEL_VALUE)))

            if ioc_rel_data:
                relationships_data = []
                for ioc_rel in ioc_rel_data:
                    if LABEL_INDICATOR != ioc_rel.get(LABEL_TYPE) and LABEL_RELATIONSHIP != ioc_rel.get(LABEL_TYPE):
                        in_rel_ti_data_ = self.build_threat_intel_indicator_obj(ioc_rel, tlp_color, feed_tags)
                        if ThreatIntel.ObjectsNames.THREAT_ACTOR == in_rel_ti_data_.get(LABEL_TYPE):
                            tis_data = self.convert_decyfir_ti_to_indicator_format(decyfir_api_key, in_rel_ti_data_, tlp_color,
                                                                                   feed_tags,
                                                                                   ThreatIntel.ObjectsNames.THREAT_ACTOR)
                            for t_rel_d in tis_data:
                                return_data.append(t_rel_d)
                                if ThreatIntel.ObjectsNames.THREAT_ACTOR == t_rel_d.get(LABEL_TYPE):
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
                         feed_tags: Optional[List]) -> List[Dict]:

        # Indicators from DeCYFIR
        iocs_data = self.get_decyfir_api_iocs_ti_data(IOC_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key))

        # Threat Intel Data from DeCYFIR
        tas_data = self.get_decyfir_api_iocs_ti_data(TA_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key))

        return_data = []

        # Converting indicators data to XSOAR indicators format
        ioc_indicators = self.convert_decyfir_ioc_to_indicators_formats(decyfir_api_key, iocs_data, reputation, tlp_color,
                                                                        feed_tags)
        return_data.extend(ioc_indicators)

        # Converting threat intel data to XSOAR indicators format
        ta_indicators = self.convert_decyfir_ti_to_indicators_formats(decyfir_api_key, tas_data, tlp_color, feed_tags,
                                                                      ThreatIntel.ObjectsNames.THREAT_ACTOR)
        return_data.extend(ta_indicators)

        return return_data


def test_module_command(client, decyfir_api_key):
    url = IOC_API_STIX_2_1_PATH_SUFFIX.format(decyfir_api_key)
    response = client._http_request(url_suffix=url, method='GET', resp_type='response')
    if response.status_code == 200:
        return 'ok'
    elif response.status_code == 401 or response.status_code == 403:
        return 'Not Authorized'
    else:
        return f"Error_code: {response.status_code}, Please contact the DeCYFIR team to assist you further on this."
    # return client.fetch_indicators(decyfir_api_key, None, None, None)


def fetch_indicators_command(client: Client, decyfir_api_key: str, tlp_color: Optional[str], reputation: Optional[str],
                             feed_tags: Optional[List]) -> List[Dict]:

    return client.fetch_indicators(decyfir_api_key, reputation, tlp_color, feed_tags)


def main():
    try:
        args = demisto.args()
        params = demisto.params()
        decyfir_url = params['url'].rstrip('/')
        decyfir_api_key = params.get('api_key').get("password")
        use_ssl = params.get('insecure', False)
        proxy = params.get('proxy', False)
        feed_tags = argToList(params.get('feedTags'))
        tlp_color = params.get('tlp_color')
        # indicator_type = params.get('indicatorType')
        # indicator = params.get('indicator')
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
        else:
            raise NotImplementedError('DeCYFIR error: ' + f'command {demisto.command()} is not implemented')

    except Exception as e:
        err = f'Failed to execute {demisto.command()} command. DeCYFIR error: {e}'
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
