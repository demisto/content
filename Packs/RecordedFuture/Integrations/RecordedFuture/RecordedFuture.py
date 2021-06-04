"""Recorded Future Integration for Demisto."""
from typing import Dict, Any, List, Tuple
from urllib import parse
import requests
import json
import re

# flake8: noqa: F402,F405 lgtm
import demistomock as demisto
from CommonServerPython import *

STATUS_TO_RETRY = [500, 501, 502, 503, 504]

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint:disable=no-member

__version__ = '2.1.1'


def rename_keys(old_to_new: Dict[str, str], original: Dict[str, Any]):
    for old, new in old_to_new.items():
        original[new] = original[old]
        del original[old]
    return original


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:
        """Entity lookup."""
        return self._http_request(
            method="get",
            url_suffix="info/whoami",
            timeout=60,
        )

    def entity_lookup(
            self, entities: List[str], entity_type: str) -> Dict[str, Any]:
        """Entity lookup."""
        if entity_type == "file":
            entity_type = "hash"
        elif entity_type == "cve":
            entity_type = "vulnerability"
        return self._http_request(
            method="post",
            url_suffix="soar/enrichment",
            json_data={entity_type: entities},
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )

    def entity_enrich(
        self, entity: str, entity_type: str,
            related: bool, risky: bool,
            profile: str = 'All'
    ) -> Dict[str, Any]:
        """Entity enrich."""

        profiles = {
            "Vulnerability Analyst": [
                "RelatedMalwareCategory",
                "RelatedMalware",
                "RelatedThreatActor"
            ],
            "TI Analyst": [
                "RelatedIpAddress",
                "RelatedMalwareCategory",
                "RelatedMalware",
                "RelatedThreatActor"
            ],
            "SecOp Analyst": [
                "RelatedMalwareCategory",
                "RelatedMalware",
            ],
            "Threat Hunter": [
                "RelatedInternetDomainName",
                "RelatedHash",
                "RelatedMalware",
                "RelatedAttackVector"
            ]
        }

        intel_map = {
            "ip": [
                "entity",
                "risk",
                "timestamps",
                "threatLists",
                "intelCard",
                "metrics",
                "location",
                "relatedEntities",
                "riskyCIDRIPs",
            ],
            "domain": [
                "entity",
                "risk",
                "timestamps",
                "threatLists",
                "intelCard",
                "metrics",
                "relatedEntities",
            ],
            "hash": [
                "entity",
                "risk",
                "timestamps",
                "threatLists",
                "intelCard",
                "metrics",
                "hashAlgorithm",
                "relatedEntities",
            ],
            "vulnerability": [
                "entity",
                "risk",
                "timestamps",
                "threatLists",
                "intelCard",
                "metrics",
                "cvss",
                "nvdDescription",
                "relatedEntities",
                "cpe",
                "relatedLinks"
            ],
            "url": [
                "entity",
                "risk",
                "timestamps",
                "metrics",
                "relatedEntities",
            ],
        }
        if entity_type == "url":
            entity = parse.quote_plus(entity)
        elif entity_type == "file":
            entity_type = "hash"
        elif entity_type == "cve":
            entity_type = "vulnerability"
        cmd_url = f"{entity_type}/{entity.strip()}"
        fields = intel_map[entity_type]
        if entity_type == "ip" and not risky:
            fields.remove("riskyCIDRIPs")
        if not related and profile != 'All':
            fields.remove("relatedEntities")
        req_fields = ",".join(fields)
        params = {"fields": req_fields}
        resp = self._http_request(
            method="get", url_suffix=cmd_url, params=params, timeout=30,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )
        if profile != 'All' and related:
            related_entities = resp['data']['relatedEntities']
            related_entities = [
                entry for entry in related_entities
                if entry['type'] in profiles[profile]
            ]
            resp['data']['relatedEntities'] = related_entities
        return resp

    def get_single_alert(self, _id):
        """Get a single alert"""
        return self._http_request(
            method="get",
            url_suffix=f"alert/{_id}",
            timeout=30,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )

    def get_alert_rules(self, rule_name: str, limit: int) -> Dict[str, Any]:
        """Get Alert Rules."""
        params: Dict[str, Any] = {}
        if rule_name:
            params["freetext"] = rule_name.strip()
        if limit:
            params["limit"] = limit
        return self._http_request(
            method="get",
            url_suffix="alert/rule",
            params=params,
            timeout=30,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )

    def get_alerts(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get Alerts."""
        return self._http_request(
            method="get",
            url_suffix="alert/search",
            params=params,
            timeout=30,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )

    def get_triage(
        self, entities: Dict[str, List], context: str
    ) -> Dict[str, Any]:
        """SOAR triage lookup."""
        return self._http_request(
            method="post",
            url_suffix=f"soar/triage/contexts/{context}" "?format=phantom",
            json_data=entities,
            timeout=30,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY
        )


def translate_score(score: int, threshold: int) -> int:
    """Translate Recorded Future score to DBot score."""
    RISK_SCORE_THRESHOLD = 25
    # see https://support.recordedfuture.com/hc/en-us/articles/115000894468-Vulnerability-Risk-Rules # noqa
    if score >= threshold:
        return Common.DBotScore.BAD
    elif score >= RISK_SCORE_THRESHOLD:
        return Common.DBotScore.SUSPICIOUS
    else:
        return Common.DBotScore.NONE


def parse_cpe(cpes: list) -> list:
    dicts = []
    parts = {
        'o': 'Operating System',
        'a': 'Application',
        'h': 'Hardware',
        '*': 'Any',
        '-': 'NA'
    }
    cpe_regex = re.compile(
        r'cpe:2\.3:(?P<Part>[aoh*-]):(?P<Vendor>[a-zA-Z_-]+):'
        r'(?P<Product>[A-Za-z0-9_-]+):(?P<Version>[0-9.]+):(?P<Update>[a-zA-Z0-9*]+):'
        r'(?P<Edition>[a-zA-Z0-9*]+):(?P<Language>[a-zA-Z0-9*]+):'
        r'(?P<swedition>[a-zA-Z0-9*]+):(?P<targetsw>[a-zA-Z0-9*]+):'
        r'(?P<targethw>[a-zA-Z0-9*]+):(?P<Other>[a-zA-Z0-9*]+)'
    )
    for cpe in cpes:
        try:
            match = cpe_regex.match(cpe)
            if match:
                tmp_dict = match.groupdict()
                tmp_dict['Part'] = parts[tmp_dict.get('Part', '-')]
                tmp_dict['Software Edition'] = tmp_dict.pop('swedition')
                tmp_dict['Target Software'] = tmp_dict.pop('targetsw')
                tmp_dict['Target Hardware'] = tmp_dict.pop('targethw')
                dicts.append(tmp_dict)
        except:
            continue
    return dicts


def determine_hash(hash_value: str) -> str:
    """Determine hash type by length."""
    hash_length = len(hash_value)
    if hash_length == 128:
        return "SHA512"
    elif hash_length == 64:
        return "SHA256"
    elif hash_length == 40:
        return "SHA1"
    elif hash_length == 32:
        return "MD5"
    elif hash_length == 8:
        return "CRC32"
    else:
        return "CTPH"


def level_to_criticality(level: int) -> str:
    """Translate level integer to Criticality string."""
    if level >= 4:
        return "Very Malicious"
    elif level >= 3:
        return "Malicious"
    elif level >= 2:
        return "Suspicious"
    elif level >= 1:
        return "Informational"
    return "Unknown"


def rf_type_to_xsoar_type(entity_type: str) -> str:
    if entity_type == "IpAddress":
        return "ip"
    elif entity_type == "Hash":
        return "file"
    elif entity_type == "URL":
        return "url"
    elif entity_type == "CyberVulnerability":
        return "cve"
    elif entity_type == "InternetDomainName":
        return "domain"
    raise DemistoException(
        f"Unknown Recorded Future " f"entity type: {entity_type}"
    )


def prettify_time(time_string: str) -> str:
    """Fix timestamps to a better format."""
    if time_string:
        parsed = datetime.strptime(time_string, "%Y-%m-%dT%H:%M:%S.%fZ")
        return datetime.strftime(parsed, "%Y-%m-%d %H:%M:%S")
    else:
        return "N/A"


def create_indicator(
    entity: str,
    entity_type: str,
    score: int,
    description: str,
    location: Dict[str, Any] = {},
) -> Common.Indicator:
    """Create an Indicator object."""
    demisto_params = demisto.params()
    thresholds = {
        "file": int(demisto_params.get("file_threshold", 65)),
        "ip": int(demisto_params.get("ip_threshold", 65)),
        "domain": int(demisto_params.get("domain_threshold", 65)),
        "url": int(demisto_params.get("url_threshold", 65)),
        "cve": int(demisto_params.get("cve_threshold", 65)),
    }
    dbot_score = translate_score(score, thresholds[entity_type])
    dbot_description = (
        f"Score above {thresholds[entity_type]}"
        if dbot_score == Common.DBotScore.BAD
        else None
    )
    dbot_vendor = "Recorded Future v2"
    if entity_type == "ip":
        return Common.IP(
            entity,
            Common.DBotScore(
                entity,
                DBotScoreType.IP,
                dbot_vendor,
                dbot_score,
                dbot_description,
            ),
            asn=location.get("asn", None),
            geo_country=location.get("location", {}).get("country", None),
        )
    elif entity_type == "domain":
        return Common.Domain(
            entity,
            Common.DBotScore(
                entity,
                DBotScoreType.DOMAIN,
                dbot_vendor,
                dbot_score,
                dbot_description,
            ),
        )
    elif entity_type == "file":
        dbot_obj = Common.DBotScore(
            entity,
            DBotScoreType.FILE,
            dbot_vendor,
            dbot_score,
            dbot_description,
        )
        hash_type = determine_hash(entity)
        if hash_type == "MD5":
            return Common.File(dbot_obj, md5=entity)
        elif hash_type == "SHA1":
            return Common.File(dbot_obj, sha1=entity)
        elif hash_type == "SHA256":
            return Common.File(dbot_obj, sha256=entity)
        elif hash_type == "SHA512":
            return Common.File(dbot_obj, sha512=entity)
        else:
            return Common.File(dbot_obj)
    elif entity_type == "cve":
        return Common.CVE(entity, "", "", "", description)
    elif entity_type == "url":
        return Common.URL(
            entity,
            Common.DBotScore(
                entity,
                DBotScoreType.URL,
                dbot_vendor,
                dbot_score,
                dbot_description,
            ),
        )
    else:
        raise Exception(
            "Could not create indicator for this "
            f"type of entity: {entity_type}"
        )


def get_output_prefix(entity_type: str) -> str:
    if entity_type in ["cve", "vulnerability"]:
        return "RecordedFuture.CVE"
    elif entity_type == "ip":
        return "RecordedFuture.IP"
    elif entity_type == "domain":
        return "RecordedFuture.Domain"
    elif entity_type == "url":
        return "RecordedFuture.URL"
    elif entity_type in ["file", "vulnerability"]:
        return "RecordedFuture.File"
    else:
        raise Exception(f"Unknown entity type: {entity_type}")


#####################
#    Actions        #
#####################


def lookup_command(
    client: Client, entities: List[str], entity_type: str
) -> List[CommandResults]:
    """Entity lookup command."""
    entity_data = client.entity_lookup(entities, entity_type)
    command_results = build_rep_context(entity_data, entity_type)
    return command_results


def build_rep_markdown(ent: Dict[str, Any], entity_type: str) -> str:
    """Build Reputation Markdown."""
    markdown = []
    entity_title = (
        entity_type.upper()
        if entity_type in ["ip", "url", "cve"]
        else entity_type.title()
    )
    try:
        evidence = ent["risk"]["rule"]["evidence"]
    except KeyError:
        evidence = {}
    markdown.append(
        "\n".join(
            [
                f"### Recorded Future {entity_title} reputation "
                f'for {ent["entity"]["name"]}',
                f'Risk score: {int(ent["risk"]["score"])}',
                f'Risk Summary: {ent["risk"]["rule"]["count"]} out of '
                f'{ent["risk"]["rule"]["maxCount"]} '
                f"Risk Rules currently observed",
                f'Criticality: {level_to_criticality(ent["risk"]["level"])}'
                f"\n",
            ]
        )
    )
    if ent["entity"].get("description", None):
        markdown.append(
            f"NVD Vulnerability Description: "
            f'{ent["entity"]["description"]}\n'
        )
    if ent["entity"].get("id", None):
        markdown.append(
            "[Intelligence Card]"
            "(https://app.recordedfuture.com"
            f'/live/sc/entity/{ent["entity"]["id"]})\n'
        )
    if evidence:
        evid_table = [
            {
                "Rule": detail["rule"],
                "Criticality": level_to_criticality(detail["level"]),
                "Evidence": detail["description"],
                "Timestamp": prettify_time(detail["timestamp"]),
                "Level": detail["level"],
            }
            for x, detail in evidence.items()
        ]
        evid_table.sort(key=lambda x: x.get("Level"), reverse=True) # type: ignore
        markdown.append(
            tableToMarkdown(
                "Risk Rules Triggered",
                evid_table,
                ["Criticality", "Rule", "Evidence", "Timestamp"],
                removeNull=True,
            )
        )
    return "\n".join(markdown)


def build_rep_context(
    entity_data: Dict[str, Any], entity_type: str
) -> List[CommandResults]:
    """Build Reputation Context."""
    if entity_type == "hash":
        entity_type = "file"
    elif entity_type == "vulnerability":
        entity_type = "cve"

    command_results: List[CommandResults] = []
    if entity_data and ("error" not in entity_data):
        for ent in entity_data["data"]["results"]:
            try:
                evidence = ent["risk"]["rule"]["evidence"]
            except KeyError:
                evidence = {}
            concat_rules = ','.join([e["rule"] for e in evidence.values()])
            context = (
                {
                    "riskScore": ent["risk"]["score"],
                    "Evidence": [
                        {
                            "rule": dic["rule"],
                            "mitigation": dic["mitigation"],
                            "description": dic["description"],
                            "timestamp": prettify_time(dic["timestamp"]),
                            "level": dic["level"],
                            "ruleid": key,
                        }
                        if dic.get("mitigation", None)
                        else {
                            "rule": dic["rule"],
                            "description": dic["description"],
                            "timestamp": prettify_time(dic["timestamp"]),
                            "level": dic["level"],
                            "ruleid": key,
                        }
                        for key, dic in evidence.items()
                    ],
                    "riskLevel": ent["risk"]["level"],
                    "id": ent["entity"]["id"],
                    "ruleCount": ent["risk"]["rule"]["count"],
                    "rules": concat_rules,
                    "maxRules": ent["risk"]["rule"]["maxCount"],
                    "description": ent["entity"].get("description", ""),
                    "name": ent["entity"]["name"],
                }
            )
            indicator = create_indicator(
                ent["entity"]["name"],
                entity_type,
                ent["risk"]["score"],
                ent["entity"].get("description", ""),
            )
            command_results.append(CommandResults(
                outputs_prefix=get_output_prefix(entity_type),
                outputs=context,
                raw_response=entity_data,
                readable_output=build_rep_markdown(ent, entity_type),
                outputs_key_field='name',
                indicator=indicator
            ))
        return command_results
    else:
        return [CommandResults(
            readable_output="No records found"
        )]


def triage_command(
    client: Client, entities: Dict[str, List[str]], context: str
) -> List[CommandResults]:
    """Do Auto Triage."""
    zero_filter = entities.pop('filter', False)

    def include_score(score):
        if zero_filter and score > 0:
            return True
        elif not zero_filter:
            return True
        else:
            return False

    context_data = client.get_triage(entities, context)
    entities = [e for e in context_data["entities"] if include_score(e["score"])]  # type: ignore
    context_data["entities"] = entities
    output_context, command_results = build_triage_context(context_data)
    command_results.append(
        CommandResults(
            outputs_prefix="RecordedFuture",
            outputs=output_context,
            raw_response=context_data,
            readable_output=build_triage_markdown(context_data, context),
            outputs_key_field="verdict",
        )
    )
    return command_results


def build_triage_markdown(context_data: Dict[str, Any], context: str) -> str:
    """Build Auto Triage output."""
    verdict = (
        "Suspected Malicious" if context_data["verdict"] else "Non-malicious"
    )
    md = "\n".join(
        [
            "### Recorded Future Threat Assessment with regards "
            f"to {context}",
            f"Verdict: {verdict}",
            f'Max/Min Score: {context_data["scores"]["max"]}/'
            f'{context_data["scores"]["min"]}\n',
        ]
    )
    tables = [md, "### Entities"]
    for entity in context_data.get("entities", []):
        header = "\n".join(
            [
                f'Entity: {entity["name"]}',
                f'Score: {entity["score"]}',
                f'Rule count: {entity["rule"]["count"]} out '
                f'of {entity["rule"]["maxCount"]}',
            ]
        )
        table = [
            {
                "Rule Name": x["rule"],
                "Rule Criticality": level_to_criticality(x["level"]),
                "Rule Timestamp": prettify_time(x["timestamp"]),
                "Rule Description": x["description"],
                "Level": x["level"],
            }
            for x in entity["rule"]["evidence"]
        ]
        table.sort(key=lambda x: x.get("Level"), reverse=True)  # type: ignore
        tables.append(
            "\n".join(
                [
                    header,
                    tableToMarkdown(
                        "Evidence",
                        table,
                        [
                            "Rule Name",
                            "Rule Criticality",
                            "Rule Timestamp",
                            "Rule Description",
                        ],
                        removeNull=True,
                    ),
                ]
            )
        )
    return "\n".join(tables)


def build_triage_context(
    context_data: Dict[str, Any]
) -> Tuple[Dict[str, Any], List]:
    """Build Auto Triage output."""
    context = {
        "context": context_data.get("context", "Unknown"),
        "verdict": context_data.get("verdict", "Unknown"),
        "riskScore": context_data["scores"]["max"],
        "Entities": [
            {
                "id": entity["id"],
                "name": entity["name"],
                "type": entity["type"],
                "score": entity["score"],
                "Evidence": entity["rule"]["evidence"],
                "context": context_data.get("context", '') if entity["rule"]["evidence"] else ""
            }
            for entity in context_data["entities"]
        ],
    }
    command_results: List[CommandResults] = []
    for entity in context_data['entities']:
        indicator = create_indicator(
            entity['name'],
            rf_type_to_xsoar_type(entity['type']),
            entity['score'],
            ''
        )
        readable_output = tableToMarkdown(
            'New Indicator was created', indicator.to_context()
        )
        command_result = CommandResults(
            outputs=context,
            readable_output=readable_output,
            indicator=indicator
        )
        command_results.append(command_result)
    return context, command_results


def enrich_command(
    client: Client, entity: str, entity_type: str, related: bool, risky: bool, profile: str = 'All'
) -> List[CommandResults]:
    """Enrich command."""
    try:
        entity_data = client.entity_enrich(entity, entity_type, related, risky, profile)
        markdown = build_intel_markdown(entity_data, entity_type)
        return build_intel_context(entity, entity_data, entity_type, markdown)
    except DemistoException as err:
        if "404" in str(err):
            return [CommandResults(
                outputs_prefix="",
                outputs={},
                raw_response={},
                readable_output="No results found.",
                outputs_key_field="",
            )]
        else:
            raise err


def build_intel_markdown(entity_data: Dict[str, Any], entity_type: str) -> str:
    """Build Intelligence markdown."""
    if entity_data and ("error" not in entity_data):
        if entity_type == "hash":
            entity_type = "file"
        elif entity_type == "vulnerability":
            entity_type = "cve"
        entity_title = (
            entity_type.upper()
            if entity_type in ["ip", "url", "cve"]
            else entity_type.title()
        )
        data = entity_data["data"]
        risk = data["risk"]
        for hits in data["metrics"]:
            if hits["type"] == "totalHits":
                total_hits = hits["value"]
                break
        else:
            total_hits = 0
        markdown = [
            f"### Recorded Future {entity_title} Intelligence for "
            f'{data["entity"]["name"]}',
            f'Risk Score: {risk.get("score", "N/A")}',
            f'Summary: {risk.get("riskSummary", "N/A")}',
            f"Criticality label: " f'{risk.get("criticalityLabel", "N/A")}',
            f"Total references to this entity: {total_hits}",
        ]
        if entity_type == "ip":
            loc = data.get("location", {})
            locloc = loc.get("location", {})
            markdown.extend(
                [
                    "ASN and Geolocation",
                    f'AS Number: {loc.get("asn", "N/A")}',
                    f'AS Name: {loc.get("organization", "N/A")}',
                    f'CIDR: {loc.get("cidr", {}).get("name", "N/A")}',
                    "Geolocation (city): " f'{locloc.get("city", "N/A")}',
                    "Geolocation (country): "
                    f'{locloc.get("country", "N/A")}',
                ]
            )
        tstamps = data.get("timestamps", {})
        markdown.extend(
            [
                "First reference collected on: "
                f'{prettify_time(tstamps.get("firstSeen"))}',
                "Latest reference collected on: "
                f'{prettify_time(tstamps.get("lastSeen"))}',
            ]
        )
        if data.get("intelCard", None):
            markdown.append(f'[Intelligence Card]({data["intelCard"]})\n')
        else:
            markdown.append(
                "[Intelligence Card]"
                "(https://app.recordedfuture.com/"
                f'live/sc/entity/{data["entity"]["id"]})\n'
            )
        if entity_type == "cve":
            markdown.append(
                "NVD Summary: " f'{data.get("nvdDescription", "N/A")}'
            )
            if data.get("cvssv3", None):
                cdata = data["cvssv3"]
                cvss = [
                    "CVSSv3 Information",
                    "Attack Vector: "
                    f'{cdata.get("attackVector", "N/A").title()}',
                    "Attack Complexity: "
                    f'{cdata.get("attackComplexity", "N/A").title()}',
                    f'CVSSv3 Score: {cdata.get("baseScore", "N/A")}',
                    f'Impact Score: {cdata.get("impactScore", "N/A")},'
                    "Exploitability Score: "
                    f'{cdata.get("exploitabilityScore", "N/A")}',
                    "Availability: "
                    f'{cdata.get("availabilityImpact", "N/A").title()}',
                    "Availability Impact: "
                    f'{cdata.get("availabilityImpact", "N/A").title()}',
                    "User Interaction: "
                    f'{cdata.get("userInteraction", "N/A").title()}',
                    "Privileges Required: "
                    f'{cdata.get("privilegesRequired", "N/A").title()}',
                    "Integrity Impact: "
                    f'{cdata.get("integrityImpact", "N/A").title()}',
                    "Confidentiality Impact: "
                    f'{cdata.get("confidentialityImpact", "N/A").title()}',
                    f'Published: {prettify_time(cdata.get("created"))}',
                    "Last Modified: "
                    f'{prettify_time(cdata.get("modified"))}',
                ]
            else:
                cdata = data.get("cvss", {})
                cvss = [
                    "CVSS Information",
                    "Access Vector: "
                    f'{cdata.get("accessVector", "N/A").title()}',
                    "Availability: "
                    f'{cdata.get("availability", "N/A").title()}',
                    f'CVSS Score: {cdata.get("score", "N/A")}',
                    "Access Complexity: "
                    f'{cdata.get("accessComplexity", "N/A").title()}',
                    "Authentication: "
                    f'{cdata.get("authentication", "N/A").title()}',
                    "Confidentiality: "
                    f'{cdata.get("confidentiality", "N/A").title()}',
                    "Integrity Impact: "
                    f'{cdata.get("integrity", "N/A").title()}',
                    f'Published: {prettify_time(cdata.get("published"))}',
                    "Last Modified: "
                    f'{prettify_time(cdata.get("lastModified"))}',
                ]
            markdown.extend(cvss)
            if data.get("cpe", None):
                markdown.append(
                    tableToMarkdown(
                        "CPE Information",
                        parse_cpe(data.get("cpe")),
                        ['Part', 'Vendor', 'Product', 'Version', 'Update', 'Edition',
                         'Language', 'Software Edition', 'Target Software',
                         'Target Hardware', 'Other']
                    )
                )
            if data.get('relatedLinks', None):
                markdown.append(tableToMarkdown(
                    "Related Links",
                    [{'Related Links': x} for x in data.get('relatedLinks')]
                ))
        evidence_table = [
            {
                "Rule Criticality": detail.get("criticalityLabel"),
                "Evidence Summary": detail.get("evidenceString"),
                "Rule Triggered": detail.get("rule"),
                "Rule Triggered Time": detail.get("timestamp"),
                "Criticality": detail.get("criticality"),
                "Mitigation": detail.get("mitigationString"),
            }
            for detail in risk["evidenceDetails"]
        ]
        evidence_table.sort(key=lambda x: x.get("Criticality"), reverse=True)  # type: ignore
        markdown.append(
            tableToMarkdown(
                "Triggered Risk Rules",
                evidence_table,
                [
                    "Rule Criticality",
                    "Rule Triggered",
                    "Evidence Summary",
                    "Mitigation",
                    "Rule Triggered Time",
                ],
                removeNull=True,
            )
        )
        threatlist_table = [
            {"Threat List Name": tl["name"], "Description": tl["description"]}
            for tl in data.get("threatLists", [])
        ]
        markdown.append(
            tableToMarkdown(
                "Threat Lists",
                threatlist_table,
                ["Threat List Name", "Description"],
            )
        )
        return "\n".join(markdown)
    else:
        return "No records found"


def build_intel_context(
    entity: str, entity_data: Dict[str, Any], entity_type: str, markdown: str
) -> List[CommandResults]:
    """Build Intelligence context."""
    if entity_type == "hash":
        entity_type = "file"
    elif entity_type == "vulnerability":
        entity_type = "cve"
    command_results: List[CommandResults] = []
    if entity_data and ("error" not in entity_data):
        data = entity_data.get("data")  # type: ignore
        if data:
            data.update(data.pop("entity"))
            data.update(data.pop("risk"))
            data.update(data.pop("timestamps"))
            evidence_details = data['evidenceDetails']
            rules = ','.join([e['rule'] for e in evidence_details])
            data['concatRules'] = rules
            if data.get('relatedEntities'):
                data['relatedEntities'] = handle_related_entities(
                    data.pop('relatedEntities')
                )

        command_results.append(
            CommandResults(
                outputs_prefix=get_output_prefix(entity_type),
                outputs=data,
                raw_response=entity_data,
                readable_output=markdown,
                outputs_key_field='name'
            )
        )

        indicator = create_indicator(
            entity,
            entity_type,
            data['score'],
            data.get('description', ''),
            location=data.get('location')
        )
        command_results.append(
            CommandResults(
                readable_output=tableToMarkdown(
                    'New indicator was created',
                    indicator.to_context()
                ),
                indicator=indicator
            )
        )

        for cidr in data.get('riskyCIDRIPs', []):
            indicator = create_indicator(
                cidr['ip']['name'],
                'ip',
                cidr['score'],
                f'IP in the same CIDR as {entity}',
            )
            command_results.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        "New indicator was created",
                        indicator.to_context()
                    ),
                    indicator=indicator
                )
            )
    else:
        indicator = create_indicator(entity, entity_type, 0, '')
        command_results.append(
            CommandResults(
                readable_output=tableToMarkdown(
                    'New indicator was created',
                    indicator.to_context()
                ),
                indicator=indicator
            )
        )
    return command_results


def handle_related_entities(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return_data = []
    for related in data:
        return_data.append(
            {
                related["type"]: [
                    {
                        "count": x.get("count", 0),
                        "id": x.get("entity", {}).get("id", ""),
                        "name": x.get("entity", {}).get("name", ""),
                        "type": x.get("entity", {}).get("type", ""),
                    }
                    for x in related["entities"]
                ]
            }
        )
    return return_data


def get_alert_rules_command(
    client: Client, rule_name: str, limit: int
) -> Dict[str, Any]:
    """Get Alert Rules Command."""
    response = client.get_alert_rules(rule_name, limit)

    mapped_rules = [
        {"name": r.get("title", "N/A"), "id": r.get("id", "")}
        for r in response.get("data", {}).get("results", [])
    ]
    if not mapped_rules:
        return {
            "Type": entryTypes["note"],
            "Contents": {},
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": "No results found",
            "EntryContext": {},
        }
    return {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(
            "Recorded Future Alerting Rules", mapped_rules, removeNull=True
        ),
        "EntryContext": {
            "RecordedFuture.AlertRule(val.ID === obj.id)": createContext(
                mapped_rules
            )
        },
    }


def document_formatting(data):
    title = data['title']

    def move_fragment_to_entity(entity, reference):
        entity['fragment'] = reference.get('fragment', '')
        return entity

    # flattens the document so that we only get documents in all entities
    documents = [doc for elem in data["entities"] for doc in elem['documents']]
    markdown_fragments = []
    data['documents'] = documents
    flat_entities = []
    for doc in documents:
        flatten_entities = [
            move_fragment_to_entity(entity, ref) for ref in doc['references']
            for entity in ref['entities']
        ]
        flat_entities.extend(flatten_entities)
        entity_table = tableToMarkdown(
            "Entities for document",
            flatten_entities,
            removeNull=True
        )

        markdown_snippet = f"""
            ### Title: {doc['title']}
            URL: {doc['url']}
            Source: {doc['source']['name']}
            Source id: {doc['source']['id']}

            {entity_table}

        """
        markdown_snippet = re.sub(r'\n\s+', '\n', markdown_snippet)
        markdown_fragments.append(markdown_snippet)
        doc.pop('references')

    data['flat_entities'] = flat_entities
    documents = '\n'.join(markdown_fragments)

    markdown = f"""
        ## {title}
        {documents}
    """
    markdown = re.sub(r'\n\s+', '\n', markdown)
    return {
        "Type": entryTypes["note"],
        "Contents": data,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": markdown,
        "EntryContext": {
            "RecordedFuture.SingleAlert(val.ID === obj.id)": createContext(
                data
            )
        }
    }


def entity_formatting(data):
    entities = []
    evidences = {}  # name: list
    # evidence part of risk.
    entity_headers = ["name", "type", "description", "risk"]
    for entity in data["entities"]:
        entity_data = {
            "id": entity["entity"]["id"],
            "name": entity["entity"]["name"],
            "type": entity["entity"]["type"],
            "description": entity["entity"].get("description"),
            "risk": entity["risk"].get("criticalityLabel")
        }
        entities.append(entity_data)
        if not entity["risk"].get("evidence"):
            continue

        evidence_list = entity["risk"]["evidence"]
        evidence_mapping = {
            "criticalityLabel": "criticality",
            "evidenceString": "evidence"
        }
        evidence_list = [
            rename_keys(evidence_mapping, evidence) for evidence in evidence_list
        ]

        evidences[entity["entity"]["name"]] = evidence_list

    entity_markdown = tableToMarkdown(
        "Entities for alert", entities, headers=entity_headers, removeNull=True,
    )

    evidence_headers = ["rule", "criticality", "evidence"]
    evidence_markdown = ''
    for name, evidence in evidences.items():
        evidence_markdown = evidence_markdown + tableToMarkdown(
            f"Evidence belonging to {name}",
            evidence,
            headers=evidence_headers
        ) + '\n'

    markdown = f"""
        ## {data["title"]} - {data["triggered"]}

        {entity_markdown}

        {evidence_markdown}
    """
    return {
        "Type": entryTypes["note"],
        "Contents": data,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": re.sub(r'\n\s+', '\n', markdown),
        "EntryContext": {
            "RecordedFuture.SingleAlert(val.ID === obj.id)": createContext(
                data
            )
        }
    }


def get_alert_single_command(client: Client, _id: str) -> CommandResults:
    """Command to get a single alert"""
    data = client.get_single_alert(_id)["data"]

    try:
        has_entity = all([entity.get('entity') for entity in data['entities']])
        if has_entity:
            return entity_formatting(data)
        return document_formatting(data)
    except Exception:
        msg = 'This alert rule currently does not support a human readable format, ' \
              'please let us know if you want it to be supported'
        return CommandResults(
            outputs_prefix="",
            outputs={},
            raw_response={},
            readable_output=msg,
            outputs_key_field="",
        )


def get_alerts_command(
    client: Client, params: Dict[str, str]
) -> Dict[str, Any]:
    """Get Alerts Command."""
    resp = client.get_alerts(params)
    headers = ["Alert ID", "Rule", "Alert Title", "Triggered", "Status", "Assignee"]
    alerts_context = [
        {
            "id": a["id"],
            "name": a.get("title", "N/A"),
            "triggered": prettify_time(a.get("triggered")),
            "status": a.get("review", {}).get("status"),
            "assignee": a.get("review", {}).get("assignee"),
            "rule": a.get("rule", {}).get("name"),
            "type": a.get("type"),
            "entities": a.get("entities", []),
        }
        for a in resp.get("data", {}).get("results", [])
    ]
    if not alerts_context:
        return {
            "Type": entryTypes["note"],
            "Contents": {},
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": "No results found",
            "EntryContext": {},
        }
    alerts_table = [
        {
            "Alert ID": ma["id"],
            "Alert Title": ma["name"],
            "Rule": ma["rule"],
            "Status": ma["status"],
            "Triggered": ma["triggered"],
            "Assignee": ma["assignee"],
        }
        for ma in alerts_context
    ]
    return {
        "Type": entryTypes["note"],
        "Contents": resp,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(
            "Recorded Future Alerts",
            alerts_table,
            headers=headers,
            removeNull=True,
        ),
        "EntryContext": {
            "RecordedFuture.Alert(val.ID === obj.id)": createContext(
                alerts_context
            )
        },
    }


def main() -> None:
    """Main method used to run actions."""
    try:
        demisto_params = demisto.params()
        demisto_args = demisto.args()
        base_url = demisto_params.get("server_url", "").rstrip("/")
        verify_ssl = not demisto_params.get("unsecure", False)
        proxy = demisto_params.get("proxy", False)
        headers = {
            "X-RFToken": demisto_params["token"],
            "X-RF-User-Agent": f"Cortex_XSOAR/{__version__} Cortex_XSOAR_"
            f'{demisto.demistoVersion()["version"]}',
        }
        client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy
        )
        command = demisto.command()
        if command == "test-module":
            try:
                client.whoami()
                return_results("ok")
            except Exception as err:
                try:
                    error = json.loads(str(err).split("\n")[1])
                    if "error" in error:
                        message = error.get("error", {})["message"]
                        return_results(f"Failed due to: {message}")
                except Exception as err2:
                    return_results(
                        "Unknown error. Please verify that the API"
                        " URL and Token are correctly configured."
                    )
        elif command in ["url", "ip", "domain", "file", "cve"]:
            entities = argToList(demisto_args.get(command))
            return_results(lookup_command(client, entities, command))
        elif command == "recordedfuture-threat-assessment":
            context = demisto_args.get("context")
            entities = {
                "ip": argToList(demisto_args.get("ip")),
                "domain": argToList(demisto_args.get("domain")),
                "hash": argToList(demisto_args.get("file")),
                "url": argToList(demisto_args.get("url")),
                "vulnerability": argToList(demisto_args.get("cve")),
                "filter": demisto_args.get("filter") == "yes"
            }
            return_results(triage_command(client, entities, context))
        elif command == 'recordedfuture-single-alert':
            _id = demisto_args['id']
            return_results(get_alert_single_command(client, _id))
        elif command == "recordedfuture-alert-rules":
            rule_name = demisto_args.get("rule_name", "")
            limit = demisto_args.get("limit", 10)
            return_results(get_alert_rules_command(client, rule_name, limit))
        elif command == "recordedfuture-alerts":
            params = {
                x: demisto_args.get(x)
                for x in demisto_args
                if not x == "detailed"
            }
            if params.get("rule_id", None):
                params["alertRule"] = params.pop("rule_id")
            if params.get("offset", None):
                params["from"] = params.pop("offset")
            if params.get("triggered_time", None):
                date, _ = parse_date_range(
                    params.pop("triggered_time"),
                    date_format="%Y-%m-%d %H:%M:%S",
                )
                params["triggered"] = "[{},)".format(date)

            return_results(get_alerts_command(client, params))
        elif command == "recordedfuture-intelligence":
            return_results(
                enrich_command(
                    client,
                    demisto_args.get("entity"),
                    demisto_args.get("entity_type"),
                    demisto_args.get("fetch_related_entities") == "yes",
                    demisto_args.get("fetch_riskyCIDRips") == "yes",
                    demisto_args.get("profile", '')
                )
            )
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command. "
            f"Error: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
