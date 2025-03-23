import copy
from contextlib import suppress
from urllib.parse import parse_qs

from CommonServerPython import *  # noqa: F401

FEEDLY_BASE_URL = "https://api.feedly.com"

# Constants copied from the command StixParser
DFLT_LIMIT_PER_REQUEST = 100
API_USERNAME = "_api_token_key"
HEADER_USERNAME = "_header:"
SYSTEM_FIELDS = [
    "id",
    "version",
    "modified",
    "sortValues",
    "timestamp",
    "indicator_type",
    "value",
    "sourceInstances",
    "sourceBrands",
    "investigationIDs",
    "lastSeen",
    "firstSeen",
    "firstSeenEntryID",
    "score",
    "insightCache",
    "moduleToFeedMap",
    "expirationStatus",
    "expirationSource",
    "calculatedTime",
    "lastReputationRun",
    "modifiedTime",
    "aggregatedReliability",
]

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Pattern Regexes - used to extract indicator type and value, spaces are removed before matching the following regexes
INDICATOR_OPERATOR_VAL_FORMAT_PATTERN = r"(\w.*?{value}{operator})'(.*?)'"
INDICATOR_IN_VAL_PATTERN = r"(\w.*?valueIN)\(+('.*?')\)"
INDICATOR_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="value", operator="=")
CIDR_ISSUBSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="value", operator="ISSUBSET")
CIDR_ISUPPERSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="value", operator="ISSUPPERSET")
HASHES_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value=r"hashes\..*?", operator="=")
REGISTRY_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="key", operator="=")


STIX_2_TYPES_TO_CORTEX_TYPES = {
    "mutex": FeedIndicatorType.MUTEX,
    "windows-registry-key": FeedIndicatorType.Registry,
    "user-account": FeedIndicatorType.Account,
    "email-addr": FeedIndicatorType.Email,
    "autonomous-system": FeedIndicatorType.AS,
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain": FeedIndicatorType.Domain,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
    "md5": FeedIndicatorType.File,
    "sha-1": FeedIndicatorType.File,
    "sha-256": FeedIndicatorType.File,
    "file:hashes": FeedIndicatorType.File,
    "vulnerability": FeedIndicatorType.CVE,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "report": "Feedly Report",
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "infrastructure": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
}

MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS = {
    "build-capabilities": ThreatIntel.KillChainPhases.BUILD_CAPABILITIES,
    "privilege-escalation": ThreatIntel.KillChainPhases.PRIVILEGE_ESCALATION,
    "adversary-opsec": ThreatIntel.KillChainPhases.ADVERSARY_OPSEC,
    "credential-access": ThreatIntel.KillChainPhases.CREDENTIAL_ACCESS,
    "exfiltration": ThreatIntel.KillChainPhases.EXFILTRATION,
    "lateral-movement": ThreatIntel.KillChainPhases.LATERAL_MOVEMENT,
    "defense-evasion": ThreatIntel.KillChainPhases.DEFENSE_EVASION,
    "persistence": ThreatIntel.KillChainPhases.PERSISTENCE,
    "collection": ThreatIntel.KillChainPhases.COLLECTION,
    "impact": ThreatIntel.KillChainPhases.IMPACT,
    "initial-access": ThreatIntel.KillChainPhases.INITIAL_ACCESS,
    "discovery": ThreatIntel.KillChainPhases.DISCOVERY,
    "execution": ThreatIntel.KillChainPhases.EXECUTION,
    "installation": ThreatIntel.KillChainPhases.INSTALLATION,
    "delivery": ThreatIntel.KillChainPhases.DELIVERY,
    "weaponization": ThreatIntel.KillChainPhases.WEAPONIZATION,
    "act-on-objectives": ThreatIntel.KillChainPhases.ACT_ON_OBJECTIVES,
    "command-and-control": ThreatIntel.KillChainPhases.COMMAND_AND_CONTROL,
}

STIX_2_TYPES_TO_CORTEX_CIDR_TYPES = {
    "ipv4-addr": FeedIndicatorType.CIDR,
    "ipv6-addr": FeedIndicatorType.IPv6CIDR,
}

THREAT_INTEL_TYPE_TO_DEMISTO_TYPES = {
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "infrastructure": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
}


class Client(BaseClient):
    def fetch_indicators_from_stream(self, stream_id: str, newer_than: float, *, limit: Optional[int] = None) -> list:
        params = {
            "streamId": stream_id,
            "count": 20,
            "newerThan": int(newer_than * 1_000),
            "client": "feedly.demisto.client",
        }

        objects = []

        while True:
            resp = self._http_request("GET", "/v3/enterprise/ioc", params=params, resp_type="response")
            objects.extend(resp.json().get("objects", []))

            if "link" not in resp.headers:
                break

            next_url = resp.headers["link"][1:].split(">")[0]
            params["continuation"] = parse_qs(next_url)["continuation"][0]

        demisto.debug(f"Fetched {len(objects)} objects from stream {stream_id}")

        indicators = STIX2Parser().parse_stix2_objects(objects)

        if limit:
            indicators = indicators[:limit]

        for indicator in indicators:
            indicator["type"] = indicator.get("indicator_type", "")
            indicator["fields"] = indicator.get("customFields", {})

        return indicators


class STIX2Parser:
    """
    STIX2 Parser copied from the command StixParser
    """

    OBJECTS_TO_PARSE = [
        "indicator",
        "report",
        "malware",
        "campaign",
        "attack-pattern",
        "course-of-action",
        "intrusion-set",
        "tool",
        "threat-actor",
        "infrastructure",
        "autonomous-system",
        "domain-name",
        "email-addr",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mutex",
        "url",
        "user-account",
        "windows-registry-key",
        "relationship",
        "extension-definition",
        "vulnerability",
    ]

    def __init__(self):
        self.indicator_regexes = [
            re.compile(INDICATOR_EQUALS_VAL_PATTERN),
            re.compile(INDICATOR_IN_VAL_PATTERN),
            re.compile(HASHES_EQUALS_VAL_PATTERN),
            re.compile(REGISTRY_EQUALS_VAL_PATTERN),
        ]
        self.cidr_regexes = [
            re.compile(CIDR_ISSUBSET_VAL_PATTERN),
            re.compile(CIDR_ISUPPERSET_VAL_PATTERN),
        ]
        self.id_to_object: dict[str, Any] = {}
        self.parsed_object_id_to_object: dict[str, Any] = {}

    @staticmethod
    def get_indicator_publication(indicator: dict[str, Any]):
        """
        Build publications grid field from the indicator external_references field

        Args:
            indicator: The indicator with publication field

        Returns:
            list. publications grid field
        """
        publications = []
        for external_reference in indicator.get("external_references", []):
            url = external_reference.get("url", "")
            description = external_reference.get("description", "")
            source_name = external_reference.get("source_name", "")
            publications.append({"link": url, "title": description, "source": source_name})
        return publications

    @staticmethod
    def change_ip_to_cidr(indicators):
        """
        Iterates over indicators list and changes IP to CIDR type if needed.
        :param indicators: list of parsed indicators.
        :return: changes indicators list in-place.
        """
        for indicator in indicators:
            if indicator.get("indicator_type") == FeedIndicatorType.IP:
                value = indicator.get("value")
                if value.endswith("/32"):
                    pass
                elif "/" in value:
                    indicator["indicator_type"] = FeedIndicatorType.CIDR

    """ PARSING FUNCTIONS"""

    def parse_indicator(self, indicator_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single indicator object
        :param indicator_obj: indicator object
        :return: indicators extracted from the indicator object in cortex format
        """
        field_map: dict = {}
        pattern = indicator_obj.get("pattern")
        indicators = []
        if pattern:
            # this is done in case the server doesn't properly space the operator,
            # supported indicators have no spaces, so this action shouldn't affect extracted values
            trimmed_pattern = pattern.replace(" ", "")

            indicator_groups = self.extract_indicator_groups_from_pattern(trimmed_pattern, self.indicator_regexes)

            indicators.extend(
                self.get_indicators_from_indicator_groups(
                    indicator_groups,
                    indicator_obj,
                    STIX_2_TYPES_TO_CORTEX_TYPES,
                    field_map,
                )
            )

            cidr_groups = self.extract_indicator_groups_from_pattern(trimmed_pattern, self.cidr_regexes)
            indicators.extend(
                self.get_indicators_from_indicator_groups(
                    cidr_groups,
                    indicator_obj,
                    STIX_2_TYPES_TO_CORTEX_CIDR_TYPES,
                    field_map,
                )
            )
            self.change_ip_to_cidr(indicators)

        return indicators

    @staticmethod
    def parse_attack_pattern(attack_pattern_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single attack pattern object
        :param attack_pattern_obj: attack pattern object
        :return: attack pattern extracted from the attack pattern object in cortex format
        """
        publications = STIX2Parser.get_indicator_publication(attack_pattern_obj)

        kill_chain_mitre = [chain.get("phase_name", "") for chain in attack_pattern_obj.get("kill_chain_phases", [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        attack_pattern = {
            "value": attack_pattern_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
            "rawJSON": attack_pattern_obj,
        }
        fields = {
            "stixid": attack_pattern_obj.get("id"),
            "killchainphases": kill_chain_phases,
            "firstseenbysource": attack_pattern_obj.get("created"),
            "modified": attack_pattern_obj.get("modified"),
            "description": attack_pattern_obj.get("description", ""),
            "operatingsystemrefs": attack_pattern_obj.get("x_mitre_platforms"),
            "publications": publications,
        }

        attack_pattern["customFields"] = fields

        return [attack_pattern]

    @staticmethod
    def parse_report(report_obj: dict[str, Any]):
        """
        Parses a single report object
        :param report_obj: report object
        :return: report extracted from the report object in cortex format
        """
        object_refs = report_obj.get("object_refs", [])
        new_relationships = []
        for obj_id in object_refs:
            new_relationships.append(
                {
                    "type": "relationship",
                    "id": "relationship--fakeid",
                    "created": report_obj.get("created"),
                    "modified": report_obj.get("modified"),
                    "relationship_type": "contains",
                    "source_ref": report_obj.get("id"),
                    "target_ref": obj_id,
                }
            )

        report = {
            "indicator_type": "Feedly Report",
            "value": report_obj.get("name"),
            "score": ThreatIntel.ObjectsScore.REPORT,
            "rawJSON": report_obj,
        }
        fields = {
            "stixid": report_obj.get("id"),
            "firstseenbysource": report_obj.get("created"),
            "published": report_obj.get("published"),
            "description": report_obj.get("description", ""),
            "report_types": report_obj.get("report_types", []),
            "tags": list(set(report_obj.get("labels", []))),
        }

        report["customFields"] = fields

        return [report], new_relationships

    @staticmethod
    def parse_threat_actor(threat_actor_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single threat actor object
        :param threat_actor_obj: report object
        :return: threat actor extracted from the threat actor object in cortex format
        """

        threat_actor = {
            "value": threat_actor_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.THREAT_ACTOR,
            "score": ThreatIntel.ObjectsScore.THREAT_ACTOR,
            "rawJSON": threat_actor_obj,
        }
        fields = {
            "stixid": threat_actor_obj.get("id"),
            "firstseenbysource": threat_actor_obj.get("created"),
            "modified": threat_actor_obj.get("modified"),
            "description": threat_actor_obj.get("description", ""),
            "aliases": threat_actor_obj.get("aliases", []),
            "threat_actor_types": threat_actor_obj.get("threat_actor_types", []),
            "roles": threat_actor_obj.get("roles", []),
            "goals": threat_actor_obj.get("goals", []),
            "sophistication": threat_actor_obj.get("sophistication", ""),
            "resource_level": threat_actor_obj.get("resource_level", ""),
            "primary_motivation": threat_actor_obj.get("primary_motivation", ""),
            "secondary_motivations": threat_actor_obj.get("secondary_motivations", []),
            "tags": list(set(threat_actor_obj.get("labels", []))),
        }

        threat_actor["customFields"] = fields

        return [threat_actor]

    @staticmethod
    def parse_infrastructure(infrastructure_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single infrastructure object
        :param infrastructure_obj: infrastructure object
        :return: infrastructure extracted from the infrastructure object in cortex format
        """
        kill_chain_mitre = [chain.get("phase_name", "") for chain in infrastructure_obj.get("kill_chain_phases", [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        infrastructure = {
            "value": infrastructure_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
            "score": ThreatIntel.ObjectsScore.INFRASTRUCTURE,
            "rawJSON": infrastructure_obj,
        }
        fields = {
            "stixid": infrastructure_obj.get("id"),
            "description": infrastructure_obj.get("description", ""),
            "infrastructure_types": infrastructure_obj.get("infrastructure_types", []),
            "aliases": infrastructure_obj.get("aliases", []),
            "kill_chain_phases": kill_chain_phases,
            "firstseenbysource": infrastructure_obj.get("created"),
            "modified": infrastructure_obj.get("modified"),
        }

        infrastructure["customFields"] = fields
        return [infrastructure]

    @staticmethod
    def parse_malware(malware_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single malware object
        :param malware_obj: malware object
        :return: malware extracted from the malware object in cortex format
        """

        kill_chain_mitre = [chain.get("phase_name", "") for chain in malware_obj.get("kill_chain_phases", [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        malware = {
            "value": malware_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.MALWARE,
            "score": ThreatIntel.ObjectsScore.MALWARE,
            "rawJSON": malware_obj,
        }
        fields = {
            "stixid": malware_obj.get("id"),
            "firstseenbysource": malware_obj.get("created"),
            "modified": malware_obj.get("modified"),
            "description": malware_obj.get("description", ""),
            "malware_types": malware_obj.get("malware_types", []),
            "is_family": malware_obj.get("is_family", False),
            "aliases": malware_obj.get("aliases", []),
            "kill_chain_phases": kill_chain_phases,
            "os_execution_envs": malware_obj.get("os_execution_envs", []),
            "architecture_execution_envs": malware_obj.get("architecture_execution_envs", []),
            "capabilities": malware_obj.get("capabilities", []),
            "sample_refs": malware_obj.get("sample_refs", []),
            "tags": list(set(malware_obj.get("labels", []))),
        }

        malware["customFields"] = fields
        return [malware]

    @staticmethod
    def parse_tool(tool_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single tool object
        :param tool_obj: tool object
        :return: tool extracted from the tool object in cortex format
        """
        kill_chain_mitre = [chain.get("phase_name", "") for chain in tool_obj.get("kill_chain_phases", [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        tool = {
            "value": tool_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.TOOL,
            "score": ThreatIntel.ObjectsScore.TOOL,
            "rawJSON": tool_obj,
        }
        fields = {
            "stixid": tool_obj.get("id"),
            "killchainphases": kill_chain_phases,
            "firstseenbysource": tool_obj.get("created"),
            "modified": tool_obj.get("modified"),
            "tool_types": tool_obj.get("tool_types", []),
            "description": tool_obj.get("description", ""),
            "aliases": tool_obj.get("aliases", []),
            "tool_version": tool_obj.get("tool_version", ""),
        }

        tool["customFields"] = fields
        return [tool]

    @staticmethod
    def parse_course_of_action(coa_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single course of action object
        :param coa_obj: course of action object
        :return: course of action extracted from the course of action object in cortex format
        """
        publications = STIX2Parser.get_indicator_publication(coa_obj)

        course_of_action = {
            "value": coa_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
            "score": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
            "rawJSON": coa_obj,
        }
        fields = {
            "stixid": coa_obj.get("id"),
            "firstseenbysource": coa_obj.get("created"),
            "modified": coa_obj.get("modified"),
            "description": coa_obj.get("description", ""),
            "action_type": coa_obj.get("action_type", ""),
            "publications": publications,
        }

        course_of_action["customFields"] = fields
        return [course_of_action]

    @staticmethod
    def parse_campaign(campaign_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single campaign object
        :param campaign_obj: campaign object
        :return: campaign extracted from the campaign object in cortex format
        """
        campaign = {
            "value": campaign_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.CAMPAIGN,
            "score": ThreatIntel.ObjectsScore.CAMPAIGN,
            "rawJSON": campaign_obj,
        }
        fields = {
            "stixid": campaign_obj.get("id"),
            "firstseenbysource": campaign_obj.get("created"),
            "modified": campaign_obj.get("modified"),
            "description": campaign_obj.get("description", ""),
            "aliases": campaign_obj.get("aliases", []),
            "objective": campaign_obj.get("objective", ""),
        }

        campaign["customFields"] = fields
        return [campaign]

    @staticmethod
    def parse_intrusion_set(intrusion_set_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single intrusion set object
        :param intrusion_set_obj: intrusion set object
        :return: intrusion set extracted from the intrusion set object in cortex format
        """
        publications = STIX2Parser.get_indicator_publication(intrusion_set_obj)

        intrusion_set = {
            "value": intrusion_set_obj.get("name"),
            "indicator_type": ThreatIntel.ObjectsNames.INTRUSION_SET,
            "score": ThreatIntel.ObjectsScore.INTRUSION_SET,
            "rawJSON": intrusion_set_obj,
        }
        fields = {
            "stixid": intrusion_set_obj.get("id"),
            "firstseenbysource": intrusion_set_obj.get("created"),
            "modified": intrusion_set_obj.get("modified"),
            "description": intrusion_set_obj.get("description", ""),
            "aliases": intrusion_set_obj.get("aliases", []),
            "goals": intrusion_set_obj.get("goals", []),
            "resource_level": intrusion_set_obj.get("resource_level", ""),
            "primary_motivation": intrusion_set_obj.get("primary_motivation", ""),
            "secondary_motivations": intrusion_set_obj.get("secondary_motivations", []),
            "publications": publications,
            "tags": list(set(intrusion_set_obj.get("labels", []))),
        }
        intrusion_set["customFields"] = fields
        return [intrusion_set]

    @staticmethod
    def parse_general_sco_indicator(sco_object: dict[str, Any], value_mapping: str = "value") -> list[dict[str, Any]]:
        """
        Parses a single SCO indicator.

        Args:
            sco_object (dict): indicator as an observable object.
            value_mapping (str): the key that extracts the value from the indicator response.
        """
        sco_indicator = {
            "value": sco_object.get(value_mapping),
            "score": Common.DBotScore.NONE,
            "rawJSON": sco_object,
            "indicator_type": STIX_2_TYPES_TO_CORTEX_TYPES.get(sco_object.get("type")),  # type: ignore[arg-type]
        }

        fields = {"stixid": sco_object.get("id")}

        sco_indicator["customFields"] = fields
        return [sco_indicator]

    @staticmethod
    def parse_sco_autonomous_system_indicator(autonomous_system_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses autonomous_system indicator type to cortex format.

        Args:
            autonomous_system_obj (dict): indicator as an observable object of type autonomous-system.
        """
        autonomous_system_indicator = STIX2Parser.parse_general_sco_indicator(autonomous_system_obj, value_mapping="number")
        autonomous_system_indicator[0]["customFields"]["name"] = autonomous_system_obj.get("name")

        return autonomous_system_indicator

    @staticmethod
    def parse_sco_file_indicator(file_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses file indicator type to cortex format.

        Args:
            file_obj (dict): indicator as an observable object of file type.
        """
        file_hashes = file_obj.get("hashes", {})
        value = file_hashes.get("SHA-256") or file_hashes.get("SHA-1") or file_hashes.get("MD5")
        if not value:
            return []

        file_obj["value"] = value

        file_indicator = STIX2Parser.parse_general_sco_indicator(file_obj)
        file_indicator[0]["customFields"].update(
            {
                "associatedfilenames": file_obj.get("name"),
                "size": file_obj.get("size"),
                "path": file_obj.get("parent_directory_ref"),
                "md5": file_hashes.get("MD5"),
                "sha1": file_hashes.get("SHA-1"),
                "sha256": file_hashes.get("SHA-256"),
            }
        )

        return file_indicator

    @staticmethod
    def parse_sco_mutex_indicator(mutex_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses mutex indicator type to cortex format.

        Args:
            mutex_obj (dict): indicator as an observable object of mutex type.
        """
        return STIX2Parser.parse_general_sco_indicator(sco_object=mutex_obj, value_mapping="name")

    @staticmethod
    def parse_sco_account_indicator(account_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses account indicator type to cortex format.

        Args:
            account_obj (dict): indicator as an observable object of account type.
        """
        account_indicator = STIX2Parser.parse_general_sco_indicator(account_obj, value_mapping="user_id")
        account_indicator[0]["customFields"].update(
            {"displayname": account_obj.get("user_id"), "accounttype": account_obj.get("account_type")}
        )
        return account_indicator

    @staticmethod
    def parse_sco_windows_registry_key_indicator(registry_key_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses registry_key indicator type to cortex format.

        Args:
            registry_key_obj (dict): indicator as an observable object of registry_key type.
        """
        registry_key_indicator = STIX2Parser.parse_general_sco_indicator(registry_key_obj, value_mapping="key")
        registry_key_indicator[0]["customFields"].update(
            {
                "registryvalue": registry_key_obj.get("values"),
                "modified_time": registry_key_obj.get("modified_time"),
                "number_of_subkeys": registry_key_obj.get("number_of_subkeys"),
            }
        )
        return registry_key_indicator

    @staticmethod
    def parse_vulnerability(vulnerability_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses vulnerability indicator type to cortex format.

        Args:
            vulnerability_obj (dict): indicator as an observable object of vulnerability type.
        """
        vulnerability = {
            "value": vulnerability_obj.get("name"),
            "indicator_type": FeedIndicatorType.CVE,
            "rawJSON": vulnerability_obj,
        }
        fields = {
            "stixid": vulnerability_obj.get("id"),
            "firstseenbysource": vulnerability_obj.get("created"),
            "modified": vulnerability_obj.get("modified"),
            "description": vulnerability_obj.get("description", ""),
            "external_references": vulnerability_obj.get("external_references", []),
            "tags": list(set(vulnerability_obj.get("labels", []))),
        }

        vulnerability["customFields"] = fields
        return [vulnerability]

    def parse_relationships(self, relationships_lst: list[dict[str, Any]]) -> dict[str, Any]:
        """Parse the Relationships objects retrieved from the feed.

        Returns:
            A dict of relationship value to processed relationships as indicator object.
        """
        a_value_to_relationship: dict[str, Any] = {}
        for relationships_object in relationships_lst:
            relationship_type: str = relationships_object.get("relationship_type", "")
            if not EntityRelationship.Relationships.is_valid(relationship_type):
                if relationship_type == "indicates":
                    relationship_type = "indicated-by"
                else:
                    demisto.debug(f"Invalid relation type: {relationship_type}")
                    continue

            a_stixid = relationships_object.get("source_ref", "")
            a_object = self.parsed_object_id_to_object.get(a_stixid, {})
            b_stixid = relationships_object.get("target_ref", "")
            b_object = self.parsed_object_id_to_object.get(b_stixid, {})

            if not a_object or not b_object:
                demisto.debug(f"Cant find {a_object=} or {b_object=}.")
                continue

            a_value, a_type = a_object.get("value"), a_object.get("indicator_type")
            b_value, b_type = b_object.get("value"), b_object.get("indicator_type")

            if not (a_value and a_type and b_value and b_type):
                continue

            if b_type in {ThreatIntel.ObjectsNames.THREAT_ACTOR, ThreatIntel.ObjectsNames.MALWARE}:
                a_object["customFields"].setdefault("tags", []).append(b_value)
            elif b_type in {ThreatIntel.ObjectsNames.ATTACK_PATTERN}:
                with suppress(StopIteration):
                    mitre_id = next(
                        ref["external_id"]
                        for ref in b_object["rawJSON"].get("external_references", [])
                        if ref.get("source_name") == "mitre-attack"
                    )
                    a_object["customFields"].setdefault("tags", []).append(mitre_id)

            mapping_fields = {
                "lastseenbysource": relationships_object.get("modified"),
                "firstseenbysource": relationships_object.get("created"),
            }

            entity_relation = EntityRelationship(
                name=relationship_type,
                entity_a=a_value,
                entity_a_type=a_type,
                entity_b=b_value,
                entity_b_type=b_type,
                fields=mapping_fields,
            )
            indicator_relationship = entity_relation.to_indicator()
            if a_value_to_relationship.get(a_value):
                a_value_to_relationship[a_value].append(indicator_relationship)
            else:
                a_value_to_relationship[a_value] = [indicator_relationship]

        return a_value_to_relationship

    def parse_stix2_objects(self, objects: list[dict]) -> list[dict[str, Any]]:
        """
        Builds a list of cortex indicators objects from the STIX2 objects
        :return: Cortex indicators list
        """
        envelopes = STIX2Parser.create_envelopes_by_type(objects)
        indicators = self.load_stix_objects_from_envelope(envelopes)

        return indicators

    def load_stix_objects_from_envelope(self, envelopes: dict[str, Any]):
        parse_stix_2_objects = {
            "indicator": self.parse_indicator,
            "attack-pattern": self.parse_attack_pattern,
            "malware": self.parse_malware,
            "report": self.parse_report,
            "course-of-action": self.parse_course_of_action,
            "campaign": self.parse_campaign,
            "intrusion-set": self.parse_intrusion_set,
            "tool": self.parse_tool,
            "threat-actor": self.parse_threat_actor,
            "infrastructure": self.parse_infrastructure,
            "domain-name": self.parse_general_sco_indicator,
            "ipv4-addr": self.parse_general_sco_indicator,
            "ipv6-addr": self.parse_general_sco_indicator,
            "email-addr": self.parse_general_sco_indicator,
            "url": self.parse_general_sco_indicator,
            "autonomous-system": self.parse_sco_autonomous_system_indicator,
            "file": self.parse_sco_file_indicator,
            "mutex": self.parse_sco_mutex_indicator,
            "user-account": self.parse_sco_account_indicator,
            "windows-registry-key": self.parse_sco_windows_registry_key_indicator,
            "vulnerability": self.parse_vulnerability,
        }
        indicators = self.parse_dict_envelope(envelopes, parse_stix_2_objects)
        return indicators

    def parse_dict_envelope(self, envelopes: dict[str, Any], parse_objects_func):
        indicators = []
        relationships_list: list[dict[str, Any]] = []

        for obj_type, stix_objects in envelopes.items():
            if obj_type == "relationship":
                relationships_list.extend(stix_objects)
            else:
                for obj in stix_objects:
                    # handled separately
                    if obj.get("type") == "extension-definition":
                        continue
                    self.id_to_object[obj.get("id")] = obj
                    if obj.get("type") == "report":
                        result, relationships = self.parse_report(obj)
                        relationships_list.extend(relationships)
                    else:
                        result = parse_objects_func[obj_type](obj)
                    if not result:
                        continue
                    self.parsed_object_id_to_object[obj.get("id")] = result[0]
                    indicators.extend(result)

        if relationships_list:
            relationships_mapping = self.parse_relationships(relationships_list)
            STIX2Parser.add_relationship_to_indicator(relationships_mapping, indicators)
        return indicators

    @staticmethod
    def create_envelopes_by_type(objects) -> dict:
        """
        Creates objects envelops by type
        """
        types_envelopes: dict = {}
        index = 0
        for obj in objects:
            obj_type = obj.get("type")
            if obj_type not in STIX2Parser.OBJECTS_TO_PARSE:
                demisto.debug(f"Cannot parse object of type {obj_type}, skipping.")
                index += 1
                continue
            if obj_type not in types_envelopes:
                types_envelopes[obj_type] = []
            types_envelopes[obj_type].append(obj)

        return types_envelopes

    @staticmethod
    def get_indicators_from_indicator_groups(
        indicator_groups: list[tuple[str, str]],
        indicator_obj: dict[str, str],
        indicator_types: dict[str, str],
        field_map: dict[str, str],
    ) -> list[dict[str, str]]:
        """
        Get indicators from indicator regex groups
        :param indicator_groups: caught regex group in pattern of: [`type`, `indicator`]
        :param indicator_obj: stix indicator object
        :param indicator_types: supported indicator types -> cortex types
        :param field_map: map used to create fields entry ({field_name: field_value})
        :return: Indicators list
        """
        indicators = []
        if indicator_groups:
            for term in indicator_groups:
                for stix_type in indicator_types:
                    # term should be list with 2 argument parsed with regex - [`type`, `indicator`]
                    if len(term) == 2 and stix_type in term[0]:
                        type_ = indicator_types[stix_type]
                        value = term[1]

                        # support added for cases as 'value1','value2','value3' for 3 different indicators
                        for indicator_value in value.split(","):
                            indicator_value = indicator_value.strip("'")
                            indicator = STIX2Parser.create_indicator(indicator_obj, type_, indicator_value.strip("'"), field_map)
                            indicators.append(indicator)
                        break
        return indicators

    @staticmethod
    def create_indicator(indicator_obj, type_, value, field_map):
        """
        Create a cortex indicator from a stix indicator
        :param indicator_obj: rawJSON value of the indicator
        :param type_: cortex type of the indicator
        :param value: indicator value
        :param field_map: field map used for mapping fields ({field_name: field_value})
        :return: Cortex indicator
        """
        ioc_obj_copy = copy.deepcopy(indicator_obj)
        ioc_obj_copy["value"] = value
        ioc_obj_copy["type"] = type_
        indicator = {
            "value": value,
            "indicator_type": type_,
            "rawJSON": ioc_obj_copy,
        }
        fields = {}
        tags = []
        # create tags from labels:
        for label in ioc_obj_copy.get("labels", []):
            tags.append(label)

        # add description if able
        if "description" in ioc_obj_copy:
            fields["description"] = ioc_obj_copy["description"]

        # add field_map fields
        for field_name, field_path in field_map.items():
            if field_path in ioc_obj_copy:
                fields[field_name] = ioc_obj_copy.get(field_path)

        # union of tags and labels
        if "tags" in fields:
            field_tag = fields.get("tags")
            if isinstance(field_tag, list):
                tags.extend(field_tag)
            else:
                tags.append(field_tag)

        fields["tags"] = tags

        indicator["customFields"] = fields
        return indicator

    @staticmethod
    def extract_indicator_groups_from_pattern(pattern: str, regexes: list) -> list[tuple[str, str]]:
        """
        Extracts indicator [`type`, `indicator`] groups from pattern
        :param pattern: stix pattern
        :param regexes: regexes to run to pattern
        :return: extracted indicators list from pattern
        """
        groups: list[tuple[str, str]] = []
        for regex in regexes:
            find_result = regex.findall(pattern)
            if find_result:
                groups.extend(find_result)
        return groups

    @staticmethod
    def add_relationship_to_indicator(relationships_mapping, indicators):
        """
        Adds relationship to right indicator
        :param relationships_mapping: maps a_value to relationship object
        :param indicators: all indicators that were fetched from file.
        """
        for indicator in indicators:
            if (a_value := indicator.get("value")) and (relationships := relationships_mapping.get(a_value)):
                indicator["relationships"] = relationships


def test_module(client: Client, params: dict) -> str:  # pragma: no cover
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
        params: demisto.params()
    Returns:
        Outputs.
    """
    try:
        client.fetch_indicators_from_stream(params["feedly_stream_id"], newer_than=time.time() - 3600)
        return "ok"
    except DemistoException as e:
        return e.message
    except Exception as e:
        return str(e)


def get_indicators_command(client: Client, params: dict[str, str], args: dict[str, str]) -> CommandResults:  # pragma: no cover
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    indicators = client.fetch_indicators_from_stream(
        params["feedly_stream_id"], newer_than=time.time() - 24 * 3600, limit=int(args.get("limit", "10"))
    )
    demisto.createIndicators(indicators)  # type: ignore
    return CommandResults(readable_output=f"Created {len(indicators)} indicators.")


def fetch_indicators_command(client: Client, params: dict[str, str], context: dict[str, str]) -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
        context: demisto.getIntegrationContext()
    Returns:
        Indicators.
    """
    return client.fetch_indicators_from_stream(
        params["feedly_stream_id"], newer_than=float(context.get("last_successful_run", time.time() - 7 * 24 * 3600))
    )


def main():  # pragma: no cover
    params = demisto.params()

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=FEEDLY_BASE_URL,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            headers={"Authorization": f"Bearer {params['credentials']['password']}"},
        )

        if command == "test-module":
            return_results(test_module(client, params))

        elif command == "feedly-get-indicators":
            return_results(get_indicators_command(client, params, args))

        elif command == "fetch-indicators":
            now = time.time()
            indicators = fetch_indicators_command(client, params, demisto.getLastRun())
            for indicators_batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(indicators_batch)  # type: ignore
            demisto.setLastRun({"last_successful_run": str(now)})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback stack
        return_error(f"Failed to execute {command} command.\nError:\n{repr(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
