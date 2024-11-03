import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
import tempfile

from lxml import etree
from bs4 import BeautifulSoup
import dateutil.parser
from netaddr import IPNetwork
from six import string_types
import pytz
import collections

EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)
SCRIPT_NAME = 'STIXParser'

# CONSTANTS
TAXII_VER_2_0 = "2.0"
TAXII_VER_2_1 = "2.1"

DFLT_LIMIT_PER_REQUEST = 100
API_USERNAME = "_api_token_key"
HEADER_USERNAME = "_header:"
XSOAR_TAXII2_SERVER_SCHEMA = "https://github.com/demisto/content/blob/4265bd5c71913cd9d9ed47d9c37d0d4d3141c3eb/" \
                             "Packs/TAXIIServer/doc_files/XSOAR_indicator_schema.json"
SYSTEM_FIELDS = ['id', 'version', 'modified', 'sortValues', 'timestamp', 'indicator_type',
                 'value', 'sourceInstances', 'sourceBrands', 'investigationIDs', 'lastSeen', 'firstSeen',
                 'firstSeenEntryID', 'score', 'insightCache', 'moduleToFeedMap', 'expirationStatus',
                 'expirationSource', 'calculatedTime', 'lastReputationRun', 'modifiedTime', 'aggregatedReliability']
ERR_NO_COLL = "No collection is available for this user, please make sure you entered the configuration correctly"

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

# Pattern Regexes - used to extract indicator type and value, spaces are removed before matching the following regexes
INDICATOR_OPERATOR_VAL_FORMAT_PATTERN = r"(\w.*?{value}{operator})'(.*?)'"
INDICATOR_IN_VAL_PATTERN = r"(\w.*?valueIN)\(+('.*?')\)"
INDICATOR_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="="
)
CIDR_ISSUBSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="ISSUBSET"
)
CIDR_ISUPPERSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="ISSUPPERSET"
)
HASHES_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value=r"hashes\..*?", operator="="
)
REGISTRY_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="key", operator="="
)

TAXII_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

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
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "infrastructure": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,

}

MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS = {
    'build-capabilities': ThreatIntel.KillChainPhases.BUILD_CAPABILITIES,
    'privilege-escalation': ThreatIntel.KillChainPhases.PRIVILEGE_ESCALATION,
    'adversary-opsec': ThreatIntel.KillChainPhases.ADVERSARY_OPSEC,
    'credential-access': ThreatIntel.KillChainPhases.CREDENTIAL_ACCESS,
    'exfiltration': ThreatIntel.KillChainPhases.EXFILTRATION,
    'lateral-movement': ThreatIntel.KillChainPhases.LATERAL_MOVEMENT,
    'defense-evasion': ThreatIntel.KillChainPhases.DEFENSE_EVASION,
    'persistence': ThreatIntel.KillChainPhases.PERSISTENCE,
    'collection': ThreatIntel.KillChainPhases.COLLECTION,
    'impact': ThreatIntel.KillChainPhases.IMPACT,
    'initial-access': ThreatIntel.KillChainPhases.INITIAL_ACCESS,
    'discovery': ThreatIntel.KillChainPhases.DISCOVERY,
    'execution': ThreatIntel.KillChainPhases.EXECUTION,
    'installation': ThreatIntel.KillChainPhases.INSTALLATION,
    'delivery': ThreatIntel.KillChainPhases.DELIVERY,
    'weaponization': ThreatIntel.KillChainPhases.WEAPONIZATION,
    'act-on-objectives': ThreatIntel.KillChainPhases.ACT_ON_OBJECTIVES,
    'command-and-control': ThreatIntel.KillChainPhases.COMMAND_AND_CONTROL,
}

STIX_2_TYPES_TO_CORTEX_CIDR_TYPES = {
    "ipv4-addr": FeedIndicatorType.CIDR,
    "ipv6-addr": FeedIndicatorType.IPv6CIDR,
}

THREAT_INTEL_TYPE_TO_DEMISTO_TYPES = {
    'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
    'attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'report': ThreatIntel.ObjectsNames.REPORT,
    'malware': ThreatIntel.ObjectsNames.MALWARE,
    'course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    'intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
    'tool': ThreatIntel.ObjectsNames.TOOL,
    'threat-actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
    'infrastructure': ThreatIntel.ObjectsNames.INFRASTRUCTURE,
}


def convert_to_json(string):
    """Will try to convert given string to json.

    Args:
        string: str of stix/json file. may be xml, then function will fail

    Returns:
        json object if succeed
        False if failed
    """
    try:
        js = json.loads(string)
        return js
    except ValueError:
        return None


class STIX2Parser:
    OBJECTS_TO_PARSE = ["indicator", "report", "malware", "campaign", "attack-pattern", "course-of-action",
                        "intrusion-set", "tool", "threat-actor", "infrastructure", "autonomous-system",
                        "domain-name", "email-addr", "file", "ipv4-addr", "ipv6-addr", "mutex", "url",
                        "user-account", "windows-registry-key", "relationship", "extension-definition"]

    def __init__(
            self
    ):
        """
        TAXII 2 Client used to poll and parse indicators in XSOAR formar
        """
        self.indicator_regexes = [
            re.compile(INDICATOR_EQUALS_VAL_PATTERN),
            re.compile(INDICATOR_IN_VAL_PATTERN),
            re.compile(HASHES_EQUALS_VAL_PATTERN),
            re.compile(REGISTRY_EQUALS_VAL_PATTERN)
        ]
        self.cidr_regexes = [
            re.compile(CIDR_ISSUBSET_VAL_PATTERN),
            re.compile(CIDR_ISUPPERSET_VAL_PATTERN),
        ]
        self.id_to_object: Dict[str, Any] = {}
        self.parsed_object_id_to_object: Dict[str, Any] = {}

    @staticmethod
    def get_indicator_publication(indicator: Dict[str, Any]):
        """
        Build publications grid field from the indicator external_references field

        Args:
            indicator: The indicator with publication field

        Returns:
            list. publications grid field
        """
        publications = []
        for external_reference in indicator.get('external_references', []):
            url = external_reference.get('url', '')
            description = external_reference.get('description', '')
            source_name = external_reference.get('source_name', '')
            publications.append({'link': url, 'title': description, 'source': source_name})
        return publications

    @staticmethod
    def change_attack_pattern_to_stix_attack_pattern(indicator: Dict[str, Any]):
        indicator['indicator_type'] = f'STIX {indicator["indicator_type"]}'
        indicator['customFields']['stixkillchainphases'] = indicator['customFields'].pop('killchainphases', None)
        indicator['customFields']['stixdescription'] = indicator['customFields'].pop('description', None)

        return indicator

    @staticmethod
    def get_ioc_type(indicator: str, id_to_object: Dict[str, Dict[str, Any]]) -> str:
        """
        Get IOC type by extracting it from the pattern field.

        Args:
            indicator: the indicator to get information on.
            id_to_object: a dict in the form of - id: stix_object.

        Returns:
            str. the IOC type.
        """
        ioc_type = ''
        indicator_obj = id_to_object.get(indicator, {})
        pattern = indicator_obj.get('pattern', '')
        for stix_type in STIX_2_TYPES_TO_CORTEX_TYPES:
            if pattern.startswith(f'[{stix_type}'):
                ioc_type = STIX_2_TYPES_TO_CORTEX_TYPES.get(stix_type)  # type: ignore
                break
        return ioc_type

    @staticmethod
    def change_ip_to_cidr(indicators):
        """
        Iterates over indicators list and changes IP to CIDR type if needed.
        :param indicators: list of parsed indicators.
        :return: changes indicators list in-place.
        """
        for indicator in indicators:
            if indicator.get('indicator_type') == FeedIndicatorType.IP:
                value = indicator.get('value')
                if value.endswith('/32'):
                    pass
                elif '/' in value:
                    indicator['indicator_type'] = FeedIndicatorType.CIDR

    """ PARSING FUNCTIONS"""

    def parse_indicator(self, indicator_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
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

            indicator_groups = self.extract_indicator_groups_from_pattern(
                trimmed_pattern, self.indicator_regexes
            )

            indicators.extend(
                self.get_indicators_from_indicator_groups(
                    indicator_groups,
                    indicator_obj,
                    STIX_2_TYPES_TO_CORTEX_TYPES,
                    field_map,
                )
            )

            cidr_groups = self.extract_indicator_groups_from_pattern(
                trimmed_pattern, self.cidr_regexes
            )
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
    def parse_attack_pattern(attack_pattern_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single attack pattern object
        :param attack_pattern_obj: attack pattern object
        :return: attack pattern extracted from the attack pattern object in cortex format
        """
        publications = STIX2Parser.get_indicator_publication(attack_pattern_obj)

        kill_chain_mitre = [chain.get('phase_name', '') for chain in attack_pattern_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        attack_pattern = {
            "value": attack_pattern_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
            "rawJSON": attack_pattern_obj,
        }
        fields = {
            'stixid': attack_pattern_obj.get('id'),
            "killchainphases": kill_chain_phases,
            "firstseenbysource": attack_pattern_obj.get('created'),
            "modified": attack_pattern_obj.get('modified'),
            'description': attack_pattern_obj.get('description', ''),
            'operatingsystemrefs': attack_pattern_obj.get('x_mitre_platforms'),
            "publications": publications,
        }

        attack_pattern["customFields"] = fields

        if not is_demisto_version_ge('6.2.0'):
            # For versions less than 6.2 - that only support STIX and not the newer types - Malware, Tool, etc.
            attack_pattern = STIX2Parser.change_attack_pattern_to_stix_attack_pattern(attack_pattern)

        return [attack_pattern]

    @staticmethod
    def parse_report(report_obj: Dict[str, Any]):
        """
        Parses a single report object
        :param report_obj: report object
        :return: report extracted from the report object in cortex format
        """
        object_refs = report_obj.get('object_refs', [])
        new_relationships = []
        for obj_id in object_refs:
            new_relationships.append({
                "type": "relationship",
                "id": "relationship--fakeid",
                "created": report_obj.get('created'),
                "modified": report_obj.get('modified'),
                "relationship_type": "contains",
                "source_ref": report_obj.get('id'),
                "target_ref": obj_id,
            })

        report = {
            "indicator_type": ThreatIntel.ObjectsNames.REPORT,
            "value": report_obj.get('name'),
            "score": ThreatIntel.ObjectsScore.REPORT,
            "rawJSON": report_obj,
        }
        fields = {
            'stixid': report_obj.get('id'),
            'firstseenbysource': report_obj.get('created'),
            'published': report_obj.get('published'),
            'description': report_obj.get('description', ''),
            "report_types": report_obj.get('report_types', []),
            "tags": list(set(report_obj.get('labels', []))),
        }

        report['customFields'] = fields

        return [report], new_relationships

    @staticmethod
    def parse_threat_actor(threat_actor_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single threat actor object
        :param threat_actor_obj: report object
        :return: threat actor extracted from the threat actor object in cortex format
        """

        threat_actor = {
            "value": threat_actor_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.THREAT_ACTOR,
            "score": ThreatIntel.ObjectsScore.THREAT_ACTOR,
            "rawJSON": threat_actor_obj
        }
        fields = {
            'stixid': threat_actor_obj.get('id'),
            "firstseenbysource": threat_actor_obj.get('created'),
            "modified": threat_actor_obj.get('modified'),
            'description': threat_actor_obj.get('description', ''),
            'aliases': threat_actor_obj.get("aliases", []),
            "threat_actor_types": threat_actor_obj.get('threat_actor_types', []),
            'roles': threat_actor_obj.get("roles", []),
            'goals': threat_actor_obj.get("goals", []),
            'sophistication': threat_actor_obj.get("sophistication", ''),
            "resource_level": threat_actor_obj.get('resource_level', ''),
            "primary_motivation": threat_actor_obj.get('primary_motivation', ''),
            "secondary_motivations": threat_actor_obj.get('secondary_motivations', []),
            "tags": list(set(threat_actor_obj.get('labels', []))),
        }

        threat_actor['customFields'] = fields

        return [threat_actor]

    @staticmethod
    def parse_infrastructure(infrastructure_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single infrastructure object
        :param infrastructure_obj: infrastructure object
        :return: infrastructure extracted from the infrastructure object in cortex format
        """
        kill_chain_mitre = [chain.get('phase_name', '') for chain in infrastructure_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        infrastructure = {
            "value": infrastructure_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
            "score": ThreatIntel.ObjectsScore.INFRASTRUCTURE,
            "rawJSON": infrastructure_obj

        }
        fields = {
            "stixid": infrastructure_obj.get('id'),
            "description": infrastructure_obj.get('description', ''),
            "infrastructure_types": infrastructure_obj.get("infrastructure_types", []),
            "aliases": infrastructure_obj.get('aliases', []),
            "kill_chain_phases": kill_chain_phases,
            "firstseenbysource": infrastructure_obj.get('created'),
            "modified": infrastructure_obj.get('modified'),
        }

        infrastructure['customFields'] = fields
        return [infrastructure]

    @staticmethod
    def parse_malware(malware_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single malware object
        :param malware_obj: malware object
        :return: malware extracted from the malware object in cortex format
        """

        kill_chain_mitre = [chain.get('phase_name', '') for chain in malware_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        malware = {
            "value": malware_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.MALWARE,
            "score": ThreatIntel.ObjectsScore.MALWARE,
            "rawJSON": malware_obj
        }
        fields = {
            'stixid': malware_obj.get('id'),
            "firstseenbysource": malware_obj.get('created'),
            "modified": malware_obj.get('modified'),
            "description": malware_obj.get('description', ''),
            "malware_types": malware_obj.get('malware_types', []),
            "is_family": malware_obj.get('is_family', False),
            "aliases": malware_obj.get('aliases', []),
            "kill_chain_phases": kill_chain_phases,
            "os_execution_envs": malware_obj.get('os_execution_envs', []),
            "architecture_execution_envs": malware_obj.get('architecture_execution_envs', []),
            "capabilities": malware_obj.get('capabilities', []),
            "sample_refs": malware_obj.get('sample_refs', []),
            "tags": list(set(malware_obj.get('labels', []))),
        }

        malware['customFields'] = fields
        return [malware]

    @staticmethod
    def parse_tool(tool_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single tool object
        :param tool_obj: tool object
        :return: tool extracted from the tool object in cortex format
        """
        kill_chain_mitre = [chain.get('phase_name', '') for chain in tool_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        tool = {
            "value": tool_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.TOOL,
            "score": ThreatIntel.ObjectsScore.TOOL,
            "rawJSON": tool_obj
        }
        fields = {
            'stixid': tool_obj.get('id'),
            "killchainphases": kill_chain_phases,
            "firstseenbysource": tool_obj.get('created'),
            "modified": tool_obj.get('modified'),
            "tool_types": tool_obj.get("tool_types", []),
            "description": tool_obj.get('description', ''),
            "aliases": tool_obj.get('aliases', []),
            "tool_version": tool_obj.get('tool_version', ''),
        }

        tool['customFields'] = fields
        return [tool]

    @staticmethod
    def parse_course_of_action(coa_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single course of action object
        :param coa_obj: course of action object
        :return: course of action extracted from the course of action object in cortex format
        """
        publications = STIX2Parser.get_indicator_publication(coa_obj)

        course_of_action = {
            "value": coa_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
            "score": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
            "rawJSON": coa_obj,
        }
        fields = {
            'stixid': coa_obj.get('id'),
            "firstseenbysource": coa_obj.get('created'),
            "modified": coa_obj.get('modified'),
            'description': coa_obj.get('description', ''),
            "action_type": coa_obj.get('action_type', ''),
            "publications": publications,
        }

        course_of_action['customFields'] = fields
        return [course_of_action]

    @staticmethod
    def parse_campaign(campaign_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single campaign object
        :param campaign_obj: campaign object
        :return: campaign extracted from the campaign object in cortex format
        """
        campaign = {
            "value": campaign_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.CAMPAIGN,
            "score": ThreatIntel.ObjectsScore.CAMPAIGN,
            "rawJSON": campaign_obj
        }
        fields = {
            'stixid': campaign_obj.get('id'),
            "firstseenbysource": campaign_obj.get('created'),
            "modified": campaign_obj.get('modified'),
            'description': campaign_obj.get('description', ''),
            "aliases": campaign_obj.get('aliases', []),
            "objective": campaign_obj.get('objective', ''),
        }

        campaign['customFields'] = fields
        return [campaign]

    @staticmethod
    def parse_intrusion_set(intrusion_set_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single intrusion set object
        :param intrusion_set_obj: intrusion set object
        :return: intrusion set extracted from the intrusion set object in cortex format
        """
        publications = STIX2Parser.get_indicator_publication(intrusion_set_obj)

        intrusion_set = {
            "value": intrusion_set_obj.get('name'),
            "indicator_type": ThreatIntel.ObjectsNames.INTRUSION_SET,
            "score": ThreatIntel.ObjectsScore.INTRUSION_SET,
            "rawJSON": intrusion_set_obj
        }
        fields = {
            'stixid': intrusion_set_obj.get('id'),
            "firstseenbysource": intrusion_set_obj.get('created'),
            "modified": intrusion_set_obj.get('modified'),
            'description': intrusion_set_obj.get('description', ''),
            "aliases": intrusion_set_obj.get('aliases', []),
            "goals": intrusion_set_obj.get('goals', []),
            "resource_level": intrusion_set_obj.get('resource_level', ''),
            "primary_motivation": intrusion_set_obj.get('primary_motivation', ''),
            "secondary_motivations": intrusion_set_obj.get('secondary_motivations', []),
            "publications": publications,
        }
        intrusion_set['customFields'] = fields
        return [intrusion_set]

    @staticmethod
    def parse_general_sco_indicator(sco_object: Dict[str, Any], value_mapping: str = 'value') -> List[Dict[str, Any]]:
        """
        Parses a single SCO indicator.

        Args:
            sco_object (dict): indicator as an observable object.
            value_mapping (str): the key that extracts the value from the indicator response.
        """
        sco_indicator = {
            'value': sco_object.get(value_mapping),
            'score': Common.DBotScore.NONE,
            'rawJSON': sco_object,
            'indicator_type': STIX_2_TYPES_TO_CORTEX_TYPES.get(sco_object.get('type'))  # type: ignore[arg-type]
        }

        fields = {
            'stixid': sco_object.get('id')
        }

        sco_indicator['customFields'] = fields
        return [sco_indicator]

    @staticmethod
    def parse_sco_autonomous_system_indicator(autonomous_system_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses autonomous_system indicator type to cortex format.

        Args:
            autonomous_system_obj (dict): indicator as an observable object of type autonomous-system.
        """
        autonomous_system_indicator = STIX2Parser.parse_general_sco_indicator(autonomous_system_obj,
                                                                              value_mapping='number')
        autonomous_system_indicator[0]['customFields']['name'] = autonomous_system_obj.get('name')

        return autonomous_system_indicator

    @staticmethod
    def parse_sco_file_indicator(file_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses file indicator type to cortex format.

        Args:
            file_obj (dict): indicator as an observable object of file type.
        """
        file_hashes = file_obj.get('hashes', {})
        value = file_hashes.get('SHA-256') or file_hashes.get('SHA-1') or file_hashes.get('MD5')
        if not value:
            return []

        file_obj['value'] = value

        file_indicator = STIX2Parser.parse_general_sco_indicator(file_obj)
        file_indicator[0]['customFields'].update(
            {
                'associatedfilenames': file_obj.get('name'),
                'size': file_obj.get('size'),
                'path': file_obj.get('parent_directory_ref'),
                'md5': file_hashes.get('MD5'),
                'sha1': file_hashes.get('SHA-1'),
                'sha256': file_hashes.get('SHA-256')
            }
        )

        return file_indicator

    @staticmethod
    def parse_sco_mutex_indicator(mutex_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses mutex indicator type to cortex format.

        Args:
            mutex_obj (dict): indicator as an observable object of mutex type.
        """
        return STIX2Parser.parse_general_sco_indicator(sco_object=mutex_obj, value_mapping='name')

    @staticmethod
    def parse_sco_account_indicator(account_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses account indicator type to cortex format.

        Args:
            account_obj (dict): indicator as an observable object of account type.
        """
        account_indicator = STIX2Parser.parse_general_sco_indicator(account_obj, value_mapping='user_id')
        account_indicator[0]['customFields'].update(
            {
                'displayname': account_obj.get('user_id'),
                'accounttype': account_obj.get('account_type')
            }
        )
        return account_indicator

    @staticmethod
    def parse_sco_windows_registry_key_indicator(registry_key_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses registry_key indicator type to cortex format.

        Args:
            registry_key_obj (dict): indicator as an observable object of registry_key type.
        """
        registry_key_indicator = STIX2Parser.parse_general_sco_indicator(registry_key_obj, value_mapping='key')
        registry_key_indicator[0]['customFields'].update(
            {
                'registryvalue': registry_key_obj.get('values'),
                'modified_time': registry_key_obj.get('modified_time'),
                'number_of_subkeys': registry_key_obj.get('number_of_subkeys')
            }
        )
        return registry_key_indicator

    def parse_relationships(self, relationships_lst: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Parse the Relationships objects retrieved from the feed.

        Returns:
            A dict of relationship value to processed relationships as indicator object.
        """
        a_value_to_relationship: Dict[str, Any] = dict()
        for relationships_object in relationships_lst:
            relationship_type = relationships_object.get('relationship_type')
            if relationship_type not in EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys():
                if relationship_type == 'indicates':
                    relationship_type = 'indicated-by'
                else:
                    demisto.debug(f"Invalid relation type: {relationship_type}")
                    continue

            a_stixid = relationships_object.get('source_ref', '')
            a_object = self.parsed_object_id_to_object.get(a_stixid, {})
            b_stixid = relationships_object.get('target_ref', '')
            b_object = self.parsed_object_id_to_object.get(b_stixid, {})

            if not a_object or not b_object:
                demisto.debug(f'Cant find {a_object=} or {b_object=}.')
                continue

            a_value, a_type = a_object.get('value'), a_object.get('indicator_type')
            b_value, b_type = b_object.get('value'), b_object.get('indicator_type')

            if not (a_value and a_type and b_value and b_type):
                continue

            mapping_fields = {
                'lastseenbysource': relationships_object.get('modified'),
                'firstseenbysource': relationships_object.get('created'),
            }

            entity_relation = EntityRelationship(name=relationship_type,
                                                 entity_a=a_value,
                                                 entity_a_type=a_type,
                                                 entity_b=b_value,
                                                 entity_b_type=b_type,
                                                 fields=mapping_fields)
            indicator_relationship = entity_relation.to_indicator()
            if a_value_to_relationship.get(a_value):
                a_value_to_relationship[a_value].append(indicator_relationship)
            else:
                a_value_to_relationship[a_value] = [indicator_relationship]

        return a_value_to_relationship

    def parse_stix2(self, js_content) -> List[Dict[str, str]]:
        """
        Polls the taxii server and builds a list of cortex indicators objects from the result
        :return: Cortex indicators list
        """
        if js_content.get('objects'):
            envelopes = STIX2Parser.create_envelopes_by_type(js_content['objects'])
        else:
            envelopes = STIX2Parser.create_envelopes_by_type([js_content])
        indicators = self.load_stix_objects_from_envelope(envelopes)

        return indicators

    def load_stix_objects_from_envelope(self, envelopes: Dict[str, Any]):

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
            "windows-registry-key": self.parse_sco_windows_registry_key_indicator
        }
        indicators = self.parse_dict_envelope(envelopes, parse_stix_2_objects)
        demisto.debug(
            f"{SCRIPT_NAME} has extracted {len(indicators)} indicators"
        )
        return indicators

    def parse_dict_envelope(self, envelopes: Dict[str, Any],
                            parse_objects_func):
        indicators = []
        relationships_list: List[Dict[str, Any]] = []

        xsoar_taxii_server_extensions = self.get_taxii2_extensions_from_envelope(
            envelopes.get('extension-definition', []))

        for obj_type, stix_objects in envelopes.items():
            if obj_type == 'relationship':
                relationships_list.extend(stix_objects)
            else:
                for obj in stix_objects:
                    # handled separately
                    if obj.get('type') == 'extension-definition':
                        continue
                    self.id_to_object[obj.get('id')] = obj
                    if obj.get('type') == 'report':
                        result, relationships = self.parse_report(obj)
                        relationships_list.extend(relationships)
                    else:
                        result = parse_objects_func[obj_type](obj)
                    if not result:
                        continue
                    self.update_obj_if_extensions(xsoar_taxii_server_extensions, obj, result)
                    self.parsed_object_id_to_object[obj.get('id')] = result[0]
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
            obj_type = obj.get('type')
            if obj_type not in STIX2Parser.OBJECTS_TO_PARSE:
                demisto.debug(f'Cannot parse object of type {obj_type}, skipping.')
                index += 1
                continue
            if obj_type not in types_envelopes:
                types_envelopes[obj_type] = []
            types_envelopes[obj_type].append(obj)

        return types_envelopes

    @staticmethod
    def get_indicators_from_indicator_groups(
            indicator_groups: List[tuple[str, str]],
            indicator_obj: Dict[str, str],
            indicator_types: Dict[str, str],
            field_map: Dict[str, str],
    ) -> List[Dict[str, str]]:
        """
        Get indicators from indicator regex groups
        :param indicator_groups: caught regex group in pattern of: [`type`, `indicator`]
        :param indicator_obj: taxii indicator object
        :param indicator_types: supported indicator types -> cortex types
        :param field_map: map used to create fields entry ({field_name: field_value})
        :return: Indicators list
        """
        indicators = []
        if indicator_groups:
            for term in indicator_groups:
                for taxii_type in indicator_types.keys():
                    # term should be list with 2 argument parsed with regex - [`type`, `indicator`]
                    if len(term) == 2 and taxii_type in term[0]:
                        type_ = indicator_types[taxii_type]
                        value = term[1]

                        # support added for cases as 'value1','value2','value3' for 3 different indicators
                        for indicator_value in value.split(','):
                            indicator_value = indicator_value.strip("'")
                            indicator = STIX2Parser.create_indicator(
                                indicator_obj, type_, indicator_value.strip("'"), field_map
                            )
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

        indicator['customFields'] = fields
        return indicator

    @staticmethod
    def extract_indicator_groups_from_pattern(
            pattern: str, regexes: List
    ) -> List[tuple[str, str]]:
        """
        Extracts indicator [`type`, `indicator`] groups from pattern
        :param pattern: stix pattern
        :param regexes: regexes to run to pattern
        :return: extracted indicators list from pattern
        """
        groups: List[tuple[str, str]] = []
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
            if a_value := indicator.get('value'):
                if relationships := relationships_mapping.get(a_value):
                    indicator['relationships'] = relationships

    @staticmethod
    def update_obj_if_extensions(xsoar_taxii_server_extensions, obj, result):
        """
        If stix object has extension, check if it xsoar taxii2 server extension, if yes parse it to XSOAR.
        :param xsoar_taxii_server_extensions: ids of all XSOAR extentions in current bundle.
        :param obj: stix object
        :param result: parsed xsoar indicator
        :return: updated xsoar indicator
        """
        parsed_result = result[0]
        if extensions := obj.get('extensions'):
            custom_fields = parsed_result.get('customFields', {})
            for ext_id, extension in extensions.items():
                if ext_id in xsoar_taxii_server_extensions:
                    extension.pop('extension_type')
                    for field, value in extension.items():
                        if field in SYSTEM_FIELDS:
                            parsed_result[field] = value
                        elif field.lower() == 'customfields':
                            custom_fields.update(value)
                        else:
                            custom_fields[field] = value
                    parsed_result['customFields'] = custom_fields

    @staticmethod
    def get_taxii2_extensions_from_envelope(stix_objects):
        """
        :param stix_objects: list of all extension objects.
        :return: list of xsoar extensions ids.
        """
        xsoar_taxii_server_extensions = []
        for obj in stix_objects:
            if obj.get('schema') == XSOAR_TAXII2_SERVER_SCHEMA:
                xsoar_taxii_server_extensions.append(obj.get('id'))
        return xsoar_taxii_server_extensions

# STIX 1 Parsing


def package_extract_properties(package):
    """Extracts properties from the STIX package"""
    result: Dict[str, str] = {}

    header = package.find_all('STIX_Header')
    if len(header) == 0:
        return result

    # share level
    mstructures = header[0].find_all('Marking_Structure')
    for ms in mstructures:
        type_ = ms.get('xsi:type')
        if type_ is result:
            continue

        color = ms.get('color')
        if color is result:
            continue

        type_ = type_.lower()
        if 'tlpmarkingstructuretype' not in type_:
            continue

        result['share_level'] = color.lower()  # To keep backward compatibility
        result['TLP'] = color.upper()  # https://www.us-cert.gov/tlp
        break

    # decode title
    title = next((c for c in header[0] if c.name == 'Title'), None)
    if title is not None:
        result['stix_package_title'] = title.text

    # decode description
    description = next((c for c in header[0] if c.name == 'Description'), None)
    if description is not None:
        result['stix_package_description'] = description.text

    # decode description
    sdescription = next((c for c in header[0] if c.name == 'Short_Description'), None)
    if sdescription is not None:
        result['stix_package_short_description'] = sdescription.text

    # decode identity name from information_source
    information_source = next((c for c in header[0] if c.name == 'Information_Source'), None)
    if information_source is not None:
        identity = next((c for c in information_source if c.name == 'Identity'), None)
        if identity is not None:
            name = next(c for c in identity if c.name == 'Name')
            if name is not None:
                result['stix_package_information_source'] = name.text

    return result


def observable_extract_properties(observable):
    """Extracts properties from observable"""
    result = {}

    if id_ref := observable.get('id'):
        result['indicator_ref'] = id_ref

    title = next((c for c in observable if c.name == 'Title'), None)
    if title is not None:
        title = title.text
        result['stix_title'] = title

    description = next((c for c in observable if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['stix_description'] = description

    return result


def indicator_extract_properties(indicator) -> Dict[str, Any]:
    """Extracts the Indicator properties

    Args:
        indicator (bs4.element.Tag): The Indicator content in xml.

    Returns:
        dict: The ttp properties in a dict {'property': 'value'}. (The value can be a list)

    """

    result: Dict[str, Any] = {}

    title = next((c for c in indicator if c.name == 'Title'), None)
    if title is not None:
        title = title.text
        result['stix_indicator_name'] = title

    description = next((c for c in indicator if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['stix_indicator_description'] = description

    confidence = next((c for c in indicator if c.name == 'Confidence'), None)
    if confidence is not None:
        value = next((c for c in confidence if c.name == 'Value'), None)
        if value is not None:
            value = value.text
            result['confidence'] = value

    if indicated_ttp := indicator.find_all('Indicated_TTP'):
        result['ttp_ref'] = []
        # Each indicator can be related to few ttps
        for ttp_value in indicated_ttp:
            ttp = next((c for c in ttp_value if c.name == 'TTP'), None)
            if ttp is not None:
                value = ttp.get('idref')
                result['ttp_ref'].append(value)

    return result


def ttp_extract_properties(ttp, behavior) -> Dict[str, str]:
    """Extracts the TTP properties

    Args:
        ttp (bs4.element.Tag): The TTP content in xml.
        behavior (str): The TTP behavior ['Malware', 'Attack Pattern'].

    Returns:
        dict: The ttp properties in a dict {'property': 'value'}.

    """

    result = {'type': behavior}

    if behavior == 'Malware':
        type_ = next((c for c in ttp if c.name == 'Type'), None)
        if type_ is not None:
            type_ = type_.text
            result['malware_type'] = type_

        name = next((c for c in ttp if c.name == 'Name'), None)
        if name is not None:
            name = name.text
            result['indicator'] = name

        title = next((c for c in ttp if c.name == 'Title'), None)
        if title is not None:
            title = title.text
            result['title'] = title

    if behavior == 'Attack Pattern':
        id_ref = next((c for c in ttp if c.name == 'idref'), None)
        if id_ref is not None:
            id_ref = id_ref.text
            result['stix_id_ref'] = id_ref

        title = next((c for c in ttp if c.name == 'Title'), None)
        if title is not None:
            title = title.text
            result['indicator'] = title

    description = next((c for c in ttp if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['description'] = description

    short_description = next((c for c in ttp if c.name == 'Short_Description'), None)
    if short_description is not None:
        short_description = short_description.text
        result['short_description'] = short_description

    return result


def create_relationships(indicator):
    results = []

    for relationship in indicator.get('relationships', {}):
        if relationship.get('type') == 'Malware':
            name = 'indicator-of'
            relationship_type = 'Malware'
        else:
            name = 'related-to'
            relationship_type = 'Attack Pattern'

        entity_relationship = EntityRelationship(name=name,
                                                 entity_a=indicator.get('value'),
                                                 entity_a_type=indicator.get('type'),
                                                 entity_b=relationship.get('indicator'),
                                                 entity_b_type=relationship_type)
        results.append(entity_relationship.to_indicator())

    return results


class AddressObject:
    """
    Implements address object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/AddressObj/AddressObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        result: List[Dict[str, str]] = []

        indicator = props.find('Address_Value')
        if indicator is None:
            return result

        indicator = indicator.string.encode('ascii', 'replace').decode()
        category = props.get('category', None)
        address_list = indicator.split('##comma##')

        if category == 'e-mail':
            return [{'indicator': address, 'type': 'Email'} for address in address_list]

        try:
            for address in address_list:
                ip = IPNetwork(address)
                if ip.version == 4:
                    if len(address.split('/')) > 1:
                        type_ = 'CIDR'
                    else:
                        type_ = 'IP'
                elif ip.version == 6:
                    if len(address.split('/')) > 1:
                        type_ = 'IPv6CIDR'
                    else:
                        type_ = 'IPv6'
                else:
                    LOG(f'Unknown ip version: {ip.version!r}')
                    return []

                result.append({'indicator': address, 'type': type_})

        except Exception:
            return result

        return result


class DomainNameObject:
    """
    Implements domain object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/DomainNameObj/DomainNameObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        domains = []
        dtype = props.get('type', 'FQDN')
        if dtype != 'FQDN':
            return []

        if domain_value := props.find('Value'):
            domain_list = domain_value.string.split('##comma##')
            for domain in domain_list:
                domains.append({
                    'indicator': domain,
                    'type': 'Domain'
                })

        return domains


class FileObject:
    """
    Implements file object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/FileObj/FileObjectType/
    """

    @staticmethod
    def _decode_basic_props(props):
        result = {}

        name = next((c for c in props if c.name == 'File_Name'), None)
        if name is not None:
            result['stix_file_name'] = name.text

        size = next((c for c in props if c.name == 'File_Size'), None)
        if size is not None:
            result['stix_file_size'] = size.text

        file_format = next((c for c in props if c.name == 'File_Format'), None)
        if file_format is not None:
            result['stix_file_format'] = file_format.text

        return result

    @staticmethod
    def decode(props, **kwargs):
        result = []

        bprops = FileObject._decode_basic_props(props)

        hashes = props.find_all('Hash')
        for h in hashes:
            value = h.find('Simple_Hash_Value')
            if value is None:
                continue
            value = value.string.lower()
            value_list = value.split('##comma##')
            for v in value_list:
                v = v.strip()
                if type := detect_file_indicator_type(v):
                    result.append({
                        'indicator': v,
                        'htype': type,
                        'type': 'File'
                    })

        for r in result:
            for r2 in result:
                if r['htype'] == r2['htype']:
                    continue

                r[f"stix_file_{r2['htype']}"] = r2['indicator']

            r.update(bprops)

        return result


class URIObject:
    """
    Implements URI object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/URIObj/URIObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        urls = []
        utype = props.get('type', 'URL')
        if utype == 'URL':
            type_ = 'URL'
        elif utype == 'Domain Name':
            type_ = 'Domain'
        else:
            return []

        if url_value := props.find('Value'):
            url_list = url_value.string.split('##comma##')
            for url in url_list:
                urls.append({
                    'indicator': url,
                    'type': type_
                })

        return urls


class SocketAddressObject:
    """
    Implements socket address object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/SocketAddressObj/SocketAddressObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        ip = props.get('ip_address', None)
        if ip:
            return AddressObject.decode(ip)
        return []


class LinkObject:
    """
    Implements link object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/LinkObj/LinkObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        ltype = props.get('type', 'URL')
        if ltype != 'URL':
            LOG(f'Unhandled LinkObjectType type: {ltype}')
            return []
        value = props.get('value', None)
        if value is None:
            LOG('no value in observable LinkObject')
            return []
        if not isinstance(value, string_types):
            value = value.get('value', None)
            if value is None:
                LOG('no value in observable LinkObject')
                return []
        return [{
            'indicator': value,
            'type': ltype
        }]


class HTTPSessionObject:
    """
    Implements http session object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/HTTPSessionObj/HTTPSessionObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        if props.get('http_request_response'):
            tmp = props.get('http_request_response')

            if len(tmp) == 1:
                item = tmp[0]
                http_client_request = item.get('http_client_request', None)
                if http_client_request is not None:
                    http_request_header = http_client_request.get('http_request_header', None)
                    if http_request_header is not None:
                        raw_header = http_request_header.get('raw_header', None)
                        if raw_header is not None:
                            return [{
                                'indicator': raw_header.split('\n')[0],
                                'type': 'http-session',  # we don't support this type natively in demisto
                                'header': raw_header
                            }]
            else:
                LOG('multiple HTTPSessionObjectTypes not supported')
        return []


class StixDecode:
    """
    Decode STIX strings formatted as xml, and extract indicators from them
    """
    DECODERS = {
        'DomainNameObjectType': DomainNameObject.decode,
        'FileObjectType': FileObject.decode,
        'WindowsFileObjectType': FileObject.decode,
        'URIObjectType': URIObject.decode,
        'AddressObjectType': AddressObject.decode,
        'SocketAddressObjectType': SocketAddressObject.decode,
        'LinkObjectType': LinkObject.decode,
        'HTTPSessionObjectType': HTTPSessionObject.decode,
    }

    @staticmethod
    def object_extract_properties(props, kwargs):
        type_ = props.get('xsi:type').rsplit(':')[-1]

        if type_ not in StixDecode.DECODERS:
            LOG(f'Unhandled cybox Object type: {type_!r} - {props!r}')
            return []

        return StixDecode.DECODERS[type_](props, **kwargs)

    @staticmethod
    def _parse_stix_timestamp(stix_timestamp):
        dt = dateutil.parser.parse(stix_timestamp)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC)
        delta = dt - EPOCH
        return int(delta.total_seconds() * 1000)

    @staticmethod
    def _deduplicate(indicators):
        result = {}

        for iv in indicators:
            result['{}:{}'.format(iv['indicator'], iv['type'])] = iv

        return list(result.values())

    @staticmethod
    def decode(content, **kwargs):
        observable_result = []
        indicator_result: Dict[str, dict] = {}
        ttp_result: Dict[str, dict] = {}

        package = BeautifulSoup(content, 'xml')

        timestamp = package.get('timestamp', None)
        if timestamp is not None:
            timestamp = StixDecode._parse_stix_timestamp(timestamp)

        # extract the Observable info
        if observables := package.find_all('Observable'):
            pprops = package_extract_properties(package)

            for o in observables:
                gprops = observable_extract_properties(o)

                obj = next((ob for ob in o if ob.name == 'Object'), None)
                if obj is None:
                    continue

                # main properties
                properties = next((c for c in obj if c.name == 'Properties'), None)
                if properties is not None:
                    for r in StixDecode.object_extract_properties(properties, kwargs):
                        r.update(gprops)
                        r.update(pprops)

                        observable_result.append(r)

                # then related objects
                related = next((c for c in obj if c.name == 'Related_Objects'), None)
                if related is not None:
                    for robj in related:
                        if robj.name != 'Related_Object':
                            continue

                        properties = next((c for c in robj if c.name == 'Properties'), None)
                        if properties is None:
                            continue

                        for r in StixDecode.object_extract_properties(properties, kwargs):
                            r.update(gprops)
                            r.update(pprops)
                            observable_result.append(r)

        # extract the Indicator info
        if indicators := package.find_all('Indicator'):

            if observables:
                indicator_ref = observables[0].get('idref')

                if indicator_ref:
                    indicator_info = indicator_extract_properties(indicators[0])
                    indicator_result[indicator_ref] = indicator_info

        # extract the TTP info
        if ttp := package.find_all('TTP'):
            ttp_info: Dict[str, str] = {}

            id_ref = ttp[0].get('id')

            title = next((c for c in ttp[0] if c.name == 'Title'), None)
            if title is not None:
                title = title.text
                ttp_info['stix_ttp_title'] = title

            description = next((c for c in ttp[0] if c.name == 'Description'), None)
            if description is not None:
                description = description.text
                ttp_info['ttp_description'] = description

            if behavior := package.find_all('Behavior'):
                if behavior[0].find_all('Malware'):
                    ttp_info.update(ttp_extract_properties(package.find_all('Malware_Instance')[0], 'Malware'))

                elif behavior[0].find_all('Attack_Patterns'):
                    ttp_info.update(ttp_extract_properties(package.find_all('Attack_Pattern')[0], 'Attack Pattern'))

                ttp_result[id_ref] = ttp_info

        return timestamp, StixDecode._deduplicate(observable_result), indicator_result, ttp_result


def build_observables(file_name):
    tag_stack = collections.deque()  # type: ignore
    observables = []
    indicators = {}
    ttps = {}

    for action, element in etree.iterparse(file_name, events=('start', 'end'), recover=True):
        if action == 'start':
            tag_stack.append(element.tag)

        else:
            last_tag = tag_stack.pop()
            if last_tag != element.tag:
                raise RuntimeError(
                    f'{SCRIPT_NAME} - error parsing poll response, mismatched tags')

        if action == 'end' and element.tag.endswith('STIX_Package'):
            for c in element:
                content = etree.tostring(c, encoding='unicode')
                timestamp, observable, indicator, ttp = StixDecode.decode(content)
                if observable:
                    observables.extend(observable)
                if indicator:
                    indicators.update(indicator)
                if ttp:
                    ttps.update(ttp)

            element.clear()

    for observable in observables:

        if indicator_ref := observable.get('indicator_ref'):
            if indicator_info := indicators.get(indicator_ref):
                observable.update(indicator_info)

        ttp_ref = observable.get('ttp_ref', [])
        relationships = []

        for reference in ttp_ref:
            if relationship := ttps.get(reference):
                relationships.append(relationship)
        if relationships:
            observable['relationships'] = relationships

    return observables, ttps


def parse_stix(file_name):
    """
    :param file_name: the file with xml indicators
    :return: Parsed indicators in XSOAR format
    """
    indicators = []

    indicator_custom_fields = {
        'title': 'stix_title',
        'description': 'stix_description',
        'name': 'stix_indicator_name',
        'stixdescription': 'stix_indicator_description',
        'confidence': 'confidence'
    }

    # Create the indicators from the observables
    observables, ttps = build_observables(file_name)
    for item in observables:
        if indicator := item.get('indicator'):
            item['value'] = indicator.strip()
            indicator_obj = {
                'value': indicator.strip(),
                'indicator_type': item.get('type'),
                'customFields': {
                    xsoar_field: item.get(stix_field)
                    for xsoar_field, stix_field in indicator_custom_fields.items() if item.get(stix_field)
                }
            }

            if item.get('relationships'):
                relationships = create_relationships(item)
                indicator_obj['relationships'] = relationships

            indicator_obj['rawJSON'] = item
            indicators.append(indicator_obj)

    # Create the indicators from the ttps
    ttps_custom_fields = {
        'title': 'title',
        'description': 'description',
        'shortdescription': 'short_description',
        'stixdescription': 'ttp_description',
        'stixttptitle': 'stix_ttp_title'
    }
    for item in ttps.values():
        if indicator := item.get('indicator'):
            item['value'] = indicator.strip()
            indicator_obj = {
                'value': indicator.strip(),
                'indicator_type': item.get('type'),
                'customFields': {
                    xsoar_field: item.get(stix_field)
                    for xsoar_field, stix_field in ttps_custom_fields.items() if item.get(stix_field)
                }
            }

            if item.get('type') == 'Malware':
                indicator_obj['score'] = ThreatIntel.ObjectsScore.MALWARE
                indicator_obj['stixmalwaretypes'] = item.get('malware_type', '').lower().replace(' ', '-')
            else:
                indicator_obj['score'] = ThreatIntel.ObjectsScore.ATTACK_PATTERN

            indicator_obj['rawJSON'] = item

            indicators.append(indicator_obj)

    return indicators


def main():  # pragma: no cover
    args = demisto.args()

    indicator_txt = args.get('iocXml')
    entry_id = args.get('entry_id')

    if not indicator_txt and not entry_id:
        raise Exception('You must enter iocXml or entry_id of the Indicator.')
    elif entry_id:
        file_path = demisto.getFilePath(entry_id).get('path')
        with open(file_path) as f:
            indicator_txt = f.read()

    if stix2 := convert_to_json(indicator_txt):
        stix2_parser = STIX2Parser()
        observables = stix2_parser.parse_stix2(stix2)
    else:
        if 'file_path' not in locals():
            with tempfile.NamedTemporaryFile() as temp:
                temp.write(str.encode(indicator_txt))
                temp.flush()
                observables = parse_stix(temp.name)
        else:
            observables = parse_stix(file_path)
    json_data = json.dumps(observables)
    return_results(json_data)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
