import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Union, Optional, List, Dict, Tuple
from requests.sessions import merge_setting, CaseInsensitiveDict
import re
import copy
import types
import urllib3
from taxii2client import v20, v21
from taxii2client.common import TokenAuth, _HTTPConnection
import tempfile

# disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
TAXII_VER_2_0 = "2.0"
TAXII_VER_2_1 = "2.1"

DFLT_LIMIT_PER_REQUEST = 100
API_USERNAME = "_api_token_key"
HEADER_USERNAME = "_header:"

ERR_NO_COLL = "No collection is available for this user, please make sure you entered the configuration correctly"

# Pattern Regexes - used to extract indicator type and value
INDICATOR_OPERATOR_VAL_FORMAT_PATTERN = r"(\w.*?{value}{operator})'(.*?)'"
INDICATOR_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="="
)
CIDR_ISSUBSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="ISSUBSET"
)
CIDR_ISUPPERSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="ISUPPERSET"
)
HASHES_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value=r"hashes\..*?", operator="="
)

TAXII_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TAXII_TIME_FORMAT_NO_MS = "%Y-%m-%dT%H:%M:%SZ"

STIX_2_TYPES_TO_CORTEX_TYPES = {
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain": FeedIndicatorType.Domain,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "md5": FeedIndicatorType.File,
    "sha-1": FeedIndicatorType.File,
    "sha-256": FeedIndicatorType.File,
    "file:hashes": FeedIndicatorType.File,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "Threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
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
    'command-and-control': ThreatIntel.KillChainPhases.COMMAND_AND_CONTROL
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
    'infrastructure': ThreatIntel.ObjectsNames.INFRASTRUCTURE
}


class Taxii2FeedClient:
    def __init__(
            self,
            url: str,
            collection_to_fetch,
            proxies,
            verify: bool,
            skip_complex_mode: bool = False,
            username: Optional[str] = None,
            password: Optional[str] = None,
            field_map: Optional[dict] = None,
            tags: Optional[list] = None,
            tlp_color: Optional[str] = None,
            limit_per_request: int = DFLT_LIMIT_PER_REQUEST,
            cert_text: str = None,
            key_text: str = None
    ):
        """
        TAXII 2 Client used to poll and parse indicators in XSOAR formar
        :param url: discovery service URL
        :param collection_to_fetch: Collection to fetch objects from
        :param proxies: proxies used in request
        :param skip_complex_mode: if set to True will skip complex observations
        :param verify: verify https
        :param username: username used for basic authentication OR api_key used for authentication
        :param password: password used for basic authentication
        :param field_map: map used to create fields entry ({field_name: field_value})
        :param tags: custom tags to be added to the created indicator
        :param limit_per_request: Limit the objects requested per poll request
        :param tlp_color: Traffic Light Protocol color
        :param cert_text: Certificate File as Text
        :param key_text: Key File as Text
        """
        self._conn = None
        self.server = None
        self.api_root = None
        self.collections = None
        self.last_fetched_indicator__modified = None

        self.collection_to_fetch = collection_to_fetch
        self.skip_complex_mode = skip_complex_mode
        if not limit_per_request:
            limit_per_request = DFLT_LIMIT_PER_REQUEST
        self.limit_per_request = limit_per_request

        self.base_url = url
        self.proxies = proxies
        self.verify = verify

        self.auth = None
        self.auth_header = None
        self.auth_key = None
        self.crt = None
        if username and password:
            # authentication methods:
            # 1. API Token
            # 2. Authentication Header
            # 3. Basic
            if username == API_USERNAME:
                self.auth = TokenAuth(key=password)
            elif username.startswith(HEADER_USERNAME):
                self.auth_header = username.split(HEADER_USERNAME)[1]
                self.auth_key = password
            else:
                self.auth = requests.auth.HTTPBasicAuth(username, password)

        if (cert_text and not key_text) or (not cert_text and key_text):
            raise Exception('You can not configure either certificate text or key, both are required.')
        if cert_text and key_text:

            cert_text_list = cert_text.split('-----')
            # replace spaces with newline characters
            cert_text_fixed = '-----'.join(cert_text_list[:2] + [cert_text_list[2].replace(' ', '\n')] + cert_text_list[3:])
            cf = tempfile.NamedTemporaryFile(delete=False)
            cf.write(cert_text_fixed.encode())
            cf.flush()

            key_text_list = key_text.split('-----')
            # replace spaces with newline characters
            key_text_fixed = '-----'.join(key_text_list[:2] + [key_text_list[2].replace(' ', '\n')] + key_text_list[3:])
            kf = tempfile.NamedTemporaryFile(delete=False)
            kf.write(key_text_fixed.encode())
            kf.flush()
            self.crt = (cf.name, kf.name)

        self.field_map = field_map if field_map else {}
        self.tags = tags if tags else []
        self.tlp_color = tlp_color
        self.indicator_regexes = [
            re.compile(INDICATOR_EQUALS_VAL_PATTERN),
            re.compile(HASHES_EQUALS_VAL_PATTERN),
        ]
        self.cidr_regexes = [
            re.compile(CIDR_ISSUBSET_VAL_PATTERN),
            re.compile(CIDR_ISUPPERSET_VAL_PATTERN),
        ]
        self.id_to_object: Dict[str, Any] = {}
        self.objects_data: Dict[str, Any] = {}

    def init_server(self, version=TAXII_VER_2_0):
        """
        Initializes a server in the requested version
        :param version: taxii version key (either 2.0 or 2.1)
        """
        server_url = urljoin(self.base_url)
        self._conn = _HTTPConnection(
            verify=self.verify, proxies=self.proxies, version=version, auth=self.auth, cert=self.crt
        )
        if self.auth_header:
            # add auth_header to the session object
            self._conn.session.headers = (  # type: ignore[attr-defined]
                merge_setting(
                    self._conn.session.headers,  # type: ignore[attr-defined]
                    {self.auth_header: self.auth_key},
                    dict_class=CaseInsensitiveDict,
                ),
            )
        if version is TAXII_VER_2_0:
            self.server = v20.Server(
                server_url, verify=self.verify, proxies=self.proxies, conn=self._conn,
            )
        else:
            self.server = v21.Server(
                server_url, verify=self.verify, proxies=self.proxies, conn=self._conn,
            )

    def init_roots(self):
        """
        Initializes the api roots (used to get taxii server objects)
        """
        if not self.server:
            self.init_server()
        try:
            # try TAXII 2.0
            self.api_root = self.server.api_roots[0]  # type: ignore[union-attr, attr-defined]
            # override _conn - api_root isn't initialized with the right _conn
            self.api_root._conn = self._conn  # type: ignore[attr-defined]
        # (TAXIIServiceException, HTTPError) should suffice, but sometimes it raises another type of HTTPError
        except Exception as e:
            if "406 Client Error" not in str(e):
                raise e
            # switch to TAXII 2.1
            self.init_server(version=TAXII_VER_2_1)
            self.api_root = self.server.api_roots[0]  # type: ignore[union-attr, attr-defined]
            # override _conn - api_root isn't initialized with the right _conn
            self.api_root._conn = self._conn  # type: ignore[attr-defined]

    def init_collections(self):
        """
        Collects available taxii collections
        """
        self.collections = [x for x in self.api_root.collections]  # type: ignore[union-attr, attr-defined, assignment]

    def init_collection_to_fetch(self, collection_to_fetch=None):
        """
        Tries to initialize `collection_to_fetch` if possible
        """
        if collection_to_fetch is None and isinstance(self.collection_to_fetch, str):
            # self.collection_to_fetch will be changed from str -> Union[v20.Collection, v21.Collection]
            collection_to_fetch = self.collection_to_fetch
        if not self.collections:
            raise DemistoException(ERR_NO_COLL)
        if collection_to_fetch:
            collection_found = False
            for collection in self.collections:
                if collection.title == collection_to_fetch:
                    self.collection_to_fetch = collection
                    collection_found = True
                    break
            if not collection_found:
                raise DemistoException(
                    "Could not find the provided Collection name in the available collections. "
                    "Please make sure you entered the name correctly."
                )

    def initialise(self):
        self.init_server()
        self.init_roots()
        self.init_collections()
        self.init_collection_to_fetch()

    @staticmethod
    def get_indicator_publication(indicator):

        """
        Build publications grid field from the indicator external_references field

        Args:
            indicator: The indicator with publication field

        Returns:
            list. publications grid field
        """
        publications = []
        for external_reference in indicator.get('external_references', []):
            if external_reference.get('external_id'):
                continue
            url = external_reference.get('url', '')
            description = external_reference.get('description', '')
            source_name = external_reference.get('source_name', '')
            publications.append({'link': url, 'title': description, 'source': source_name})
        return publications

    @staticmethod
    def get_attack_id_and_value_from_name(attack_indicator):

        """
        Split indicator name into MITRE ID and indicator value: 'T1108: Redundant Access' -> MITRE ID = T1108,
        indicator value = 'Redundant Access'.
        """
        ind_name = attack_indicator.get('name')
        idx = ind_name.index(':')
        ind_id = ind_name[:idx]
        value = ind_name[idx + 2:]

        if attack_indicator.get('x_mitre_is_subtechnique'):
            value = attack_indicator.get('x_panw_parent_technique_subtechnique')

        return ind_id, value

    @staticmethod
    def handle_multiple_dates_in_one_field(field_name: str, field_value: Any):
        """Parses datetime fields to handle one value or more

        Args:
            field_name (str): The field name that holds the data (created/modified).
            field_value (str): Raw value returned from feed.

        Returns:
            str. One datetime value (min/max) according to the field name.
        """
        dates_as_string = field_value.splitlines()
        dates_as_datetime = [datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ') for date in dates_as_string]

        if field_name == 'created':
            return f"{min(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"
        else:
            return f"{max(dates_as_datetime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"

    @staticmethod
    def change_attack_pattern_to_stix_attack_pattern(indicator: dict):
        kill_chain_phases = indicator['fields']['killchainphases']
        del indicator['fields']['killchainphases']
        description = indicator['fields']['description']
        del indicator['fields']['description']

        indicator_type = indicator['type']
        indicator['type'] = f'STIX {indicator_type}'
        indicator['fields']['stixkillchainphases'] = kill_chain_phases
        indicator['fields']['stixdescription'] = description

        return indicator

    @staticmethod
    def is_sub_report(report_obj):
        obj_refs = report_obj.get('object_refs', [])
        for obj_ref in obj_refs:
            if obj_ref.startswith('report--'):
                return False
        return True

    @staticmethod
    def get_ioc_type(indicator, id_to_object):
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

    """ PARSING FUNVTIONS"""

    def parse_indicator(self, indicator_obj: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Parses a single indicator object
        :param indicator_obj: indicator object
        :return: indicators extracted from the indicator object in cortex format
        """
        field_map = self.field_map if self.field_map else {}
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

        return indicators

    def parse_attack_pattern(self, attack_pattern_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single attack pattern object
        :param attack_pattern_obj: attack pattern object
        :return: attack pattern extracted from the attack pattern object in cortex format
        """
        publications = self.get_indicator_publication(attack_pattern_obj)
        mitre_id, value = self.get_attack_id_and_value_from_name(attack_pattern_obj)

        kill_chain_mitre = [chain.get('phase_name', '') for chain in attack_pattern_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        attack_pattern = {
            "value": value,
            "type": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
            "rawJSON": attack_pattern_obj,
            "fields": {
                'stixid': attack_pattern_obj.get('id'),
                "killchainphases": kill_chain_phases,
                "firstseen": self.handle_multiple_dates_in_one_field('created', attack_pattern_obj.get('created')),
                "modified": self.handle_multiple_dates_in_one_field('modified', attack_pattern_obj.get('modified')),
                'description': attack_pattern_obj.get('description', ''),
                'operatingsystemrefs': attack_pattern_obj.get('x_mitre_platforms'),
                "publications": publications,
                "mitreid": mitre_id,
                "reportedby": 'Unit42',
                "tags": [tag for tag in list(self.tags)],
            }
        }
        attack_pattern['fields']['tags'].extend([mitre_id])
        if self.tlp_color:
            attack_pattern['fields']['trafficlightprotocol'] = self.tlp_color

        if not is_demisto_version_ge('6.2.0'):
            # For versions less than 6.2 - that only support STIX and not the newer types - Malware, Tool, etc.
            attack_pattern = self.change_attack_pattern_to_stix_attack_pattern(attack_pattern)

        return [attack_pattern]

    def parse_report(self, report_obj):
        """
        Parses a single report object
        :param report_obj: report object
        :return: report extracted from the report object in cortex format
        """
        if self.is_sub_report(report_obj):
            return []

        report = {
            "type": ThreatIntel.ObjectsNames.REPORT,
            "value": report_obj.get('name'),
            "score": ThreatIntel.ObjectsScore.REPORT,
            "rawJSON": report_obj
        }
        fields = {
            'stixid': report_obj.get('id'),
            'firstseen': report_obj.get('created'),
            'published': report_obj.get('published'),
            'description': report_obj.get('description', ''),
            "report_types": report_obj.get('report_types', []),
            "reportedby": 'Unit42',
            "tags": list((set(report_obj.get('labels'))).union(set(self.tags))),
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        report["fields"] = fields

        return [report]

    def parse_threat_actor(self, threat_actor_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single threat actor object
        :param threat_actor_obj: report object
        :return: threat actor extracted from the threat actor object in cortex format
        """

        threat_actor = {
            "value": threat_actor_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.THREAT_ACTOR,
            "score": ThreatIntel.ObjectsScore.THREAT_ACTOR,
            "rawJSON": threat_actor_obj
        }
        fields = {
            'stixid': threat_actor_obj.get('id'),
            "firstseen": self.handle_multiple_dates_in_one_field('created', threat_actor_obj.get('created')),
            "modified": self.handle_multiple_dates_in_one_field('modified', threat_actor_obj.get('modified')),
            'description': threat_actor_obj.get('description', ''),
            'aliases': threat_actor_obj.get("aliases", []),
            "threat_actor_types": threat_actor_obj.get('threat_actor_types', []),
            'roles': threat_actor_obj.get("roles", []),
            'goals': threat_actor_obj.get("goals", []),
            'sophistication': threat_actor_obj.get("sophistication", ''),
            "resource_level": threat_actor_obj.get('resource_level', ''),
            "primary_motivation": threat_actor_obj.get('primary_motivation', ''),
            "secondary_motivations": threat_actor_obj.get('secondary_motivations', []),
            "reportedby": 'Unit42',
            "tags": list((set(threat_actor_obj.get('labels', []))).union(set(self.tags))),
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        threat_actor["fields"] = fields

        return [threat_actor]

    def parse_infrastructure(self, infrastructure_obj):
        """
        Parses a single infrastructure object
        :param infrastructure_obj: infrastructure object
        :return: infrastructure extracted from the infrastructure object in cortex format
        """
        kill_chain_mitre = [chain.get('phase_name', '') for chain in infrastructure_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        infrastructure = {
            "value": infrastructure_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
            "score": ThreatIntel.ObjectsScore.INFRASTRUCTURE,
            "rawJSON": infrastructure_obj

        }
        fields = {
            "stixid": infrastructure_obj.get('id'),
            "description": infrastructure_obj.get('description', ''),
            "infrastructure_types": infrastructure_obj.get("infrastructure_types", []),
            "aliases": infrastructure_obj.get('aliases', []),
            "kill_chain_phases": kill_chain_phases,
            "firstseen": self.handle_multiple_dates_in_one_field('created', infrastructure_obj.get('created')),
            "modified": self.handle_multiple_dates_in_one_field('modified', infrastructure_obj.get('modified')),
            "reportedby": 'Unit42',
            "tags": list(set(self.tags))
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        infrastructure["fields"] = fields
        return [infrastructure]

    def parse_malware(self, malware_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single malware object
        :param malware_obj: malware object
        :return: malware extracted from the malware object in cortex format
        """

        kill_chain_mitre = [chain.get('phase_name', '') for chain in malware_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        malware = {
            "value": malware_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.MALWARE,
            "score": ThreatIntel.ObjectsScore.MALWARE,
            "rawJSON": malware_obj
        }
        fields = {
            'stixid': malware_obj.get('id'),
            "firstseen": malware_obj.get('created'),
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
            "reportedby": 'Unit42',
            "tags": list((set(malware_obj.get('labels', []))).union(set(self.tags)))
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        malware["fields"] = fields
        return [malware]

    def parse_tool(self, tool_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single tool object
        :param tool_obj: tool object
        :return: tool extracted from the tool object in cortex format
        """
        kill_chain_mitre = [chain.get('phase_name', '') for chain in tool_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        tool = {
            "value": tool_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.TOOL,
            "score": ThreatIntel.ObjectsScore.TOOL,
            "rawJSON": tool_obj
        }
        fields = {
            'stixid': tool_obj.get('id'),
            "killchainphases": kill_chain_phases,
            "firstseen": self.handle_multiple_dates_in_one_field('created', tool_obj.get('created')),
            "modified": self.handle_multiple_dates_in_one_field('modified', tool_obj.get('modified')),
            "tool_types": tool_obj.get("tool_types", []),
            "description": tool_obj.get('description', ''),
            "aliases": tool_obj.get('aliases', []),
            "tool_version": tool_obj.get('tool_version', ''),
            "reportedby": 'Unit42',
            "tags": list(set(self.tags))
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        tool["fields"] = fields
        return [tool]

    def parse_course_of_action(self, coa_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single course of action object
        :param coa_obj: course of action object
        :return: course of action extracted from the course of action object in cortex format
        """
        publications = self.get_indicator_publication(coa_obj)

        course_of_action = {
            "value": coa_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
            "score": ThreatIntel.ObjectsScore.COURSE_OF_ACTION,
            "rawJSON": coa_obj,
        }
        fields = {
            'stixid': coa_obj.get('id'),
            "firstseen": self.handle_multiple_dates_in_one_field('created', coa_obj.get('created')),
            "modified": self.handle_multiple_dates_in_one_field('modified', coa_obj.get('modified')),
            'description': coa_obj.get('description', ''),
            "action_type": coa_obj.get('action_type', ''),
            "publications": publications,
            "reportedby": 'Unit42',
            "tags": [tag for tag in self.tags]
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        course_of_action["fields"] = fields
        return [course_of_action]

    def parse_campaign(self, campaign_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single campaign object
        :param campaign_obj: campaign object
        :return: campaign extracted from the campaign object in cortex format
        """
        campaign = {
            "value": campaign_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.CAMPAIGN,
            "score": ThreatIntel.ObjectsScore.CAMPAIGN,
            "rawJSON": campaign_obj
        }
        fields = {
            'stixid': campaign_obj.get('id'),
            "firstseen": campaign_obj.get('created'),
            "modified": campaign_obj.get('modified'),
            'description': campaign_obj.get('description', ''),
            "aliases": campaign_obj.get('aliases', []),
            "objective": campaign_obj.get('objective', ''),
            "reportedby": 'Unit42',
            "tags": [tag for tag in self.tags],
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        campaign["fields"] = fields
        return [campaign]

    def parse_intrusion_set(self, intrusion_set_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single intrusion set object
        :param intrusion_set_obj: intrusion set object
        :return: intrusion set extracted from the intrusion set object in cortex format
        """
        publications = self.get_indicator_publication(intrusion_set_obj)

        intrusion_set = {
            "value": intrusion_set_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.INTRUSION_SET,
            "score": ThreatIntel.ObjectsScore.INTRUSION_SET,
            "rawJSON": intrusion_set_obj
        }
        fields = {
            'stixid': intrusion_set_obj.get('id'),
            "firstseen": self.handle_multiple_dates_in_one_field('created', intrusion_set_obj.get('created')),
            "modified": self.handle_multiple_dates_in_one_field('modified', intrusion_set_obj.get('modified')),
            'description': intrusion_set_obj.get('description', ''),
            "aliases": intrusion_set_obj.get('aliases', []),
            "goals": intrusion_set_obj.get('goals', []),
            "resource_level": intrusion_set_obj.get('resource_level', ''),
            "primary_motivation": intrusion_set_obj.get('primary_motivation', ''),
            "secondary_motivations": intrusion_set_obj.get('secondary_motivations', []),
            "publications": publications,
            "reportedby": 'Unit42',
            "tags": [tag for tag in self.tags],
        }
        if self.tlp_color:
            fields['trafficlightprotocol'] = self.tlp_color
        intrusion_set["fields"] = fields
        return [intrusion_set]

    def parse_relationships(self):
        """Parse the Relationships objects retrieved from the feed.

        Returns:
            A list of processed relationships.
        """
        relationships_list = []
        for relationships_object in self.objects_data.get('relationship', []):
            relationship_type = relationships_object.get('relationship_type')
            if relationship_type not in EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys():
                if relationship_type == 'indicates':
                    relationship_type = 'indicated-by'
                else:
                    demisto.debug(f"Invalid relation type: {relationship_type}")
                    continue

            a_threat_intel_type = relationships_object.get('source_ref').split('--')[0]
            a_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(a_threat_intel_type, '')  # type: ignore
            if a_threat_intel_type == 'indicator':
                id = relationships_object.get('source_ref')
                a_type = self.get_ioc_type(id, self.id_to_object)

            b_threat_intel_type = relationships_object.get('target_ref').split('--')[0]
            b_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(b_threat_intel_type, '')  # type: ignore
            if b_threat_intel_type == 'indicator':
                b_type = self.get_ioc_type(relationships_object.get('target_ref'), self.id_to_object)

            if not a_type or not b_type:
                continue

            mapping_fields = {
                'lastseenbysource': relationships_object.get('modified'),
                'firstseenbysource': relationships_object.get('created')
            }

            entity_a = self.get_ioc_value(relationships_object.get('source_ref'), self.id_to_object)
            entity_b = self.get_ioc_value(relationships_object.get('target_ref'), self.id_to_object)

            entity_relation = EntityRelationship(name=relationship_type,
                                                 entity_a=entity_a,
                                                 entity_a_type=a_type,
                                                 entity_b=entity_b,
                                                 entity_b_type=b_type,
                                                 fields=mapping_fields)
            relationships_list.append(entity_relation.to_indicator())

        return relationships_list

    def build_iterator(self, limit: int = -1, **kwargs) -> List[Dict[str, str]]:
        """
        Polls the taxii server and builds a list of cortex indicators objects from the result
        :param limit: max amount of indicators to fetch
        :return: Cortex indicators list
        """

        if not isinstance(self.collection_to_fetch, (v20.Collection, v21.Collection)):
            raise DemistoException(
                "Could not find a collection to fetch from. "
                "Please make sure you provided a collection."
            )
        if limit is None:
            limit = -1

        page_size = self.get_page_size(limit, limit)
        if page_size <= 0:
            return []
        envelope = self.poll_collection(page_size, **kwargs)  # got data from server for all objects
        self.extract_stix_objects_from_envelope(envelope, limit)  # sorted objects in client class
        indicators = self.parse_stix_objects(limit)

        # indicators = self.extract_indicators_from_envelope_and_parse(envelope, limit)
        return indicators

    def extract_stix_objects_from_envelope(self, envelope: Union[types.GeneratorType, Dict[str, str]], limit: int = -1):

        objects_types = ['report', 'indicator', 'malware', 'campaign', 'attack-pattern',
                         'course-of-action', 'intrusion-set', 'tool', 'threat-actor', 'infrastructure', 'relationship']
        self.objects_data = {obj_type: [] for obj_type in objects_types}

        # TAXII 2.0
        if isinstance(envelope, types.GeneratorType):
            for sub_envelope in envelope:
                stix_objects = sub_envelope.get("objects")
                if not stix_objects:
                    # no fetched objects
                    break
                for obj in stix_objects:
                    if obj.get('type') in objects_types:
                        self.objects_data[obj.get('type', 'other')].append(obj)
                    self.id_to_object[obj.get('id')] = obj

        # TAXII 2.1
        elif isinstance(envelope, Dict):
            cur_limit = limit
            stix_objects = envelope.get("objects")
            for obj in stix_objects:
                if obj.get('type') in objects_types:
                    self.objects_data[obj.get('type', 'other')].append(obj)
                self.id_to_object[obj.get('id')] = obj

            # indicators = self.parse_indicators_list(stix_objects)
            while envelope.get("more", False):
                page_size = self.get_page_size(limit, cur_limit)
                envelope = self.collection_to_fetch.get_objects(
                    limit=page_size, next=envelope.get("next", "")
                )
                if isinstance(envelope, Dict):
                    stix_objects = envelope.get("objects")
                    for obj in stix_objects:
                        if obj.get('type') in objects_types:
                            self.objects_data[obj.get('type', 'other')].append(obj)
                        self.id_to_object[obj.get('id')] = obj
                else:
                    raise DemistoException(
                        "Error: TAXII 2 client received the following response while requesting "
                        f"indicators: {str(envelope)}\n\nExpected output is json"
                    )

    def parse_stix_objects(self, limit: int = -1):
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
            "infrastructure": self.parse_infrastructure
        }
        indicators = []
        for obj_type in parse_stix_2_objects.keys():
            stix_object_list = self.objects_data.get(obj_type, [])
            if stix_object_list:
                for obj in stix_object_list:
                    result = parse_stix_2_objects[obj_type](obj)
                    if not result:
                        continue
                    indicators.extend(result)
                    indicator_modified_str = obj.get("modified")
                    if self.last_fetched_indicator__modified is None:
                        self.last_fetched_indicator__modified = indicator_modified_str  # type: ignore[assignment]
                    else:
                        last_datetime = self.stix_time_to_datetime(
                            self.last_fetched_indicator__modified
                        )
                        indicator_created_datetime = self.stix_time_to_datetime(
                            indicator_modified_str
                        )
                        if indicator_created_datetime > last_datetime:
                            self.last_fetched_indicator__modified = indicator_modified_str

        if self.objects_data.get('relationship'):
            relationship_lst = self.parse_relationships()

            dummy_indicator = {
                "value": "$$DummyIndicator$$",
                "relationships": relationship_lst
            }

            if dummy_indicator:
                indicators.append(dummy_indicator)
        demisto.debug(
            f"TAXII 2 Feed has extracted {len(indicators)} indicators"
        )
        if limit > -1:
            return indicators[:limit]
        return indicators

    def poll_collection(
            self, page_size: int, **kwargs
    ) -> Union[types.GeneratorType, Dict[str, str]]:
        """
        Polls a taxii collection
        :param page_size: size of the request page
        """
        get_objects = self.collection_to_fetch.get_objects
        if isinstance(self.collection_to_fetch, v20.Collection):
            envelope = v20.as_pages(get_objects, per_request=page_size, **kwargs)
        else:
            envelope = get_objects(limit=page_size, **kwargs)
        return envelope

    def get_page_size(self, max_limit: int, cur_limit: int) -> int:
        """
        Get a page size given the limit on entries `max_limit` and the limit on the current poll
        :param max_limit: max amount of entries allowed overall
        :param cur_limit: max amount of entries allowed in a page
        :return: page size
        """
        return (
            min(self.limit_per_request, cur_limit)
            if max_limit > -1
            else self.limit_per_request
        )

    @staticmethod
    def extract_indicators_from_stix_objects(
            stix_objs: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Extracts indicators from taxii objects
        :param stix_objs: taxii objects
        :return: indicators in json format
        """
        indicators_objs = [
            item for item in stix_objs if item.get("type") == "malware"
        ]  # retrieve only required type

        return indicators_objs

    def get_indicators_from_indicator_groups(
            self,
            indicator_groups: List[Tuple[str, str]],
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
                        indicator = self.create_indicator(
                            indicator_obj, type_, value, field_map
                        )
                        indicators.append(indicator)
                        break
        if self.skip_complex_mode and len(indicators) > 1:
            # we managed to pull more than a single indicator - indicating complex relationship
            return []
        return indicators

    def create_indicator(self, indicator_obj, type_, value, field_map):
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
            "type": type_,
            "rawJSON": ioc_obj_copy,
        }
        fields = {}
        tags = list(self.tags)
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

        if self.tlp_color:
            fields["trafficlightprotocol"] = self.tlp_color

        indicator["fields"] = fields
        return indicator

    @staticmethod
    def extract_indicator_groups_from_pattern(
            pattern: str, regexes: List
    ) -> List[Tuple[str, str]]:
        """
        Extracts indicator [`type`, `indicator`] groups from pattern
        :param pattern: stix pattern
        :param regexes: regexes to run to pattern
        :return: extracted indicators list from pattern
        """
        groups: List[Tuple[str, str]] = []
        for regex in regexes:
            find_result = regex.findall(pattern)
            if find_result:
                groups.extend(find_result)
        return groups

    @staticmethod
    def stix_time_to_datetime(s_time):
        """
        Converts datetime to str in "%Y-%m-%dT%H:%M:%S.%fZ" format
        :param s_time: time in string format
        :return: datetime
        """
        try:
            return datetime.strptime(s_time, TAXII_TIME_FORMAT)
        except ValueError:
            return datetime.strptime(s_time, TAXII_TIME_FORMAT_NO_MS)

    @staticmethod
    def get_ioc_value(ioc, id_to_obj):
        """
        Get IOC value from the indicator name field.

        Args:
            ioc: the indicator to get information on.
            id_to_obj: a dict in the form of - id: stix_object.

        Returns:
            str. the IOC value. if its reports we add to it [Unit42 ATOM] prefix,
            if its attack pattern remove the id from the name.
        """
        ioc_obj = id_to_obj.get(ioc)
        if ioc_obj:
            if ioc_obj.get('type') == 'report':
                return f"[Unit42 ATOM] {ioc_obj.get('name')}"
            elif ioc_obj.get('type') == 'attack-pattern':
                _, value = Taxii2FeedClient.get_attack_id_and_value_from_name(ioc_obj)
                return value
            elif "file:hashes.'SHA-256' = '" in ioc_obj.get('name'):
                return Taxii2FeedClient.get_ioc_value_from_ioc_name(ioc_obj)
            else:
                return ioc_obj.get('name')

    @staticmethod
    def get_ioc_value_from_ioc_name(ioc_obj):
        """
        Extract SHA-256 from string:
        ([file:name = 'blabla' OR file:name = 'blabla'] AND [file:hashes.'SHA-256' = '1111'])" -> 1111
        """
        ioc_value = ioc_obj.get('name', '')
        try:
            ioc_value_groups = re.search("(?<='SHA-256' = ').*?(?=')", ioc_value)
            if ioc_value_groups:
                ioc_value = ioc_value_groups.group(0)
        except AttributeError:
            ioc_value = None
        return ioc_value
