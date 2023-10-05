import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=E9010, E9011
from CommonServerUserPython import *

from typing import Optional, Tuple
from requests.sessions import merge_setting, CaseInsensitiveDict
import re
import copy
import types
import urllib3
from taxii2client import v20, v21
from taxii2client.common import TokenAuth, _HTTPConnection
from taxii2client.exceptions import InvalidJSONError
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
    "sha-512": FeedIndicatorType.File,
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
    "identity": FeedIndicatorType.Identity,
    "location": FeedIndicatorType.Location,
    "vulnerability": FeedIndicatorType.CVE,
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

# marking definitions of TLPs are constant (marking definitions of statements can vary)
MARKING_DEFINITION_TO_TLP = {'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9': 'WHITE',
                             'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da': 'GREEN',
                             'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82': 'AMBER',
                             'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed': 'RED'}

# country codes are in ISO-2 format
COUNTRY_CODES_TO_NAMES = {'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
                          'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
                          'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
                          'AX': 'Aland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
                          'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
                          'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthelemy', 'BM': 'Bermuda', 'BN': 'Brunei',
                          'BO': 'Bolivia', 'BQ': 'Bonaire, Saint Eustatius and Saba ', 'BR': 'Brazil', 'BS': 'Bahamas',
                          'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
                          'CA': 'Canada', 'CC': 'Cocos Islands', 'CD': 'Democratic Republic of the Congo',
                          'CF': 'Central African Republic', 'CG': 'Republic of the Congo', 'CH': 'Switzerland',
                          'CI': 'Ivory Coast', 'CK': 'Cook Islands', 'CL': 'Chile', 'CM': 'Cameroon', 'CN': 'China',
                          'CO': 'Colombia', 'CR': 'Costa Rica', 'CU': 'Cuba', 'CV': 'Cape Verde', 'CW': 'Curacao',
                          'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czech Republic', 'DE': 'Germany', 'DJ': 'Djibouti',
                          'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic', 'DZ': 'Algeria', 'EC': 'Ecuador',
                          'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara', 'ER': 'Eritrea', 'ES': 'Spain',
                          'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji', 'FK': 'Falkland Islands', 'FM': 'Micronesia',
                          'FO': 'Faroe Islands', 'FR': 'France', 'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada',
                          'GE': 'Georgia', 'GF': 'French Guiana', 'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar',
                          'GL': 'Greenland', 'GM': 'Gambia', 'GN': 'Guinea', 'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea',
                          'GR': 'Greece', 'GS': 'South Georgia and the South Sandwich Islands', 'GT': 'Guatemala', 'GU': 'Guam',
                          'GW': 'Guinea-Bissau', 'GY': 'Guyana', 'HK': 'Hong Kong', 'HM': 'Heard Island and McDonald Islands',
                          'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti', 'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland',
                          'IL': 'Israel', 'IM': 'Isle of Man', 'IN': 'India', 'IO': 'British Indian Ocean Territory',
                          'IQ': 'Iraq', 'IR': 'Iran', 'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica',
                          'JO': 'Jordan', 'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
                          'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
                          'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
                          'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia', 'LS': 'Lesotho',
                          'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya', 'MA': 'Morocco', 'MC': 'Monaco',
                          'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin', 'MG': 'Madagascar', 'MH': 'Marshall Islands',
                          'MK': 'Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia', 'MO': 'Macao',
                          'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania', 'MS': 'Montserrat',
                          'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi', 'MX': 'Mexico', 'MY': 'Malaysia',
                          'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia', 'NE': 'Niger', 'NF': 'Norfolk Island',
                          'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands', 'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru',
                          'NU': 'Niue', 'NZ': 'New Zealand', 'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia',
                          'PG': 'Papua New Guinea', 'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland',
                          'PM': 'Saint Pierre and Miquelon', 'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestinian Territory',
                          'PT': 'Portugal', 'PW': 'Palau', 'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Reunion', 'RO': 'Romania',
                          'RS': 'Serbia', 'RU': 'Russia', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SB': 'Solomon Islands',
                          'SC': 'Seychelles', 'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore', 'SH': 'Saint Helena',
                          'SI': 'Slovenia', 'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone',
                          'SM': 'San Marino', 'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan',
                          'ST': 'Sao Tome and Principe', 'SV': 'El Salvador', 'SX': 'Sint Maarten', 'SY': 'Syria',
                          'SZ': 'Swaziland', 'TC': 'Turks and Caicos Islands', 'TD': 'Chad', 'TF': 'French Southern Territories',
                          'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan', 'TK': 'Tokelau', 'TL': 'East Timor',
                          'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga', 'TR': 'Turkey', 'TT': 'Trinidad and Tobago',
                          'TV': 'Tuvalu', 'TW': 'Taiwan', 'TZ': 'Tanzania', 'UA': 'Ukraine', 'UG': 'Uganda',
                          'UM': 'United States Minor Outlying Islands', 'US': 'United States', 'UY': 'Uruguay',
                          'UZ': 'Uzbekistan', 'VA': 'Vatican', 'VC': 'Saint Vincent and the Grenadines', 'VE': 'Venezuela',
                          'VG': 'British Virgin Islands', 'VI': 'U.S. Virgin Islands', 'VN': 'Vietnam', 'VU': 'Vanuatu',
                          'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'XK': 'Kosovo', 'YE': 'Yemen', 'YT': 'Mayotte',
                          'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'}


def reached_limit(limit: int, element_count: int):
    return element_count >= limit > -1


class Taxii2FeedClient:
    def __init__(
            self,
            url: str,
            collection_to_fetch,
            proxies,
            verify: bool,
            objects_to_fetch: list[str],
            skip_complex_mode: bool = False,
            username: Optional[str] = None,
            password: Optional[str] = None,
            field_map: Optional[dict] = None,
            tags: Optional[list] = None,
            tlp_color: Optional[str] = None,
            limit_per_request: int = DFLT_LIMIT_PER_REQUEST,
            certificate: str = None,
            key: str = None,
            default_api_root: str = None,
            update_custom_fields: bool = False
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
        :param certificate: TLS Certificate
        :param key: TLS Certificate key
        :param default_api_root: The default API Root to use
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

        if (certificate and not key) or (not certificate and key):
            raise DemistoException('Both certificate and key should be provided or neither should be.')
        if certificate and key:
            self.crt = (self.build_certificate(certificate), self.build_certificate(key))

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
        self.id_to_object: dict[str, Any] = {}
        self.objects_to_fetch = objects_to_fetch
        self.default_api_root = default_api_root
        self.update_custom_fields = update_custom_fields

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
            self._conn.session.headers = merge_setting(self._conn.session.headers,    # type: ignore[attr-defined]
                                                       {self.auth_header: self.auth_key},
                                                       dict_class=CaseInsensitiveDict)

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
            # disable logging as we might receive client error and try 2.1
            logging.disable(logging.ERROR)
            # try TAXII 2.0
            self.set_api_root()
        # (TAXIIServiceException, HTTPError) should suffice, but sometimes it raises another type of HTTPError
        except Exception as e:
            if "406 Client Error" not in str(e) and "version=2.1" not in str(e):
                raise e
            # switch to TAXII 2.1
            self.init_server(version=TAXII_VER_2_1)
            self.set_api_root()
        finally:
            # enable logging
            logging.disable(logging.NOTSET)

    def set_api_root(self):
        roots_to_api = {}
        for api_root in self.server.api_roots:  # type: ignore[attr-defined]
            # ApiRoots are initialized with wrong _conn because we are not providing auth or cert to Server
            # closing wrong unused connections
            api_root_name = str(api_root.url).split('/')[-2]
            demisto.debug(f'closing api_root._conn for {api_root_name}')
            api_root._conn.close()
            roots_to_api[api_root_name] = api_root

        if self.default_api_root:
            if not roots_to_api.get(self.default_api_root):
                raise DemistoException(f'The given default API root {self.default_api_root} doesn\'t exist. '
                                       f'Available API roots are {list(roots_to_api.keys())}.')
            self.api_root = roots_to_api.get(self.default_api_root)

        elif server_default := self.server.default:  # type: ignore[attr-defined]
            self.api_root = server_default

        else:
            self.api_root = self.server.api_roots[0]  # type: ignore[attr-defined]

        # override _conn - api_root isn't initialized with the right _conn
        self.api_root._conn = self._conn  # type: ignore[union-attr]

    def init_collections(self):
        """
        Collects available taxii collections
        """
        self.collections = list(self.api_root.collections)  # type: ignore[union-attr, attr-defined, assignment]

    def init_collection_to_fetch(self, collection_to_fetch=None):
        """
        Tries to initialize `collection_to_fetch` if possible
        """
        if not collection_to_fetch and isinstance(self.collection_to_fetch, str):
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
    def build_certificate(cert_var):
        var_list = cert_var.split('-----')
        # replace spaces with newline characters
        certificate_fixed = '-----'.join(
            var_list[:2] + [var_list[2].replace(' ', '\n')] + var_list[3:])
        cf = tempfile.NamedTemporaryFile(delete=False)
        cf.write(certificate_fixed.encode())
        cf.flush()
        return cf.name

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
        for external_reference in indicator.get('external_references', []):
            url = external_reference.get('url', '')
            description = external_reference.get('description', '')
            source_name = external_reference.get('source_name', '')
            publications.append({'link': url, 'title': description, 'source': source_name})
        return publications

    @staticmethod
    def change_attack_pattern_to_stix_attack_pattern(indicator: dict[str, Any]):
        indicator['type'] = f'STIX {indicator["type"]}'
        indicator['fields']['stixkillchainphases'] = indicator['fields'].pop('killchainphases', None)
        indicator['fields']['stixdescription'] = indicator['fields'].pop('description', None)

        return indicator

    @staticmethod
    def parse_report_relationships(report_obj: dict[str, Any],
                                   id_to_object: dict[str, dict[str, Any]]) -> Tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        obj_refs = report_obj.get('object_refs', [])
        relationships: list[dict[str, Any]] = []
        obj_refs_excluding_relationships_prefix = []

        for related_obj in obj_refs:
            # relationship-- objects ref handled in parse_relationships
            if not related_obj.startswith('relationship--'):
                obj_refs_excluding_relationships_prefix.append(related_obj)
                if (entity_b_obj := id_to_object.get(related_obj, {})):
                    entity_b_type = STIX_2_TYPES_TO_CORTEX_TYPES.get(entity_b_obj.get('type', ''), '')
                    relationships.append(
                        EntityRelationship(
                            name='related-to',
                            entity_a=report_obj.get('name'),
                            entity_a_type=ThreatIntel.ObjectsNames.REPORT,
                            entity_b=entity_b_obj.get('name'),
                            entity_b_type=entity_b_type
                        ).to_indicator()
                    )
        return relationships, obj_refs_excluding_relationships_prefix

    @staticmethod
    def get_ioc_type(indicator: str, id_to_object: dict[str, dict[str, Any]]) -> str:
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

    def update_last_modified_indicator_date(self, indicator_modified_str: str):
        if not indicator_modified_str:
            return
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

    """ PARSING FUNCTIONS"""

    @staticmethod
    def get_tlp(indicator_json: dict) -> str:
        object_marking_definition_list = indicator_json.get('object_marking_refs', '')
        tlp_color: str = ''
        for object_marking_definition in object_marking_definition_list:
            if tlp := MARKING_DEFINITION_TO_TLP.get(object_marking_definition):
                tlp_color = tlp
                break
        return tlp_color

    def set_default_fields(self, obj_to_parse):
        fields = {
            'stixid': obj_to_parse.get('id', ''),
            'firstseenbysource': obj_to_parse.get('created', ''),
            'modified': obj_to_parse.get('modified', ''),
            'description': obj_to_parse.get('description', ''),
        }

        tlp_from_marking_refs = self.get_tlp(obj_to_parse)
        tlp_color = tlp_from_marking_refs if tlp_from_marking_refs else self.tlp_color

        if tlp_color:
            fields['trafficlightprotocol'] = tlp_color

        return fields

    @staticmethod
    def parse_custom_fields(extensions):
        custom_fields = {}
        score = None
        for key, value in extensions.items():
            if key.startswith('extension-definition--'):
                custom_fields = value.get('CustomFields', {})
                if not custom_fields:
                    custom_fields = value
                score = value.get('score', None)
                break
        return custom_fields, score

    def parse_indicator(self, indicator_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

    def parse_attack_pattern(self, attack_pattern_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single attack pattern object
        :param attack_pattern_obj: attack pattern object
        :return: attack pattern extracted from the attack pattern object in cortex format
        """
        publications = self.get_indicator_publication(attack_pattern_obj)

        kill_chain_mitre = [chain.get('phase_name', '') for chain in attack_pattern_obj.get('kill_chain_phases', [])]
        kill_chain_phases = [MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS.get(phase) for phase in kill_chain_mitre]

        attack_pattern = {
            "value": attack_pattern_obj.get('name'),
            "type": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
            "rawJSON": attack_pattern_obj,
        }

        fields = self.set_default_fields(attack_pattern_obj)
        fields.update({
            "killchainphases": kill_chain_phases,
            'operatingsystemrefs': attack_pattern_obj.get('x_mitre_platforms'),
            "publications": publications,
        })
        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(attack_pattern_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                attack_pattern['score'] = score
        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))

        attack_pattern["fields"] = fields

        if not is_demisto_version_ge('6.2.0'):
            # For versions less than 6.2 - that only support STIX and not the newer types - Malware, Tool, etc.
            attack_pattern = self.change_attack_pattern_to_stix_attack_pattern(attack_pattern)

        return [attack_pattern]

    def parse_report(self, report_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single report object
        :param report_obj: report object
        :return: report extracted from the report object in cortex format
        """
        report = {
            "type": ThreatIntel.ObjectsNames.REPORT,
            "value": report_obj.get('name'),
            "score": ThreatIntel.ObjectsScore.REPORT,
            "rawJSON": report_obj,
        }

        fields = self.set_default_fields(report_obj)
        fields.update({
            'published': report_obj.get('published'),
            "report_types": report_obj.get('report_types', []),
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(report_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                report['score'] = score

        tags = list((set(report_obj.get('labels', []))).union(set(self.tags)))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))

        relationships, obj_refs_excluding_relationships_prefix = self.parse_report_relationships(report_obj, self.id_to_object)
        report['relationships'] = relationships
        if obj_refs_excluding_relationships_prefix:
            fields['Report Object References'] = [{'objectstixid': object} for object in obj_refs_excluding_relationships_prefix]
        report["fields"] = fields
        return [report]

    def parse_threat_actor(self, threat_actor_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(threat_actor_obj)
        fields.update({
            'aliases': threat_actor_obj.get("aliases", []),
            "threat_actor_types": threat_actor_obj.get('threat_actor_types', []),
            'roles': threat_actor_obj.get("roles", []),
            'goals': threat_actor_obj.get("goals", []),
            'sophistication': threat_actor_obj.get("sophistication", ''),
            "resource_level": threat_actor_obj.get('resource_level', ''),
            "primary_motivation": threat_actor_obj.get('primary_motivation', ''),
            "secondary_motivations": threat_actor_obj.get('secondary_motivations', []),
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(threat_actor_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                threat_actor['score'] = score

        tags = list((set(threat_actor_obj.get('labels', []))).union(set(self.tags)))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))
        threat_actor["fields"] = fields

        return [threat_actor]

    def parse_infrastructure(self, infrastructure_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(infrastructure_obj)
        fields.update({
            "infrastructure_types": infrastructure_obj.get("infrastructure_types", []),
            "aliases": infrastructure_obj.get('aliases', []),
            "kill_chain_phases": kill_chain_phases,
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(infrastructure_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                infrastructure['score'] = score

        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))

        infrastructure["fields"] = fields

        return [infrastructure]

    def parse_malware(self, malware_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(malware_obj)
        fields.update({
            "malware_types": malware_obj.get('malware_types', []),
            "is_family": malware_obj.get('is_family', False),
            "aliases": malware_obj.get('aliases', []),
            "kill_chain_phases": kill_chain_phases,
            "os_execution_envs": malware_obj.get('os_execution_envs', []),
            "architecture_execution_envs": malware_obj.get('architecture_execution_envs', []),
            "capabilities": malware_obj.get('capabilities', []),
            "sample_refs": malware_obj.get('sample_refs', [])
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(malware_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                malware['score'] = score

        tags = list((set(malware_obj.get('labels', []))).union(set(self.tags)))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))

        malware["fields"] = fields

        return [malware]

    def parse_tool(self, tool_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(tool_obj)
        fields.update({
            "killchainphases": kill_chain_phases,
            "tool_types": tool_obj.get("tool_types", []),
            "aliases": tool_obj.get('aliases', []),
            "tool_version": tool_obj.get('tool_version', '')
        })
        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(tool_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                tool['score'] = score

        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))

        tool["fields"] = fields

        return [tool]

    def parse_course_of_action(self, coa_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(coa_obj)
        fields.update({
            "action_type": coa_obj.get('action_type', ''),
            "publications": publications,
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(coa_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                course_of_action['score'] = score

        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))

        course_of_action["fields"] = fields

        return [course_of_action]

    def parse_campaign(self, campaign_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(campaign_obj)
        fields.update({
            "aliases": campaign_obj.get('aliases', []),
            "objective": campaign_obj.get('objective', ''),
        })
        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(campaign_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                campaign['score'] = score
        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))
        campaign["fields"] = fields

        return [campaign]

    def parse_intrusion_set(self, intrusion_set_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        fields = self.set_default_fields(intrusion_set_obj)
        fields.update({
            "aliases": intrusion_set_obj.get('aliases', []),
            "goals": intrusion_set_obj.get('goals', []),
            "resource_level": intrusion_set_obj.get('resource_level', ''),
            "primary_motivation": intrusion_set_obj.get('primary_motivation', ''),
            "secondary_motivations": intrusion_set_obj.get('secondary_motivations', []),
            "publications": publications,
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(intrusion_set_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                intrusion_set['score'] = score
        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))

        intrusion_set["fields"] = fields

        return [intrusion_set]

    def parse_general_sco_indicator(
            self, sco_object: dict[str, Any], value_mapping: str = 'value'
    ) -> list[dict[str, Any]]:
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
            'type': STIX_2_TYPES_TO_CORTEX_TYPES.get(sco_object.get('type'))  # type: ignore[arg-type]
        }

        fields = self.set_default_fields(sco_object)

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(sco_object.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                sco_indicator['score'] = score
        fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))

        sco_indicator['fields'] = fields

        return [sco_indicator]

    def parse_sco_autonomous_system_indicator(self, autonomous_system_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses autonomous_system indicator type to cortex format.

        Args:
            autonomous_system_obj (dict): indicator as an observable object of type autonomous-system.
        """
        autonomous_system_indicator = self.parse_general_sco_indicator(autonomous_system_obj, value_mapping='number')
        autonomous_system_indicator[0]['fields']['name'] = autonomous_system_obj.get('name')

        return autonomous_system_indicator

    def parse_sco_file_indicator(self, file_obj: dict[str, Any]) -> list[dict[str, Any]]:
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

        file_indicator = self.parse_general_sco_indicator(file_obj)
        file_indicator[0]['fields'].update(
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

    def parse_sco_mutex_indicator(self, mutex_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses mutex indicator type to cortex format.

        Args:
            mutex_obj (dict): indicator as an observable object of mutex type.
        """
        return self.parse_general_sco_indicator(sco_object=mutex_obj, value_mapping='name')

    def parse_sco_account_indicator(self, account_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses account indicator type to cortex format.

        Args:
            account_obj (dict): indicator as an observable object of account type.
        """
        account_indicator = self.parse_general_sco_indicator(account_obj, value_mapping='user_id')
        account_indicator[0]['fields'].update(
            {
                'displayname': account_obj.get('user_id'),
                'accounttype': account_obj.get('account_type')
            }
        )
        return account_indicator

    def parse_sco_windows_registry_key_indicator(self, registry_key_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses registry_key indicator type to cortex format.

        Args:
            registry_key_obj (dict): indicator as an observable object of registry_key type.
        """
        registry_key_indicator = self.parse_general_sco_indicator(registry_key_obj, value_mapping='key')
        registry_key_indicator[0]['fields'].update(
            {
                'registryvalue': registry_key_obj.get('values'),
                'modified_time': registry_key_obj.get('modified_time'),
                'number_of_subkeys': registry_key_obj.get('number_of_subkeys')
            }
        )
        return registry_key_indicator

    def parse_identity(self, identity_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single identity object
        :param identity_obj: identity object
        :return: identity extracted from the identity object in cortex format
        """
        identity = {
            'value': identity_obj.get('name'),
            'type': FeedIndicatorType.Identity,
            'score': Common.DBotScore.NONE,
            'rawJSON': identity_obj
        }
        fields = self.set_default_fields(identity_obj)
        fields.update({
            'identityclass': identity_obj.get('identity_class', ''),
            'industrysectors': identity_obj.get('sectors', [])
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(identity_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                identity['score'] = score

        tags = list((set(identity_obj.get('labels', []))).union(set(self.tags)))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))

        identity['fields'] = fields

        return [identity]

    def parse_location(self, location_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single location object
        :param location_obj: location object
        :return: location extracted from the location object in cortex format
        """
        country_name = COUNTRY_CODES_TO_NAMES.get(str(location_obj.get('country', '')).upper(), '')

        location = {
            'value': location_obj.get('name') or country_name,
            'type': FeedIndicatorType.Location,
            'score': Common.DBotScore.NONE,
            'rawJSON': location_obj
        }

        fields = self.set_default_fields(location_obj)
        fields.update({
            'countrycode': location_obj.get('country', ''),
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(location_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                location['score'] = score

        tags = list((set(location_obj.get('labels', []))).union(set(self.tags)))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))

        location['fields'] = fields

        return [location]

    def parse_vulnerability(self, vulnerability_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single vulnerability object
        :param vulnerability_obj: vulnerability object
        :return: vulnerability extracted from the vulnerability object in cortex format
        """
        name = ''
        for external_reference in vulnerability_obj.get('external_references', []):
            if external_reference.get('source_name') == 'cve':
                name = external_reference.get('external_id')
                break

        cve = {
            'value': name,
            'type': FeedIndicatorType.CVE,
            'score': Common.DBotScore.NONE,
            'rawJSON': vulnerability_obj
        }

        fields = self.set_default_fields(vulnerability_obj)

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(vulnerability_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                cve['score'] = score

        tags = list((set(vulnerability_obj.get('labels', []))).union(set(self.tags), {name} if name else {}))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))

        cve['fields'] = fields

        return [cve]

    def parse_relationships(self, relationships_lst: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse the Relationships objects retrieved from the feed.

        Returns:
            A list of processed relationships an indicator object.
        """
        relationships_list = []
        for relationships_object in relationships_lst:
            relationship_type = relationships_object.get('relationship_type')
            if relationship_type not in EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys():
                if relationship_type == 'indicates':
                    relationship_type = 'indicated-by'
                else:
                    demisto.debug(f"Invalid relation type: {relationship_type}")
                    continue

            a_threat_intel_type = relationships_object.get('source_ref', '').split('--')[0]
            a_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(
                a_threat_intel_type, '') or STIX_2_TYPES_TO_CORTEX_TYPES.get(a_threat_intel_type, '')  # type: ignore
            if a_threat_intel_type == 'indicator':
                id = relationships_object.get('source_ref', '')
                a_type = self.get_ioc_type(id, self.id_to_object)

            b_threat_intel_type = relationships_object.get('target_ref', '').split('--')[0]
            b_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(
                b_threat_intel_type, '') or STIX_2_TYPES_TO_CORTEX_TYPES.get(b_threat_intel_type, '')  # type: ignore
            if b_threat_intel_type == 'indicator':
                b_type = self.get_ioc_type(relationships_object.get('target_ref', ''), self.id_to_object)

            if not a_type or not b_type:
                continue

            mapping_fields = {
                'lastseenbysource': relationships_object.get('modified'),
                'firstseenbysource': relationships_object.get('created'),
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

        dummy_indicator = {
            "value": "$$DummyIndicator$$",
            "relationships": relationships_list
        }
        return [dummy_indicator] if dummy_indicator else []

    def build_iterator(self, limit: int = -1, **kwargs) -> list[dict[str, str]]:
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

        try:
            envelopes = self.poll_collection(page_size, **kwargs)  # got data from server
            indicators = self.load_stix_objects_from_envelope(envelopes, limit)
        except InvalidJSONError as e:
            demisto.debug(f'Excepted InvalidJSONError, continuing with empty result.\nError: {e}')
            # raised when the response is empty, because {} is parsed into '筽'
            indicators = []

        return indicators

    def load_stix_objects_from_envelope(self, envelopes: types.GeneratorType, limit: int = -1):

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
            "identity": self.parse_identity,
            "location": self.parse_location,
            "vulnerability": self.parse_vulnerability
        }

        indicators, relationships_lst = self.parse_generator_type_envelope(envelopes, parse_stix_2_objects, limit)
        if relationships_lst:
            indicators.extend(self.parse_relationships(relationships_lst))
        demisto.debug(
            f"TAXII 2 Feed has extracted {len(indicators)} indicators"
        )

        return indicators

    def parse_generator_type_envelope(self, envelopes: types.GeneratorType, parse_objects_func, limit: int = -1):
        indicators = []
        relationships_lst = []
        for envelope in envelopes:
            stix_objects = envelope.get("objects")
            if not stix_objects:
                # no fetched objects
                break

            # we should build the id_to_object dict before iteration as some object reference each other
            self.id_to_object.update(
                {
                    obj.get('id'): obj for obj in stix_objects
                    if obj.get('type') not in ['extension-definition', 'relationship']
                }
            )

            # now we have a list of objects, go over each obj, save id with obj, parse the obj
            for obj in stix_objects:
                obj_type = obj.get('type')

                # we currently don't support extension object
                if obj_type == 'extension-definition':
                    continue
                elif obj_type == 'relationship':
                    relationships_lst.append(obj)
                    continue

                if not parse_objects_func.get(obj_type):
                    demisto.debug(f'There is no parsing function for object type {obj_type}, '
                                  f'available parsing functions are for types: {",".join(parse_objects_func.keys())}.')
                    continue
                if result := parse_objects_func[obj_type](obj):
                    indicators.extend(result)
                    self.update_last_modified_indicator_date(obj.get("modified"))

                if reached_limit(limit, len(indicators)):
                    return indicators, relationships_lst

        return indicators, relationships_lst

    def poll_collection(
            self, page_size: int, **kwargs
    ) -> types.GeneratorType:
        """
        Polls a taxii collection
        :param page_size: size of the request page
        """
        get_objects = self.collection_to_fetch.get_objects
        if self.objects_to_fetch:
            if 'relationship' not in self.objects_to_fetch and \
                    len(self.objects_to_fetch) > 1:  # when fetching one type no need to fetch relationship
                self.objects_to_fetch.append('relationship')
            kwargs['type'] = self.objects_to_fetch
        if isinstance(self.collection_to_fetch, v20.Collection):
            return v20.as_pages(get_objects, per_request=page_size, **kwargs)
        return v21.as_pages(get_objects, per_request=page_size, **kwargs)

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
            stix_objs: list[dict[str, str]], required_objects: list[str]
    ) -> list[dict[str, str]]:
        """
        Extracts indicators from taxii objects
        :param stix_objs: taxii objects
        :return: indicators in json format
        """
        extracted_objs = [
            item for item in stix_objs if item.get("type") in required_objects
        ]  # retrieve only required type

        return extracted_objs

    def get_indicators_from_indicator_groups(
            self,
            indicator_groups: list[tuple[str, str]],
            indicator_obj: dict[str, str],
            indicator_types: dict[str, str],
            field_map: dict[str, str],
    ) -> list[dict[str, str]]:
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
                for taxii_type in indicator_types:
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

        if not fields.get('trafficlightprotocol'):
            tlp_from_marking_refs = self.get_tlp(ioc_obj_copy)
            fields["trafficlightprotocol"] = tlp_from_marking_refs if tlp_from_marking_refs else self.tlp_color

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(ioc_obj_copy.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                indicator['score'] = score

        # union of tags and labels
        if "tags" in fields:
            field_tag = fields.get("tags")
            if isinstance(field_tag, list):
                tags.extend(field_tag)
            else:
                tags.append(field_tag)

        fields["tags"] = list(set(tags))

        indicator["fields"] = fields
        return indicator

    @staticmethod
    def extract_indicator_groups_from_pattern(
            pattern: str, regexes: list
    ) -> list[tuple[str, str]]:
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
            name = ioc_obj.get('name', '') or ioc_obj.get('value', '')
            if "file:hashes.'SHA-256' = '" in name:
                return Taxii2FeedClient.get_ioc_value_from_ioc_name(ioc_obj)
            else:
                return name
        return None

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
