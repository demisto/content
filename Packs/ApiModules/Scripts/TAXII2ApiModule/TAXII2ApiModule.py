import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=E9010, E9011

from typing import Optional, Tuple
from requests.sessions import merge_setting, CaseInsensitiveDict
from requests.exceptions import HTTPError
import re
import copy
import logging
import traceback
import types
import urllib3
from taxii2client import v20, v21
from taxii2client.common import TokenAuth, _HTTPConnection
from taxii2client.exceptions import InvalidJSONError
import tempfile
import uuid
from dateutil.parser import parse
from stix2patterns.pattern import Pattern

# disable insecure warnings
urllib3.disable_warnings()


class XsoarSuppressWarningFilter(logging.Filter):    # pragma: no cover
    def filter(self, record):
        # Suppress all logger records, but send the important ones to demisto logger
        if record.levelno == logging.WARNING:
            demisto.debug(record.getMessage())
        elif record.levelno in [logging.ERROR, logging.CRITICAL]:
            demisto.error(record.getMessage())
        return False


# Make sure we have only one XsoarSuppressWarningFilter
v21_logger = logging.getLogger("taxii2client.v21")
demisto.debug(f'Logging Filters before cleaning: {v21_logger.filters=}')
for current_filter in list(v21_logger.filters):    # pragma: no cover
    if 'XsoarSuppressWarningFilter' in type(current_filter).__name__:
        v21_logger.removeFilter(current_filter)
v21_logger.addFilter(XsoarSuppressWarningFilter())
demisto.debug(f'Logging Filters: {v21_logger.filters=}')

# CONSTANTS
TAXII_VER_2_0 = "2.0"
TAXII_VER_2_1 = "2.1"

DFLT_LIMIT_PER_REQUEST = 100
API_USERNAME = "_api_token_key"
HEADER_USERNAME = "_header:"
ALLOWED_VERSIONS = [TAXII_VER_2_0, TAXII_VER_2_1]
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

STIX_2_TYPES_TO_CORTEX_TYPES = {       # pragma: no cover
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
    "x509-certificate": FeedIndicatorType.X509,
}
STIX_SUPPORTED_TYPES = {
    'url': ('value',),
    'ip': ('value',),
    'domain-name': ('value',),
    'email-addr': ('value',),
    'ipv4-addr': ('value',),
    'ipv6-addr': ('value',),
    'attack-pattern': ('name',),
    'campaign': ('name',),
    'identity': ('name',),
    'infrastructure': ('name',),
    'intrusion-set': ('name',),
    'malware': ('name',),
    'report': ('name',),
    'threat-actor': ('name',),
    'tool': ('name',),
    'vulnerability': ('name',),
    'mutex': ('name',),
    'software': ('name',),
    'autonomous-system': ('number',),
    'file': ('hashes',),
    'user-account': ('user_id',),
    'location': ('name', 'country'),
    'x509-certificate': ('serial_number', 'issuer'),
    'windows-registry-key': ('key', 'values')
}
MITRE_CHAIN_PHASES_TO_DEMISTO_FIELDS = {       # pragma: no cover
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

STIX_2_TYPES_TO_CORTEX_CIDR_TYPES = {          # pragma: no cover
    "ipv4-addr": FeedIndicatorType.CIDR,
    "ipv6-addr": FeedIndicatorType.IPv6CIDR,
}

THREAT_INTEL_TYPE_TO_DEMISTO_TYPES = {         # pragma: no cover
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
COUNTRY_CODES_TO_NAMES = {'AD': 'Andorra', 'AE': 'United Arab Emirates',        # pragma: no cover
                          'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
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


STIX2_TYPES_TO_XSOAR: dict[str, Union[str, tuple[str, ...]]] = {        # pragma: no cover
    'campaign': ThreatIntel.ObjectsNames.CAMPAIGN,
    'attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    'report': ThreatIntel.ObjectsNames.REPORT,
    'malware': ThreatIntel.ObjectsNames.MALWARE,
    'course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    'intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
    'tool': ThreatIntel.ObjectsNames.TOOL,
    'threat-actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
    'infrastructure': ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    'vulnerability': FeedIndicatorType.CVE,
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'domain-name': (FeedIndicatorType.DomainGlob, FeedIndicatorType.Domain),
    'user-account': FeedIndicatorType.Account,
    'email-addr': FeedIndicatorType.Email,
    'url': FeedIndicatorType.URL,
    'file': FeedIndicatorType.File,
    'windows-registry-key': FeedIndicatorType.Registry,
    'indicator': (FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.DomainGlob,
                  FeedIndicatorType.Domain, FeedIndicatorType.Account, FeedIndicatorType.Email,
                  FeedIndicatorType.URL, FeedIndicatorType.File, FeedIndicatorType.Registry),
    'software': FeedIndicatorType.Software,
    'autonomous-system': FeedIndicatorType.AS,
    'x509-certificate': FeedIndicatorType.X509,
}


PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')
XSOAR_TYPES_TO_STIX_SDO = {        # pragma: no cover
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'attack-pattern',
    ThreatIntel.ObjectsNames.CAMPAIGN: 'campaign',
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: 'course-of-action',
    ThreatIntel.ObjectsNames.INFRASTRUCTURE: 'infrastructure',
    ThreatIntel.ObjectsNames.INTRUSION_SET: 'intrusion-set',
    ThreatIntel.ObjectsNames.REPORT: 'report',
    ThreatIntel.ObjectsNames.THREAT_ACTOR: 'threat-actor',
    ThreatIntel.ObjectsNames.TOOL: 'tool',
    ThreatIntel.ObjectsNames.MALWARE: 'malware',
    FeedIndicatorType.CVE: 'vulnerability',
    FeedIndicatorType.Identity: 'identity',
    FeedIndicatorType.Location: 'location'
}

XSOAR_TYPES_TO_STIX_SCO = {         # pragma: no cover
    FeedIndicatorType.CIDR: 'ipv4-addr',
    FeedIndicatorType.DomainGlob: 'domain-name',
    FeedIndicatorType.IPv6: 'ipv6-addr',
    FeedIndicatorType.IPv6CIDR: 'ipv6-addr',
    FeedIndicatorType.Account: 'user-account',
    FeedIndicatorType.Domain: 'domain-name',
    FeedIndicatorType.Email: 'email-addr',
    FeedIndicatorType.IP: 'ipv4-addr',
    FeedIndicatorType.Registry: 'windows-registry-key',
    FeedIndicatorType.File: 'file',
    FeedIndicatorType.URL: 'url',
    FeedIndicatorType.Software: 'software',
    FeedIndicatorType.AS: 'autonomous-system',
    FeedIndicatorType.X509: 'x509-certificate',
}

HASH_TYPE_TO_STIX_HASH_TYPE = {         # pragma: no cover
    'md5': 'MD5',
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha512': 'SHA-512',
}

STIX_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
SCO_DET_ID_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')


def reached_limit(limit: int, element_count: int):
    return element_count >= limit > -1


PatternComparisons = dict[str, list[tuple[list[str], str, str]]]


class XSOAR2STIXParser:

    def __init__(self, namespace_uuid, fields_to_present,
                 types_for_indicator_sdo, server_version=TAXII_VER_2_1):
        self.server_version = server_version
        if server_version not in ALLOWED_VERSIONS:
            raise Exception(f'Wrong TAXII 2 Server version: {server_version}. '
                            f'Possible values: {", ".join(ALLOWED_VERSIONS)}.')
        self.namespace_uuid = namespace_uuid
        self.fields_to_present = fields_to_present
        self.has_extension = fields_to_present != {'name', 'type'}
        self.types_for_indicator_sdo = types_for_indicator_sdo or []

    def create_indicators(self, indicator_searcher: IndicatorsSearcher, is_manifest: bool):
        """
        Args:
            indicator_searcher: indicators list
            is_manifest: whether this call is for manifest or indicators

        Returns: Created indicators and its extensions.
        """
        total = 0
        extensions_dict: dict = {}
        iocs = []
        extensions = []
        for ioc in indicator_searcher:
            found_indicators = ioc.get('iocs') or []
            total = ioc.get('total')
            for xsoar_indicator in found_indicators:
                xsoar_type = xsoar_indicator.get('indicator_type')
                if is_manifest:
                    manifest_entry = self.create_manifest_entry(xsoar_indicator, xsoar_type)
                    if manifest_entry:
                        iocs.append(manifest_entry)
                else:
                    stix_ioc, extension_definition, extensions_dict = \
                        self.create_stix_object(xsoar_indicator, xsoar_type, extensions_dict)
                    if XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type) in self.types_for_indicator_sdo:
                        stix_ioc = self.convert_sco_to_indicator_sdo(
                            stix_ioc, xsoar_indicator)
                    if self.has_extension and stix_ioc:
                        iocs.append(stix_ioc)
                        if extension_definition:
                            extensions.append(extension_definition)
                    elif stix_ioc:
                        iocs.append(stix_ioc)
        if not is_manifest and iocs \
                and is_demisto_version_ge('6.6.0') and \
                (relationships := self.create_relationships_objects(iocs, extensions)):
            total += len(relationships)
            iocs.extend(relationships)
            iocs = sorted(iocs, key=lambda k: k['modified'])
        return iocs, extensions, total

    def create_manifest_entry(self, xsoar_indicator: dict, xsoar_type: str) -> dict:
        """

        Args:
            xsoar_indicator: to create manifest entry from
            xsoar_type: type of indicator in xsoar system

        Returns:
            manifest entry for given indicator.
        """
        if stix_type := XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type):
            stix_id = self.create_sco_stix_uuid(xsoar_indicator, stix_type)
        elif stix_type := XSOAR_TYPES_TO_STIX_SDO.get(xsoar_type):
            stix_id = self.create_sdo_stix_uuid(xsoar_indicator, stix_type, self.namespace_uuid)
        else:
            demisto.debug(f'No such indicator type: {xsoar_type} in stix format.')
            return {}
        entry = {
            'id': stix_id,
            'date_added': parse(xsoar_indicator.get('timestamp')).strftime(STIX_DATE_FORMAT),  # type: ignore[arg-type]
        }
        if self.server_version == TAXII_VER_2_1:
            entry['version'] = parse(xsoar_indicator.get('modified')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]
        return entry

    def create_stix_object(self, xsoar_indicator: dict, xsoar_type: str, extensions_dict: dict = {}) -> tuple[dict, dict, dict]:
        """

        Args:
            xsoar_indicator: to create stix object entry from
            xsoar_type: type of indicator in xsoar system
            extensions_dict: dict contains all object types that already have their extension defined
        Returns:
            Stix object entry for given indicator, and extension. Format described here:
            (https://docs.google.com/document/d/1wE2JibMyPap9Lm5-ABjAZ02g098KIxlNQ7lMMFkQq44/edit#heading=h.naoy41lsrgt0)
            extensions_dict: dict contains all object types that already have their extension defined
        """
        is_sdo = False
        if stix_type := XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type):
            stix_id = self.create_sco_stix_uuid(xsoar_indicator, stix_type)
            object_type = stix_type
        elif stix_type := XSOAR_TYPES_TO_STIX_SDO.get(xsoar_type):
            stix_id = self.create_sdo_stix_uuid(xsoar_indicator, stix_type, self.namespace_uuid)
            object_type = stix_type
            is_sdo = True
        else:
            demisto.debug(f'No such indicator type: {xsoar_type} in stix format.')
            return {}, {}, {}

        indicator_value = xsoar_indicator.get("value")
        if (stix_type == "file") and (get_hash_type(indicator_value) == "Unknown"):
            demisto.debug(f"Skip indicator of type 'file' with value: '{indicator_value}', as it is not a valid hash.")
            return {}, {}, {}

        created_parsed = parse(xsoar_indicator.get('timestamp')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]

        try:
            modified_parsed = parse(xsoar_indicator.get('modified')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]
        except Exception:
            modified_parsed = ''
        # Properties required for STIX objects in all versions: id, type, created, modified.
        stix_object: Dict[str, Any] = {
            'id': stix_id,
            'type': object_type,
            'spec_version': self.server_version,
            'created': created_parsed,
            'modified': modified_parsed,
        }
        if xsoar_type == ThreatIntel.ObjectsNames.REPORT:
            stix_object['object_refs'] = [ref['objectstixid']
                                          for ref in xsoar_indicator['CustomFields'].get('reportobjectreferences', [])]
        if is_sdo:
            stix_object['name'] = indicator_value
            stix_object = self.add_sdo_required_field_2_1(stix_object, xsoar_indicator)
            stix_object = self.add_sdo_required_field_2_0(stix_object, xsoar_indicator)
        else:
            stix_object = self.build_sco_object(stix_object, xsoar_indicator)

        xsoar_indicator_to_return = {}

        # filter only requested fields
        if self.has_extension and self.fields_to_present:
            # if Server fields_to_present is None - no filters, return all. If Existing fields - filter
            for field in self.fields_to_present:
                value = xsoar_indicator.get(field)
                if not value:
                    value = (xsoar_indicator.get('CustomFields') or {}).get(field)
                xsoar_indicator_to_return[field] = value
        else:
            xsoar_indicator_to_return = xsoar_indicator
        extension_definition = {}

        if self.has_extension and object_type not in self.types_for_indicator_sdo:
            stix_object, extension_definition, extensions_dict = \
                self.create_extension_definition(object_type, extensions_dict, xsoar_type,
                                                 created_parsed, modified_parsed,
                                                 stix_object, xsoar_indicator_to_return)

        if is_sdo:
            stix_object['description'] = (xsoar_indicator.get('CustomFields') or {}).get('description', "")
        return stix_object, extension_definition, extensions_dict

    def handle_report_relationships(self, relationships: list[dict[str, Any]], stix_iocs: list[dict[str, Any]]):
        """Handle specific behavior of report relationships.

        Args:
            relationships (list[dict[str, Any]]): the created relationships list.
            stix_iocs (list[dict[str, Any]]): the ioc objects.
        """
        id_to_report_objects = {
            stix_ioc.get('id'): stix_ioc
            for stix_ioc in stix_iocs
            if stix_ioc.get('type') == 'report'}
        for relationship in relationships:
            if source_report := id_to_report_objects.get(relationship.get('source_ref')):
                object_refs = source_report.get('object_refs', [])
                object_refs.extend(
                    [relationship.get('target_ref'), relationship.get('id')]
                )
                source_report['object_refs'] = sorted(object_refs)
            if target_report := id_to_report_objects.get(relationship.get('target_ref')):
                object_refs = target_report.get('object_refs', [])
                object_refs.extend(
                    [relationship.get('source_ref'), relationship.get('id')]
                )
                target_report['object_refs'] = sorted(object_refs)

    @staticmethod
    def get_stix_object_value(stix_ioc):
        demisto.debug(f'{stix_ioc=}')
        if stix_ioc.get('type') == "file":
            for hash_type in ["SHA-256", "MD5", "SHA-1", "SHA-512"]:
                if hash_value := stix_ioc.get("hashes", {}).get(hash_type):
                    return hash_value
            return None

        else:
            return stix_ioc.get('value') or stix_ioc.get('name')

    def create_extension_definition(self, object_type, extensions_dict, xsoar_type,
                                    created_parsed, modified_parsed, stix_object, xsoar_indicator_to_return):
        """
        Args:
            object_type: the type of the stix_object.
            xsoar_type: type of indicator in xsoar system.
            extensions_dict: dict contains all object types that already have their extension defined.
            created_parsed: the stix object creation time.
            modified_parsed: the stix object last modified time.
            stix_object: Stix object entry.
            xsoar_indicator_to_return: the xsoar indicator to return.

        Create an extension definition and update the stix object and extensions dict accordingly.

        Returns:
            the updated Stix object, its extension and updated extensions_dict.
        """
        extension_definition = {}
        xsoar_indicator_to_return['extension_type'] = 'property_extension'
        extension_id = f'extension-definition--{uuid.uuid4()}'
        if object_type not in extensions_dict:
            extension_definition = {
                'id': extension_id,
                'type': 'extension-definition',
                'spec_version': self.server_version,
                'name': f'Cortex XSOAR TIM {xsoar_type}',
                'description': 'This schema adds TIM data to the object',
                'created': created_parsed,
                'modified': modified_parsed,
                'created_by_ref': f'identity--{str(PAWN_UUID)}',
                'schema':
                    'https://github.com/demisto/content/blob/4265bd5c71913cd9d9ed47d9c37d0d4d3141c3eb/'
                    'Packs/TAXIIServer/doc_files/XSOAR_indicator_schema.json',
                'version': '1.0',
                'extension_types': ['property-extension']
            }
            extensions_dict[object_type] = True
        stix_object['extensions'] = {
            extension_id: xsoar_indicator_to_return
        }
        return stix_object, extension_definition, extensions_dict

    def convert_sco_to_indicator_sdo(self, stix_object: dict, xsoar_indicator: dict) -> dict:
        """
        Create a STIX domain object of 'indicator' type from a STIX Cyber Observable Objects.

        Args:
            stix_object: The STIX Cyber Observable Object
            xsoar_indicator: The stix object entry from which the 'stix_object' has been created.

        Returns:
            Stix indicator domain object for given indicator. Format described here:
            https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_muftrcpnf89v
        """
        try:
            expiration_parsed = parse(xsoar_indicator.get('expiration')).strftime(STIX_DATE_FORMAT)  # type: ignore[arg-type]
        except Exception:
            expiration_parsed = ''

        indicator_value = xsoar_indicator.get('value')
        if isinstance(indicator_value, str):
            indicator_pattern_value: Any = indicator_value.replace("'", "\\'")
        else:
            indicator_pattern_value = json.dumps(indicator_value)

        object_type = stix_object['type']
        stix_type = 'indicator'

        pattern = ''
        if object_type == 'file':
            hash_type = HASH_TYPE_TO_STIX_HASH_TYPE.get(get_hash_type(indicator_value), 'Unknown')
            pattern = f"[file:hashes.'{hash_type}' = '{indicator_pattern_value}']"
        else:
            pattern = f"[{object_type}:value = '{indicator_pattern_value}']"

        labels = self.get_labels_for_indicator(xsoar_indicator.get('score'))

        stix_domain_object: Dict[str, Any] = assign_params(
            type=stix_type,
            id=self.create_sdo_stix_uuid(xsoar_indicator, stix_type, self.namespace_uuid),
            pattern=pattern,
            valid_from=stix_object['created'],
            valid_until=expiration_parsed,
            description=(xsoar_indicator.get('CustomFields') or {}).get('description', ''),
            pattern_type='stix',
            labels=labels
        )
        return dict({k: v for k, v in stix_object.items()
                    if k in ('spec_version', 'created', 'modified')}, **stix_domain_object)

    @staticmethod
    def create_sdo_stix_uuid(xsoar_indicator: dict, stix_type: Optional[str],
                             uuid_value: uuid.UUID, value: Optional[str] = None) -> str:
        """
        Create uuid for SDO objects.
        Args:
            xsoar_indicator: dict - The XSOAR representation of the indicator.
            stix_type: Optional[str] - The indicator type according to STIX.
            value: str - The value of the indicator.
        Returns:
            The uuid that represents the indicator according to STIX.
        """
        if stixid := xsoar_indicator.get('CustomFields', {}).get('stixid'):
            return stixid
        value = value if value else xsoar_indicator.get('value')
        if stix_type == 'attack-pattern':
            if mitre_id := xsoar_indicator.get('CustomFields', {}).get('mitreid'):
                unique_id = uuid.uuid5(uuid_value, f'{stix_type}:{mitre_id}')
            else:
                unique_id = uuid.uuid5(uuid_value, f'{stix_type}:{value}')
        else:
            unique_id = uuid.uuid5(uuid_value, f'{stix_type}:{value}')

        return f'{stix_type}--{unique_id}'

    @staticmethod
    def create_sco_stix_uuid(xsoar_indicator: dict, stix_type: Optional[str], value: Optional[str] = None) -> str:
        """
        Create uuid for sco objects.
        """
        if stixid := (xsoar_indicator.get('CustomFields') or {}).get('stixid'):
            return stixid
        if not value:
            value = xsoar_indicator.get('value')
        if stix_type == 'user-account':
            account_type = (xsoar_indicator.get('CustomFields') or {}).get('accounttype')
            user_id = (xsoar_indicator.get('CustomFields') or {}).get('userid')
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE,
                                   f'{{"account_login":"{value}","account_type":"{account_type}","user_id":"{user_id}"}}')
        elif stix_type == 'windows-registry-key':
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"key":"{value}"}}')
        elif stix_type == 'file':
            if get_hash_type(value) == 'md5':
                unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"MD5":"{value}"}}}}')
            elif get_hash_type(value) == 'sha1':
                unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-1":"{value}"}}}}')
            elif get_hash_type(value) == 'sha256':
                unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-256":"{value}"}}}}')
            elif get_hash_type(value) == 'sha512':
                unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-512":"{value}"}}}}')
            else:
                unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"value":"{value}"}}')
        else:
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"value":"{value}"}}')

        stix_id = f'{stix_type}--{unique_id}'
        return stix_id

    def create_entity_b_stix_objects(self, relationships: list[dict[str, Any]], iocs_value_to_id: dict, extensions: list) -> list:
        """
        Generates a list of STIX objects for the 'entityB' values in the provided 'relationships' list.
        :param relationships: A list of dictionaries representing relationships between entities
        :param iocs_value_to_id: A dictionary mapping IOC values to their corresponding ID values.
        :param extensions: A list of dictionaries representing extension properties to include in the generated STIX objects.
        :return: A list of dictionaries representing STIX objects for the 'entityB' values
        """
        entity_b_objects: list[dict[str, Any]] = []
        entity_b_values = ""
        for relationship in relationships:
            if relationship:
                if (relationship.get('CustomFields') or {}).get('revoked', False):
                    continue
                if (entity_b_value := relationship.get('entityB')) and entity_b_value not in iocs_value_to_id:
                    iocs_value_to_id[entity_b_value] = ""
                    entity_b_values += f'\"{entity_b_value}\" '
            else:
                demisto.debug(f'relationship is empty {relationship=}')
        if not entity_b_values:
            return entity_b_objects

        try:
            found_indicators = demisto.searchIndicators(query=f'value:({entity_b_values})').get('iocs') or []
        except AttributeError:
            demisto.debug(f'Could not find indicators from using query value:({entity_b_values})')
            found_indicators = []

        extensions_dict: dict = {}
        for xsoar_indicator in found_indicators:
            if xsoar_indicator:
                xsoar_type = xsoar_indicator.get('indicator_type')
                stix_ioc, extension_definition, extensions_dict = self.create_stix_object(
                    xsoar_indicator, xsoar_type, extensions_dict)
                if XSOAR_TYPES_TO_STIX_SCO.get(xsoar_type) in self.types_for_indicator_sdo:
                    stix_ioc = self.convert_sco_to_indicator_sdo(stix_ioc, xsoar_indicator)
                if self.has_extension and stix_ioc:
                    entity_b_objects.append(stix_ioc)
                    if extension_definition:
                        extensions.append(extension_definition)
                elif stix_ioc:
                    entity_b_objects.append(stix_ioc)
            else:
                demisto.debug(f"{xsoar_indicator=} is emtpy")

                iocs_value_to_id[(self.get_stix_object_value(stix_ioc))] = stix_ioc.get('id') if stix_ioc else None
        demisto.debug(f"Generated {len(entity_b_objects)} STIX objects for 'entityB' values.")
        return entity_b_objects

    def create_relationships_objects(self, stix_iocs: list[dict[str, Any]], extensions: list) -> list[dict[str, Any]]:
        """
        Create entries for the relationships returned by the searchRelationships command.
        :param stix_iocs: Entries for the Stix objects associated with given indicators
        :param extensions: A list of dictionaries representing extension properties to include in the generated STIX objects.
        :return: A list of dictionaries representing the relationships objects, including entityBs objects
        """
        relationships_list: list[dict[str, Any]] = []
        iocs_value_to_id = {self.get_stix_object_value(stix_ioc): stix_ioc.get('id') for stix_ioc in stix_iocs}
        search_relationships = demisto.searchRelationships({'entities': list(iocs_value_to_id.keys())}).get('data') or []
        demisto.debug(f"Found {len(search_relationships)} relationships for {len(iocs_value_to_id)} Stix IOC values.")

        relationships_list.extend(self.create_entity_b_stix_objects(search_relationships, iocs_value_to_id, extensions))

        for relationship in search_relationships:

            if demisto.get(relationship, 'CustomFields.revoked'):
                continue

            if not iocs_value_to_id.get(relationship.get('entityB')):
                demisto.debug(f'TAXII: {iocs_value_to_id=} When {relationship.get("entityB")=}')
                demisto.debug(f"WARNING: Invalid entity B - Relationships will not be created to entity A:"
                              f" {relationship.get('entityA')} with relationship name {relationship.get('name')}")
                continue
            try:
                created_parsed = parse(relationship.get('createdInSystem')).strftime(STIX_DATE_FORMAT)
                modified_parsed = parse(relationship.get('modified')).strftime(STIX_DATE_FORMAT)
            except Exception as e:
                created_parsed, modified_parsed = '', ''
                demisto.debug(f"Error parsing dates for relationship {relationship.get('id')}: {e}")

            relationship_unique_id = uuid.uuid5(self.namespace_uuid, f'relationship:{relationship.get("id")}')
            relationship_stix_id = f'relationship--{relationship_unique_id}'

            relationship_object: dict[str, Any] = {
                'type': "relationship",
                'spec_version': self.server_version,
                'id': relationship_stix_id,
                'created': created_parsed,
                'modified': modified_parsed,
                "relationship_type": relationship.get('name'),
                'source_ref': iocs_value_to_id.get(relationship.get('entityA')),
                'target_ref': iocs_value_to_id.get(relationship.get('entityB')),
            }
            if description := demisto.get(relationship, 'CustomFields.description'):
                relationship_object['Description'] = description

            relationships_list.append(relationship_object)
        self.handle_report_relationships(relationships_list, stix_iocs)
        return relationships_list

    def add_sdo_required_field_2_1(self, stix_object: Dict[str, Any], xsoar_indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            stix_object: A stix object from
            xsoar_type: indicator from xsoar system
        Returns:
            Stix object entry for given indicator
        """
        if self.server_version == TAXII_VER_2_1:
            custom_fields = xsoar_indicator.get("CustomFields", {})
            stix_type = stix_object['type']
            if stix_type == 'malware':
                stix_object['is_family'] = custom_fields.get('ismalwarefamily', False)
            elif stix_type == 'report' and (published := custom_fields.get('published')):
                stix_object['published'] = published
        return stix_object

    def add_sdo_required_field_2_0(self, stix_object: Dict[str, Any], xsoar_indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            stix_object: A stix object from
            xsoar_type: indicator from xsoar system
        Returns:
            Stix object entry for given indicator
        """
        if self.server_version == TAXII_VER_2_0:
            custom_fields = xsoar_indicator.get("CustomFields", {}) or {}
            stix_type = stix_object['type']
            if stix_type in {"indicator", "malware", "report", "threat-actor", "tool"}:
                tags = custom_fields.get('tags', []) if custom_fields.get('tags', []) != [] else [stix_object['type']]
                stix_object['labels'] = [x.lower().replace(" ", "-") for x in tags]
            if stix_type == 'identity' and (identity_class := custom_fields.get('identityclass', 'unknown')):
                stix_object['identity_class'] = identity_class
        return stix_object

    def create_x509_certificate_subject_issuer(self, list_dict_values: list) -> str:
        """
        Args:
            dict_values: A dict with keys and values for subject/issuer
            Example: [{'title': 'title', 'data': 'data'}, {'title': 'title1', 'data': 'data1'}]
        Returns:
            A string
            Example: 'title=data, title1=data1'
        """
        string_to_return = ""
        if list_dict_values:
            for dict_values in list_dict_values:
                title = dict_values.get("title")
                data = dict_values.get("data")
                if data is not None:
                    string_to_return += f"{title}={data}, "
            string_to_return = string_to_return.rstrip(", ")
            return string_to_return
        return ''

    def create_x509_certificate_object(self, stix_object: Dict[str, Any], xsoar_indicator: Dict[str, Any]) -> dict:
        """
        Builds a correct JSON object for specific x509 certificate.

        Args:
            stix_object (Dict[str, Any]): A JSON object of a STIX indicator
            xsoar_indicator (Dict[str, Any]): A JSON object of an XSOAR indicator

        Returns:
            Dict[str, Any]: A JSON object of a STIX indicator.
        """
        custom_fields = xsoar_indicator.get('CustomFields') or {}
        stix_object['validity_not_before'] = custom_fields.get('validitynotbefore')
        stix_object['validity_not_after'] = custom_fields.get('validitynotafter')
        stix_object['serial_number'] = xsoar_indicator.get('value')
        stix_object['subject'] = self.create_x509_certificate_subject_issuer(custom_fields.get('subject', []))
        stix_object['issuer'] = self.create_x509_certificate_subject_issuer(custom_fields.get('issuer', []))
        remove_nulls_from_dictionary(stix_object)
        return stix_object

    def build_sco_object(self, stix_object: Dict[str, Any], xsoar_indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds a correct JSON object for specific SCO types

        Args:
            stix_object (Dict[str, Any]): A JSON object of a STIX indicator
            xsoar_indicator (Dict[str, Any]): A JSON object of an XSOAR indicator

        Returns:
            Dict[str, Any]: A JSON object of a STIX indicator
        """
        custom_fields = xsoar_indicator.get('CustomFields') or {}

        if stix_object['type'] == 'autonomous-system':
            # number is the only required field for autonomous-system
            stix_object['number'] = xsoar_indicator.get('value', '')
            stix_object['name'] = custom_fields.get('name', '')

        elif stix_object['type'] == 'file':
            # hashes is the only required field for file
            value = xsoar_indicator.get('value')
            stix_object['hashes'] = {HASH_TYPE_TO_STIX_HASH_TYPE[get_hash_type(value)]: value}
            for hash_type in ('md5', 'sha1', 'sha256', 'sha512'):
                try:
                    stix_object['hashes'][HASH_TYPE_TO_STIX_HASH_TYPE[hash_type]] = custom_fields[hash_type]

                except KeyError:
                    pass

        elif stix_object['type'] == 'windows-registry-key':
            # key is the only required field for windows-registry-key
            stix_object['key'] = xsoar_indicator.get('value')
            stix_object['values'] = []
            for keyvalue in custom_fields['keyvalue']:
                if keyvalue:
                    stix_object['values'].append(keyvalue)
                    stix_object['values'][-1]['data_type'] = stix_object['values'][-1]['type']
                    del stix_object['values'][-1]['type']
                else:
                    pass
        elif stix_object['type'] in ('mutex', 'software'):
            stix_object['name'] = xsoar_indicator.get('value')
        # user_id is the only required field for user-account
        elif stix_object['type'] == 'user-account':
            user_id = (xsoar_indicator.get('CustomFields') or {}).get('userid')
            if user_id:
                stix_object['user_id'] = user_id
        elif stix_object['type'] == 'x509-certificate':
            self.create_x509_certificate_object(stix_object, xsoar_indicator)
        # ipv4-addr or ipv6-addr or URL
        else:
            stix_object['value'] = xsoar_indicator.get('value')

        return stix_object

    @staticmethod
    def get_labels_for_indicator(score):
        """Get indicator label based on the DBot score"""
        return {
            0: [''],
            1: ['benign'],
            2: ['anomalous-activity'],
            3: ['malicious-activity']
        }.get(int(score))


class STIX2XSOARParser(BaseClient):

    def __init__(self, id_to_object: dict[str, Any], verify: bool = True,
                 base_url: Optional[str] = None, proxy: bool = False,
                 tlp_color: Optional[str] = None,
                 field_map: Optional[dict] = None, skip_complex_mode: bool = False,
                 tags: Optional[list] = None, update_custom_fields: bool = False,
                 enrichment_excluded: bool = False):

        super().__init__(base_url=base_url, verify=verify,
                         proxy=proxy)
        self.skip_complex_mode = skip_complex_mode
        self.indicator_regexes = [
            re.compile(INDICATOR_EQUALS_VAL_PATTERN),
            re.compile(HASHES_EQUALS_VAL_PATTERN),
        ]
        self.tlp_color = tlp_color
        self.id_to_object = id_to_object
        self.cidr_regexes = [
            re.compile(CIDR_ISSUBSET_VAL_PATTERN),
            re.compile(CIDR_ISUPPERSET_VAL_PATTERN),
        ]
        self.field_map = field_map or {}
        self.update_custom_fields = update_custom_fields
        self.tags = tags or []
        self.last_fetched_indicator__modified = None
        self.enrichment_excluded = enrichment_excluded

    @staticmethod
    def get_pattern_comparisons(pattern: str, supported_only: bool = True) -> Optional[PatternComparisons]:
        """
        Parses a pattern and comparison and extracts the comparisons as a dictionary.
        If the pattern is invalid, the return value will be "None".

        For Example:

        >>> STIX2XSOARParser.get_pattern_comparisons(
        >>>     "[ipv4-addr:value = '1.1.1.1/32' "
        >>>     "OR ipv4-addr:value = '8.8.8.8/32' "
        >>>     "AND domain-name:value = 'example.com' "
        >>>     "OR file:hashes.'SHA-256' = '13987239847...']"
        >>> )
        {
            'ipv4-addr': [(['value'], '=', "'1.1.1.1/32'"), (['value'], '=', "'8.8.8.8/32'")],
            'domain-name': [(['value'], '=', "'example.com'")],
            'file': [(['hashes', 'SHA-256'], '=', "'13987239847...'")]
        }

        Args:
            pattern: the pattern to extract the value from.
            supported_only: Whether to remove comparisons that are not supported by Cortex XSOAR.

        Returns:
            Optional[PatternComparisons]. the value in the pattern.
        """
        try:
            comparisons = cast(PatternComparisons, Pattern(pattern).inspect().comparisons)
            return (
                STIX2XSOARParser.get_supported_pattern_comparisons(comparisons)
                if supported_only else comparisons
            )
        except Exception as error:
            demisto.debug(f'Unable to parse {pattern=}, {error=}')
        return None

    @staticmethod
    def get_supported_pattern_comparisons(comparisons: PatternComparisons) -> PatternComparisons:
        """
        Get only the patterns supported by XSOAR from a parsed pattern.

        Args:
            comparisons: The comparisons of the pattern to extract the supported values from.

        Returns:
            PatternComparisons. the value in the pattern.
        """
        def get_comparison_field(comparison: tuple[list[str], str, str]) -> str:
            '''retrieves the field of a STIX comparison.'''
            return cast(str, dict_safe_get(comparison, [0, 0]))

        supported_comparisons: PatternComparisons = {}
        for indicator_type, comps in comparisons.items():
            if indicator_type in STIX_SUPPORTED_TYPES:
                field_comparisons = [
                    comp for comp in comps
                    if (get_comparison_field(comp) in STIX_SUPPORTED_TYPES[indicator_type])
                ]
                if field_comparisons:
                    supported_comparisons[indicator_type] = field_comparisons
        return supported_comparisons

    @staticmethod
    def get_indicator_publication(indicator: dict[str, Any], ignore_external_id: bool = False):
        """
        Build publications grid field from the indicator external_references field

        Args:
            indicator: The indicator with publication field.
            ignore_external_id: Whether to ignore external_id or not.

        Returns:
            list. publications grid field
        """
        publications = []
        for external_reference in indicator.get('external_references', []):
            if ignore_external_id and external_reference.get('external_id'):
                continue
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
    def get_entity_b_type_and_value(related_obj: str, id_to_object: dict[str, dict[str, Any]],
                                    is_unit42_report: bool = False) -> tuple:
        """
       Gets the type and value of the indicator in entity_b.

        Args:
            related_obj: the indicator to get information on.
            id_to_object: a dict in the form of - id: stix_object.
            is_unit42_report: represents whether unit42 report or not.

        Returns:
            tuple. the indicator type and value.
        """
        indicator_obj = id_to_object.get(related_obj, {})
        entity_b_value = indicator_obj.get('name', '')
        entity_b_obj_type = STIX_2_TYPES_TO_CORTEX_TYPES.get(
            indicator_obj.get('type', ''), STIX2XSOARParser.get_ioc_type(related_obj, id_to_object))
        if indicator_obj.get('type') == "indicator":
            entity_b_value = STIX2XSOARParser.get_single_pattern_value(id_to_object.get(related_obj, {}).get('pattern', ''))
        elif indicator_obj.get('type') == "attack-pattern" and is_unit42_report:
            _, entity_b_value = STIX2XSOARParser.get_mitre_attack_id_and_value_from_name(indicator_obj)
        elif indicator_obj.get('type') == "report" and is_unit42_report:
            entity_b_value = f"[Unit42 ATOM] {indicator_obj.get('name')}"
        return entity_b_obj_type, entity_b_value

    @staticmethod
    def get_mitre_attack_id_and_value_from_name(attack_indicator):
        """
        Split indicator name into MITRE ID and indicator value: 'T1108: Redundant Access' -> MITRE ID = T1108,
        indicator value = 'Redundant Access'.
        """
        ind_name = attack_indicator.get('name')
        separator = ':'
        try:
            partition_result = ind_name.partition(separator)
            if partition_result[1] != separator:
                raise DemistoException(f"Failed parsing attack indicator {ind_name}")
        except ValueError:
            raise DemistoException(f"Failed parsing attack indicator {ind_name}")
        ind_id = partition_result[0]
        value = partition_result[2].strip()

        if attack_indicator.get('x_mitre_is_subtechnique'):
            value = attack_indicator.get('x_panw_parent_technique_subtechnique')

        return ind_id, value

    @staticmethod
    def parse_report_relationships(report_obj: dict[str, Any],
                                   id_to_object: dict[str, dict[str, Any]],
                                   relationships_prefix: str = '',
                                   ignore_reports_relationships: bool = False,
                                   is_unit42_report: bool = False) \
            -> Tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        obj_refs = report_obj.get('object_refs', [])
        relationships: list[dict[str, Any]] = []
        obj_refs_excluding_relationships_prefix = []

        for related_obj in obj_refs:
            # relationship-- objects ref handled in parse_relationships
            if not related_obj.startswith('relationship--'):
                if ignore_reports_relationships and related_obj.startswith('report--'):
                    continue
                obj_refs_excluding_relationships_prefix.append(related_obj)
                if id_to_object.get(related_obj):
                    entity_b_obj_type, entity_b_value = STIX2XSOARParser.get_entity_b_type_and_value(related_obj, id_to_object,
                                                                                                     is_unit42_report)
                    if not entity_b_obj_type:
                        demisto.debug(f"Could not find the type of {related_obj} skipping.")
                        continue
                    relationships.append(
                        EntityRelationship(
                            name='related-to',
                            entity_a=f"{relationships_prefix}{report_obj.get('name')}",
                            entity_a_type=ThreatIntel.ObjectsNames.REPORT,
                            entity_b=entity_b_value,
                            entity_b_type=entity_b_obj_type
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
                if STIX2XSOARParser.is_supported_iocs_type(pattern):
                    ioc_type = STIX_2_TYPES_TO_CORTEX_TYPES.get(stix_type, '')  # type: ignore
                    break
                demisto.debug(f"Indicator {indicator_obj.get('id')} is not supported indicator.")
        return ioc_type

    @staticmethod
    def is_supported_iocs_type(pattern: str):
        """
        Get pattern and check if the type is supported by XSOAR.

        Args:
            pattern: the indicator pattern.

        Returns:
            bool.
        """
        return any(
            any(
                pattern.startswith(f"[{key}:{field}")
                for field in STIX_SUPPORTED_TYPES[key]
            )
            for key in STIX_SUPPORTED_TYPES
        )

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

        if obj_to_parse.get('confidence', ''):
            fields['confidence'] = obj_to_parse.get('confidence', '')

        if obj_to_parse.get('lang', ''):
            fields['languages'] = obj_to_parse.get('lang', '')

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

    @staticmethod
    def get_single_pattern_value(pattern: str) -> str | None:
        """
        Parses a pattern with a single comparison and extracts the right hand value of the comparison.
        If the pattern is invalid, the pattern itself will be returned.

        For Example:

        >>> STIX2XSOARParser.get_single_pattern_value("[domain-name:value = 'www.example.com']")
        'www.example.com'

        Args:
            pattern: the pattern to extract the value from.

        Returns:
            str. the value in the pattern.
        """
        comparisons = STIX2XSOARParser.get_pattern_comparisons(pattern) or {}
        if comparisons:
            return dict_safe_get(tuple(comparisons.values()), [0, 0, -1], '', str).strip("'") or None
        return None

    def parse_indicator(self, indicator_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses a single indicator object
        :param indicator_obj: indicator object
        :return: indicators extracted from the indicator object in cortex format
        """
        field_map = self.field_map or {}
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

    def parse_attack_pattern(self, attack_pattern_obj: dict[str, Any], ignore_external_id: bool = False) -> list[dict[str, Any]]:
        """
        Parses a single attack pattern object
        :param attack_pattern_obj: attack pattern object
        :return: attack pattern extracted from the attack pattern object in cortex format
        """
        publications = self.get_indicator_publication(attack_pattern_obj, ignore_external_id)

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

        if self.enrichment_excluded:
            attack_pattern['enrichmentExcluded'] = self.enrichment_excluded

        return [attack_pattern]

    def create_obj_refs_list(self, obj_refs_list: list):
        """
        Creates a list of object references for a STIX report type and organize it for an XSOAR "object refs" grid field.

        :param obj_refs_list: A list of obj refs
        :return: A list of dicts.
        """
        # remove duplicates
        obj_refs_list_result = []
        obj_refs_list_without_dup = list(dict.fromkeys(obj_refs_list))
        omitted_object_number = len(obj_refs_list) - len(obj_refs_list_without_dup)
        demisto.debug(f"Omitting {omitted_object_number} object ref form the report")
        if obj_refs_list:
            obj_refs_list_result.extend([{'objectstixid': object} for object in obj_refs_list_without_dup])
        return obj_refs_list_result

    def parse_report(self, report_obj: dict[str, Any],
                     relationships_prefix: str = '',
                     ignore_reports_relationships: bool = False,
                     is_unit42_report: bool = False) -> list[dict[str, Any]]:
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

        relationships, obj_refs_excluding_relationships_prefix = self.parse_report_relationships(report_obj, self.id_to_object,
                                                                                                 relationships_prefix,
                                                                                                 ignore_reports_relationships,
                                                                                                 is_unit42_report)
        report['relationships'] = relationships
        if obj_refs_excluding_relationships_prefix:
            fields['Report Object References'] = self.create_obj_refs_list(obj_refs_excluding_relationships_prefix)
        report["fields"] = fields

        if self.enrichment_excluded:
            report['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            threat_actor['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            infrastructure['enrichmentExcluded'] = self.enrichment_excluded

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
            "ismalwarefamily": malware_obj.get('is_family', False),
            "aliases": malware_obj.get('aliases', []),
            "kill_chain_phases": kill_chain_phases,
            "os_execution_envs": malware_obj.get('os_execution_envs', []),
            "architecture": malware_obj.get('architecture_execution_envs', []),
            "capabilities": malware_obj.get('capabilities', []),
            "samples": malware_obj.get('sample_refs', [])
        })

        if self.update_custom_fields:
            custom_fields, score = self.parse_custom_fields(malware_obj.get('extensions', {}))
            fields.update(assign_params(**custom_fields))
            if score:
                malware['score'] = score

        tags = list((set(malware_obj.get('labels', []))).union(set(self.tags)))
        fields['tags'] = list(set(list(fields.get('tags', [])) + tags))

        malware["fields"] = fields

        if self.enrichment_excluded:
            malware['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            tool['enrichmentExcluded'] = self.enrichment_excluded

        return [tool]

    def parse_course_of_action(self, coa_obj: dict[str, Any], ignore_external_id: bool = False) -> list[dict[str, Any]]:
        """
        Parses a single course of action object
        :param coa_obj: course of action object
        :return: course of action extracted from the course of action object in cortex format
        """
        publications = self.get_indicator_publication(coa_obj, ignore_external_id)

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

        if self.enrichment_excluded:
            course_of_action['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            campaign['enrichmentExcluded'] = self.enrichment_excluded

        return [campaign]

    def parse_intrusion_set(self, intrusion_set_obj: dict[str, Any], ignore_external_id: bool = False) -> list[dict[str, Any]]:
        """
        Parses a single intrusion set object
        :param intrusion_set_obj: intrusion set object
        :return: intrusion set extracted from the intrusion set object in cortex format
        """
        publications = self.get_indicator_publication(intrusion_set_obj, ignore_external_id)

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

        if self.enrichment_excluded:
            intrusion_set['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            sco_indicator['enrichmentExcluded'] = self.enrichment_excluded

        return [sco_indicator]

    def parse_sco_autonomous_system_indicator(self, autonomous_system_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses autonomous_system indicator type to cortex format.

        Args:
            autonomous_system_obj (dict): indicator as an observable object of type autonomous-system.
        """
        if isinstance(autonomous_system_obj, dict) and 'number' in autonomous_system_obj:
            autonomous_system_obj['number'] = str(autonomous_system_obj.get('number', ''))
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

    def create_keyvalue_dict(self, registry_key_obj_values: list[dict[str, Any]]) -> list:
        """
        Creates a grid field related to the keyvalue field of the registry key.

        Args:
            registry_key_obj_values (dict[str, Any]): A list of dict from the stix object.

        Returns:
            list: The return value. A list of dict.
        """
        returned_grid = []
        for stix_values_entry in registry_key_obj_values:
            returned_grid.append({"name": stix_values_entry.get("name", ''),
                                  "type": stix_values_entry.get("data_type"),
                                  "data": stix_values_entry.get("data")})
        return returned_grid

    def parse_sco_windows_registry_key_indicator(self, registry_key_obj: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parses registry_key indicator type to cortex format.

        Args:
            registry_key_obj (dict): indicator as an observable object of registry_key type.
        """
        registry_key_indicator = self.parse_general_sco_indicator(registry_key_obj, value_mapping='key')
        registry_key_indicator[0]["fields"].update(
            {
                "keyvalue": self.create_keyvalue_dict(
                    registry_key_obj.get("values", [])
                ),
                "modified_time": registry_key_obj.get("modified_time"),
                "numberofsubkeys": registry_key_obj.get("number_of_subkeys"),
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

        if self.enrichment_excluded:
            identity['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            location['enrichmentExcluded'] = self.enrichment_excluded

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

        if self.enrichment_excluded:
            cve['enrichmentExcluded'] = self.enrichment_excluded

        return [cve]

    def create_x509_certificate_grids(self, string_object: Optional[str]) -> list:
        """
        Creates a grid field related to the subject and issuer field of the x509 certificate object.

        Args:
            string_object (Optional[str]): A str in format of C=ZA, ST=Western Cape, L=Cape Town, O=Thawte.

        Returns:
            list: The return value. A list of dict [{"title": "C", "data": "ZA"}].
        """
        result_grid_list = []
        if string_object:
            key_value_pairs = string_object.split(', ')
            for pair in key_value_pairs:
                result_grid = {}
                key, value = pair.split('=', 1)
                result_grid['title'] = key
                result_grid['data'] = value
                result_grid_list.append(result_grid)
        return result_grid_list

    def parse_x509_certificate(self, x509_certificate_obj: dict[str, Any]):
        """
        Parses a single x509_certificate object
        :param x509_certificate_obj: x509_certificate object
        :return: x509_certificate extracted from the x509_certificate object in cortex format.
        """
        if x509_certificate_obj.get('serial_number'):
            x509_certificate = {
                "value": x509_certificate_obj.get('serial_number'),
                'type': FeedIndicatorType.X509,
                'score': Common.DBotScore.NONE,
                "rawJSON": x509_certificate_obj,

            }
            fields = {"stixid": x509_certificate_obj.get('id', ''),
                      "validitynotbefore": x509_certificate_obj.get('validity_not_before'),
                      "validitynotafter": x509_certificate_obj.get('validity_not_after'),
                      "subject": self.create_x509_certificate_grids(x509_certificate_obj.get('subject')),
                      "issuer": self.create_x509_certificate_grids(x509_certificate_obj.get('issuer'))}
            if self.update_custom_fields:
                custom_fields, score = self.parse_custom_fields(x509_certificate.get('extensions', {}))
                fields.update(assign_params(**custom_fields))
                if score:
                    x509_certificate['score'] = score
            fields['tags'] = list(set(list(fields.get('tags', [])) + self.tags))
            x509_certificate["fields"] = fields

            if self.enrichment_excluded:
                x509_certificate['enrichmentExcluded'] = self.enrichment_excluded

            return [x509_certificate]
        return []

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
        demisto.debug(f'Extracted {len(list(extracted_objs))} out of {len(list(stix_objs))} Stix objects with the types: '
                      f'{required_objects}')

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
        fields = self.set_default_fields(indicator_obj)
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
        fields["publications"] = self.get_indicator_publication(indicator_obj)

        if self.enrichment_excluded:
            indicator['enrichmentExcluded'] = self.enrichment_excluded

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
        Get IOC value from the indicator name/value/pattern field.

        Args:
            ioc: the indicator to get information on.
            id_to_obj: a dict in the form of - id: stix_object.

        Returns:
            str. the IOC value.
            if its attack pattern remove the id from the name.
        """
        ioc_obj = id_to_obj.get(ioc)
        if ioc_obj:
            for key in ('name', 'value', 'pattern'):
                if ("file:hashes.'SHA-256' = '" in ioc_obj.get(key, '')) and \
                        (ioc_value := Taxii2FeedClient.extract_ioc_value(ioc_obj, key)):
                    return ioc_value
            return ioc_obj.get('name') or ioc_obj.get('value')
        return None

    @staticmethod
    def extract_ioc_value(ioc_obj, key: str = "name"):
        """
        Extract SHA-256 from specific key, default key is name.
        "([file:name = 'blabla' OR file:name = 'blabla'] AND [file:hashes.'SHA-256' = '1111'])" -> 1111
        """
        ioc_value = ioc_obj.get(key, '')
        comps = STIX2XSOARParser.get_pattern_comparisons(ioc_value) or {}
        return next(
            (comp[-1].strip("'") for comp in comps.get('file', []) if ['hashes', 'SHA-256'] in comp), None)

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
            "vulnerability": self.parse_vulnerability,
            "x509-certificate": self.parse_x509_certificate,
        }

        indicators, relationships_lst = self.parse_generator_type_envelope(envelopes, parse_stix_2_objects, limit)
        if relationships_lst:
            indicators.extend(self.parse_relationships(relationships_lst))
        demisto.debug(
            f"TAXII 2 Feed has extracted {len(list(indicators))} indicators"
        )

        return indicators

    def increase_count(self, counter: Dict[str, int], id: str):
        if id in counter:
            counter[id] = counter[id] + 1
        else:
            counter[id] = 1

    def parse_generator_type_envelope(self, envelopes: types.GeneratorType, parse_objects_func, limit: int = -1):
        indicators = []
        relationships_lst = []
        # Used mainly for logging
        parsed_objects_counter: Dict[str, int] = {}
        try:
            for envelope in envelopes:
                self.increase_count(parsed_objects_counter, 'envelope')
                try:
                    stix_objects = envelope.get("objects")
                    if not stix_objects:
                        # no fetched objects
                        self.increase_count(parsed_objects_counter, 'not-parsed-envelope-not-stix')
                        break
                except Exception as e:
                    demisto.info(f"Exception trying to get envelope objects: {e}, {traceback.format_exc()}")
                    self.increase_count(parsed_objects_counter, 'exception-envelope-get-objects')
                    continue

                # we should build the id_to_object dict before iteration as some object reference each other
                self.id_to_object.update(
                    {
                        obj.get('id'): obj for obj in stix_objects
                        if obj.get('type') not in ['extension-definition', 'relationship']
                    }
                )
                # now we have a list of objects, go over each obj, save id with obj, parse the obj
                for obj in stix_objects:
                    try:
                        obj_type = obj.get('type')
                    except Exception as e:
                        demisto.info(f"Exception trying to get stix_object-type: {e}, {traceback.format_exc()}")
                        self.increase_count(parsed_objects_counter, 'exception-stix-object-type')
                        continue

                    # we currently don't support extension object
                    if obj_type == 'extension-definition':
                        demisto.debug(f'There is no parsing function for object type "extension-definition", for object {obj}.')
                        self.increase_count(parsed_objects_counter, 'not-parsed-extension-definition')
                        continue
                    elif obj_type == 'relationship':
                        relationships_lst.append(obj)
                        self.increase_count(parsed_objects_counter, 'not-parsed-relationship')
                        continue

                    if not parse_objects_func.get(obj_type):
                        demisto.debug(f'There is no parsing function for object type {obj_type}, for object {obj}.')
                        self.increase_count(parsed_objects_counter, f'not-parsed-{obj_type}')
                        continue
                    try:
                        if result := parse_objects_func[obj_type](obj):
                            indicators.extend(result)
                            self.update_last_modified_indicator_date(obj.get("modified"))
                    except Exception as e:
                        demisto.info(f"Exception parsing stix_object-type {obj_type}: {e}, {traceback.format_exc()}")
                        self.increase_count(parsed_objects_counter, f'exception-parsing-{obj_type}')
                        continue
                    self.increase_count(parsed_objects_counter, f'parsed-{obj_type}')

                    if reached_limit(limit, len(indicators)):
                        demisto.debug(f"Reached the limit ({limit}) of indicators to fetch. Indicators len: {len(indicators)}."
                                      f' Got {len(indicators)} indicators and {len(list(relationships_lst))} relationships.'
                                      f' Objects counters: {parsed_objects_counter}')

                        return indicators, relationships_lst
        except Exception as e:
            demisto.info(f"Exception trying to parse envelope: {e}, {traceback.format_exc()}")
            if len(indicators) == 0:
                demisto.debug("No Indicator were parsed")
                raise e
            demisto.debug(f"Failed while parsing envelopes, succeeded to retrieve {len(indicators)} indicators.")
        demisto.debug(f'Finished parsing all objects. Got {len(list(indicators))} indicators '
                      f'and {len(list(relationships_lst))} relationships. Objects counters: {parsed_objects_counter}')
        return indicators, relationships_lst


class Taxii2FeedClient(STIX2XSOARParser):
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
        update_custom_fields: bool = False,
        enrichment_excluded: bool = False,
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

        super().__init__(
            tlp_color=tlp_color,
            id_to_object={},
            field_map=field_map if field_map else {},
            skip_complex_mode=skip_complex_mode,
            update_custom_fields=update_custom_fields,
            tags=tags if tags else [],
            enrichment_excluded=enrichment_excluded,
        )
        self._conn = None
        self.server = None
        self.api_root = None
        self.collections = None

        self.collection_to_fetch = collection_to_fetch
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

        self.objects_to_fetch = objects_to_fetch
        self.default_api_root = default_api_root

    def init_server(self, version=TAXII_VER_2_1):
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
            self._conn.session.headers = merge_setting(self._conn.session.headers,  # type: ignore[attr-defined]
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
            # disable logging as we might receive client error and try 2.0
            logging.disable(logging.ERROR)
            # try TAXII 2.1
            self.set_api_root()
        # (TAXIIServiceException, HTTPError) should suffice, but sometimes it raises another type of HTTPError
        except HTTPError as e:
            if e.response.status_code != 406 and "version=2.0" not in str(e):
                raise e
            # switch to TAXII 2.0
            self.init_server(version=TAXII_VER_2_0)
            self.set_api_root()
        except Exception as e:
            if "406 Client Error" not in str(e) and "version=2.0" not in str(e):
                raise e
            # switch to TAXII 2.0
            self.init_server(version=TAXII_VER_2_0)
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
                    f"Could not find the provided Collection name {collection_to_fetch} in the available collections. "
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
            demisto.debug(f"Fetching {page_size} objects from TAXII server")
            envelopes = self.poll_collection(page_size, **kwargs)  # got data from server
            indicators = self.load_stix_objects_from_envelope(envelopes, limit)
        except InvalidJSONError as e:
            demisto.debug(f'Excepted InvalidJSONError, continuing with empty result.\nError: {e}, {traceback.format_exc()}')
            # raised when the response is empty, because {} is parsed into '筽'
            indicators = []

        return indicators

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
            demisto.debug(f'Collection is a v20 type collction, {self.collection_to_fetch}')
            return v20.as_pages(get_objects, per_request=page_size, **kwargs)
        demisto.debug(f'Collection is a v21 type collction, {self.collection_to_fetch}')
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
