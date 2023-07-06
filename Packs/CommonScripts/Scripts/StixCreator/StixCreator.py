import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser as dateparser


''' IMPORTS '''
import json
import uuid
from stix2 import Bundle, ExternalReference, Indicator, Vulnerability
from stix2 import AttackPattern, Campaign, Malware, Infrastructure, IntrusionSet, Report, ThreatActor
from stix2 import Tool, CourseOfAction
from typing import Any, Callable

SCOs: dict[str, str] = {  # pragma: no cover
    "md5": "file:hashes.md5",
    "sha1": "file:hashes.sha1",
    "sha256": "file:hashes.sha256",
    "ssdeep": "file:hashes.ssdeep",
    "ip": "ipv4-addr:value",
    "cidr": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "ipv6cidr": "ipv6-addr:value",
    "url": "url:value",
    "email": "email-message:sender_ref.value",
    "account": "user-account:account_login",
    "domain": "domain-name:value",
    "host": "domain-name:value",
    "registry key": "windows-registry-key:key",
    "asn": "autonomous-system:name"
}

SDOs: dict[str, Callable] = {  # pragma: no cover
    "malware": Malware,
    "attack pattern": AttackPattern,
    "campaign": Campaign,
    "infrastructure": Infrastructure,
    "tool": Tool,
    "intrusion set": IntrusionSet,
    "report": Report,
    "threat actor": ThreatActor,
    "cve": Vulnerability,
    "course of action": CourseOfAction
}

SCO_DET_ID_NAMESPACE = uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7')
PAWN_UUID = uuid.uuid5(uuid.NAMESPACE_URL, 'https://www.paloaltonetworks.com')

XSOAR_TYPES_TO_STIX_SCO = {   # pragma: no cover
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
}

XSOAR_TYPES_TO_STIX_SDO = {  # pragma: no cover
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
}


HASH_TYPE_TO_STIX_HASH_TYPE = {  # pragma: no cover
    'md5': 'MD5',
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha512': 'SHA-512',
}


def hash_type(value: str) -> str:  # pragma: no cover
    length = len(value)
    if length == 32:
        return 'md5'
    if length == 40:
        return 'sha1'
    if length == 64 and ":" in value:
        return 'ssdeep'
    elif length == 64:
        return 'sha256'
    if length == 128:
        return 'sha512'
    return ''


def guess_indicator_type(type_: str, val: str) -> str:
    # try to guess by key
    for sco in SCOs:
        if sco in type_:
            return sco

    # try to auto_detect by value
    return (auto_detect_indicator_type(val) or type_).lower()


def create_sco_stix_uuid(xsoar_indicator: dict, stix_type: Optional[str], value: str) -> str:
    """
    Create uuid for SCO objects.
    Args:
        xsoar_indicator: dict - The XSOAR representation of the indicator.
        stix_type: Optional[str] - The indicator type according to STIX.
        value: str - The value of the indicator.
    Returns:
        The uuid that represents the indicator according to STIX.
    """
    if stixid := xsoar_indicator.get('CustomFields', {}).get('stixid'):
        return stixid
    if stix_type == 'user-account':
        account_type = xsoar_indicator.get('CustomFields', {}).get('accounttype')
        user_id = xsoar_indicator.get('CustomFields', {}).get('userid')
        unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE,
                               f'{{"account_login":"{value}","account_type":"{account_type}","user_id":"{user_id}"}}')
    elif stix_type == 'windows-registry-key':
        unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"key":"{value}"}}')
    elif stix_type == 'file':
        if 'md5' == get_hash_type(value):
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"MD5":"{value}"}}}}')
        elif 'sha1' == get_hash_type(value):
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-1":"{value}"}}}}')
        elif 'sha256' == get_hash_type(value):
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-256":"{value}"}}}}')
        elif 'sha512' == get_hash_type(value):
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"hashes":{{"SHA-512":"{value}"}}}}')
        else:
            unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"value":"{value}"}}')
    else:
        unique_id = uuid.uuid5(SCO_DET_ID_NAMESPACE, f'{{"value":"{value}"}}')

    return f'{stix_type}--{unique_id}'


def create_sdo_stix_uuid(xsoar_indicator: dict, stix_type: Optional[str], value: str) -> str:
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
    if stix_type == 'attack-pattern':
        if mitre_id := xsoar_indicator.get('CustomFields', {}).get('mitreid'):
            unique_id = uuid.uuid5(PAWN_UUID, f'{stix_type}:{mitre_id}')
        else:
            unique_id = uuid.uuid5(PAWN_UUID, f'{stix_type}:{value}')
    else:
        unique_id = uuid.uuid5(PAWN_UUID, f'{stix_type}:{value}')

    return f'{stix_type}--{unique_id}'


def add_file_fields_to_indicator(xsoar_indicator: Dict, value: str) -> Dict:
    """
    Create the hashes dictionary for the indicator object.
    Args:
        xsoar_indicator: Dict - The XSOAR representation of the indicator.
        value: str - The value of the indicator.
    Returns:
        The dictionary with the file hashes.
    """
    hashes_dict = {}
    for hash_kind in ['md5', 'sha1', 'sha256', 'sha512']:
        if get_hash_type(value) == hash_kind:
            hashes_dict[HASH_TYPE_TO_STIX_HASH_TYPE.get(hash_kind)] = value
        elif hash_kind in xsoar_indicator:
            hashes_dict[HASH_TYPE_TO_STIX_HASH_TYPE.get(hash_kind)] = xsoar_indicator.get(hash_kind, '')
    return hashes_dict


def create_stix_sco_indicator(stix_id: Optional[str], stix_type: Optional[str], value: str, xsoar_indicator: Dict) -> Dict:
    """
    Create stix sco indicator object.
    Args:
        stix_id: Optional[str] - The stix id of the indicator.
        stix_type: str - the stix type of the indicator.
        xsoar_indicator: Dict - The XSOAR representation of the indicator.
        value: str - The value of the indicator.
    Returns:
        The Dictionary representing the stix indicator.
    """
    stix_indicator: Dict[str, Any] = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id
    }
    if stix_type == 'file':
        stix_indicator['hashes'] = add_file_fields_to_indicator(xsoar_indicator, value)
    elif stix_type == 'autonomous-system':
        stix_indicator['number'] = value
        stix_indicator['name'] = xsoar_indicator.get('name', '')
    else:
        stix_indicator['value'] = value
    return stix_indicator


def main():

    user_args = demisto.args().get('indicators', 'Unknown')
    doubleBackslash = demisto.args().get('doubleBackslash', True)
    is_sco = argToBoolean(demisto.args().get('sco_flag', False))
    all_args = {}

    if isinstance(user_args, dict):
        all_args = json.loads(json.dumps(user_args))

    else:
        try:
            all_args = json.loads(demisto.args().get('indicators', 'Unknown'))
        except:     # noqa: E722
            return_error('indicators argument is invalid json object')

    indicators = []

    for indicator_fields in all_args:
        kwargs: dict[str, Any] = {"allow_custom": True}

        xsoar_indicator = all_args[indicator_fields]
        demisto_indicator_type = xsoar_indicator.get('indicator_type', 'Unknown')

        if doubleBackslash:
            value = xsoar_indicator.get('value', '').replace('\\', r'\\')
        else:
            value = xsoar_indicator.get('value', '')

        if demisto_indicator_type in XSOAR_TYPES_TO_STIX_SCO and is_sco:
            stix_type = XSOAR_TYPES_TO_STIX_SCO.get(demisto_indicator_type)
            stix_id = create_sco_stix_uuid(xsoar_indicator, stix_type, value)
            stix_indicator = create_stix_sco_indicator(stix_id, stix_type, value, xsoar_indicator)
            indicators.append(stix_indicator)

        else:
            demisto_score = xsoar_indicator.get('score', '').lower()

            if demisto_score in ["bad", "malicious"]:
                kwargs["score"] = "High"

            elif demisto_score == "suspicious":
                kwargs["score"] = "Medium"

            elif demisto_score in ["good", "benign"]:
                kwargs["score"] = "None"

            else:
                kwargs["score"] = "Not Specified"

            stix_type = XSOAR_TYPES_TO_STIX_SDO.get(demisto_indicator_type, 'indicator')
            stix_id = create_sdo_stix_uuid(xsoar_indicator, stix_type, value)
            kwargs["id"] = stix_id

            kwargs["created"] = dateparser.parse(xsoar_indicator.get('timestamp', ''))
            kwargs["modified"] = dateparser.parse(xsoar_indicator.get('lastSeen', f'{kwargs["created"]}'))
            kwargs["labels"] = [demisto_indicator_type.lower()]
            kwargs["description"] = xsoar_indicator.get('description', '')

            kwargs = {k: v for k, v in kwargs.items() if v}  # Removing keys with empty strings

            try:
                indicator_type = demisto_indicator_type.lower().replace("-", "")
                if indicator_type == 'file':
                    indicator_type = hash_type(value)
                if indicator_type not in SCOs and indicator_type not in SDOs:
                    indicator_type = guess_indicator_type(indicator_type, value)
                indicator = Indicator(pattern=f"[{SCOs[indicator_type]} = '{value}']",
                                      pattern_type='stix',
                                      **kwargs)
                indicators.append(indicator)

            except KeyError:

                demisto.debug(f"{demisto_indicator_type} isn't a SCO, checking other IOC types")

                try:
                    indicator_type = demisto_indicator_type.lower()

                    if indicator_type == 'cve':
                        kwargs["external_references"] = [ExternalReference(source_name="cve", external_id=value)]

                    elif indicator_type == "attack pattern":
                        try:
                            mitreid = xsoar_indicator.get('mitreid', '')
                            if mitreid:
                                kwargs["external_references"] = [ExternalReference(source_name="mitre", external_id=mitreid)]

                        except KeyError:
                            pass

                    elif indicator_type == 'malware':

                        kwargs['is_family'] = argToBoolean(xsoar_indicator.get('ismalwarefamily', 'False').lower())

                    indicator = SDOs[indicator_type](
                        name=value,
                        **kwargs
                    )

                    indicators.append(indicator)

                except (KeyError, TypeError) as e:
                    demisto.info(
                        "Indicator type: {}, with the value: {} is not STIX compatible".format(demisto_indicator_type, value))
                    demisto.info("Export failure excpetion: {}".format(e))
                    continue

    if len(indicators) > 1:
        bundle = Bundle(indicators, allow_custom=True)
        context = {
            'StixExportedIndicators(val.pattern && val.pattern == obj.pattern)': json.loads(str(bundle))
        }
        res = (CommandResults(readable_output="",
                              outputs=context,
                              raw_response=str(bundle)))

    elif len(indicators) == 1:
        bundle = Bundle(indicators, allow_custom=True)
        bundle_obj = bundle.get('objects', [])[0]
        context = {
            'StixExportedIndicators(val.pattern && val.pattern == obj.pattern)': json.loads(str(bundle_obj))
        }
        res = (CommandResults(readable_output="",
                              outputs=context,
                              raw_response=str(bundle_obj)))
    else:
        context = {
            'StixExportedIndicators': {}
        }
        res = CommandResults(readable_output="",
                             outputs=context,
                             raw_response={})

    return_results(res)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
