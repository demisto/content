import dateparser as dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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
    "registry key": "windows-registry-key:key"
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

XSOAR_TYPES_TO_STIX_SCO = {
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
    FeedIndicatorType.AS: 'asn',
}

XSOAR_TYPES_TO_STIX_SDO = {
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: 'attack-pattern',
    ThreatIntel.ObjectsNames.CAMPAIGN: 'campaign',
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: 'course-of-action',
    ThreatIntel.ObjectsNames.INFRASTRUCTURE: 'infrastructure',
    ThreatIntel.ObjectsNames.INTRUSION_SET: 'instruction-set',
    ThreatIntel.ObjectsNames.REPORT: 'report',
    ThreatIntel.ObjectsNames.THREAT_ACTOR: 'threat-actor',
    ThreatIntel.ObjectsNames.TOOL: 'tool',
    ThreatIntel.ObjectsNames.MALWARE: 'malware',
    FeedIndicatorType.CVE: 'vulnerability',
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
    Create uuid for sco objects.
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
    Create uuid for sdo objects.
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

    demisto.debug(f'StixCreator {demisto.args()=}\n{user_args=}\n{all_args=}')
    indicators = []

    for indicator_fields in all_args:
        kwargs: dict[str, Any] = {"allow_custom": True}

        demisto_indicator_type = all_args[indicator_fields].get('indicator_type', 'Unknown')

        if doubleBackslash:
            value = all_args[indicator_fields].get('value', '').replace('\\', r'\\')
        else:
            value = all_args[indicator_fields].get('value', '')

        if demisto_indicator_type in XSOAR_TYPES_TO_STIX_SCO and is_sco:
            stix_type = XSOAR_TYPES_TO_STIX_SCO.get(demisto_indicator_type)
            stix_id = create_sco_stix_uuid(all_args[indicator_fields], stix_type, value)
            indicator = {
                "type": stix_type,
                "spec_version": "2.1",
                "value": value,
                "id": stix_id
            }
            indicators.append(indicator)
        else:
            demisto_score = all_args[indicator_fields].get('score', '').lower()

            if demisto_score in ["bad", "malicious"]:
                kwargs["score"] = "High"

            elif demisto_score == "suspicious":
                kwargs["score"] = "Medium"

            elif demisto_score in ["good", "benign"]:
                kwargs["score"] = "None"

            else:
                kwargs["score"] = "Not Specified"

            stix_type = XSOAR_TYPES_TO_STIX_SDO.get(demisto_indicator_type, 'indicator')
            stix_id = create_sdo_stix_uuid(all_args[indicator_fields], stix_type, value)
            kwargs["id"] = stix_id

            kwargs["created"] = dateparser.parse(all_args[indicator_fields].get('timestamp', ''))
            kwargs["modified"] = dateparser.parse(all_args[indicator_fields].get('lastSeen', f'{kwargs["created"]}'))
            kwargs["labels"] = [demisto_indicator_type.lower()]
            kwargs["description"] = all_args[indicator_fields].get('description', '')

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
                            mitreid = all_args[indicator_fields].get('mitreid', '')
                            if mitreid:
                                kwargs["external_references"] = [ExternalReference(source_name="mitre", external_id=mitreid)]

                        except KeyError:
                            pass

                    elif indicator_type == 'malware':

                        kwargs['is_family'] = argToBoolean(all_args[indicator_fields].get('ismalwarefamily', 'False').lower())

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
