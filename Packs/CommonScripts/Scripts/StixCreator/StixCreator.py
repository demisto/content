import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser


''' IMPORTS '''
import json
from stix2 import Bundle, ExternalReference, Indicator, Vulnerability
from stix2 import AttackPattern, Campaign, Malware, Infrastructure, IntrusionSet, Report, ThreatActor
from stix2 import Tool, CourseOfAction
from stix2.exceptions import InvalidValueError, MissingPropertiesError
from typing import Any
from collections.abc import Callable

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


def search_related_indicators(value: str) -> list[dict]:    # pragma: no cover
    relationships = demisto.searchRelationships({"entities": [value]}).get("data", [])
    demisto.debug(f"found {len(relationships)} relationships")
    query = ""
    for rel in relationships:
        entity_a = rel.get("entityA", "").lower()
        entity_b = rel.get("entityB", "").lower()
        if entity_a == value.lower():
            query += f'"{entity_b}"'
        elif entity_b == value.lower():
            query += f'"{entity_a}"'
        else:
            demisto.info(f"Relationship: {rel} is not relevant for indicator: {value}")
            continue
        query += " or "
    if not query:
        demisto.info(f"No relevant relationship found for indicator: {value}")
        return []
    query = query[:-4]
    demisto.debug(f"using query: {query}")
    demisto_indicators = demisto.searchIndicators(query=query).get("iocs", [])
    demisto.debug(f"found {len(demisto_indicators)} related indicators")
    return demisto_indicators


def get_indicators_stix_ids(value: str, indicator_type: str, indicators: list[dict]) -> list[str]:
    stix_ids = []
    for indicator in indicators:
        if stix_id := indicator.get("stixid"):
            demisto.debug(f"Found stix id: {stix_id} for indicator: {indicator}")
            stix_ids.append(stix_id)
        else:
            if indicator_type in SDOs:
                stix_type = XSOAR_TYPES_TO_STIX_SDO.get(indicator.get("indicator_type", "indicator"))
                stix_id = XSOAR2STIXParser.create_sdo_stix_uuid(indicator, stix_type, PAWN_UUID, indicator.get("value", ""))
            elif indicator_type in SCOs:
                stix_type = XSOAR_TYPES_TO_STIX_SCO.get(indicator.get("indicator_type", "indicator"), 'indicator')
                stix_id = XSOAR2STIXParser.create_sco_stix_uuid(indicator, stix_type, indicator.get("value", ""))
            else:
                demisto.info(f"Indicator type: {indicator_type}, with the value: {value} is unknown.")
                continue
            demisto.debug(f"Created stix id: {stix_id} for indicator: {indicator}")
        stix_ids.append(stix_id)
    return stix_ids


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

        value = xsoar_indicator.get("value", "").replace("\\", "\\\\") if doubleBackslash else xsoar_indicator.get("value", "")

        if demisto_indicator_type in XSOAR_TYPES_TO_STIX_SCO and is_sco:
            stix_type = XSOAR_TYPES_TO_STIX_SCO.get(demisto_indicator_type)
            stix_id = XSOAR2STIXParser.create_sco_stix_uuid(xsoar_indicator, stix_type, value)
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
            stix_id = XSOAR2STIXParser.create_sdo_stix_uuid(xsoar_indicator, stix_type, PAWN_UUID, value)
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
                demisto.debug(f"Creating an indicator with the following pattern: [{SCOs[indicator_type]} = '{value}']")

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

                    if indicator_type == 'report':
                        kwargs['published'] = dateparser.parse(xsoar_indicator.get('timestamp', ''))

                        related_indicators = search_related_indicators(value)
                        stix_ids = get_indicators_stix_ids(value, indicator_type, related_indicators)
                        kwargs["object_refs"] = stix_ids
                    demisto.debug(f"Creating {indicator_type} indicator: {value}, with the following kwargs: {kwargs}")
                    indicator = SDOs[indicator_type](
                        name=value,
                        **kwargs
                    )

                    indicators.append(indicator)

                except (KeyError, TypeError):
                    demisto.info(
                        f"Indicator type: {demisto_indicator_type}, with the value: {value} is not STIX compatible")
                    demisto.info(f"Export failure exception: {traceback.format_exc()}")
                    continue

                except (InvalidValueError, MissingPropertiesError):
                    demisto.info(
                        f"Indicator type: {demisto_indicator_type}, with the value: {value} is not STIX compatible. Skipping.")
                    demisto.info(f"Export failure exception: {traceback.format_exc()}")
                    continue

            except (InvalidValueError, MissingPropertiesError):
                demisto.info(
                    f"Indicator type: {demisto_indicator_type}, with the value: {value} is not STIX compatible. Skipping.")
                demisto.info(f"Export failure exception: {traceback.format_exc()}")
                continue
    if len(indicators) > 1:
        bundle = Bundle(indicators, allow_custom=True, spec_version='2.1')
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


from TAXII2ApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
