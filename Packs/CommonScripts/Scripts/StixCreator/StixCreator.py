import dateparser as dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' IMPORTS '''
import json

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
    "username": "user-account:account_login",
    "domain": "domain-name:value",
    "hostname": "domain-name:value",
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


def main():

    user_args = demisto.args().get('indicators', 'Unknown')
    doubleBackslash = demisto.args().get('doubleBackslash', True)
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

        demisto_indicator_type = all_args[indicator_fields].get('indicator_type', 'Unknown')

        if doubleBackslash:
            value = all_args[indicator_fields].get('value', '').replace('\\', r'\\')
        else:
            value = all_args[indicator_fields].get('value', '')

        demisto_score = all_args[indicator_fields].get('score', '').lower()

        if demisto_score in ["bad", "malicious"]:
            kwargs["score"] = "High"

        elif demisto_score == "suspicious":
            kwargs["score"] = "Medium"

        elif demisto_score in ["good", "benign"]:
            kwargs["score"] = "None"

        else:
            kwargs["score"] = "Not Specified"

        kwargs["created"] = dateparser.parse(all_args[indicator_fields].get('timestamp', ''))
        kwargs["modified"] = dateparser.parse(all_args[indicator_fields].get('lastSeen', f'{kwargs["created"]}'))
        kwargs["id"] = all_args[indicator_fields].get('stixid', '')
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

            demisto.debug(f"{demisto_indicator_type} isn't an SCO checking other IOC types")

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
        context = {
            'StixExportedIndicators(val.pattern && val.pattern == obj.pattern)': json.loads(str(indicators[0]))
        }
        res = (CommandResults(readable_output="",
                              outputs=context,
                              raw_response=str(indicators[0])))
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
