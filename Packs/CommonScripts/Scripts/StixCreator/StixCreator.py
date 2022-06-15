import dateparser as dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' IMPORTS '''
import json

from stix2 import Bundle, ExternalReference, Indicator
from stix2 import AttackPattern, Campaign, Malware, Infrastructure, IntrusionSet, Report, ThreatActor
from stix2 import Tool, Vulnerability, CourseOfAction

SCOs = {
    "file md5": "[file:hashes.md5 ='{}']",
    "file sha1": "[file:hashes.sha1 = '{}']",
    "file sha256": "[file:hashes.sha256 = '{}']",
    "ssdeep": "[file:hashes.ssdeep = '']",
    "ip": "[ipv4-addr:value = '{}']",
    "cidr": "[ipv4-addr:value = '{}']",
    "ipv6": "[ipv6-addr:value = '{}']",
    "ipv6cidr": "[ipv6-addr:value = '{}']",
    "url": "[url:value = '{}']",
    "email": "[email-message:sender_ref.value = '{}']",
    "username": "[user-account:account_login = '{}']",
    "domain": "[domain-name:value = '{}']",
    "hostname": "[domain-name:value = '{}']",
    "registry path reputation": "[windows-registry-key:key = '{}']"
}

SDOs = {
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

indicators = []


userArgs = demisto.args().get('indicators', 'Unknown')
doubleBackslash = demisto.args().get('doubleBackslash', True)
all_args = {}

if isinstance(userArgs, dict):
    all_args = json.loads(json.dumps(userArgs))

else:
    try:
        all_args = json.loads(demisto.args().get('indicators', 'Unknown'))
    except:     # noqa: E722
        return_error('indicators argument is invalid json object')

for indicator_fields in all_args:
    kwargs = {"allow_custom": True}

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
        indicator = Indicator(pattern=SCOs[indicator_type].format(value),
                              pattern_type='stix',
                              **kwargs)

        indicators.append(indicator)

    except KeyError:
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

            indicator = SDOs.get(indicator_type)(
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
    bundle = Bundle(indicators)
    context = {
        'StixExportedIndicators(val.pattern && val.pattern == obj.pattern)': json.loads(str(bundle))
    }
    return_outputs(readable_output="",
                   outputs=context,
                   raw_response=str(bundle))
elif len(indicators) == 1:
    context = {
        'StixExportedIndicators(val.pattern && val.pattern == obj.pattern)': json.loads(str(indicators[0]))
    }
    return_outputs(readable_output="",
                   outputs=context,
                   raw_response=str(indicators[0]))
else:
    context = {
        'StixExportedIndicators': {}
    }
    return_outputs(readable_output="",
                   outputs=context,
                   raw_response={})
