import dateparser as dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json

from stix2 import Bundle, ExternalReference, Indicator, Vulnerability

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

counter = 0
for indicator_fields in all_args:
    isIndicator = True
    demisto_indicator_type = all_args[indicator_fields].get('indicator_type', 'Unknown')
    if doubleBackslash:
        value = all_args[indicator_fields].get('value', '').replace('\\', r'\\')
    else:
        value = all_args[indicator_fields].get('value', '')
    source_system = all_args[indicator_fields].get('source', '')
    demisto_score = all_args[indicator_fields].get('score', '')
    first_seen = dateparser.parse(all_args[indicator_fields].get('firstSeen', '1970-01-01T00:00:00+00:00'))
    last_seen = dateparser.parse(all_args[indicator_fields].get('lastSeen', '1970-01-01T00:00:00+00:00'))
    stix_type_and_value = ""

    if "File MD5".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[file:hashes.md5 = '" + value + "']"
    elif "File SHA-1".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[file:hashes.sha1 = '" + value + "']"
    elif "File SHA1".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[file:hashes.sha1 = '" + value + "']"
    elif "File SHA256".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[file:hashes.sha256 = '" + value + "']"
    elif "File SHA-256".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[file:hashes.sha256 = '" + value + "']"
    elif "IP".lower() == demisto_indicator_type.lower():
        stix_type_and_value = "[ipv4-addr:value = '" + value + "']"
    elif "URL".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[url:value = '" + value + "']"
    elif "Email".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[email-message:sender_ref.value = '" + value + "']"
    elif "ssdeep".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[file:hashes.ssdeep = '" + value + "']"
    elif "Username".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[user-account:account_login = '" + value + "']"
    elif "Domain".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[domain-name:value = '" + value + "']"
    elif "Hostname".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[domain-name:value = '" + value + "']"
    elif "Registry Path Reputation".lower() in demisto_indicator_type.lower():
        stix_type_and_value = "[windows-registry-key:key = '{}']".format(value)
    elif "CVE CVSS Score".lower() in demisto_indicator_type.lower():
        stix_type_and_value = value
        isIndicator = False
    else:
        stix_type_and_value = "[{}:value = '{}']".format(demisto_indicator_type.lower(), value)
    label_as_type = demisto_indicator_type.lower()
    if demisto_score.lower() in ["bad", "malicious"]:
        demisto_score = "High"
    elif demisto_score.lower() == "suspicious":
        demisto_score = "Medium"
    elif demisto_score.lower() in ["good", "benign"]:
        demisto_score = "None"
    else:
        demisto_score = "Not Specified"
    if isIndicator:
        try:
            indicator = Indicator(labels=[label_as_type],
                                  pattern=stix_type_and_value,
                                  source=source_system,
                                  created=first_seen,
                                  modified=last_seen,
                                  score=demisto_score,
                                  allow_custom=True,
                                  pattern_type='stix')
        except Exception as ex:
            demisto.info("Indicator type: {}, with the value: {} is not STIX compatible".format(demisto_indicator_type, value))
            demisto.info("Export failure excpetion: {}".format(ex))
            continue
        indicators.append(indicator)
    else:
        try:
            vulnerability = Vulnerability(name=stix_type_and_value,
                                          description=label_as_type,
                                          labels=[label_as_type],
                                          external_references=[ExternalReference(source_name="cve",
                                                                                 external_id=stix_type_and_value)])
        except Exception as ex:
            demisto.info("Indicator type: {}, with the value: {} is not STIX compatible".format(demisto_indicator_type, value))
            demisto.info("Export failure excpetion: {}".format(ex))
            continue
        indicators.append(vulnerability)
    counter += 1
if counter > 1:
    bundle = Bundle(indicators)
    context = {
        'StixExportedIndicators(val.pattern && val.pattern == obj.pattern)': json.loads(str(bundle))
    }
    return_outputs(readable_output="",
                   outputs=context,
                   raw_response=str(bundle))
elif counter == 1:
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
