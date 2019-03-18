
from stix2 import Indicator, Bundle

demisto_indicator_type = demisto.args().get('indicator_type','')
value = demisto.args().get('value','')
source_System = demisto.args().get('source','')
demisto_Score = demisto.args().get('score','')
first_seen = demisto.args().get('firstSeen','')
demisto_created = demisto.args().get('timestamp','')
last_seen = demisto.args().get('lastSeen','')
createBundle = demisto.args().get('createBundle','False')

stix_type_and_value = ""

if demisto_indicator_type.lower() == "File MD5".lower():
    stix_type_and_value = "[file:hashes.md5 = '" + value + "']"
if demisto_indicator_type.lower() == "File SHA-1".lower():
    stix_type_and_value = "[file:hashes.sha-1 = '" + value + "']"
if demisto_indicator_type.lower() == "File SHA-256".lower():
    stix_type_and_value = "[file:hashes.sha-256 = '" + value + "']"
if demisto_indicator_type.lower() == "IP".lower():
    stix_type_and_value = "[ipv4-addr:value = '" + value + "']"
if demisto_indicator_type.lower() == "URL".lower():
    stix_type_and_value = "[url:value = '" + value + "']"
else:
    stix_type_and_value = "[" + demisto_indicator_type.lower() +":value = '" + value + "']"

indicator = Indicator(labels=demisto_indicator_type,
                      pattern=stix_type_and_value,
                      source=source_System,
                      created=demisto_created,
                      modified=last_seen,
                      firstSeen=first_seen,
                      score=demisto_Score,
                      allow_custom=True)

if createBundle.lower() == "true":
    bundle = Bundle(indicator)
    print(bundle)
else:
    print(indicator)

