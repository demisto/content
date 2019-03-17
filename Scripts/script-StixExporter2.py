from stix2 import Indicator, Bundle

demisto_indicator_type = demisto.args().get('indicator_type', '')
value = demisto.args().get('value', '')
source_System = demisto.args().get('source', '')
demisto_Score = demisto.args().get('score', '')
first_seen = demisto.args().get('firstSeen', '')
demisto_created = demisto.args().get('timestamp', '')
last_seen = demisto.args().get('lastSeen', '')

stix_type_and_value = ""

if demisto_indicator_type.lower() == "FileMD5".lower():
    stix_type_and_value = "[file:hashes.md5 = '" + value + "']"
if demisto_indicator_type.lower() == "File SHA1".lower():
    stix_type_and_value = "[file:hashes.md5 = '" + value + "']"

indicator = Indicator(labels=demisto_indicator_type,
                      pattern=stix_type_and_value,
                      source=source_System,
                      created=demisto_created,  # created - timestamp
                      modified=last_seen,  # modified - lastSeen
                      firstSeen=first_seen,  # first_seen - firstSeen
                      score=demisto_Score,  # Reputation
                      allow_custom=True)
bundle = Bundle(indicator)
print(bundle)