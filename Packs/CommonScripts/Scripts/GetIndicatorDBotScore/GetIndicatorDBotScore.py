import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

INDICATOR_TYPE_DICTIONARY = {
    'IP': "ip",
    'File SHA1': "file",
    'File MD5': "file",
    'File SHA256': "file",
    'Email': "email",
    'URL': "url"
}

indicator = demisto.args()['indicator']
resp = demisto.executeCommand("getIndicator", {'value': indicator})

if True in [isError(entry) for entry in resp]:
    demisto.results(resp)
    sys.exit(0)

data = demisto.get(resp[0], "Contents")

if not data:
    demisto.results("No results.")
    sys.exit(0)

ec = {}  # type: ignore
ec["DBotScore"] = []

for entry in data:
    indicator_type = entry["indicator_type"]
    score = entry["score"]
    source = entry.get('source', '')
    if hasattr(INDICATOR_TYPE_DICTIONARY, indicator_type):
        indicator_type = INDICATOR_TYPE_DICTIONARY[indicator_type]

    ec["DBotScore"].append({
        "Indicator": indicator,
        "Type": indicator_type,
        "Vendor": source,
        "Score": score
    })

md = tableToMarkdown("Indicator DBot Score", ec["DBotScore"])

demisto.results({
    "Type": entryTypes["note"],
    "ContentsFormat": formats["json"],
    "Contents": ec,
    "HumanReadable": md,
    "EntryContext": ec
})
