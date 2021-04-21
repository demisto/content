import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
value = demisto.args().get("value", None)

res = demisto.executeCommand("getIndicator", {"value": value})

if len(res[0]["Contents"]) > 0:
    data = res[0]["Contents"][0]
    score = data["score"]
    vendor = "XSOAR"
    reliability = data["aggregatedReliability"]
    indicatorType = data["indicator_type"]
    expirationStatus = False if data["expirationStatus"] == "active" else True

    dbotscore = {
        "Indicator": value,
        "Type": indicatorType,
        "Vendor": vendor,
        "Score": score,
        "Reliability": reliability,
        "Expired": expirationStatus
    }

    md = tableToMarkdown("Indicator", dbotscore)

    entry = {
        "Type": entryTypes["note"],
        "ReadableContentsFormat": formats['markdown'],
        "ContentsFormat": formats["json"],
        "Contents": dbotscore,
        "EntryContext": {"DBotScoreCache": dbotscore},
        "HumanReadable": md
    }

    demisto.results(entry)

else:
    demisto.results(f"Could not find {value} in cache")
