import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    value = demisto.args().get("value", None)

    res = demisto.executeCommand("getIndicator", {"value": value})

    if len(res[0]["Contents"]) > 0:
        data = res[0]["Contents"][0]
        score = data["score"]
        vendor = "XSOAR"
        reliability = data.get("aggregatedReliability")
        indicatorType = data["indicator_type"]
        expirationStatus = False if data.get("expirationStatus") == "active" else True

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

        return_results(entry)

    else:
        return_results(f"Could not find {value} in cache")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
