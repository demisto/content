import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    values = argToList(demisto.args().get("value", None))
    unique_values = list(set(values))

    return_entries = []
    values_not_found = []
    value_string = f'({" ".join(unique_values)})'
    res = demisto.searchIndicators(
        query=f'value:{value_string}',
        populateFields='value,score,aggregatedReliability,type,expirationStatus',
    )

    if 'iocs' in res and len(res['iocs']) > 0:
        for data in res['iocs']:
            score = data["score"]
            vendor = "XSOAR"
            reliability = data.get("aggregatedReliability")
            indicatorType = data["indicator_type"]
            expirationStatus = data.get("expirationStatus") != "active"
            value = data['value']

            dbotscore = {
                "Indicator": value,
                "Type": indicatorType,
                "Vendor": vendor,
                "Score": score,
                "Reliability": reliability,
                "Expired": expirationStatus
            }

            return_entries.append(dbotscore)
            unique_values.remove(value)

    values_not_found = unique_values

    if len(return_entries) > 0:
        md = tableToMarkdown("Indicator", return_entries)

        entry = {
            "Type": entryTypes["note"],
            "ReadableContentsFormat": formats['markdown'],
            "ContentsFormat": formats["json"],
            "Contents": return_entries,
            "EntryContext": {"DBotScoreCache": return_entries},
            "HumanReadable": md
        }

        return_results(entry)

    if len(values_not_found) == 1:
        return_results(f"Could not find {values_not_found[0]} in cache")

    elif len(values_not_found) > 1:
        md = tableToMarkdown("Could not find in cache", values_not_found, headers=['Values'])
        not_found_values_entry = {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats['markdown'],
            "Contents": md,
            "HumanReadable": md
        }
        return_results(not_found_values_entry)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
