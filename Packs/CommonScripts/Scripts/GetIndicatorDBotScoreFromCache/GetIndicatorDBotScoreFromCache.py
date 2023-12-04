import contextlib
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    values: list[str] = argToList(demisto.args().get("value", None))
    unique_values: set[str] = {v.lower() for v in values}  # search query is case insensitive

    query = f"""value:({' '.join([f'"{value}"' for value in unique_values])})"""
    demisto.debug(f'{query=}')

    res = demisto.searchIndicators(
        query=query,
        populateFields='name,score,aggregatedReliability,type,expirationStatus',
    )

    return_entries = []

    if 'iocs' in res and len(res['iocs']) > 0:
        for data in res['iocs']:
            score = data["score"]
            vendor = "XSOAR"
            reliability = data.get("aggregatedReliability")
            indicatorType = data["indicator_type"]
            expirationStatus = data.get("expirationStatus") != "active"
            value: str = data["value"]

            dbotscore = {
                "Indicator": value,
                "Type": indicatorType,
                "Vendor": vendor,
                "Score": score,
                "Reliability": reliability,
                "Expired": expirationStatus
            }

            return_entries.append(dbotscore)
            with contextlib.suppress(KeyError):  # for multiple IOCs with same value but different casing
                unique_values.remove(value.lower())

    values_not_found = list({v for v in values if v.lower() in unique_values})  # return the values with the original casing

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


if __name__ in ("__builtin__", "builtins", "__main__"):  # pragma: no cover
    main()
