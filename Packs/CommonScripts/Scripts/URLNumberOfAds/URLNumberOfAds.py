import re
from functools import reduce

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401


def ads(html, termlist):
    results: dict = {}
    tags = re.findall("<[^/][^>]*>", html)
    for item in termlist.split("\n"):
        if not item.strip():
            continue
        if item.startswith(("!", "[Adbl", "@@")):
            continue
        if item.startswith("###"):
            item = item[3:]
        if item.startswith("||"):
            item = item[2 : item.find("^$")]
        for t in tags:
            if item in t:
                results[item] = (results[item] + 1) if item in results else 1
    return results


def main():  # pragma: no cover
    u = demisto.args()["url"]
    r = requests.get(u)
    reasy = requests.get(demisto.args().get("easylist", "https://easylist.github.io/easylist/easylist.txt"))
    res = ads(r.text, reasy.text)
    nicerRes = [{"URL": k, "Count": res[k]} for k in res]
    totalAds = reduce(lambda x, y: x + y["Count"], nicerRes, 0)
    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": nicerRes,
            "ContentsFormat": formats["json"],
            "HumanReadable": tableToMarkdown("AD URLs", nicerRes) + "\nTotal: " + str(totalAds),
            "EntryContext": {"Ads": nicerRes, "URL(val.Data == obj.Data)": {"Data": u, "AdsCount": totalAds}},
        }
    )


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
