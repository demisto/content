import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from langdetect import detect_langs

res = detect_langs(demisto.args()["text"])

md = "### Detected languages (probability):\n"
langs = []

for line in res:
    lang = str(line).split(':')[0]
    prob = float(str(line).split(':')[1])
    langs.append({"lang": lang, "probability": prob})
    md += "- " + lang + " (" + str(prob) + ")\n"

demisto.results({"ContentsFormat": formats["json"], "Type": entryTypes["note"],
                "Contents": langs, "HumanReadable": md, "EntryContext": {"langDetect": langs}})
