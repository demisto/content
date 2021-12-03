import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from langdetect import detect_langs


def detect_language(text):
    res = detect_langs(text)

    md = "### Detected languages (probability):\n"
    langs = []

    for line in res:
        lang = str(line).split(':')[0]
        prob = float(str(line).split(':')[1])
        langs.append({"lang": lang, "probability": prob})
        md += "- " + lang + " (" + str(prob) + ")\n"

    demisto.results({"ContentsFormat": formats["json"], "Type": entryTypes["note"],
                     "Contents": langs, "HumanReadable": md, "EntryContext": {"langDetect": langs}})


def main():
    text = demisto.args().get('text')
    detect_language(text)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
