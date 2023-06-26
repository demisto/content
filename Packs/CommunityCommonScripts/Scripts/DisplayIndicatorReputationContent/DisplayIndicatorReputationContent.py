import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
try:
    scores = demisto.args()["cache"]["scores"]
except Exception:
    demisto.results("No scores cached")
    sys.exit(0)

md = ""

for k, v in scores.items():
    md += v["content"]
    md += "\r\n\r\n"


entry = {
    'Type': entryTypes["note"],
    'Contents': md,
    'ContentsFormat': formats['markdown'],
    'HumanReadable': md,
    'ReadableContentsFormat': formats['markdown']
}

demisto.results(entry)
