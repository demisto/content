import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

filter_arg = json.loads(demisto.args().get("filter", json.dumps({"tags": ["report"]})))

raw_entries = None

if filter_arg:
    raw_entries = demisto.executeCommand('getEntries', {"id": demisto.incident().get("id"), "filter": filter_arg})

if raw_entries:
    entries = []

    for entry in raw_entries:
        entries.append(str(entry["Contents"]))

else:
    entries = ["No entries tagged with 'report' tag"]

# demisto.results(str(entries))

result = {
    'Type': entryTypes["note"],
    'Contents': "\n".join(entries),
    'ContentsFormat': formats['markdown'],
    'HumanReadable': "\n".join(entries),
    'ReadableContentsFormat': formats['markdown']
}

demisto.results(result)
