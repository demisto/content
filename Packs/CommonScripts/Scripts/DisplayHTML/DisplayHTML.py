import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

html = demisto.args().get("html")
note = demisto.args().get("markAsNote")
header = demisto.args().get("header")

note = True if note and note.lower() == "true" else False
if header:
    html = "<h1>{0}</h1></br>{1}".format(header, html)

demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html,
    'Note': note
})
