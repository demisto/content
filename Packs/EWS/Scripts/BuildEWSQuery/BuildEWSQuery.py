import re
import sys

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

reload(sys)
sys.setdefaultencoding("utf-8")    # pylint: disable=E1101

# Regex for removing forward/replay prefixes
p = re.compile('([\[\(] *)?(RE|FWD?) *([-:;)\]][ :;\])-]*|$)|\]+ *$', re.IGNORECASE)

args = {}

if demisto.args().get("from"):
    args["From"] = demisto.args().get("from")
if demisto.args().get("subject"):
    args["Subject"] = demisto.args().get("subject")
if demisto.args().get("attachmentName"):
    args["Attachment"] = demisto.args().get("attachmentName")
if demisto.args().get("body"):
    args["Body"] = demisto.args().get("body")

stripSubject = True if demisto.args().get("stripSubject").lower() == "true" else False
escapeColons = True if demisto.args().get("escapeColons").lower() == "true" else False
if stripSubject and args.get("Subject"):
    # Recursively remove the regex matches only from the beginning of the string
    match_string = args["Subject"]
    location_match = p.match(match_string)
    location = location_match.start() if location_match else -1

    while location == 0 and match_string:
        match_string = p.sub("", match_string, 1)
        location_match = p.match(match_string)
        location = location_match.start() if location_match else -1

    args["Subject"] = match_string

if escapeColons:
    query = " AND ".join(r'{0}\\:"{1}"'.format(key, value) for (key, value) in args.items())

else:
    query = " AND ".join('{0}:"{1}"'.format(key, value) for (key, value) in args.items())


search_last_week = True if demisto.args().get("searchThisWeek").lower() == "true" else False
if search_last_week:
    query = query + ' AND Received:"this week"'

demisto.results({
    'ContentsFormat': formats["json"],
    'Type': entryTypes["note"],
    'Contents': {"EWS": {"Query": query or ' '}},
    "HumanReadable": query or ' ',
    "EntryContext": {"EWS": {"Query": query or ' '}}
})
