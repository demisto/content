import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import base64

inc = demisto.incident()
notable_eventid = demisto.args()['event_id']

if notable_eventid:
    notable_eventid = notable_eventid.encode('UTF-8')
    sha1_object = hashlib.sha1(notable_eventid)     # nosec
    sha1 = sha1_object.digest()
    base64_object = base64.b64encode(sha1)
    base64_string = base64_object.decode('UTF-8')
    xref_id = base64_string[:6]
    notable_eventid = notable_eventid.decode()

    splunk_query = f"""`notable`
    | where isnull(notable_xref) and event_id=\"{notable_eventid}\"
    | eval notable_time=_time, xref_label=\"Short ID\", xref_name=\"short_id\", xref_id=\"{xref_id}\"
    | table event_id, notable_time, xref_id, xref_label, xref_name
    | outputlookup append=t notable_xref_lookup"""

    res = demisto.executeCommand("splunk-search", {"query": splunk_query})
    return_results(res[0])
