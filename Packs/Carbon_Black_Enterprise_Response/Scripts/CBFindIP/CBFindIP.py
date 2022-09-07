import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

t = []  # type: list
found = []
args = demisto.args()
ips = argToList(args.get("ip"))
for ip in ips:
    for e in demisto.executeCommand("cb-get-processes", {"query": "ipaddr:" + ip}):
        if isError(e):
            return_error(e.get("Contents"))
        else:
            found.append(ip)
            t += e.get("HumanReadable")
if t:
    appendContext("found_ips", ",".join(found), dedup=True)
    return_results(
        {
            "ContentsFormat": formats.get("markdown"),
            "Type": entryTypes.get("note"),
            "Contents": e.get("HumanReadable"),
            "EntryContext": e.get("EntryContext"),
        }
    )
