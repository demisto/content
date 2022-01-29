import socket

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ip = demisto.args().get('ip')

try:
    host_info = socket.gethostbyaddr(ip)
except Exception as e:
    demisto.results({
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "Couln't get the ip host info. Error information: \"{0}\"".format(str(e))
    })
    sys.exit(0)

if not host_info:
    demisto.results({
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "Received an error while trying to get the host information"
    })
    sys.exit(0)

hostname = host_info[0]

output = {
    "Hostname": str(hostname),
    "IP": ip
}

context = {}
context["Endpoint(val.Hostname && val.Hostname === obj.Hostname)"] = output

md = tableToMarkdown("IP to Host", [output])

demisto.results({
    'Type': entryTypes['note'],
    'Contents': context,
    'ContentsFormat': formats['json'],
    'HumanReadable': md,
    'ReadableContentsFormat': formats['markdown'],
    'EntryContext': context
})
