import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

#
ip = demisto.args()["ip"]

if ip.startsWith("172"):
    demisto.results({
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "could not block IP for internal ip address"

    })
    return

demisto.resulst(demisto.executeCommand('BlockIPCopy', demisto.args()))
