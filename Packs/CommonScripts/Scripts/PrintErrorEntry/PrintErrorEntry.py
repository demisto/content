import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

demisto.results({
    "Type": entryTypes["error"],
    "ContentsFormat": formats["text"],
    "Contents": demisto.getArg("message")
})
