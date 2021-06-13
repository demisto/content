import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


MT = "false"
DR = "false"
MR = "false"
ES = "false"

MT = demisto.executeCommand(
    "demisto-api-get",
    {
        "uri": "/proxyMode",
    })[0]["Contents"]['response']

if MT == True:
    print("true")


DR = demisto.executeCommand(
    "demisto-api-get",
    {
        "uri": "/drMode",
    })[0]["Contents"]['response']

if DR == False:
    print("true")
else:
    print("DR false")


architecture = {
    "multitenant": MT,
    "dr": DR,
    "elasticsearch": ES,
    "multirepo": MR}


demisto.executeCommand("setIncident", architecture)
