import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

# Get current incident data
emailto = demisto.get(demisto.incidents()[0], 'CustomFields.emailto')
emailfrom = demisto.get(demisto.incidents()[0], 'CustomFields.emailfrom')

if not (emailto and emailfrom):
    demisto.results("None")
    sys.exit(0)

resp = demisto.executeCommand("getIncidents", {"query": "emailto:{0} --status:Closed".format(emailto)})
if isError(resp[0]):
    demisto.results(resp)
    sys.exit(0)

emailto_total = demisto.get(resp[0], "Contents.total")

resp = demisto.executeCommand("getIncidents", {"query": "emailfrom:{0} --status:Closed".format(emailfrom)})
if isError(resp[0]):
    demisto.results(resp)
    sys.exit(0)

emailfrom_total = demisto.get(resp[0], "Contents.total")

data = {
    "Type": 17,
    "ContentsFormat": "bar",
    "Contents": {
        "stats": [
            {
                "data": [
                    emailto_total
                ],
                "groups": None,
                "name": str(emailto),
                "label": "To: " + str(emailto),
                "color": "rgb(255, 23, 68)"
            },
            {
                "data": [
                    emailfrom_total
                ],
                "groups": None,
                "name": str(emailfrom),
                "label": "From: " + str(emailfrom),
                "color": "rgb(255, 144, 0)"
            }
        ],
        "params": {
            "layout": "vertical"
        }
    }
}

demisto.results(data)
