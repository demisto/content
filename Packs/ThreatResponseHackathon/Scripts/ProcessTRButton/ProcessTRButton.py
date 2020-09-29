import demistomock as demisto
from CommonServerPython import *  # noqa: F401

block = demisto.args().get("block")
indicator = demisto.args().get("indicator")

indicatorvalue = indicator["Name"]

# demisto.log(indicator)


if block == "True":
    status = "Blocking in Progress"
else:
    status = "Unblocking in Progress"

demisto.executeCommand("setIndicator", {"id": indicator["id"], "blockprogress": status})

demisto.executeCommand("createNewIncident",
                       {
                           "name": f"Threat Response - {indicatorvalue} [{status}]",
                           "block": block, "type": "Threat Response",
                           "blockedindicator": indicatorvalue,
                           "blockedindicatortype": indicator["Type"]

                       }
                       )
