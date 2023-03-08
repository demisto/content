import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# check to see if they already exist, so you can't run it more than once
results = demisto.executeCommand("demisto-api-get", {"uri": "/indicators/whitelisted"})[0]["Contents"]["response"]

if results:
    current_whitelist = [{"type": x["reputations"], "value":x["value"]} for x in results]
    current_whitelist_names = [x["value"] for x in results]
else:
    current_whitelist = []
    current_whitelist_names = []
required_type = "IP"
values = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

created = []
for value in values:
    if value not in current_whitelist_names:
        demisto.results(demisto.executeCommand("excludeIndicators", {
                        "indicatorsValues": value, "indicatorsTypes": "IP", "reason": "excluded by XSOAR Engineer Training Pack"}))
        created.append(value)
    if value in current_whitelist_names:
        # check if its the IP indicator:
        for current in current_whitelist:
            if current["value"] == value and required_type not in current["type"]:
                demisto.results(demisto.executeCommand("excludeIndicators", {
                                "indicatorsValues": value, "indicatorsTypes": "IP", "reason": "excluded by XSOAR Engineer Training Pack"}))
                created.append(value)

if created:
    demisto.results(f"Created following exclusions: {created}")
else:
    demisto.results("The required exclusions already exist")
