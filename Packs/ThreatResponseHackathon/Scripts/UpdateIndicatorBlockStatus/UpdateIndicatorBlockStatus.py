import demistomock as demisto
from CommonServerPython import *  # noqa: F401

# Python template - reading arguments, calling a command, handling errors and returning results
res = []
# Constant and mandatory arguments
dArgs = {
    "indicator": demisto.args()["indicator"],
    "integration": demisto.args()["integration"],
    "blocked": demisto.args()["blocked"]
}


res = demisto.executeCommand("getIndicator", {"value": dArgs["indicator"]})

if "blockstatus" in res[0]["Contents"][0]["CustomFields"]:
    bsGridField = res[0]["Contents"][0]["CustomFields"]["blockstatus"]
else:
    bsGridField = []


indicatorID = res[0]["Contents"][0]["id"]

if not isinstance(bsGridField, list):
    bsGridField = [bsGridField]

found = False

for entry in bsGridField:
    if "integration" in entry and entry["integration"] == dArgs["integration"]:
        entry["blocked"] = dArgs["blocked"]
        found = True


if not found:
    bsGridField.append({"blocked": dArgs["blocked"], "integration": dArgs["integration"]})

demisto.executeCommand("setIndicator", {"id": indicatorID, "blockstatus": bsGridField})

demisto.results("Success")
