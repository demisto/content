import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

payload = {"query": "system:T"}
res = demisto.executeCommand("core-api-post", {"uri": "automation/search", "body": json.dumps(payload)})[0]["Contents"][
    "response"
]

if not res["scripts"]:
    res["scripts"] = []

scriptsList = []
for item in res["scripts"]:
    script = {}
    if item.get("detached") is not None and item["detached"] is True:
        script["name"] = item["name"]
        scriptsList.append(script)


return_results({"total": len(scriptsList), "data": scriptsList})
