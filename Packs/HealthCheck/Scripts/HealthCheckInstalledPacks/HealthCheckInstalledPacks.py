import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

packs = []
need_update = 0

incident = demisto.incidents()[0]
accountName = incident.get("account")
accountName = f"acc_{accountName}/" if accountName != "" else ""

config_json = demisto.executeCommand("core-api-get", {"uri": f"{accountName}contentpacks/installed-expired"})[0]["Contents"][
    "response"
]

for item in config_json:
    packs.append({"packs": item["name"], "currentversion": item["currentVersion"], "updateavailable": item["updateAvailable"]})
    if item["updateAvailable"]:
        need_update += 1


res = []

if need_update > 0:
    res.append(
        {
            "category": "Content packs",
            "severity": "Low",
            "description": "Updates are needed for various content packs",
            "resolution": "Navigate to the market place and update the outdated packs",
        }
    )

if len(packs) > 70:
    res.append(
        {
            "category": "Content packs",
            "severity": "Medium",
            "description": "The number of installed packs on your system is too high",
            "resolution": "Delete unneeded packs, refer to:  https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-6/"
            "cortex-xsoar-admin/marketplace/content-pack-installation/delete-a-content-pack",
        }
    )

demisto.executeCommand(
    "setIncident",
    {
        "healthcheckinstalledpacks": packs,
        "healthchecktotalpacksinstalled": len(packs),
        "healthchecktotaloutdatedpacks": need_update,
    },
)

results = CommandResults(
    readable_output="HealchCheckInstalledPacks Done", outputs_prefix="HealthCheck.ActionableItems", outputs=res
)

return_results(results)
