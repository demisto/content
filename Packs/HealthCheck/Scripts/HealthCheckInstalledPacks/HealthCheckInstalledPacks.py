import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

PACK_THRESHOLD = 70
RESOLUTION_V6 = (
    "Delete unneeded packs, refer to: "
    "https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.14/Cortex-XSOAR-Administrator-Guide/Delete-a-Content-Pack"
)
RESOLUTION_V8 = (
    "Delete unneeded packs, refer to: "
    "https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Manage-content-packs"
)


def main():
    if is_demisto_version_ge("8.0.0"):
        uri = "contentpacks/installed-expired"
        resolution = RESOLUTION_V8
    else:
        account_name = demisto.incidents()[0].get("account", "")
        uri = f"acc_{account_name}/contentpacks/installed-expired" if account_name else "contentpacks/installed-expired"
        resolution = RESOLUTION_V6

    result = execute_command("core-api-get", {"uri": uri})
    if isinstance(result, list):
        config_json = result[0].get("response", []) if result else []
    else:
        config_json = result.get("response", [])

    packs = []
    need_update = 0
    for item in config_json:
        packs.append(
            {
                "packs": item["name"],
                "currentversion": item["currentVersion"],
                "updateavailable": item["updateAvailable"],
            }
        )
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

    if len(packs) > PACK_THRESHOLD:
        res.append(
            {
                "category": "Content packs",
                "severity": "Medium",
                "description": "The number of installed packs on your system is too high",
                "resolution": resolution,
            }
        )

    execute_command(
        "setIncident",
        {
            "healthcheckinstalledpacks": packs,
            "healthchecktotalpacksinstalled": len(packs),
            "healthchecktotaloutdatedpacks": need_update,
        },
    )
    return_results(
        CommandResults(
            readable_output="HealthCheckInstalledPacks Done",
            outputs_prefix="HealthCheck.ActionableItems",
            outputs=res,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
