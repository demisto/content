import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import re


def get_xsiam_license_data():
    """
    Fetches license and tenant info for XSIAM using the /public_api/v1/system/get_tenant_info endpoint.
    """
    try:
        res = demisto.executeCommand(
            "core-api-post",
            {"uri": "/public_api/v1/system/get_tenant_info", "body": {}},
        )

        if is_error(res):
            return_error(f"Failed to fetch XSIAM tenant info: {get_error(res)}")

        contents = res[0].get("Contents", {}).get("response", {})
        details = contents.get("reply", {})

        licenseTypeKey = [key for key, value in details.items() if re.match(r"purchased_xsiam_(?!gb).*$", key)][0]
        licenseTypeString = licenseTypeKey.removeprefix("purchased_")
        licenseType = licenseTypeString.replace("_", " ").title()
        split = licenseType.split(" ")
        split[0] = split[0].upper()
        licenseType = " ".join(split)

        licenseDetails = []

        licenseDetails.append({"field": "License Type", "value": licenseType})

        licenseBreakdownRaw = details.get(licenseTypeKey, {})
        if licenseBreakdownRaw != {}:
            licenseBreakdown = []
            licenseBreakdown.append(
                str(licenseBreakdownRaw.get("agents"))
                + " Agents (enabled: "
                + str(details.get("data_enabled_pro_per_endpoint"))
                + ")"
            )
            licenseBreakdown.append(str(licenseBreakdownRaw.get("users")) + " Users")
            licenseBreakdown.append(str(licenseBreakdownRaw.get("gb")) + " GB")
            licenseDetails.append({"field": "License Breakdown", "value": ",\n".join(licenseBreakdown)})

        expirationString = licenseTypeString + "_expiration"
        licenseDetails.append({"field": "License Expiration", "value": details.get(expirationString)})

        licenseDetails.append(
            {
                "field": "Purchased Compute Units",
                "value": details.get("purchased_compute_unit"),
            }
        )
        licenseDetails.append(
            {
                "field": "Hot Storage Retention (months)",
                "value": details.get("purchased_xsiam_gb_hot"),
            }
        )
        licenseDetails.append(
            {
                "field": "Cold Storage Retention (months)",
                "value": details.get("purchased_xsiam_gb_cold"),
            }
        )

        trialsRaw = [key for key, value in details.items() if re.compile(r"_is_trial").search(key)]
        trialNames = []
        for item in trialsRaw:
            item = item.removesuffix("_is_trial").replace("_", " ")
            item = item.upper() if item == "xth" else item.title()
            trialNames.append(item)
        licenseDetails.append({"field": "Modules \ Features in Trial", "value": ",\n".join(trialNames)})

        expirations = {
            key: value
            for key, value in details.items()
            if (re.compile(r"_expiration").search(key) and value != details.get(expirationString) and value != 0)
        }
        licenseDetails.append(
            {
                "field": "Odd expirations",
                "value": expirations
                if expirations != {}
                else "No components found expiring with a date different from the main license.",
            }
        )

        cloudPostureBreakdownRaw = details.get("installed_cloud_posture_breakdown", {})
        if cloudPostureBreakdownRaw != {}:
            cloudPostureBreakdown = []
            cloudPostureBreakdown.append("Total Workloads: " + str(details.get("purchased_cloud_posture").get("workloads")))
            for item in cloudPostureBreakdownRaw:
                string = str(item.get("usage")) + " " + item.get("name")
                cloudPostureBreakdown.append(string)
            licenseDetails.append(
                {
                    "field": "Cloud Posture Workloads Breakdown",
                    "value": ",\n".join(cloudPostureBreakdown),
                }
            )

        cloudRuntimeBreakdownRaw = details.get("installed_pro_cloud_breakdown", {})
        if cloudRuntimeBreakdownRaw != {}:
            cloudRuntimeBreakdown = []
            cloudRuntimeBreakdown.append("Total Workloads: " + str(details.get("purchased_pro_cloud").get("agents")))
            for item in cloudRuntimeBreakdownRaw:
                string = str(item.get("usage")) + " " + item.get("name")
                cloudRuntimeBreakdown.append(string)
            licenseDetails.append(
                {
                    "field": "Cloud Runtime Workloads Breakdown",
                    "value": ",\n".join(cloudRuntimeBreakdown),
                }
            )

        demisto.executeCommand("setIncident", {"healthchecklicensedetails": licenseDetails})

        return_results(CommandResults(readable_output="HealchCheckInstalledPacks Done"))

    except Exception as e:
        return_error(f"Error in XSIAM license logic: {str(e)}")


def get_xsoar6_license_data():
    """
    Original logic for XSOAR 6 which parses a license file provided via entryID.
    """
    validTil = []
    customer = []
    permittedUsers = []
    usedUsers = []
    licenseType = []
    uid = []

    res = demisto.executeCommand("getFilePath", {"id": demisto.args().get("entryID")})
    if not res or res[0]["Type"] == entryTypes["error"]:
        return_error("File not found or entryID is missing.")

    try:
        with open(res[0]["Contents"]["path"]) as file:
            python_dict = json.loads(str(file.read()))
            if "validTil" in python_dict:
                validTil = python_dict["validTil"]
            elif "soar" in python_dict["license"]:
                validTil = python_dict["license"]["soar"]["validTil"]
            else:
                validTil = python_dict["license"]["validTil"]

            if "customer" in python_dict:
                customer = python_dict["customer"]
            elif "soar" in python_dict["license"]:
                customer = python_dict["license"]["soar"]["customer"]
            else:
                customer = python_dict["license"]["customer"]

            if "permittedUsers" in python_dict:
                permittedUsers = python_dict["permittedUsers"]
            elif "soar" in python_dict["license"]:
                permittedUsers = python_dict["license"]["soar"]["permittedUsers"]
            else:
                permittedUsers = python_dict["license"]["permittedUsers"]

            if "usedUsers" in python_dict:
                usedUsers = python_dict["usedUsers"]
            elif "soar" in python_dict["license"]:
                usedUsers = python_dict["license"]["soar"]["usedUsers"]
            else:
                usedUsers = python_dict["license"]["usedUsers"]

            if "type" in python_dict:
                licenseType = python_dict["type"]
            elif "soar" in python_dict["license"]:
                licenseType = python_dict["license"]["soar"]["type"]
            elif "types" in python_dict["license"]:
                licenseType = python_dict["license"]["types"]["soar"]
            else:
                licenseType = python_dict["license"]["type"]

            if "id" in python_dict:
                uid = python_dict["id"]
            elif "soar" in python_dict["license"]:
                uid = python_dict["license"]["soar"]["id"]
            else:
                uid = python_dict["license"]["id"]

            demisto.executeCommand(
                "setIncident",
                {
                    "healthcheckpermittedusers": permittedUsers,
                    "healthcheckusedusers": usedUsers,
                    "xsoarcustomername": customer,
                    "xsoarlicense": licenseType,
                    "xsoarlicensevalidtill": validTil,
                    "xsoartelemetryuuid": uid,
                },
            )
    except ValueError:
        return_error("Decoding JSON has failed")


def main():
    is_xsiam = demisto.demistoVersion().get("platform") == "unified_platform"

    # 1. Check for XSOAR 8 (Unsupported)
    if is_demisto_version_ge("8.0.0") and not is_xsiam:
        return_error("Not Available for XSOAR v8")

    # 2. Branch logic based on Platform
    if is_xsiam:
        get_xsiam_license_data()
    else:
        # Default to XSOAR 6 logic
        get_xsoar6_license_data()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
