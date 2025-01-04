import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


if is_demisto_version_ge("8.0.0"):
    return_error("Not Available for XSOAR v8")
validTil = []
customer = []
permittedUsers = []
usedUsers = []
licenseType = []
uid = []
TimLicenseType = []

res = demisto.executeCommand("getFilePath", {"id": demisto.args()["entryID"]})
if res[0]["Type"] == entryTypes["error"]:
    demisto.results("File not found")

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
            TimLicenseType = python_dict["license"]["types"]["tim"]
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


except ValueError:  # includes simplejson.decoder.JSONDecodeError
    return_error("Decoding JSON has failed")
