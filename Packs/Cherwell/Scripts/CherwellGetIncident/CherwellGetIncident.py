import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

args = demisto.args()

# ####################################################################################
# ############################## CONFIGURATION PART ##################################
# ####################################################################################

"""
 `BUSINESS_OBJECT_TYPE` is the name of business object you wish to retrieve using this script.
 In this case we set it to be 'incident' as this script is in charge of retrieving incidents.
"""

BUSINESS_OBJECT_TYPE = "Incident"

"""
 `OUTPUT_FIELDS` should contain all the fields you wish to include in the returned business object.
 Make sure the field name is identical to the field name in the Cherwell system.
 In order for the fields to appear in the script outputs you will need to to update the script outputs
 (found in the script settings).

 For example: we wished to retrieve an incident such that the fields: RecordID, Description, Priority,
 CustomerDisplayName, etc., will appear in the returned object, thus, we added all of those field names
 to this `OUTPUT_FIELDS` variable.
 In addition, we added the field names to the script outputs so they will appear as an official output of
 the script, using the following syntax: Cherwell.BusinessObjects.RecordID, Cherwell.BusinessObjects.PublicID,
 Cherwell.BusinessObjects.Description, Cherwell.BusinessObjects.Priority, etc.
 Make sure to leave the prefix of the output definition (`Cherwell.BusinessObjects`) identical to what you have filed in
 the `OUTPUT_PATH` variable.
"""
OUTPUT_FIELDS = [
    "RecordId",
    "PublicId",
    "Description",
    "Priority",
    "CustomerDisplayName",
    "OwnedBy",
    "Service",
    "CreatedDateTime",
    "TotalTasks",
]

"""
`OUTPUT_PATH` is the path where all retrieved business objects will appear after. You can modify this path if you wish,
but remember to change the output prefix in the integration outputs as well.
"""
OUTPUT_PATH = "Cherwell.BusinessObjects"


# ####################################################################################
# ############################## EXECUTION PART ######################################
# ####################################################################################


def build_arguments():
    arguments = {"type": BUSINESS_OBJECT_TYPE, "id_type": args.get("id_type"), "id_value": args.get("id_value")}
    return arguments


def build_context(object_dict, filter_fileds):
    sanitized_business_object = {}
    for key, value in object_dict.items():
        if key in filter_fileds:
            sanitized_business_object[key] = value
    return sanitized_business_object


def build_output_list():
    output_fields = OUTPUT_FIELDS
    if "RecordId" not in output_fields:
        output_fields.append("RecordId")
    if "PublicId" not in output_fields:
        output_fields.append("PublicId")
    return output_fields


result = demisto.executeCommand("cherwell-get-business-object", build_arguments())[0]
business_object = list(result.get("EntryContext").items())[0][1]
md = tableToMarkdown(
    "{0}: {1}".format(BUSINESS_OBJECT_TYPE.capitalize(), args.get("id_value")),
    business_object,
    headers=build_output_list(),
    headerTransform=pascalToSpace,
)
context = build_context(business_object, build_output_list())
demisto.results(
    {
        "Type": result.get("Type"),
        "ContentsFormat": result.get("ContentsFormat"),
        "Contents": result.get("Contents"),
        "HumanReadable": md,
        "EntryContext": {f"{OUTPUT_PATH}(val.RecordId == obj.RecordId)": context},
    }
)
