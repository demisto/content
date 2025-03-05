import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

args = demisto.args()

# ####################################################################################
# ############################## CONFIGURATION PART ##################################
# ####################################################################################

"""
 `BUSINESS_OBJECT_TYPE` is the name of business object you wish to query using this script.
 In this case we set it to be 'incident' as this script is in charge of querying incidents.
"""

BUSINESS_OBJECT_TYPE = "Incident"

"""
 `OUTPUT_FIELDS` should contain all the fields you wish to include in the returned business object list.
 Make sure the field name is identical to the field name in the Cherwell system.
 In order for the fields to appear in the script outputs, you will need to to update the script outputs
 (found in the script settings).

 For example: This script was built to query incidents such that the fields: RecordID, Description, Priority,
 CustomerDisplayName, etc., will appear in the returned object list. We added all of these field
 names to the `OUTPUT_FIELDS` variable.
 In addition we added the same field names to the script outputs so they will appear as an official output of
 the script, using the following syntax: Cherwell.QueryResults.RecordID, Cherwell.QueryResults.PublicID,
 Cherwell.QueryResults.Description, Cherwell.QueryResults.Priority, etc.
 Make sure to leave the prefix of the output definition (`Cherwell.QueryResults`) identical to what you have filed in
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
`OUTPUT_PATH` is the path where all queried results will appear after the search. You can modify this path if you wish,
but remember to change the output prefix in the integration outputs as well.
"""
OUTPUT_PATH = "Cherwell.QueryResults"

# ####################################################################################
# ############################## EXECUTION PART ######################################
# ####################################################################################


def build_arguments():
    arguments = {"type": BUSINESS_OBJECT_TYPE, "query": args.get("query")}
    return arguments


def build_context(object_list, filter_fields):
    new_business_object_list = []
    for object_dict in object_list:
        new_business_object = {}
        for key, value in object_dict.items():
            if key in filter_fields:
                new_business_object[key] = value
        new_business_object_list.append(new_business_object)
    return new_business_object_list


def build_output_list():
    output_fields = OUTPUT_FIELDS
    if "RecordId" not in output_fields:
        output_fields.append("RecordId")
    if "PublicId" not in output_fields:
        output_fields.append("PublicId")
    return output_fields


result = demisto.executeCommand("cherwell-query-business-object", build_arguments())[0]
business_object_list = list(result.get("EntryContext").items())[0][1]
md = tableToMarkdown("Query Results", business_object_list, headers=build_output_list(), headerTransform=pascalToSpace)
demisto.results(
    {
        "Type": result.get("Type"),
        "ContentsFormat": result.get("ContentsFormat"),
        "Contents": result.get("Contents"),
        "HumanReadable": md,
        "EntryContext": {OUTPUT_PATH: build_context(business_object_list, build_output_list())},
    }
)
