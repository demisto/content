import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

args = demisto.args()

# ####################################################################################
# ############################## CONFIGURATION PART ##################################
# ####################################################################################

"""
 `BUSINESS_OBJECT_TYPE` is the name of business object you wish to retrieve using this script.
 In this case we set it to be 'incident' as this script is in charge of retrieving incidents
"""

BUSINESS_OBJECT_TYPE = 'Incident'

"""
 `OUTPUT_FIELDS` should contain all the fields you wish to include in the returned business object.
 Make sure the field name is identical to the field name in Cherwell system.
 In order for the fields to appear in the script outputs you will need to to update the script outputs
 (found in the script settings).

 For example: we wished to retrieve an incident such that the fields: RecordID, Description, Priority,
 CustomerDisplayName, OwnedBy and Service will appear in the returned object, thus, we added all of those field names
 to this `OUTPUT_FIELDS` variable.
 In addition we added the field names to the script outputs so they will appear as an official output of
 the script, using the following syntax: Cherwell.BusinessObject.RecordID, Cherwell.BusinessObject.PublicID,
 Cherwell.BusinessObject.Description, Cherwell.BusinessObject.Priority and so on.
 Make sure to leave the first part in the output definition (`Cherwell.BusinessObject`) as is.
"""
OUTPUT_FIELDS = [
    'RecordID',
    'PublicID',
    'Description',
    'Priority',
    'CustomerDisplayName',
    'OwnedBy',
    'Service',
]


# ####################################################################################
# ############################## EXECUTION PART ######################################
# ####################################################################################


def build_arguments():
    arguments = {
        'type': BUSINESS_OBJECT_TYPE,
        'query': args.get('query')
    }
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
    if 'RecordID' not in output_fields:
        output_fields.append('RecordID')
    if 'PublicID' not in output_fields:
        output_fields.append('PublicID')
    return output_fields


result = demisto.executeCommand('cherwell-query-business-object', build_arguments())[0]
business_object_list = result.get('EntryContext').items()[0][1]
md = tableToMarkdown('Query Results', business_object_list, headers=build_output_list(), headerTransform=pascalToSpace)
demisto.results({
    'Type': result.get('Type'),
    'ContentsFormat': result.get('ContentsFormat'),
    'Contents': result.get('Contents'),
    'HumanReadable': md,
    'EntryContext': {'Cherwell.QueryResults': build_context(business_object_list, build_output_list())}
})
