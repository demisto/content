import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

args = demisto.args()

# ####################################################################################
# ############################## CONFIGURATION PART ##################################
# ####################################################################################

"""
 `BUSINESS_OBJECT_TYPE` is the name of business object you wish to create using this script.
 In this case we set it to be 'incident' as this script is in charge of creating incidents.
"""

BUSINESS_OBJECT_TYPE = "Incident"

"""
 `FIELDS` contains all the fields you wish to include in your business object.
 In order to add a field to a business object you will need to have a corresponding argument in the script arguments.
 After you added the argument to the script arguments you will need to add its value to the `FIELDS` object by using
 `args.get('argument_name').
 Make sure the key is identical to the field name in the Cherwell system.

 For example: we wished to create an incident with a requesting customer field in it, thus, we added a
 customer_display_name argument to this script, we pulled the value of the argument by using
 `args.get('customer_display_name')` and we set the key name to be `CustomerDisplayName` - as it appears in the Cherwell
 system.

 Expert tip: if you don't want to keep Demisto's arguments naming convention, you can name your arguments exactly as
 they appear in the Cherwell system, this will shorten the `FIELDS` constant to be `FIELDS = args`
"""
FIELDS = {
    "Description": args.get("description"),
    "Priority": args.get("priority"),
    "CustomerDisplayName": args.get("customer_display_name"),
    "OwnedBy": args.get("owned_by"),
    "Service": args.get("service"),
    "CallSource": "Event",
}


# ####################################################################################
# ############################## EXECUTION PART ######################################
# ####################################################################################


def build_arguments():
    arguments = {
        "type": BUSINESS_OBJECT_TYPE,
        # As `owned_by` and `service` arguments are not mandatory we make sure to remove them by using the createContext
        # function with removeNull flag set to true.
        # If all arguments are mandatory it would be sufficient to use `json: FIELDS`
        "json": createContext(FIELDS, removeNull=True),
    }
    return arguments


result = demisto.executeCommand("cherwell-create-business-object", build_arguments())
demisto.results(result)
