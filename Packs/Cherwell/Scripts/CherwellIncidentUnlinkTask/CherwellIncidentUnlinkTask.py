from CommonServerPython import *

args = demisto.args()

# ####################################################################################
# ############################## CONFIGURATION PART ##################################
# ####################################################################################

"""
`RELATIONSHIP_ID` is the id of the relationship you wish to base your link on. In this case, we wanted to create script
for incidents to own tasks, thus, we used the "Incident Owns Task" relationship id.
"""
RELATIONSHIP_ID = "9369187528b417b4a17aaa4646b7f7a78b3c821be9"  # guardrails-disable-line

"""
 `PARENT_BUSINESS_OBJECT_TYPE` is the name of parent business object and `CHILD_BUSINESS_OBJECT_TYPE` is the name of the
 child business object. In this case, as we wanted to create a script for incidents to own tasks, we set
 `PARENT_BUSINESS_OBJECT_TYPE` to be 'Incident' and `CHILD_BUSINESS_OBJECT_TYPE` to be `Task`.
"""
PARENT_BUSINESS_OBJECT_TYPE = "Incident"
CHILD_BUSINESS_OBJECT_TYPE = "Task"

"""
`parent_record_id` and `child_record_id` stores the input ids of the parent and child records respectively.
In order to change the objects being unlinked, you will need to have corresponding arguments in the script arguments.
 After you added the argument to the script arguments, you will need to add their values by using
 `args.get('argument_name').
For example if you wish to unlink a configuration item and an incident where the parent object is the
incident, you will need to change the script arguments to be called `incident_record_id` and
`configuration_item_record_id` and then, modify the variables `parent_record_id` and `child_record_id` such that
parent_record_id = args.get('incident_record_id') and child_record_id = args.get('configuration_item_record_id').
"""
parent_record_id = args.get("incident_record_id")
child_record_id = args.get("task_record_id")


# ####################################################################################
# ############################## EXECUTION PART ######################################
# ####################################################################################


def build_arguments():
    arguments = {
        "child_record_id": child_record_id,
        "parent_record_id": parent_record_id,
        "child_type": CHILD_BUSINESS_OBJECT_TYPE,
        "parent_type": PARENT_BUSINESS_OBJECT_TYPE,
        "relationship_id": RELATIONSHIP_ID,
    }
    return arguments


result = demisto.executeCommand("cherwell-unlink-business-objects", build_arguments())[0]
demisto.results(result)
