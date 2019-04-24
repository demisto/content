import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

args = demisto.args()

# ####################################################################################
# ############################## CONFIGURATION PART ##################################
# ####################################################################################

"""
`RELATIONSHIP_ID` is the id of the relationship you wish to base your link on. In this case we wanted to create script 
for incidents to own tasks, thus, we used the "Incident Owns Task" relationship id.
"""
RELATIONSHIP_ID = '9369187528b417b4a17aaa4646b7f7a78b3c821be9'

"""
 `PARENT_BUSINESS_OBJECT_TYPE` is the name of parent business object and `CHILD_BUSINESS_OBJECT_TYPE` is the name of the 
 child business object. In this case, as we wanted to create a script for incidents to own tasks, we set 
 `PARENT_BUSINESS_OBJECT_TYPE` to be 'Incident' and `CHILD_BUSINESS_OBJECT_TYPE` to be `Task`.  
"""
PARENT_BUSINESS_OBJECT_TYPE = 'Incident'
CHILD_BUSINESS_OBJECT_TYPE = 'Task'

"""
In order to create your own link script you can just modify the arguments inside the integration settings to correspond 
to the business objects you wish to link.
For example if you wish to create a link between configuration item and an incident when 
"""
parent_record_id = args.get('incident_record_id')
child_record_id = args.get('task_record_id')


# ####################################################################################
# ############################## EXECUTION PART ######################################
# ####################################################################################

def build_arguments():
    arguments = {
        'child_record_id': child_record_id,
        'parent_record_id': parent_record_id,
        'child_type': CHILD_BUSINESS_OBJECT_TYPE,
        'parent_type': PARENT_BUSINESS_OBJECT_TYPE,
        'relationship_id': RELATIONSHIP_ID
    }
    return arguments


result = demisto.executeCommand('cherwell-unlink-business-objects', build_arguments())[0]
demisto.results(result)