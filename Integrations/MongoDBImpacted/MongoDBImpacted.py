import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
""" IMPORTS """
from datetime import datetime
from pymongo import MongoClient


""" GLOBALS/PARAMS """

# Get Credentials
USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
# Get Server
URI = demisto.params()["URI"]
# Get Database
DATABASE = demisto.params()["DB"]
# Connect to MongoDB - Need to add credentials and lock down MongoDB (add auth)
CLIENT = MongoClient(URI, username=USERNAME, password=PASSWORD,
    authSource=DATABASE, authMechanism='SCRAM-SHA-1')
DB = CLIENT[DATABASE]
# Set Collection
COLLECTION_NAME = demisto.params()["COLLECTION"]
COLLECTION = DB[COLLECTION_NAME]
# Get Incident (or set to Playground)



def test_module():
    """ Check DB Status """
    if CLIENT.server_info()["ok"] == 1.0:
        return "ok"
    return "MongoDB Server Error"


def write_impacted_command():
    """ Write impacted entity document to MondoDB """
    # Get Args needed for the command
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    incident = demisto.args()["incident_id"]
    name = demisto.args()["name"]
    if demisto.get(demisto.args(), "category"):
        category = demisto.args()["category"]
    else:
        category = None
    if demisto.get(demisto.args(), "classification"):
        classification = demisto.args()["classification"]
    else:
        classification = None
    if demisto.get(demisto.args(), "action"):
        action = demisto.args()["action"]
    else:
        action = None
    logjson = {
        incident: {
            "entity": name,
            "category": category,  # normal, privileged
            "classification": classification,  # user, server
            "created": timestamp,
            "modified": timestamp,
            "action": action,
        }
    }
    # Check for previous record/document
    search = incident + ".entity"
    cursor = COLLECTION.find_one({search: name})
    # If no record
    if cursor is None:
        # Add to MongoDB
        COLLECTION.insert_one(logjson)
        return 'Impacted incident "' + incident + '" - 1 document/record added'
    else:
        # Else modify Existing Record
        object_id = cursor.get("_id")
        if category is None:
            # Use previous value, as value has not changed
            category = cursor.get(incident).get("category")
        if classification is None:
            classification = cursor.get(incident).get("classification")
        if action is None:
            action = cursor.get(incident).get("action")
        # Don't change creation timestamp
        created = cursor.get(incident).get("created")
        COLLECTION.update_one(
            {"_id": object_id},
            {
                "$set": {
                    incident: {
                        "entity": name,
                        "category": category,  # normal, privelidged
                        "classification": classification,  # user, server
                        "created": created,
                        "modified": timestamp,
                        "action": action
                    }
                }
            },
        )
        return 'Impacted incident "' + incident + '" - 1 document/record updated'


def get_impacted_command():
    """ Get impacted entity info from MondoDB """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    name = demisto.args()["name"]
    # Search Collection for incident_id and impacted entity names
    search = incident + ".entity"
    cursor = COLLECTION.find_one({search: name}, {"_id": False})
    if cursor is not None:
        return cursor
    return (
        'Impacted document/record for incident "'
        + incident
        + '" entity "'
        + name
        + '" does not exist'
    )


def list_impacted_command():
    """ Returns all the impacted entities stored for the incident """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    # Search Collection for matching incident_id
    found = False
    records = {}
    cursor = COLLECTION.find({}, {"_id": False})
    if cursor is not None:
        # Iterate, collecting any name/value pairs associated with the incident
        for i in cursor:
            if incident in i:
                found = True
                entity = i[incident]["entity"]
                category = i[incident]["category"]
                classification = i[incident]["classification"]
                created = i[incident]["created"]
                modified = i[incident]["modified"]
                action = i[incident]["action"]
                # Construct json for record in the incident
                record = {
                    entity: [
                        {"category": category},
                        {"classification": classification},
                        {"created": created},
                        {"modified": modified},
                        {"action": action},
                    ]
                }
                records.update(record)

    if found is not True:
        # Means no records were found with that incident_id
        results = None
    else:
        # Return found records
        results = records
    return results


def purge_impacted_command():
    """ Purges all the impacted entities stored for the incident """
    incident = demisto.args()["incident_id"]
    # Search Collection for matching incident_id
    cursor = COLLECTION.find({})
    deleted = 0
    # Iterate, deleting all impacted records associated with the incident
    for i in cursor:
        if incident in i:
            object_id = i.get("_id")
            COLLECTION.delete_one({"_id": object_id})
            deleted += 1
    if deleted == 1:
        return (
            "Impacted incident '"
            + incident
            + "' impacted collection purged - "
            + str(deleted)
            + " document/record deleted"
        )
    return (
        "Incident '"
        + incident
        + "' impacted collection purged - "
        + str(deleted)
        + " documents/records deleted"
    )


def num_impacted_command():
    """ Returns the count of impacted entities for the incident """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    # Search Collection for incident_id and key
    cursor = COLLECTION.find({}, {"_id": False})
    count = 0
    for i in cursor:
        if incident in i:
            count += 1
    return count


def delete_impacted_command():
    """ Removes the the specified impacted entity from the incident """
    incident = demisto.args()["incident_id"]
    name = demisto.args()["name"]
    # Search Collection for incident_id and key
    search = incident + ".entity"
    cursor = COLLECTION.find_one({search: name})
    if cursor is not None:
        object_id = cursor.get("_id")
        COLLECTION.delete_one({"_id": object_id})
        return (
            'Impacted incident "'
            + incident
            + '" entity "'
            + name
            + '" - one document/record deleted'
        )
    return (
        'Impacted document/record for incident "'
        + incident
        + '" entity "'
        + name
        + '" does not exist'
    )


LOG("Command being called is %s" % (demisto.command()))

if demisto.command() == "test-module":
    # This is the call made when pressing the integration test button.
    RESULTS = test_module()
    demisto.results(RESULTS)
elif demisto.command() == "WriteImpacted":
    RESULTS = write_impacted_command()
    demisto.results(RESULTS)
elif demisto.command() == "GetImpacted":
    RESULTS = get_impacted_command()
    demisto.results(RESULTS)
elif demisto.command() == "ListImpacted":
    RESULTS = list_impacted_command()
    demisto.results(RESULTS)
elif demisto.command() == "DeleteImpacted":
    RESULTS = delete_impacted_command()
    demisto.results(RESULTS)
elif demisto.command() == "PurgeImpacted":
    RESULTS = purge_impacted_command()
    demisto.results(RESULTS)
elif demisto.command() == "NumImpacted":
    RESULTS = num_impacted_command()
    demisto.results(RESULTS)
