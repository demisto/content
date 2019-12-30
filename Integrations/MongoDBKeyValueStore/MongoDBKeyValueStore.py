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


def test_module():
    """ Check DB Status """
    if CLIENT.server_info()["ok"] == 1.0:
        return "ok"
    return "MongoDB Server Error"


def write_key_value_command():
    """ Write key/value document to MondoDB """
    # Get Args needed for the command
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    incident = demisto.args()["incident_id"]
    key = demisto.args()["key"]
    value = demisto.args()["value"]
    logjson = {incident: {"modified": timestamp, "key": key, "value": value}}
    # Check for previous record/document
    search = incident + ".key"
    cursor = COLLECTION.find_one({search: key})
    # If no record
    if cursor is None:
        # Add to MongoDB
        COLLECTION.insert_one(logjson)
        return 'Incident "' + incident + '" - key/value collection - 1 document added'

    # Modify Existing Record
    object_id = cursor.get("_id")
    COLLECTION.update_one(
        {"_id": object_id},
        {"$set": {incident: {"key": key, "value": value, "modified": timestamp}}},
    )
    return 'Incident "' + incident + '" - key/value collection - 1 document updated'


def get_key_info_command():
    """ Get key/value info from MondoDB """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    key = demisto.args()["key"]
    # Search Collection for incident_id and key
    search = incident + ".key"
    result = COLLECTION.find_one({search: key}, {"_id": False})
    return result


def get_key_value_command():
    """ Return value for key stored for the incident """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    key = demisto.args()["key"]
    # Search Collection for incident_id and key
    search = incident + ".key"
    result = COLLECTION.find_one({search: key}, {"_id": False})
    value = result[incident]["value"]
    answer = {key: value}
    return answer


def delete_key_command():
    """ Removes the key/value pair specified by key and incident_id """
    incident = demisto.args()["incident_id"]
    key = demisto.args()["key"]
    # Search Collection for incident_id and key
    search = incident + ".key"
    cursor = COLLECTION.find_one({search: key})
    if cursor is not None:
        object_id = cursor.get("_id")
        COLLECTION.delete_one({"_id": object_id})
        return 'Incident "' + incident + '" - key/value collection - 1 document deleted'
    return (
        'Key "'
        + key
        + '" for incident_id "'
        + incident
        + '" does not exist'
    )


def num_keys_command():
    """ Returns the count of the key/value pairs for the incident """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    # Search Collection counting matching incident_id
    cursor = COLLECTION.find({})
    count = 0
    for i in cursor:
        if incident in i:
            count += 1
    return count


def list_key_values_command():
    """ Returns all the key/value pairs stored for the incident """
    # Get Args needed for the command
    incident = demisto.args()["incident_id"]
    # Search Collection for matching incident_id
    return_json = {incident: []}
    found = False
    cursor = COLLECTION.find({}, {"_id": False})
    if cursor is None:
        # Collection doesn't exist - thus no records
        return_json = None
    else:
        # Iterate, collecting any name/value pairs associated with the incident
        for i in cursor:
            if incident in i:
                found = True
                # Append the name/value pairs for each match to the list
                return_json[incident].append({i[incident]["key"]: i[incident]["value"]})

    if found is not True:
        # Means no records were found with that incident_id
        # Discard empty return_json
        return_json = None

    # Return a useful status
    return return_json


def purge_keys_command():
    """ Purges all the key/value pairs stored for the incident """
    incident = demisto.args()["incident_id"]
    cursor = COLLECTION.find({})
    deleted = 0
    # Iterate, collecting any name/value pairs associated with the incident
    for i in cursor:
        if incident in i:
            object_id = i.get("_id")
            COLLECTION.delete_one({"_id": object_id})
            deleted += 1
    if deleted == 1:
        return (
            'Incident "'
            + incident
            + '" key/value pairs purged - '
            + str(deleted)
            + " document/record deleted"
        )
    return (
        'Incident "'
        + incident
        + '" key/value pairs purged - '
        + str(deleted)
        + " documents/records deleted"
    )


LOG("Command being called is %s" % (demisto.command()))

if demisto.command() == "test-module":
    # This is the call made when pressing the integration test button.
    RESULTS = test_module()
    demisto.results(RESULTS)
elif demisto.command() == "WriteKeyValue":
    RESULTS = write_key_value_command()
    demisto.results(RESULTS)
elif demisto.command() == "GetKeyInfo":
    RESULTS = get_key_info_command()
    demisto.results(RESULTS)
elif demisto.command() == "GetKeyValue":
    RESULTS = get_key_value_command()
    demisto.results(RESULTS)
elif demisto.command() == "ListKeyValues":
    RESULTS = list_key_values_command()
    demisto.results(RESULTS)
elif demisto.command() == "DeleteKey":
    RESULTS = delete_key_command()
    demisto.results(RESULTS)
elif demisto.command() == "PurgeKeys":
    RESULTS = purge_keys_command()
    demisto.results(RESULTS)
elif demisto.command() == "NumKeys":
    RESULTS = num_keys_command()
    demisto.results(RESULTS)
