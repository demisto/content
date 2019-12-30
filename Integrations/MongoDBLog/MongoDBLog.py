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


def write_log_json():
    """ Gather Args, form json document, write document to MondoDB """
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    entity = demisto.args()["entity"]
    playbook = demisto.args()["playbook"]
    action = demisto.args()["action"]
    analyst = demisto.args()["analyst"]
    logjson = {
        "timestamp": timestamp,
        "entity": entity,
        "playbook": playbook,
        "action": action,
        "analyst": analyst,
    }
    # Add json to the document collection in MondoDB
    COLLECTION.insert_one(logjson)
    return "MongoDB Log - 1 document/record added"


def read_log_json():
    """ Get all log documents/records from MondoDB """
    # Point to all the documents
    cursor = COLLECTION.find({}, {"_id": False})
    # Create an empty log list
    entries = []
    # Iterate through those documents
    if cursor is not None:
        for i in cursor:
            # Append log entry to list
            entries.append(i)
        return_json = {COLLECTION_NAME: entries}
        return return_json
    return "MongoDB - no documents/records - Log collection is empty"


def num_log_json():
    """ Get a count of all log documents/records from MondoDB """
    # Point to the documents
    cursor = COLLECTION.find({}, {"_id": False})
    # Get count of those documents
    return cursor.count()


LOG("Command being called is %s" % (demisto.command()))

if demisto.command() == "test-module":
    # This is the call made when pressing the integration test button.
    RESULTS = test_module()
    demisto.results(RESULTS)
elif demisto.command() == "WriteMongoLog":
    RESULTS = write_log_json()
    demisto.results(RESULTS)
elif demisto.command() == "ReadMongoLog":
    RESULTS = read_log_json()
    demisto.results(RESULTS)
elif demisto.command() == "NumMongoLog":
    RESULTS = num_log_json()
    demisto.results(RESULTS)
