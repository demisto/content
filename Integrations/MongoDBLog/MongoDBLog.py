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
URI = demisto.params().get('uri')
# Get Database
DATABASE = demisto.params().get('db')
# Connect to MongoDB - Need to add credentials and lock down MongoDB (add auth)
CLIENT = MongoClient(URI, username=USERNAME, password=PASSWORD, authSource=DATABASE, authMechanism='SCRAM-SHA-1')
DB = CLIENT[DATABASE]
# Set Collection
COLLECTION_NAME = demisto.params().get('collection')
COLLECTION = DB[COLLECTION_NAME]


def test_module():
    """ Check DB Status """
    if CLIENT.server_info().get('ok') == 1.0:
        return 'ok', {}, {}
    return 'MongoDB Server Error', {}, {}


def write_log_json():
    """ Gather Args, form json document, write document to MondoDB """
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    entity = demisto.args().get('entity')
    playbook = demisto.args().get('playbook')
    action = demisto.args().get('action')
    analyst = demisto.args().get('analyst')
    logjson = {
        'timestamp': timestamp,
        'entity': entity,
        'playbook': playbook,
        'action': action,
        'analyst': analyst,
    }
    # Add json to the document collection in MondoDB
    result = COLLECTION.insert_one(logjson)
    entry_id = result.inserted_id

    context = {
        'ID': str(entry_id),
        'Timestamp': timestamp,
        'Entity': entity,
        'Playbook': playbook,
        'Action': action,
        'Analyst': analyst
    }
    ec = {
        'MongoDB.Entry(val.ID === obj.ID)': context
    }
    return 'MongoDB Log - 1 document/record added', ec, {}


def read_log_json():
    """ Get all log documents/records from MondoDB """
    # Point to all the documents
    cursor = COLLECTION.find({}, {'_id': False})
    # Create an empty log list
    entries = []
    # Iterate through those documents
    if cursor is not None:
        for i in cursor:
            # Append log entry to list
            entries.append(i)
        return_json = {COLLECTION_NAME: entries}
        return return_json, {}, {}
    return 'MongoDB - no documents/records - Log collection is empty', {}, {}


def num_log_json():
    """ Get a count of all log documents/records from MondoDB """
    # Point to the documents
    cursor = COLLECTION.find({}, {'_id': False})
    # Get count of those documents
    log_number = cursor.count()
    human_readable = f'The count of log documents/records is {str(log_number)}'
    return human_readable, {}, {}


def main():
    LOG("Command being called is %s" % (demisto.command()))

    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        return_outputs(*test_module())
    elif demisto.command() == 'mongodb-write-log':
        return_outputs(*write_log_json())
    elif demisto.command() == 'mongodb-read-log':
        return_outputs(*read_log_json())
    elif demisto.command() == 'mongodb-logs-number':
        return_outputs(*num_log_json())


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
