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
DATABASE = demisto.params().get('database')
USE_SSL = demisto.params().get('use_ssl', False)
INSECURE = demisto.params().get('insecure', False)
TIMEOUT = 5000
if INSECURE and not USE_SSL:
    raise DemistoException('"Trust any certificate (not secure)" must be ticked with "Use TLS/SSL secured connection"')
if not INSECURE and not USE_SSL:
    # Connect to MongoDB - Need to add credentials and lock down MongoDB (add auth)
    CLIENT = MongoClient(  # type: ignore[var-annotated]
        URI, username=USERNAME, password=PASSWORD,
        authSource=DATABASE, authMechanism='SCRAM-SHA-1',
        ssl=USE_SSL, socketTimeoutMS=TIMEOUT)
else:
    CLIENT = MongoClient(URI, username=USERNAME, password=PASSWORD, authSource=DATABASE, authMechanism='SCRAM-SHA-1',
                         ssl=USE_SSL, tlsAllowInvalidCertificates=INSECURE, socketTimeoutMS=TIMEOUT)
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
    investigation = demisto.investigation()
    investigation_id = investigation.get('id')
    investigation_user = investigation.get('user')
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    id_ = demisto.args().get('id', investigation_id)
    playbook = demisto.args().get('playbook')
    action = demisto.args().get('action')
    user = demisto.args().get('user', investigation_user)
    message = demisto.args().get('message')
    logjson = {
        'timestamp': timestamp,
        'id': id_,
        'playbook': playbook,
        'action': action,
        'user': user,
        'message': message
    }
    # Add json to the document collection in MondoDB
    result = COLLECTION.insert_one(logjson)
    entry_id = result.inserted_id

    context = {
        'EntryID': str(entry_id),
        'Timestamp': timestamp,
        'ID': id_,
        'Playbook': playbook,
        'Action': action,
        'User': user,
        'Message': message
    }
    ec = {
        'MongoDB.Entry(val.EntryID === obj.EntryID)': context
    }
    return 'MongoDB Log - 1 document/record added', ec, {}


def read_log_json():
    """ Get all log documents/records from MondoDB """
    limit = int(demisto.args().get('limit'))
    # Point to all the documents
    doc_count = COLLECTION.count_documents(filter={}, limit=limit)
    cursor = COLLECTION.find({}, {'_id': False})
    # Create an empty log list
    entries = []
    # Iterate through those documents
    if doc_count > 0:
        for i in cursor:
            # Append log entry to list
            entries.append(i)
        return_json = {COLLECTION_NAME: entries}
        human_readable = tableToMarkdown(f'The log documents/records for collection "{COLLECTION_NAME}"',
                                         return_json.get(COLLECTION_NAME))
        return human_readable, {}, {}
    return 'MongoDB - no documents/records - Log collection is empty', {}, {}


def num_log_json():
    """ Get a count of all log documents/records from MondoDB """
    # Point to the documents
    doc_count = COLLECTION.count_documents(filter={})
    human_readable = f'The count of log documents/records is {str(doc_count)}'
    return human_readable, {}, {}


def main():
    LOG(f'Command being called is {demisto.command()}')
    try:
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
    except Exception as e:
        return_error(f'MongoDB: {str(e)}', error=e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
