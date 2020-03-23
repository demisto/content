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


def write_key_value_command():
    """ Write key/value document to MondoDB """
    # Get Args needed for the command
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    incident = demisto.args().get('incident_id')
    key = demisto.args().get('key')
    value = demisto.args().get('value')
    logjson = {
        incident: {
            'modified': timestamp,
            'key': key,
            'value': value
        }
    }
    # Check for previous record/document
    search = incident + '.key'
    cursor = COLLECTION.find_one({search: key})
    # If no record
    if not cursor:
        # Add to MongoDB
        result = COLLECTION.insert_one(logjson)
        entry_id = result.inserted_id
        context = {
            'ID': str(entry_id),
            'Incident': incident,
            'Modified': timestamp,
            'Key': key,
            'Value': value
        }
        ec = {
            'MongoDB.Entry(val.ID === obj.ID)': context
        }
        return f'Incident "{incident}" - key/value collection - 1 document added', ec, {}

    # Modify Existing Record
    object_id = cursor.get('_id')
    COLLECTION.update_one(
        {'_id': object_id},
        {'$set': {
            incident: {
                'key': key,
                'value': value,
                'modified': timestamp
            }
        }}
    )
    context = {
        'ID': str(object_id),
        'Incident': incident,
        'Modified': timestamp,
        'Key': key,
        'Value': value
    }
    ec = {
        'MongoDB.Entry(val.ID === obj.ID)': context
    }
    return f'Incident "{incident}" - key/value collection - 1 document updated', ec, {}


def get_key_info_command():
    """ Get key/value info from MondoDB """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    key = demisto.args().get('key')
    # Search Collection for incident_id and key
    search = incident + '.key'
    result = COLLECTION.find_one({search: key}, {'_id': False})
    contents = {
        'Incident': incident,
        'Key': key,
        'Value': result.get(incident).get('value'),
        'Modified': result.get(incident).get('modified')
    }
    human_readable = tableToMarkdown(f'Information about {key} in incident {incident}', contents)
    ec = {'MongoDB.Entry(val.Key === obj.Key)': contents}
    return human_readable, ec, {}


def get_key_value_command():
    """ Return value for key stored for the incident """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    key = demisto.args().get('key')
    # Search Collection for incident_id and key
    search = incident + '.key'
    result = COLLECTION.find_one({search: key}, {'_id': False})
    value = result[incident].get('value')
    contents = {
        'Incident': incident,
        'Key': key,
        'Value': value
    }
    human_readable = tableToMarkdown(f'The key and value that is stored for the incident', contents)
    ec = {'MongoDB.Entry(val.Key === obj.Key)': contents}
    return human_readable, ec, {}


def delete_key_command():
    """ Removes the key/value pair specified by key and incident_id """
    incident = demisto.args().get('incident_id')
    key = demisto.args().get('key')
    # Search Collection for incident_id and key
    search = incident + '.key'
    cursor = COLLECTION.find_one({search: key})
    if cursor is not None:
        object_id = cursor.get('_id')
        COLLECTION.delete_one({'_id': object_id})
        return f'Incident "{incident}" - key/value collection - 1 document deleted', {}, {}
    return f'Key "{key}" for incident_id "{incident}" does not exist', {}, {}


def num_keys_command():
    """ Returns the count of the key/value pairs for the incident """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    # Search Collection counting matching incident_id
    cursor = COLLECTION.find({})
    count = 0
    for i in cursor:
        if incident in i:
            count += 1
    return f'The count of the key/value pairs for the incident - {str(count)}', {}, {}


def list_key_values_command():
    """ Returns all the key/value pairs stored for the incident """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    # Search Collection for matching incident_id
    return_json = []
    context = []
    found = False
    cursor = COLLECTION.find({}, {'_id': False})
    if cursor is None:
        # Collection doesn't exist - thus no records
        return_json = None
    else:
        # Iterate, collecting any name/value pairs associated with the incident
        for i in cursor:
            if incident in i:
                found = True
                return_json.append({
                    'Key': i[incident]['key'],
                    'Value': i[incident]['value']
                })
                context.append({
                    'Incident': incident,
                    'Key': i[incident]['key'],
                    'Value': i[incident]['value']
                })

    if not found:
        # Means no records were found with that incident_id
        # Discard empty return_json
        return_json = None

    human_readable = tableToMarkdown(f'The key/value paires stored in incident {incident}', return_json)
    ec = {'MongoDB.Incident(val.Key === obj.Key)': context}
    # Return a useful status
    return human_readable, ec, {}


def purge_keys_command():
    """ Purges all the key/value pairs stored for the incident """
    incident = demisto.args().get('incident_id')
    cursor = COLLECTION.find({})
    deleted = 0
    # Iterate, collecting any name/value pairs associated with the incident
    for i in cursor:
        if incident in i:
            object_id = i.get('_id')
            COLLECTION.delete_one({'_id': object_id})
            deleted += 1
    if deleted == 1:
        return f'Incident "{incident}" key/value pairs purged - {str(deleted)} document/record deleted', {}, {}
    return f'Incident "{incident}" key/value pairs purged - {str(deleted)} documents/records deleted', {}, {}


def main():
    LOG("Command being called is %s" % (demisto.command()))

    if demisto.command() == "test-module":
        # This is the call made when pressing the integration test button.
        return_outputs(*test_module())
    elif demisto.command() == 'mongodb-write-key-value':
        return_outputs(*write_key_value_command())
    elif demisto.command() == 'mongodb-get-key-info':
        return_outputs(*get_key_info_command())
    elif demisto.command() == 'mongodb-get-key-value':
        return_outputs(*get_key_value_command())
    elif demisto.command() == 'mongodb-list-key-values':
        return_outputs(*list_key_values_command())
    elif demisto.command() == 'mongodb-delete-key':
        return_outputs(*delete_key_command())
    elif demisto.command() == 'mongodb-purge-keys':
        return_outputs(*purge_keys_command())
    elif demisto.command() == 'mongodb-get-keys-number':
        return_outputs(*num_keys_command())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
