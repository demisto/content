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
# Get Incident (or set to Playground)


def test_module():
    """ Check DB Status """
    if CLIENT.server_info().get('ok') == 1.0:
        return 'ok', {}, {}
    return 'MongoDB Server Error', {}, {}


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
            'entity': name,
            'category': category,  # normal, privileged
            'classification': classification,  # user, server
            'created': timestamp,
            'modified': timestamp,
            'action': action,
        }
    }
    # Check for previous record/document
    search = incident + '.entity'
    cursor = COLLECTION.find_one({search: name})
    # If no record
    if cursor is None:
        # Add to MongoDB
        result = COLLECTION.insert_one(logjson)
        entry_id = result.inserted_id
        context = {
            'ID': str(entry_id),
            'Incident': incident,
            'Entity': name,
            'Category': category,  # normal, privileged
            'Classification': classification,  # user, server
            'Created': timestamp,
            'Modified': timestamp,
            'action': action,
        }
        ec = {
            'MongoDB.Entry(val.ID === obj.ID)': context
        }
        return f'Impacted incident "{incident}" - 1 document/record added', ec, {}
    else:
        # Else modify Existing Record
        object_id = cursor.get('_id')
        print(object_id)
        if category is None:
            # Use previous value, as value has not changed
            category = cursor.get(incident).get('category')
        if classification is None:
            classification = cursor.get(incident).get('classification')
        if action is None:
            action = cursor.get(incident).get('action')
        # Don't change creation timestamp
        created = cursor.get(incident).get('created')
        COLLECTION.update_one(
            {'_id': object_id},
            {
                '$set': {
                    incident: {
                        'entity': name,
                        'category': category,  # normal, privelidged
                        'classification': classification,  # user, server
                        'created': created,
                        'modified': timestamp,
                        'action': action
                    }
                }
            }
        )
        context = {
            'ID': str(object_id),
            'Incident': incident,
            'Entity': name,
            'Category': category,  # normal, privileged
            'Classification': classification,  # user, server
            'Created': timestamp,
            'Modified': timestamp,
            'action': action,
        }
        ec = {
            'MongoDB.Entry(val.ID === obj.ID)': context
        }
        return f'Impacted incident "{incident}" - 1 document/record updated', ec, {}


def get_impacted_command():
    """ Get impacted entity info from MongoDB """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    name = demisto.args().get('name')
    # Search Collection for incident_id and impacted entity names
    search = incident + '.entity'
    cursor = COLLECTION.find_one({search: name}, {'_id': False})
    contents = {
        'IncidentID': incident,
        'Entity': name,
        'Category': cursor[incident].get('category'),
        'Classification': cursor[incident].get('classification'),
        'Created': cursor[incident].get('created'),
        'Modified': cursor[incident].get('modified'),
        'Action': cursor[incident].get('action')
    }
    if cursor is not None:
        human_readable = tableToMarkdown(f'Impacted entity information', contents, removeNull=True)
        ec = {'MongoDB.Entry(val.IncidentID === obj.IncidentID)': contents}
        return human_readable, ec, {}
    return f'Impacted document/record for incident "{incident}" entity "{name}" does not exist', {}, {}


def list_impacted_command():
    """ Returns all the impacted entities stored for the incident """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    # Search Collection for matching incident_id
    found = False
    records = []
    cursor = COLLECTION.find({}, {'_id': False})
    if cursor is not None:
        # Iterate, collecting any name/value pairs associated with the incident
        for i in cursor:
            if incident in i:
                found = True
                records.append({
                    'Incident': incident,
                    'Entity': i[incident]['entity'],
                    'Category': i[incident]['category'],
                    'Classification': i[incident]['classification'],
                    'Created': i[incident]['created'],
                    'Modified': i[incident]['modified'],
                    'Action': i[incident]['action']
                })
    if not found:
        # Means no records were found with that incident_id
        return f'No records were found for incident {incident}'

    human_readable = tableToMarkdown(f'The impacted entities for the incident', records, removeNull=True)
    ec = {'MongoDB.Entry(val.Incident === obj.Incident)': records}
    return human_readable, ec, {}


def purge_impacted_command():
    """ Purges all the impacted entities stored for the incident """
    incident = demisto.args().get('incident_id')
    # Search Collection for matching incident_id
    cursor = COLLECTION.find({})
    deleted = 0
    # Iterate, deleting all impacted records associated with the incident
    for i in cursor:
        if incident in i:
            object_id = i.get('_id')
            COLLECTION.delete_one({'_id': object_id})
            deleted += 1
    if deleted == 1:
        return f'Impacted incident "{incident}" impacted collection purged - "{str(deleted)}" ' \
                   f'document/record deleted', {}, {}
    return f'Incident "{incident}" impacted collection purged - "{str(deleted)}" documents/records deleted', {}, {}


def num_impacted_command():
    """ Returns the count of impacted entities for the incident """
    # Get Args needed for the command
    incident = demisto.args().get('incident_id')
    # Search Collection for incident_id and key
    cursor = COLLECTION.find({}, {'_id': False})
    count = 0
    for i in cursor:
        if incident in i:
            count += 1
    return f'The number of impacted entities for incident {incident} - {str(count)}', {}, {}


def delete_impacted_command():
    """ Removes the the specified impacted entity from the incident """
    incident = demisto.args().get('incident_id')
    name = demisto.args().get('name')
    # Search Collection for incident_id and key
    search = incident + '.entity'
    cursor = COLLECTION.find_one({search: name})
    if cursor is not None:
        object_id = cursor.get('_id')
        COLLECTION.delete_one({'_id': object_id})
        return f'Impacted incident "{incident}" entity "{name}" - one document/record deleted', {}, {}
    return f'Impacted document/record for incident "{incident}" entity "{name}" does not exist', {}, {}


def main():

    LOG("Command being called is %s" % (demisto.command()))

    if demisto.command() == "test-module":
        # This is the call made when pressing the integration test button.
        return_outputs(*test_module())
    elif demisto.command() == 'mongodb-write-impacted':
        return_outputs(*write_impacted_command())
    elif demisto.command() == 'mongodb-get-impacted':
        return_outputs(*get_impacted_command())
    elif demisto.command() == 'mongodb-list-impacted':
        return_outputs(*list_impacted_command())
    elif demisto.command() == 'mongodb-delete-impacted':
        return_outputs(*delete_impacted_command())
    elif demisto.command() == 'mongodb-purge-impacted':
        return_outputs(*purge_impacted_command())
    elif demisto.command() == 'mongodb-number-of-impacted':
        return_outputs(*num_impacted_command())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
