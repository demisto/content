from CommonServerPython import *

"""
This script is used to wrap the generic create-record command in ServiceNow.
You can add fields that you want to create the record with as script arguments or in the
code and work with the records easily.


Mandatory fields in your ServiceNow table settings should be changed to be mandatory arguments in this script.
You can identify such fields by trying to get a record and receiving a response
stating that a required field is missing.
"""

"""
Mapping of severity display names to their corresponding values in the API
"""
TICKET_SEVERITY = {
    '1 - High': '1',
    '2 - Medium': '2',
    '3 - Low': '3'
}

"""
Function to use the query command to retrieve records from the users table.
"""


def get_user(query):
    user_args = {
        'table_name': 'sys_user',
        'query': query
    }

    user_result = demisto.executeCommand('servicenow-query-table', user_args)[0]
    user_data = demisto.get(user_result, 'Contents')
    if not user_data:
        return_error('Could not get the contents from the command result: ' + json.dumps(user_result))
    if not isinstance(user_data, dict):
        # In case of string result, e.g "No incidents found"
        demisto.results('User not found')
        sys.exit(0)
    user = user_data['result']

    if not user or len(user) == 0:
        demisto.results('User not found')
        sys.exit(0)

    return user


def get_user_id(user_name):
    user_name = user_name.split(' ')
    query = 'first_name={}^last_name={}'.format(user_name[0], user_name[1])

    user = get_user(query)

    return user[0]['sys_id']


"""
Function to use the query command to retrieve records from the groups table.
"""


def get_group(query):
    group_args = {
        'table_name': 'sys_user_group',
        'query': query
    }

    group_result = demisto.executeCommand('servicenow-query-table', group_args)[0]
    group_data = demisto.get(group_result, 'Contents')
    if not group_data:
        return_error('Could not get the contents from the command result: ' + json.dumps(group_result))
    if not isinstance(group_data, dict):
        # In case of string result, e.g "No incidents found"
        demisto.results('Group not found')
        sys.exit(0)
    group = group_data['result']

    if not group or len(group) == 0:
        demisto.results('Group not found')
        sys.exit(0)

    return group


def get_group_id(group_name):
    query = 'name=' + group_name

    group = get_group(query)

    return group[0]['sys_id']


"""
The table name is required by the API. To acquire the table name, use the servicenow-get-table-name command.
"""
command_args = {
    'table_name': 'incident'
}

"""
These record fields(columns) are mapped from their names in ServiceNow to your choice of field names.
To view all fields for a given table, use the servicenow-list-fields command.
The ID field must be included to manage unique context entries.
"""
fields_to_map = {
    'sys_id': 'ID',
    'number': 'Number'
}

"""
For each field in the arguments, you need to check if it was provided and apply
any operations required (e.g, get a user id from a user name) to send them to the API.
"""
incident_severity = demisto.args().get('severity')
group_name = demisto.args().get('assigned_group')
user_name = demisto.args().get('assignee')
description = demisto.args().get('description')
user_id = None
group_id = None

if user_name:
    # Query the user table to get the system ID of the assignee
    user_id = get_user_id(user_name)
if group_name:
    # Query the group table to get the system ID of the assigned group
    group_id = get_group_id(group_name)

"""
Every field that was provided needs to be formatted to the following syntax: 'field1=a;field2=b;...'
to create the incident according to the arguments and execute the command.
In order to do that, to each field you need to concatenate the field'scorresponding name in the ServiceNow API
along with an '=' and the value. In the end each of those fields are joined by a ';'.
To view all the API fields for a record use the servicenow-list-fields-command.
"""
fields = []

if incident_severity:
    fields.append('severity' + '=' + TICKET_SEVERITY[incident_severity])
if user_id:
    fields.append('assigned_to' + '=' + user_id)
if description:
    fields.append('short_description' + '=' + description)
if group_id:
    fields.append('assignment_group' + '=' + group_id)

command_args['fields'] = ';'.join(fields)

command_res = demisto.executeCommand('servicenow-create-record', command_args)
result = {}
try:
    entry = command_res[0]
    if isError(entry):
        return_error(entry['Contents'])
    else:
        record_data = demisto.get(entry, 'Contents')
        if not record_data:
            return_error('Could not get the contents from the command result: ' + json.dumps(entry))
        if not isinstance(record_data, dict):
            # In case of string result, e.g "No incidents found"
            result = record_data
        else:
            # Get the actual record
            record = record_data['result']
            # Map fields according to fields_to_map that were defined earlier
            mapped_record = dict((fields_to_map[key], value) for (key, value) in
                                 list(filter(lambda (k, v): k in list(fields_to_map.keys()), record.items())))

            display_headers = ['ID', 'Number']

            # Output entry
            result = {
                'Type': entryTypes['note'],
                'Contents': record_data,
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Incident successfully created', mapped_record,
                                                 headers=display_headers, removeNull=True),
                'EntryContext': {
                    'ServiceNow.Incident(val.ID===obj.ID)': createContext(mapped_record)
                }
            }

except Exception as ex:
    return_error(ex.message)

demisto.results(result)
