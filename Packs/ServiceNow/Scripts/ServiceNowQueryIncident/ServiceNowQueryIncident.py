from CommonServerPython import *

"""
This script is used to wrap the generic query-table command in ServiceNow.
You can add fields that you want to use as inputs and outputs from the record as script arguments or in the
code and work with the records easily.


Mandatory fields in your ServiceNow table settings should be changed to be mandatory arguments in this script.
You can identify such fields by trying to get a record and receiving a response
stating that a required field is missing.
"""

"""
Mapping of priority values to their corresponding display in the UI
"""
INCIDENT_PRIORITY = {
    '1': '1 - Critical',
    '2': '2 - High',
    '3': '3 - Moderate',
    '4': '4 - Low',
    '5': '5 - Planning'
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
    query = f'first_name={user_name[0]}^last_name={user_name[1]}'

    user = get_user(query)

    return user[0]['sys_id']


def get_user_name(user_id):
    query = 'id=' + user_id

    user = get_user(query)

    return '{} {}'.format(user[0]['first_name'], user[0]['last_name'])


def main():
    """
    These record fields(columns) are mapped from their names in ServiceNow
    to your choice of field names to be in the output.
    To view all fields for a given table, use the servicenow-list-fields command.
    The ID field must be included to manage unique context entries.
    """
    fields_to_map = {
        'sys_id': 'ID',
        'priority': 'Priority',
        'opened_by': 'Caller',
        'number': 'Number',
        'short_description': 'Description'
    }

    """
    The table name is required by the API. To acquire the table name, use the servicenow-get-table-name command.
    """
    command_args = {
        'table_name': 'incident',
        'fields': list(fields_to_map.keys())
    }

    """
    For each field in the arguments, you need to check if it was provided and apply
    any operations required (e.g, get a user id from a user name) to send them to the API.
    """
    incident_id = demisto.args().get('id')
    incident_number = demisto.args().get('number')
    user_name = demisto.args().get('assignee')
    user_id = None

    if user_name:
        # Query the user table to get the system ID of the assignee
        user_id = get_user_id(user_name)

    """
    Set up the query according to the arguments and execute the command
    """
    if incident_id:
        query = 'id=' + incident_id
    elif incident_number:
        query = 'number=' + incident_number
    elif user_id:
        query = 'assigned_to=' + user_id
    else:
        query = ""
        demisto.debug(f"No incident_id,incident_number or user_id. {query=}")

    command_args['query'] = query

    command_res = demisto.executeCommand('servicenow-query-table', command_args)
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
                # Get the actual records
                records = record_data['result']
                # Map fields according to fields_to_map that were defined earlier
                mapped_records = [
                    {fields_to_map[key]: value for (key, value) in
                     [k_v for k_v in list(r.items()) if k_v[0] in list(fields_to_map.keys())]}
                    for r in records
                ]

                for mr in mapped_records:
                    # Query the user table to get the name of the caller
                    if mr.get('Caller'):
                        mr['Caller'] = get_user_name(mr['Caller'].get('value'))
                    # Map the priority
                    if mr.get('Priority'):
                        mr['Priority'] = INCIDENT_PRIORITY.get(mr['Priority'], mr['Priority'])
                display_headers = ['ID', 'Number', 'Priority', 'Description', 'Caller']

                # Output entry
                result = {
                    'Type': entryTypes['note'],
                    'Contents': record_data,
                    'ContentsFormat': formats['json'],
                    'ReadableContentsFormat': formats['markdown'],
                    'HumanReadable': tableToMarkdown('ServiceNow Incidents', mapped_records, headers=display_headers,
                                                     removeNull=True),
                    'EntryContext': {
                        'ServiceNow.Incident(val.ID===obj.ID)': createContext(mapped_records)
                    }
                }

    except Exception as ex:
        return_error(str(ex))

    demisto.results(result)


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
