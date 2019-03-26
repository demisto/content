import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from datetime import date, timedelta, datetime
from datetime import time as dttime
from decimal import Decimal

'''GLOBAL VARS'''

PARAMS = demisto.params()
CREDENTIALS = PARAMS.get('credentials')
USER = CREDENTIALS.get('identifier')
PASSWORD = CREDENTIALS.get('password')
CERTIFICATE = CREDENTIALS.get('credentials', {}).get('sshkey')
ACCOUNT = PARAMS.get('account')
AUTHENTICATOR = PARAMS.get('authenticator')
REGION = PARAMS.get('region')
WAREHOUSE = PARAMS.get('warehouse')
DATABASE = PARAMS.get('database')
SCHEMA = PARAMS.get('schema')
ROLE = PARAMS.get('role')
PROXY = PARAMS.get('proxy', False)
# How much time before the first fetch to retrieve incidents
IS_FETCH = PARAMS.get('isFetch')
FETCH_TIME = PARAMS.get('fetch_time')
FETCH_QUERY = PARAMS.get('fetch_query')
DATETIME_COLUMN = PARAMS.get('datetime_column')
INCIDENT_NAME_COLUMN = PARAMS.get('incident_name_column')
MAX_ROWS = 10000

'''SETUP'''

if not PROXY:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

if IS_FETCH and not (FETCH_QUERY and DATETIME_COLUMN):
    err_msg = 'When fetching is enabled there are two additional parameters that are required;'
    err_msg += ' The fetch query that determines what data to fetch and the name of the column'
    err_msg += ' in the fetched data that contains a datetime object or timestamp.'
    return_error(err_msg)


'''HELPER CLASSES'''


class DemistoError(Exception):
    """Basic exception for errors raised by Demisto"""
    def __init__(self, msg=None):
        if not msg:
            msg = 'A Demisto integration error occurred'
        super(DemistoError, self).__init__(msg)


class FetchError(DemistoError):
    """For errors that occur in the inside an integration's fetch_incidents method"""
    def __init__(self, msg=None):
        if not msg:
            msg = 'An error occurred whilst trying to fetch incidents'
        super(FetchError, self).__init__(msg)


'''HELPER FUNCTIONS'''


def convert_datetime_to_string(v):
    """
    Parses date, time, timedelta, or datetime object into string

    parameter: (datetime/date/time/timedelta) v
        The datetime/date/time/timedelta object to convert

    returns:
        Formatted string of the object
    """
    if isinstance(v, datetime):
        return v.strftime('%Y-%m-%d %H:%M:%S.%f %z')
    elif isinstance(v, date):
        return v.strftime('%Y-%m-%d')
    elif isinstance(v, dttime) or isinstance(v, timedelta):
        return v.strftime('%H:%M:%S.%f')
    return v


def set_provided(params, key, val1, val2=None):
    """
    If value is provided, set it in the dict
    """
    if val1:
        params[key] = val1
    elif val2:
        params[key] = val2


def process_table_row(row, checks):
    """
    Check row data and reformat if necessary

    parameter: (dict) row
        The data (table row) that needs to be processed

    parameter: (dict[str, list]) checks
        Dictionary where the key is a string indicative of the type (or bucket of types) that needs
        reformatting and the values are a list of column names whose data is of that type

    returns:
        Reformatted Row
    """
    for column_name, val in row.items():
        if column_name in checks.get('isDecimal', []):
            # Then check the value and reformat it if necessary
            if type(val) == Decimal:
                row[column_name] = str(val)
        elif column_name in checks.get('isDT', []):
            # Then reformat it if necessary
            row[column_name] = convert_datetime_to_string(val)
    return row


def format_to_json_serializable(column_descriptions, results):
    """
    Screen and reformat any data in 'results' argument that is
    not json serializable, and return 'results'. 'results' can
    be a table of data (a list of rows) or a single row.

    parameter: (list) column_descriptions
        The metadata that describes data for each column in the 'results' parameter

    parameter: (list/dict) results
        What was returned by the cursor object's execute or fetch operation

    returns:
        Reformatted 'results'
    """
    name = 0
    type_code = 1

    checks = {}
    # Screen by type_code
    for col in column_descriptions:
        if col[type_code] == 0:
            # Then need to check that column's data to see if its data type is Decimal
            checks.setdefault('isDecimal', []).append(col[name])
        elif col[type_code] in {3, 4, 6, 7, 8, 12}:
            # Then need to check that column's data to see if its data type is date, time, timedelta or datetime
            checks.setdefault('isDT', []).append(col[name])

    # if 'results' is a list then it is a data table (list of rows) and need to process each row
    # in the table, otherwise if 'results' is a dict then it a single table row
    # Check candidates and reformat if necessary
    if isinstance(results, dict):
        results = process_table_row(results, checks)
    else:
        # if 'results' isn't a dict, assume it's a list
        for i, row in enumerate(results):
            results[i] = process_table_row(row, checks)
    return results


def get_connection(args):
    """
    Build the connection based on parameters

    parameter: (dict) args
        The command arguments of the command function calling this helper function

    returns:
        Snowflake connection
    """
    params = {}
    set_provided(params, 'user', USER)
    set_provided(params, 'password', PASSWORD)
    set_provided(params, 'account', ACCOUNT)
    set_provided(params, 'authenticator', AUTHENTICATOR)
    set_provided(params, 'region', REGION)
    set_provided(params, 'warehouse', args.get('warehouse'), WAREHOUSE)
    set_provided(params, 'database', args.get('database'), DATABASE)
    set_provided(params, 'schema', args.get('schema'), SCHEMA)
    set_provided(params, 'role', args.get('role'), ROLE)
    if CERTIFICATE:
        p_key = serialization.load_pem_private_key(CERTIFICATE, backend=default_backend())
        pkb = p_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        params['private_key'] = pkb
    return snowflake.connector.connect(**params)


def row_to_incident(column_descriptions, row):
    """
    Create incident from data returned by queried database in fetch_incidents

    parameter: (list) column_descriptions
        The metadata that describes the values for each column in the 'data' parameter

    parameter: (dict) row
        The row of data where each cell's key in the row is the name of the column
        to which it belongs

    returns:
        Incident Object
    """
    incident = {}
    occurred = row.get(DATETIME_COLUMN)
    timestamp = None
    if occurred:
        if isinstance(occurred, dttime) or isinstance(occurred, timedelta):
            err_msg = 'The datetime field specified in the integration parameters must '
            err_msg += 'contain values of type "datetime" or "date".'
            raise FetchError(err_msg)
        timestamp = occurred.timestamp() * 1000
    else:
        err_msg = 'Nothing found when trying to fetch the datetime field specified in'
        err_msg += ' the integration parameters. Please check that the name was correct.'
        err_msg += ' If the field name was correct, verify that the returned value for'
        err_msg += ' the specified field is not NULL for ALL of the rows to be fetched.'
        raise FetchError(err_msg)
    # Incident Title
    if INCIDENT_NAME_COLUMN:
        name = row.get(INCIDENT_NAME_COLUMN)
    else:
        name = 'Snowflake Incident -- ' + convert_datetime_to_string(occurred) + '-' + datetime.now().timestamp()
    incident['name'] = name
    # Incident occurrence time as timestamp - the datetime field specified in the integration parameters
    incident['timestamp'] = timestamp
    # The raw response for the row (reformatted to be json serializable) returned by the db query
    reformatted_row = format_to_json_serializable(column_descriptions, row)
    incident['rawJSON'] = json.dumps(reformatted_row)
    return incident


'''MAIN FUNCTIONS / API CALLS'''


def test_module():
    """
    Test the validity of the integration instance parameters by trying to create a connection

    returns:
        An 'ok' message if valid, otherwise an error message
    """
    conn = get_connection({})
    demisto.results('ok')
    conn.close()


def fetch_incidents():
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetched_data_timestamp')
    first_fetch = False

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        first_fetch = True
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)
    args = {'rows': MAX_ROWS, 'query': FETCH_QUERY}

    column_descriptions, data = snowflake_query(args)
    # convert the data/events to demisto incidents
    incidents = []
    for row in data:
        incident = row_to_incident(column_descriptions, row)
        incident_timestamp = incident.get('timestamp')

        # Update last run and add incident if the incident is newer than last fetch
        if incident_timestamp and incident_timestamp >= last_fetch:
            if first_fetch:
                last_fetch = incident_timestamp
                incidents.append(incident)
                first_fetch = False
            elif len(incidents) >= 1 and incident.get('rawJSON') != incidents[-1].get('rawJSON'):
                last_fetch = incident_timestamp
                incidents.append(incident)

    demisto.setLastRun({'last_fetched_data_timestamp': last_fetch})
    demisto.incidents(incidents)


def snowflake_query(args):
    connection = get_connection(args)
    if connection:
        try:
            query = args.get('query')
            cur = connection.cursor(snowflake.connector.DictCursor)
            cur.execute(query)
            rows = args.get('rows')
            if rows:
                rows = int(rows)
            if rows and rows > MAX_ROWS:
                rows = MAX_ROWS
            results = cur.fetchmany(rows)
            if results:
                return cur.description, results
            else:
                return_error('No data found matching the query')
        except snowflake.connector.errors.ProgrammingError as e:
            return_error(str(e))
        finally:
            if cur:
                cur.close()
            connection.close()
    else:
        return_error('Unable to connect')


def snowflake_query_command():
    args = demisto.args()
    query = args.get('query')
    db = args.get('database') if args.get('database') else DATABASE
    schema = args.get('schema') if args.get('schema') else SCHEMA
    col_descriptions, results = snowflake_query(args)
    results = format_to_json_serializable(col_descriptions, results)

    entry_context = {
        'Database': db,
        'Schema': schema,
        'Query': query,
        'Result': results
    }
    columns = argToList(args.get('columns'))
    human_readable = tableToMarkdown(query, results, columns)
    demisto_transform = 'Snowflake(val.Query && val.Query === obj.Query'
    demisto_transform += ' && val.Database && val.Database === obj.Database'
    demisto_transform += ' && val.Schema && val.Schema === obj.Schema)'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': {
            demisto_transform: entry_context
        }
    })


def snowflake_update_command():
    args = demisto.args()
    connection = get_connection(args)
    if connection:
        try:
            db_operation = args.get('db_operation')
            cursor = connection.cursor()
            cursor.execute(db_operation)
            demisto.results('Operation executed successfully.')
        except snowflake.connector.errors.ProgrammingError as e:
            return_error(str(e))
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        return_error('Unable to connect')


'''COMMAND SWITCHBOARD'''

commands = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents,
    'snowflake-query': snowflake_query_command,
    'snowflake-update': snowflake_update_command
}


'''EXECUTION'''

try:
    if demisto.command() in commands.keys():
        commands[demisto.command()]()
except Exception as e:
    if isinstance(e, FetchError):
        raise e.with_traceback(None)
    else:
        return_error(str(e))
