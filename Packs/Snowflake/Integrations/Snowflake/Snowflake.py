import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import date, timedelta, datetime
from datetime import time as dttime
from decimal import Decimal

'''GLOBAL VARS'''

PARAMS = demisto.params()
CREDENTIALS = PARAMS.get('credentials')
USER = CREDENTIALS.get('identifier')
PASSWORD = CREDENTIALS.get('password')
CERTIFICATE = CREDENTIALS.get('credentials', {}).get('sshkey').encode()
CERT_PASSWORD = CREDENTIALS.get('credentials', {}).get('password')
CERT_PASSWORD = CERT_PASSWORD.encode() if CERT_PASSWORD else None
ACCOUNT = PARAMS.get('account')
AUTHENTICATOR = PARAMS.get('authenticator')
REGION = PARAMS.get('region')
WAREHOUSE = PARAMS.get('warehouse')
DATABASE = PARAMS.get('database')
SCHEMA = PARAMS.get('schema')
ROLE = PARAMS.get('role')
INSECURE = PARAMS.get('insecure', False)
# How much time before the first fetch to retrieve incidents
IS_FETCH = PARAMS.get('isFetch')
FETCH_TIME = PARAMS.get('fetch_time')
FETCH_QUERY = PARAMS.get('fetch_query')
DATETIME_COLUMN = PARAMS.get('datetime_column')
INCIDENT_NAME_COLUMN = PARAMS.get('incident_name_column')
MAX_ROWS = int(PARAMS.get('limit')) if PARAMS.get('limit') else 10000

TYPE_CODE_TO_DATATYPE = {
    0: 'number/int',
    1: 'real',
    2: 'varchar/string',
    3: 'date',
    4: 'timestamp',
    5: 'variant',
    6: 'timestamp_ltz',
    7: 'timestamp_tz',
    8: 'timestamp_tz',
    9: 'object',
    10: 'array',
    11: 'binary',
    12: 'time',
    13: 'boolean'
}
DT_NEEDS_CHECKING = {'date', 'timestamp', 'timestamp_ltz', 'timestamp_tz', 'time'}


'''SETUP'''

if IS_FETCH and not (FETCH_QUERY and DATETIME_COLUMN):
    err_msg = 'When fetching is enabled there are two additional parameters that are required;'
    err_msg += ' The fetch query that determines what data to fetch and the name of the column'
    err_msg += ' in the fetched data that contains a datetime object or timestamp.'
    raise Exception(err_msg)


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
        return v.strftime('%Y-%m-%d %H:%M:%S.%f %z').strip()
    elif isinstance(v, date):
        return v.strftime('%Y-%m-%d').strip()
    elif isinstance(v, dttime):
        return v.strftime('%H:%M:%S.%f').strip()
    return v


def error_message_from_snowflake_error(e):
    """
    Return formatted error message from contents of a Snowflake error

    parameter: (snowflake.connector.errors.Error) e
        The Snowflake error object

    returns:
        Formatted error message
    """
    err_msg = f'Snowflake DB error code: {e.errno}\n'
    err_msg += f'ANSI-compliant SQL State code: {e.sqlstate}\n'
    err_msg += f'Snowflake query ID: {e.sfqid}\n'
    err_msg += 'Error message: {}'
    if e.errno == 606:
        first_sentence = e.raw_msg[:e.raw_msg.find('.') + 1]
        err_msg = err_msg.format(first_sentence)
        err_msg += ' Specify an active warehouse in the command '
        err_msg += 'arguments or in the integration parameters.'
    elif e.errno == 2003:
        err_msg = err_msg.format(e.raw_msg)
        err_msg += ' A possible explanation is that the values you entered'
        err_msg += ' for the \'warehouse\' and \'database\' were incorrect.'
    else:
        err_msg = err_msg.format(e.raw_msg)
    return err_msg


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

    The 'checks' parameter contains the names of fields that have the potential to cause
    issues when they will be json decoded. This function checks the values of the fields
    flagged in the 'checks' parameter and formats the contents to a json friendly type if
    necessary.

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
            if isinstance(val, Decimal):
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

    checks: dict = {}
    # Screen by type_code
    for col in column_descriptions:
        # if col[type_code] == 0:
        if TYPE_CODE_TO_DATATYPE.get(col[type_code]) == 'number/int':
            # Then need to check that column's data to see if its data type is Decimal
            checks.setdefault('isDecimal', []).append(col[name])
        # elif col[type_code] in {3, 4, 6, 7, 8, 12}:
        elif TYPE_CODE_TO_DATATYPE.get(col[type_code]) in DT_NEEDS_CHECKING:
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


def get_connection_params(args):
    """
    Construct and return the connection parameters

    parameter: (dict) args
        The command arguments of the command function calling this helper function

    returns:
        Snowflake connection params
    """
    params: dict = {}
    set_provided(params, 'user', USER)
    set_provided(params, 'password', PASSWORD)
    set_provided(params, 'account', ACCOUNT)
    set_provided(params, 'authenticator', AUTHENTICATOR)
    set_provided(params, 'region', REGION)
    set_provided(params, 'insecure_mode', INSECURE)
    set_provided(params, 'warehouse', args.get('warehouse'), WAREHOUSE)
    set_provided(params, 'database', args.get('database'), DATABASE)
    set_provided(params, 'schema', args.get('schema'), SCHEMA)
    set_provided(params, 'role', args.get('role'), ROLE)
    if CERTIFICATE:
        p_key = serialization.load_pem_private_key(CERTIFICATE, password=CERT_PASSWORD, backend=default_backend())
        pkb = p_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        params['private_key'] = pkb
    return params


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
        if isinstance(occurred, (dttime, timedelta)):
            err_msg = 'The datetime field specified in the integration parameters must '
            err_msg += 'contain values of type "datetime" or "date".'
            raise Exception(err_msg)
        timestamp = occurred.timestamp() * 1000
    else:
        err_msg = 'Nothing found when trying to fetch the datetime field specified in'
        err_msg += ' the integration parameters. Please check that the name was correct.'
        err_msg += ' If the field name was correct, verify that the returned value for'
        err_msg += ' the specified field is not NULL for ALL of the rows to be fetched.'
        raise Exception(err_msg)
    # Incident Title
    if INCIDENT_NAME_COLUMN:
        name = row.get(INCIDENT_NAME_COLUMN)
    else:
        name = 'Snowflake Incident -- '
        name += convert_datetime_to_string(occurred) + '- ' + str(datetime.now().timestamp())
    incident['name'] = name
    incident['occurred'] = occurred.isoformat()
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
    params = get_connection_params({})
    with snowflake.connector.connect(**params):
        demisto.results('ok')


def fetch_incidents():
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
    # Get the last fetch time and data if it exists
    last_fetch = last_run.get('last_fetched_data_timestamp')
    last_fetched_data = last_run.get('last_fetched_data')

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)
    args = {'rows': MAX_ROWS, 'query': FETCH_QUERY}
    column_descriptions, data = snowflake_query(args)
    data.sort(key=lambda k: k[DATETIME_COLUMN])
    # convert the data/events to demisto incidents
    incidents = []
    for row in data:
        incident = row_to_incident(column_descriptions, row)
        incident_timestamp = incident.get('timestamp')

        # Update last run and add incident if the incident is newer than last fetch
        if incident_timestamp and incident_timestamp >= last_fetch:
            last_fetch = incident_timestamp
            if incident.get('rawJSON') != last_fetched_data:
                last_fetched_data = incident.get('rawJSON')
                del incident['timestamp']
                incidents.append(incident)

    this_run = {
        'last_fetched_data': last_fetched_data,
        'last_fetched_data_timestamp': last_fetch
    }
    demisto.setLastRun(this_run)
    demisto.incidents(incidents)


def snowflake_query(args):
    params = get_connection_params(args)
    query = args.get('query')
    limit = args.get('limit', '100')
    try:
        limit = int(limit)
    except ValueError:
        raise ValueError('The value for limit must be an integer.')
    if limit > MAX_ROWS:
        limit = MAX_ROWS
    with snowflake.connector.connect(**params) as connection:
        with connection.cursor(snowflake.connector.DictCursor) as cur:
            cur.execute(query)
            results = cur.fetchmany(limit)
            if results:
                return cur.description, results
            else:
                return [], []


def snowflake_query_command():
    args = demisto.args()
    query = args.get('query')
    db = args.get('database') if args.get('database') else DATABASE
    schema = args.get('schema') if args.get('schema') else SCHEMA
    col_descriptions, results = snowflake_query(args)
    if not results:
        demisto.results('No data found matching the query')
    else:
        results = format_to_json_serializable(col_descriptions, results)

        entry_context = {
            'Database': db,
            'Schema': schema,
            'Query': query,
            'Result': results
        }
        columns = argToList(args.get('columns'))
        human_readable = tableToMarkdown(query, results, columns, removeNull=True)
        demisto_transform = 'Snowflake(val.Query && val.Query === obj.Query'
        demisto_transform += ' && val.Database && val.Database === obj.Database'
        demisto_transform += ' && val.Schema && val.Schema === obj.Schema)'
        outputs = {demisto_transform: entry_context}

        return_outputs(
            outputs=outputs,
            readable_output=human_readable,
            raw_response=results
        )


def snowflake_update_command():
    args = demisto.args()
    db_operation = args.get('db_operation')
    params = get_connection_params(args)
    with snowflake.connector.connect(**params) as connection:
        with connection.cursor() as cursor:
            cursor.execute(db_operation)
            demisto.results('Operation executed successfully.')


'''COMMAND SWITCHBOARD'''

commands = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents,
    'snowflake-query': snowflake_query_command,
    'snowflake-update': snowflake_update_command
}


'''EXECUTION'''

try:
    handle_proxy()
    if demisto.command() in commands:
        commands[demisto.command()]()
except snowflake.connector.errors.Error as e:
    return_error(error_message_from_snowflake_error(e))
except Exception as e:
    if IS_FETCH:
        raise e
    else:
        if isinstance(e, snowflake.connector.errors.Error):
            return_error(error_message_from_snowflake_error(e))
        else:
            return_error(str(e))
