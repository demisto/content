import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from datetime import date, time
from decimal import Decimal

'''SETUP'''

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

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
MAX_ROWS = 10000


'''HELPER FUNCTIONS'''


def set_provided(params, key, val1, val2=None):
    """
    If value is provided, set it in the dict
    """
    if val1:
        params[key] = val1
    elif val2:
        params[key] = val2


def check_and_update_parameters():
    """
    Update integration instance parameters if they have changed
    """
    pass


def format_to_json_serializable(cursor, results):
    """
    Screen and reformat any data in 'results' argument that is
    not json serializable, and return 'results'

    parameter: (Cursor) cursor
        The database cursor that was used for the execute or
        fetch operation that returned the 'results' argument

    parameter: (list) results
        What was returned by the cursor object's execute or fetch operation

    returns:
        Reformatted 'results' list
    """
    name = 0
    type_code = 1

    checks = {}
    column_descriptions = cursor.description
    # Screen by type_code
    for col in column_descriptions:
        if col[type_code] == 0:
            # Then need to check that column's data to see if its data type is Decimal
            checks.setdefault('isDecimal', []).append(col[name])
        elif col[type_code] == 3:
            # Then need to check that column's data to see if its data type is date
            checks.setdefault('isDate', []).append(col[name])
        elif col[type_code] in {7, 8}:
            # Then need to check that column's data to see if its data type is datetime
            checks.setdefault('isDatetime', []).append(col[name])
        elif col[type_code] == 12:
            # Then need to check that column's data to see if its data type is time
            checks.setdefault('isTime', []).append(col[name])

    # Check candidates and reformat if necessary
    for row in results:
        for column_name, val in row.items():
            if column_name in checks.get('isDecimal', []):
                # Then check the value and reformat it if necessary
                if type(val) == Decimal:
                    row[column_name] = str(val)
            elif column_name in checks.get('isDate', []):
                # Then check the value and reformat it if necessary
                if type(val) == date:
                    row[column_name] = val.strftime('%Y-%m-%d')
            elif column_name in checks.get('isDatetime', []):
                # Then check the value and reformat it if necessary
                if type(val) == datetime:
                    row[column_name] = val.strftime('%Y-%m-%d %H:%M:%S.%f %z')
            elif column_name in checks.get('isTime', []):
                # Then check the value and reformat it if necessary
                if type(val) == time:
                    row[column_name] = val.strftime('%H:%M:%S.%f')
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
    lastRun = demisto.getLastRun()
    # You can store the last run time...
    demisto.setLastRun({'time': 'now'})
    # lastRun is a dictionary, with value "now" for key "time".
    # JSON of the incident type created by this integration
    demisto.incidents([{'Name': 'Incident #1'}, {'Name': 'Incident #2'}])


def snowflake_query_command():
    args = demisto.args()
    conn = get_connection(args)
    if conn:
        try:
            query = args.get('query')
            cur = conn.cursor(snowflake.connector.DictCursor)
            cur.execute(query)
            rows = args.get('rows')
            if rows:
                rows = int(rows)
            if rows and rows > MAX_ROWS:
                rows = MAX_ROWS
            results = cur.fetchmany(rows)
            if results:
                results = format_to_json_serializable(cur, results)

                entry_context = {
                    'Query': query,
                    'Result': results
                }
                columns = argToList(args.get('columns'))
                human_readable = tableToMarkdown(query, results, columns)

                demisto.results({
                    'Type': entryTypes['note'],
                    'ContentsFormat': formats['json'],
                    'Contents': results,
                    'ReadableContentsFormat': formats['markdown'],
                    'HumanReadable': human_readable,
                    'EntryContext': {
                        'Snowflake(val.Query && val.Query === obj.Query)': entry_context
                    }
                })
            else:
                demisto.results('No data found matching the query')
        except snowflake.connector.errors.ProgrammingError as e:
            return_error(str(e))
        finally:
            if cur:
                cur.close()
            conn.close()
    else:
        return_error('Unable to connect')


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
    return_error(e.message)
