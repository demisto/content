import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

'''SETUP'''

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

'''GLOBAL VARS'''

MAX_ROWS = 10000


'''HELPER FUNCTIONS'''


def return_error(data):
    """
    Return error as result and exit
    """
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': data
    })
    sys.exit(0)


def set_provided(params, key, val1, val2=None):
    """
    If value is provided, set it in the dict
    """
    if val1:
        params[key] = val1
    elif val2:
        params[key] = val2


def get_connection():
    """
    Build the connection based on parameters
    """
    creds = demisto.getParam('credentials')
    u = creds.get('identifier')
    p = creds.get('password')
    cert = creds.get('credentials', {}).get('sshkey')
    params = {}
    set_provided(params, 'user', u)
    set_provided(params, 'password', p)
    set_provided(params, 'account', demisto.getParam('account'))
    set_provided(params, 'authenticator', demisto.getParam('authenticator'))
    set_provided(params, 'region', demisto.getParam('region'))
    set_provided(params, 'warehouse', demisto.getArg('warehouse'), demisto.getParam('warehouse'))
    set_provided(params, 'database', demisto.getArg('database'), demisto.getParam('database'))
    set_provided(params, 'schema', demisto.getArg('schema'), demisto.getParam('schema'))
    set_provided(params, 'role', demisto.getArg('role'), demisto.getParam('role'))
    if cert:
        p_key= serialization.load_pem_private_key(cert, backend=default_backend())
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
    conn = get_connection()
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
    demisto.incidents([{"Name":"Incident #1"},{"Name":"Incident #2"}])


def snowflake_query_command():
    conn = get_connection()
    if conn:
        try:
            query = demisto.getArg('query')
            cur = conn.cursor(snowflake.connector.DictCursor)
            cur.execute(query)
            rows = demisto.getArg('rows')
            if rows:
                rows = int(rows)
            if rows and rows > MAX_ROWS:
                rows = MAX_ROWS
            results = cur.fetchmany(rows)
            if results:
                demisto.results({
                    'Type': entryTypes['note'],
                    'ContentsFormat': formats['json'],
                    'Contents': results,
                    'EntryContext': {'Snowflake': {'Query': query, 'Results': results}},
                    'HumanReadable': tableToMarkdown(query, results, argToList(demisto.getArg('columns')))
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
    pass


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

# CMD = demisto.command()
# if CMD == 'test-module':
#     conn = get_connection()
#     demisto.results('ok')
#     conn.close()
# elif CMD == 'snowflake-query':
#     conn = get_connection()
#     if conn:
#         try:
#             query = demisto.getArg('query')
#             cur = conn.cursor(snowflake.connector.DictCursor)
#             cur.execute(query)
#             rows = demisto.getArg('rows')
#             if rows:
#                 rows = int(rows)
#             if rows and rows > MAX_ROWS:
#                 rows = MAX_ROWS
#             results = cur.fetchmany(rows)
#             if results:
#                 demisto.results({
#                     'Type': entryTypes['note'],
#                     'ContentsFormat': formats['json'],
#                     'Contents': results,
#                     'EntryContext': {'Snowflake': {'Query': query, 'Results': results}},
#                     'HumanReadable': tableToMarkdown(query, results, argToList(demisto.getArg('columns')))
#                 })
#             else:
#                 demisto.results('No data found matching the query')
#         except snowflake.connector.errors.ProgrammingError as e:
#             return_error(str(e))
#         finally:
#             if cur:
#                 cur.close()
#             conn.close()
#     else:
#         return_error('Unable to connect')
# elif CMD == 'fetch-incidents':
#     lastRun = demisto.getLastRun()
#     # You can store the last run time...
#     demisto.setLastRun({'time': 'now'})
#     # lastRun is a dictionary, with value "now" for key "time".
#     # JSON of the incident type created by this integration
#     demisto.incidents([{"Name":"Incident #1"},{"Name":"Incident #2"}])
# else:
#     return_error('Unknown command: ' + CMD)
