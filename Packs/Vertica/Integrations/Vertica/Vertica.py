import demistomock as demisto
from CommonServerPython import *
from datetime import datetime

# fix for: https://github.com/vertica/vertica-python/issues/296
# (we need this for running in non-root where getpass will fail as uid doesn't map to a user name)
import getpass


class FixGetPass():
    """Class to override the getuser function such that it returns a default value on error."""

    def __init__(self):
        # Obtain the original getuser function address.
        self.getpass_getuser_org = getpass.getuser

        # Define new getuser function that does not fail.
        def getuser_no_fail():
            """Safe getuser function that returns a default value on error."""
            # getuser() fails on some systems. Provide a sane default.
            user = 'vertica'
            try:
                # Check if the getpass_getuser_org function exists and was not overriden after init.
                if self.getpass_getuser_org:  # type: ignore[truthy-function]
                    # If so, obtain the user by calling it.
                    user = self.getpass_getuser_org()
            except (NameError, KeyError):
                # If getpass_getuser_org() returns an error use the default user value.
                pass
            return user
        # Override the getpass.getuser function with our safe function.
        getpass.getuser = getuser_no_fail

    def __del__(self):
        # If the getpass_getuser_org and getpass objects are still intact
        if self.getpass_getuser_org and getpass:  # type: ignore[truthy-function]
            # return the state to as it was before the override.
            getpass.getuser = self.getpass_getuser_org


_fix_getpass = FixGetPass()

''' IMPORTS '''

import vertica_python  # noqa: E402

''' HELPER FUNCTIONS '''


def convert_datetime_to_string(v):
    """
    Parses datetime object into string
    """
    if isinstance(v, datetime):
        return v.strftime('%Y-%m-%dT%H:%M:%S')
    return v


def connect_db():
    USERNAME = demisto.params().get('credentials').get('identifier')
    PASSWORD = demisto.params().get('credentials').get('password')
    DATABASE = demisto.params().get('database (mydb)')
    PORT = int(demisto.params().get('port', 5433))
    SERVER = demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()
                                              ['url'].endswith('/')) else demisto.params()['url']
    DB_PARAMS = {
        'host': SERVER,
        'port': PORT,
        'user': USERNAME,
        'password': PASSWORD,
        'database': DATABASE,
        'connection_timeout': 5
    }
    try:
        connection = vertica_python.connect(**DB_PARAMS)
        return connection
    except vertica_python.errors.ConnectionError as err:
        return_error(f'Could not connect to DB, re-check DB params. Error: {err}')


''' COMMANDS + QUERY FUNCTIONS '''


def test_module(cursor):
    """
    Performs basic query on default system tables
    """
    cursor.execute('SELECT * FROM system_tables ORDER BY table_schema, table_name LIMIT 2;')
    cursor.fetchall()
    if cursor.rowcount == 0:
        return_error('No results were returned from the DB.')
    demisto.results('ok')


def query_command(cursor):
    """
    Execute a query against the DB
    """
    # Init main vars
    contents = []  # type: list
    context = {}
    title = ''
    human_readable = 'No results found'
    # Get arguments from user
    query = demisto.args().get('query')
    limit = int(demisto.args().get('limit', 50))
    # Query and get raw response (list of ordered dicts)
    rows = query_request(query, cursor)

    # Parse response into context & content entries
    if rows:
        if limit:
            rows = rows[:limit]

        for i, row in enumerate(rows):
            rows[i] = {underscoreToCamelCase(k): convert_datetime_to_string(v) for k, v in row.items()}

        contents = rows
        context['Vertica(val.Query && val.Query === obj.Query)'] = {
            'Query': query,
            'Row': rows
        }

        title = 'Vertica Query Results'
        human_readable = tableToMarkdown(title, contents, removeNull=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def query_request(query, cursor):
    try:
        cursor.execute(query)
    except vertica_python.errors.MissingRelation:
        return_error('Error while executing query.')
    rows = cursor.fetchall()
    # If row count is empty or number of results is unknown (in that case we want to prevent unexpected results)
    if cursor.rowcount in {0, -1}:
        return False
    else:
        return rows


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is %s' % (demisto.command()))
    connection = None
    try:
        connection = connect_db()
        cursor = connection.cursor('dict')
        if demisto.command() == 'test-module':
            test_module(cursor)
        elif demisto.command() == 'vertica-query':
            query_command(cursor)
    # Log exceptions
    except Exception as e:
        LOG(e)
        LOG.print_log()
        raise
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception as ex:
                demisto.error(f"Vertica failed connection.close(): {ex}")


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
