import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import cx_Oracle


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
INTEGRATION_NAME = "Oracle DB"


''' Client Class '''


class Client:

    def __init__(self, db_server, service, username, password, privilege, db_version="18", port="1521"):
        self.db_server = db_server
        self.db_version = db_version
        self.service = service
        self.port = port
        self.username = username
        self.password = password
        self.privilege = privilege

    def connection_request(self):
        try:
            easy_connect = self.db_server+":"+self.port+"/"+self.service
            connect = cx_Oracle.connect(self.username, self.password, easy_connect)
            return connect
        except Exception as e:
            raise ValueError("Error while connecting to the database: %s " % e)

    def get_db_version(self):
        connection = self.connection_request()
        return connection.version

    def run_query(self, query, limit):
        columns = []
        limit = int(limit) + 1
        query = query + " where ROWNUM < " + str(limit)
        connection = self.connection_request()
        cursor = connection.cursor()
        rows = cursor.execute(query).fetchall()
        for description in cursor.description:
            columns.append(description[0])
        return rows, columns

    def run_query_json(self, query, limit):
        limit = int(limit) + 1
        query = query + " where ROWNUM < " + str(limit)
        connection = self.connection_request()
        cursor = connection.cursor()
        result = cursor.execute(query).fetchall()
        return result

def test_module(client):
    results = client.connection_request().username
    if results == client.username:
        return 'ok'
    else:
        return 'Test failed, review the connection settings'


def db_query_json(client, args):
    query = args.get('query')
    limit = args.get('limit')
    result = []

    try:
        limit = int(limit)
    except ValueError:
        return_error("Please specify an integer for the limit")

    if limit > 15:
        return_error("Too much data to store, please decrease the limit to 15 rows or less")

    title = ("%s - Results for the Search Query" % INTEGRATION_NAME)

    results = client.run_query_json(query=query,limit=limit)

    for each_row in results:
        result.append(json.loads(each_row[0]))

    readable_output = tableToMarkdown(t=result, name=title)

    outputs = {
        'Oracle.Query': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def db_query(client, args):
    query = args.get('query')
    limit = args.get('limit')
    result = []

    try:
        limit = int(limit)
    except ValueError:
        return_error("Please specify an integer for the limit")

    if limit > 15:
        return_error("Too much data to store, please decrease the limit to 15 rows or less")

    title = ("%s - Results for the Search Query" % INTEGRATION_NAME)

    results = client.run_query(query=query,limit=limit)
    rows = results[0]
    colums = results[1]

    print (colums)

    for each_row in rows:
        result.append(json.loads(each_row[0]))

    readable_output = tableToMarkdown(t=result, name=title)

    outputs = {
        'Oracle.Query': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )

def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    db_server = demisto.params().get('server')
    db_version = demisto.params().get('version')
    service = demisto.params().get('service')
    port = demisto.params().get('port')
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    privilege = demisto.params().get('privilege')

    LOG('Command being called is %s' % demisto.command())

    try:
        client = Client(
            db_server=db_server,
            db_version=db_version,
            service=service,
            port=port,
            username=username,
            password=password,
            privilege=privilege
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'oracle-query-json':
            return_outputs(*db_query_json(client, demisto.args()))

        elif demisto.command() == 'oracle-query':
            return_outputs(*db_query(client, demisto.args()))
    # Log exceptions
    except Exception as e:
        return_error("Failed to execute the command with Error: %s " % str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
