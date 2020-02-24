from typing import Dict, Callable, Tuple, Any, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import sqlalchemy
import pymysql
import psycopg2

# explain why?
pymysql.install_as_MySQLdb()


def get_table_name_from_query(sql_query: str):
    """
    :param sql_query: the sql full query as string
    :return: the tables name - placed at the query after the keyword "FROM"
    """
    if "from" in sql_query.lower():
        keyword = "from"
    elif "into" in sql_query.lower():
        keyword = "into"
    elif "select" in sql_query.lower():
        keyword = "select"
    elif "update" in sql_query.lower():
        keyword = "update"
    else:
        return "table"
    # the word after the chosen keyword is the table name
    # the keyword in not case sensitive therefor we find the index and extracting the name from the origin
    # sql_query string
    before_keyword, keyword, after_keyword = sql_query.lower().partition(keyword)
    index = len(before_keyword.split()) + 1
    table_name = sql_query.split()[index]
    # if the name of the tabkle and it's values are written without space there is a need in another filter
    before_keyword, keyword, after_keyword = table_name.partition("(")
    return before_keyword


class Client:
    """
    Client to use in the SQL databases integration. Overrides BaseClient
    makes the connection to the DB server
    """
    def __init__(self, dialect: str, server_url: str, username: str, password: str, port: str,
                 database: str):
        self.dialect = dialect
        self.server_url = server_url
        self.username = username
        self.password = password
        self.port = port
        self.dbname = database
        self.engine = self._create_engine_and_connect()

    @staticmethod
    def _convert_dialect_to_module(dialect: str) -> str:
        module = ""
        if dialect == "MySQL":
            module = "mysql://"
        elif dialect == "PostgreSQL":
            module = "postgresql://"
        elif dialect == "SQLite":
            module = "sqlite:///"
        elif dialect == "Oracle":
            module = "oracle://"
        elif dialect == "MicrosoftSQLServer":
            module = "mssql://"
        else:
            module = str(dialect + "://")
        return module

    def _create_engine_and_connect(self):
        try:
            module = self._convert_dialect_to_module(self.dialect)
            db_preferences = f'{module}{self.username}:{self.password}@{self.server_url}:{self.port}/{self.dbname}'
            return sqlalchemy.create_engine(db_preferences).connect()
        except Exception as err:
            # raise Exception(generate_error_message(str(err)))
            raise Exception(err)

    def sql_query_execute_request(self, sql_query: str) -> Tuple[Dict, List]:
        """Execute query in DB via engine

        :param sql_query: bf
        :return: results of query, table headers
        """
        result = self.engine.execute(sql_query)
        results = result.fetchall()
        headers = results[0].keys()
        return results, headers

    def sql_command_execute(self, sql_query: str):
        """Execute query in DB via engine

        :param sql_query: bf
        """
        self.engine.execute(sql_query)


def generate_error_message(error_message):
    keyword = '"'
    return (error_message.split(keyword))[1].split(keyword)[0]


def generate_command_execute_messages(command: str, db_name: str, table_name: str):
    if command == 'sql-insert':
        return f'Insert command executed to {db_name} db into {table_name} table'
    elif command == 'sql-update':
        return f'Update command executed in {db_name} db in {table_name} table'
    elif command == 'sql-delete':
        return f'Delete command executed from {db_name} db from {table_name} table'
    else:
        return f'{command} command executed using {db_name} db and {table_name} table'


def test_module(client: Client, *_):
    """
    Performs basic connect to SQL server
    If the connection in the client was successful the test will return OK
    if it wasn't an exception will be raised
    """
    return 'ok', None, None


def sql_query_execute(client: Client, args: dict, *_) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Executes the sql query with the connection that was configurator in the client
    :param client: the client object with the db connection
    :param args: demisto.args() including the sql query
    :return: Demisto outputs
    """
    sql_query = args.get('query')
    result, headers = client.sql_query_execute_request(sql_query)
    limit = int(args.get('limit', 50))
    skip = int(args.get('skip', 0))
    t = [dict(row) for row in result]
    human_readable = tableToMarkdown(name="Query result:", t=t[skip:skip + limit], headers=headers, removeNull=True)
    table_name = get_table_name_from_query(str(sql_query))
    hierarchy = f'GenericSQL.{client.dialect}.{client.dbname}'
    context: Dict = {f'{hierarchy}(val.{table_name} && val.{table_name} === obj.{table_name})': t}
    return human_readable, context, t


def sql_command_execute(client: Client, args: dict, command: str) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Executes the sql query with the connection that was configurator in the client
    :param command:
    :param client: the client object with the db connection
    :param args: demisto.args() including the sql query
    :return: a message according to the chosen action
    """
    sql_query = args.get('query')
    client.engine.execute(sql_query)
    table_name = get_table_name_from_query(str(sql_query))
    human_readable = generate_command_execute_messages(command, client.dbname, table_name)
    return human_readable, {}, []


def main():
    params = demisto.params()
    dialect = params.get('dialect')
    user = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    host = params.get('url')
    database = params.get('dbname', "")
    port = params.get('port', "")
    try:
        command = demisto.command()
        LOG(f'Command being called in SQL is: {command}')
        client = Client(dialect=dialect, server_url=host, username=user, password=password,
                        port=port, database=database)
        commands: Dict[str, Callable[[Client, Dict[str, str], str], Tuple[str, Dict[Any, Any], List[Any]]]] = {
            'test-module': test_module,
            'sql-query': sql_query_execute,
            # there is not need in the execution part to separate those commands since they are not returning any
            # significant value and are executed in the same way
            'sql-insert': sql_command_execute,
            'sql-delete': sql_command_execute,
            'sql-update': sql_command_execute
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args(), command))
        else:
            raise NotImplementedError(f'{command} is not an existing Generic SQL command')
        client.engine.close() # check
    except Exception as err:
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
