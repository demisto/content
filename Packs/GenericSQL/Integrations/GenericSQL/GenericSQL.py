import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any, Tuple, Dict, List, Callable
import sqlalchemy
import pymysql
import traceback
from sqlalchemy.sql import text

# In order to use and convert from pymysql to MySQL this line is necessary
pymysql.install_as_MySQLdb()


class Client:
    """
    Client to use in the SQL databases integration. Overrides BaseClient Overrides BaseClient
    makes the connection to the DB server
    """

    def __init__(self, dialect: str, host: str, username: str, password: str, port: str,
                 database: str, connect_parameters: str, ssl_connect: bool):
        self.dialect = dialect
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.dbname = database
        self.connect_parameters = connect_parameters
        self.ssl_connect = ssl_connect
        self.connection = self._create_engine_and_connect()

    @staticmethod
    def _convert_dialect_to_module(dialect: str) -> str:
        """
        Converting a dialect to the correct string needed in order to connect the wanted dialect
        :param dialect: the SQL db
        :return: a key string needed for the connection
        """
        if dialect == "MySQL":
            module = "mysql"
        elif dialect == "PostgreSQL":
            module = "postgresql"
        elif dialect == "Oracle":
            module = "oracle"
        elif dialect == "Microsoft SQL Server":
            module = "mssql+pyodbc"
        else:
            module = str(dialect)
        return module

    def _create_engine_and_connect(self) -> sqlalchemy.engine.base.Connection:
        """
        Creating and engine according to the instance preferences and connecting
        :return: a connection object that will be used in order to execute SQL queries
        """
        try:
            module = self._convert_dialect_to_module(self.dialect)
            db_preferences = f'{module}://{self.username}:{self.password}@{self.host}:{self.port}/{self.dbname}'
            ssl_connection = {}
            if self.dialect == "Microsoft SQL Server":
                db_preferences += "?driver=FreeTDS"
            if self.connect_parameters and self.dialect == "Microsoft SQL Server":
                db_preferences += f'&{self.connect_parameters}'
            elif self.connect_parameters and self.dialect != "Microsoft SQL Server":
                # a "?" was already added when the driver was defined
                db_preferences += f'?{self.connect_parameters}'

            if self.ssl_connect:
                ssl_connection = {'ssl': {'ssl-mode': 'preferred'}}

            return sqlalchemy.create_engine(db_preferences, connect_args=ssl_connection).connect()
        except Exception as err:
            raise Exception(err)

    def sql_query_execute_request(self, sql_query: str, bind_vars: Any) -> Tuple[Dict, List]:
        """Execute query in DB via engine
        :param bind_vars: in case there are names and values - a bind_var dict, in case there are only values - list
        :param sql_query: the SQL query
        :return: results of query, table headers
        """
        if type(bind_vars) is dict:
            sql_query = text(sql_query)

        result = self.connection.execute(sql_query, bind_vars)
        results = result.fetchall()
        headers = []
        if results:
            # if the table isn't empty
            headers = results[0].keys()
        return results, headers


def generate_default_port_by_dialect(dialect: str) -> str:
    """
    In case no port was chosen, a default port will be chosen according to the SQL db type
    :param dialect: sql db type
    :return: default port needed for connection
    """
    if dialect == "MySQL":
        return "3306"
    elif dialect == "PostgreSQL":
        return "5432"
    elif dialect == "Oracle":
        return "1521"
    elif dialect == "Microsoft SQL Server":
        return "1433"
    else:
        # set default to mysql
        return "3306"


def generate_bind_vars(bind_variables_names: str, bind_variables_values: str) -> Any:
    """
    The bind variables can be given in 2 legal ways: as 2 lists - names and values, or only values
    any way defines a different executing way, therefore there are 2 legal return types
    :param bind_variables_names: the names of the bind variables, must be in the length of the values list
    :param bind_variables_values: the values of the bind variables, can be in the length of the names list
            or in case there is no name lists - at any length
    :return: a dict or lists of the bind variables
    """
    bind_variables_names_list = argToList(bind_variables_names)
    bind_variables_values_list = argToList(bind_variables_values)

    if bind_variables_values and not bind_variables_names:
        return [var for var in argToList(bind_variables_values)]
    elif len(bind_variables_names_list) is len(bind_variables_values_list):
        return dict(zip(bind_variables_names_list, bind_variables_values_list))
    else:
        raise Exception("The bind variables lists are not is the same length")


def test_module(client: Client, *_) -> Tuple[str, Dict[Any, Any], List[Any]]:
    """
    If the connection in the client was successful the test will return OK
    if it wasn't an exception will be raised
    """
    return 'ok', {}, []


def sql_query_execute(client: Client, args: dict, *_) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Executes the sql query with the connection that was configured in the client
    :param client: the client object with the db connection
    :param args: demisto.args() including the sql query
    :return: Demisto outputs
    """
    try:
        sql_query = str(args.get('query'))
        limit = int(args.get('limit', 50))
        skip = int(args.get('skip', 0))
        bind_variables_names = args.get('bind_variables_names', "")
        bind_variables_values = args.get('bind_variables_values', "")
        bind_variables = generate_bind_vars(bind_variables_names, bind_variables_values)

        result, headers = client.sql_query_execute_request(sql_query, bind_variables)
        # converting an sqlalchemy object to a table
        converted_table = [dict(row) for row in result]
        # converting b'' and datetime objects to readable ones
        table = [{str(key): str(value) for key, value in dictionary.items()} for dictionary in converted_table]
        table = table[skip:skip + limit]
        human_readable = tableToMarkdown(name="Query result:", t=table, headers=headers,
                                         removeNull=True)
        context = {
            'Result': table,
            'Query': sql_query,
            'InstanceName': f'{client.dialect}_{client.dbname}'
        }
        entry_context: Dict = {'GenericSQL(val.Query && val.Query === obj.Query)': {'GenericSQL': context}}
        return human_readable, entry_context, table

    except Exception as err:
        # In case there is no query executed and only an action e.g - insert, delete, update
        # the result will raise an exception when we try to read the data from it
        if str(err) == "This result object does not return rows. It has been closed automatically.":
            human_readable = "Command executed"
            return human_readable, {}, []
        raise err


def main():
    params = demisto.params()
    dialect = params.get('dialect')
    port = params.get('port')
    if port is None:
        port = generate_default_port_by_dialect(dialect)
    user = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    host = params.get('host')
    database = params.get('dbname')
    ssl_connect = params.get('ssl_connect')
    connect_parameters = params.get('connect_parameters')
    try:
        command = demisto.command()
        LOG(f'Command being called in SQL is: {command}')
        client = Client(dialect=dialect, host=host, username=user, password=password,
                        port=port, database=database, connect_parameters=connect_parameters, ssl_connect=ssl_connect)
        commands: Dict[str, Callable[[Client, Dict[str, str], str], Tuple[str, Dict[Any, Any], List[Any]]]] = {
            'test-module': test_module,
            'query': sql_query_execute,
            'sql-command': sql_query_execute
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args(), command))
        else:
            raise NotImplementedError(f'{command} is not an existing Generic SQL command')
        client.connection.close()
    except Exception as err:
        return_error(f'Unexpected error: {str(err)} \nquery: {demisto.args().get("query")} \n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
