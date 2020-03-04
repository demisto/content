from typing import Dict, Callable, Tuple, Any, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import sqlalchemy
import pymysql
import psycopg2
#import pyodbc

# explain why?
pymysql.install_as_MySQLdb()


class Client:
    """
    Client to use in the SQL databases integration. Overrides BaseClient
    makes the connection to the DB server
    """
    def __init__(self, dialect: str, host: str, username: str, password: str, port: str,
                 database: str, server_certificate: bool, connect_parameters: str):
        self.dialect = dialect
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.dbname = database
        self.server_certificate = server_certificate
        self.connect_parameters = connect_parameters
        self.engine = self._create_engine_and_connect()

    @staticmethod
    def _convert_dialect_to_module(dialect: str) -> str:
        module = ""
        if dialect == "MySQL":
            module = "mysql"
        elif dialect == "PostgreSQL":
            module = "postgresql"
        elif dialect == "Oracle":
            module = "oracle"
        elif dialect == "Microsoft SQL Server":
            module = "mssql"
        else:
            module = str(dialect)
        return module

    def _create_engine_and_connect(self):
        try:
            module = self._convert_dialect_to_module(self.dialect)
            db_preferences = f'{module}://{self.username}:{self.password}@{self.host}:{self.port}/{self.dbname}'
            if self.connect_parameters: # debug - make sure that if empty returns None
                db_preferences += f'?{self.connect_parameters}'
            if self.server_certificate:
                db_preferences += '?verify_ssl_cert=True'
            return sqlalchemy.create_engine(db_preferences).connect()
        except Exception as err:
            raise Exception(err)

    def sql_query_execute_request(self, sql_query: str, bind_vars: list) -> Tuple[Dict, List]:
        """Execute query in DB via engine

        :param bind_vars:
        :param sql_query: bf
        :return: results of query, table headers
        """
        result = self.engine.execute(sql_query, bind_vars)
        results = result.fetchall()
        headers = results[0].keys()
        return results, headers


def generate_default_port_by_dialect(dialect: str) -> str:
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
    bind_variables_names_list = argToList(bind_variables_names)
    bind_variables_values_list = argToList(bind_variables_values)

    if bind_variables_values and not bind_variables_names:
        a=1
        # only vars, some dialect support positaniol bind vars notation
        #??check
    elif len(bind_variables_names_list) is not len(bind_variables_values_list):
        raise Exception("The bind variables lists are not is the same length")
    else:
        return dict(zip(bind_variables_names_list, bind_variables_values_list))


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
    try:
        sql_query = args.get('query')
        limit = int(args.get('limit', 50))
        skip = int(args.get('skip', 0))
        bind_variables = generate_bind_vars(args.get('bind_variables_names'), args.get('bind_variables_values'))

        result, headers = client.sql_query_execute_request(sql_query, bind_variables)
        table = [dict(row) for row in result]
        human_readable = tableToMarkdown(name="Query result:", t=table[skip:skip + limit], headers=headers,
                                         removeNull=True)
        context = {
            'Result': table,
            'Query': sql_query,
            'InstanceName': f'{client.dialect}_{client.dbname}'
        }
        entry_context: Dict = {f'GenericSQL(val.Query && val.Query === obj.Query)': {'GenericSQL': context}}
        return human_readable, entry_context, table

    except Exception as err:
        # explain
        if str(err) == "This result object does not return rows. It has been closed automatically.":
            human_readable = "Command executed"
            return human_readable, {}, []
        else:
            return_error(err)


def main():
    params = demisto.params()
    dialect = params.get('dialect')
    port = params.get('port', generate_default_port_by_dialect(dialect))
    user = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    host = params.get('host')
    database = params.get('dbname')
    trust_server_certificate = params.get('trustServerCertificate') #'verify_ssl_cert'
    connect_parameters = params.get('connectParameters')

    try:
        command = demisto.command()
        LOG(f'Command being called in SQL is: {command}')
        client = Client(dialect=dialect, host=host, username=user, password=password,
                        port=port, database=database, server_certificate=trust_server_certificate,
                        connect_parameters=connect_parameters)
        commands: Dict[str, Callable[[Client, Dict[str, str], str], Tuple[str, Dict[Any, Any], List[Any]]]] = {
            'test-module': test_module,
            'query': sql_query_execute,
            'sql-command': sql_query_execute
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args(), command))
        else:
            raise NotImplementedError(f'{command} is not an existing Generic SQL command')
        client.engine.close()
    except Exception as err:
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
