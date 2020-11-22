import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any, Tuple, Dict, List, Callable
import sqlalchemy
import pymysql
import traceback
import hashlib
import logging
import urllib.parse
from sqlalchemy.sql import text
try:
    # if integration is using an older image (4.5 Server) we don't have expiringdict
    from expiringdict import ExpiringDict  # pylint: disable=E0401
except Exception:
    pass


# In order to use and convert from pymysql to MySQL this line is necessary
pymysql.install_as_MySQLdb()

GLOBAL_CACHE_ATTR = '_generic_sql_engine_cache'
DEFAULT_POOL_TTL = 600


class Client:
    """
    Client to use in the SQL databases integration. Overrides BaseClient
    makes the connection to the DB server
    """

    def __init__(self, dialect: str, host: str, username: str, password: str, port: str,
                 database: str, connect_parameters: str, ssl_connect: bool, use_pool=False, pool_ttl=DEFAULT_POOL_TTL):
        self.dialect = dialect
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.dbname = database
        self.connect_parameters = connect_parameters
        self.ssl_connect = ssl_connect
        self.use_pool = use_pool
        self.pool_ttl = pool_ttl
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

    @staticmethod
    def _get_cache_string(url: str, connect_args: dict) -> str:
        to_hash = url + repr(connect_args)
        return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()

    def _get_global_cache(self) -> dict:
        cache = getattr(sqlalchemy, GLOBAL_CACHE_ATTR, None)
        if cache is None:
            cache = ExpiringDict(100, max_age_seconds=self.pool_ttl)
            setattr(sqlalchemy, GLOBAL_CACHE_ATTR, cache)
        return cache

    def _create_engine_and_connect(self) -> sqlalchemy.engine.base.Connection:
        """
        Creating and engine according to the instance preferences and connecting
        :return: a connection object that will be used in order to execute SQL queries
        """
        module = self._convert_dialect_to_module(self.dialect)
        port_part = ''
        encoded_password = urllib.parse.quote_plus(self.password)
        if self.port:
            port_part = f':{self.port}'
        db_preferences = f'{module}://{self.username}:{encoded_password}@{self.host}{port_part}/{self.dbname}'
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
        engine: sqlalchemy.engine.Engine = None
        if self.use_pool:
            if 'expiringdict' not in sys.modules:
                raise ValueError('Usage of connection pool is not support in this docker image')
            cache = self._get_global_cache()
            cache_key = self._get_cache_string(db_preferences, ssl_connection)
            engine = cache.get(cache_key, None)
            if engine is None:  # (first time or expired) need to initialize
                engine = sqlalchemy.create_engine(db_preferences, connect_args=ssl_connection)
                cache[cache_key] = engine
        else:
            demisto.debug('Initializing engine with no pool (NullPool)')
            engine = sqlalchemy.create_engine(db_preferences, connect_args=ssl_connection,
                                              poolclass=sqlalchemy.pool.NullPool)
        return engine.connect()

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
    In case no port was chosen, a default port will be chosen according to the SQL db type. Only return a port for
    Microsoft SQL Server where it seems to be required. For the other drivers an empty port is supported.
    :param dialect: sql db type
    :return: default port needed for connection
    """
    if dialect == "Microsoft SQL Server":
        return "1433"
    else:
        # use default port supported by the driver
        return ""


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


# list of loggers we should set to debug when running in debug_mode
# taken from: https://docs.sqlalchemy.org/en/13/core/engines.html#configuring-logging
SQL_LOGGERS = [
    'sqlalchemy.engine',
    'sqlalchemy.pool',
    'sqlalchemy.dialects',
    'py.warnings',  # SQLAlchemy issues many warnings such as from Oracle Dialect
]


def main():
    sql_loggers: list = []  # saves the debug loggers
    try:
        logging.captureWarnings(True)
        for lgr_name in SQL_LOGGERS:
            lgr = logging.getLogger(lgr_name)
            level = logging.ERROR
            if is_debug_mode():
                level = logging.DEBUG
                sql_loggers.append(lgr)  # in debug mode we save the logger to revert back
                demisto.debug(f'setting {logging.getLevelName(level)} for logger: {repr(lgr)}')
            lgr.setLevel(level)
        params = demisto.params()
        dialect = params.get('dialect')
        port = params.get('port')
        if not port:
            port = generate_default_port_by_dialect(dialect)
        user = params.get("credentials").get("identifier")
        password = params.get("credentials").get("password")
        host = params.get('host')
        database = params.get('dbname') or ''  # Use or to make sure we don't have "None" as a database
        ssl_connect = params.get('ssl_connect')
        connect_parameters = params.get('connect_parameters')
        use_pool = params.get('use_pool', False)
        pool_ttl = int(params.get('pool_ttl') or DEFAULT_POOL_TTL)
        if pool_ttl <= 0:
            pool_ttl = DEFAULT_POOL_TTL
        command = demisto.command()
        LOG(f'Command being called in SQL is: {command}')
        client = Client(dialect=dialect, host=host, username=user, password=password,
                        port=port, database=database, connect_parameters=connect_parameters,
                        ssl_connect=ssl_connect, use_pool=use_pool, pool_ttl=pool_ttl)
        commands: Dict[str, Callable[[Client, Dict[str, str], str], Tuple[str, Dict[Any, Any], List[Any]]]] = {
            'test-module': test_module,
            'query': sql_query_execute,
            'pgsql-query': sql_query_execute,
            'sql-command': sql_query_execute
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args(), command))
        else:
            raise NotImplementedError(f'{command} is not an existing Generic SQL command')
    except Exception as err:
        return_error(f'Unexpected error: {str(err)} \nquery: {demisto.args().get("query")} \n{traceback.format_exc()}')
    finally:
        try:
            if client.connection:
                client.connection.close()
        except Exception as ex:
            demisto.error(f'Failed closing connection: {str(ex)}')
        if sql_loggers:
            for lgr in sql_loggers:
                demisto.debug(f'setting back ERROR for logger: {repr(lgr)}')
                lgr.setLevel(logging.ERROR)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
