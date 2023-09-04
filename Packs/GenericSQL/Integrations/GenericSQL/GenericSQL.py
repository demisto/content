import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any, Tuple, Dict, List, Callable, Optional
import sqlalchemy
import pymysql
import hashlib
import logging
from sqlalchemy.sql import text
from sqlalchemy.engine.url import URL
from urllib.parse import parse_qsl
import dateparser
FETCH_DEFAULT_LIMIT = '50'

try:
    # if integration is using an older image (4.5 Server) we don't have expiringdict
    from expiringdict import ExpiringDict  # pylint: disable=E0401
except Exception:  # noqa: S110
    pass


# In order to use and convert from pymysql to MySQL this line is necessary
pymysql.install_as_MySQLdb()

GLOBAL_CACHE_ATTR = '_generic_sql_engine_cache'
DEFAULT_POOL_TTL = 600

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client:
    """
    Client to use in the SQL databases integration. Overrides BaseClient
    makes the connection to the DB server
    """

    def __init__(self, dialect: str, host: str, username: str, password: str, port: str,
                 database: str, connect_parameters: str, ssl_connect: bool, use_pool=False, verify_certificate=True,
                 pool_ttl=DEFAULT_POOL_TTL):
        self.dialect = dialect
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.dbname = database
        self.connect_parameters = self.parse_connect_parameters(connect_parameters, dialect, verify_certificate)
        self.ssl_connect = ssl_connect
        self.use_pool = use_pool
        self.pool_ttl = pool_ttl
        self.connection = self._create_engine_and_connect()

    @staticmethod
    def parse_connect_parameters(connect_parameters: str, dialect: str, verify_certificate: bool) -> dict:
        """
        Parses a string of the form key1=value1&key2=value2 etc. into a dict with matching keys and values.
        In addition adds a driver key in accordance to the given 'dialect'
        Args:
            verify_certificate: False - Trust any certificate (not secure), otherwise secure
            connect_parameters: The string with query parameters
            dialect: Should be one of MySQL, PostgreSQL, Microsoft SQL Server, Oracle, Microsoft SQL Server - MS ODBC Driver

        Returns:
            A dict with the keys and values.
        """
        connect_parameters_tuple_list = parse_qsl(connect_parameters, keep_blank_values=True)
        connect_parameters_dict = dict()
        for key, value in connect_parameters_tuple_list:
            connect_parameters_dict[key] = value
        if dialect == "Microsoft SQL Server":
            connect_parameters_dict['driver'] = 'FreeTDS'
        elif dialect == 'Microsoft SQL Server - MS ODBC Driver':
            connect_parameters_dict['driver'] = 'ODBC Driver 18 for SQL Server'
            if not verify_certificate:
                connect_parameters_dict['TrustServerCertificate'] = 'yes'
        return connect_parameters_dict

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
        elif dialect in {"Microsoft SQL Server", 'Microsoft SQL Server - MS ODBC Driver'}:
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
        ssl_connection = {}
        module = self._convert_dialect_to_module(self.dialect)
        db_url = URL(drivername=module,
                     username=self.username,
                     password=self.password,
                     host=self.host,
                     port=self.port,
                     database=self.dbname,
                     query=self.connect_parameters)
        if self.ssl_connect:
            if self.dialect == 'PostgreSQL':
                ssl_connection = {'sslmode': 'require'}
            else:
                ssl_connection = {'ssl': {'ssl-mode': 'preferred'}}  # type: ignore[dict-item]
        engine: sqlalchemy.engine.Engine = None
        if self.use_pool:
            if 'expiringdict' not in sys.modules:
                raise ValueError('Usage of connection pool is not support in this docker image')
            cache = self._get_global_cache()
            cache_key = self._get_cache_string(str(db_url), ssl_connection)
            engine = cache.get(cache_key, None)
            if engine is None:  # (first time or expired) need to initialize
                engine = sqlalchemy.create_engine(db_url, connect_args=ssl_connection)
                cache[cache_key] = engine
        else:
            demisto.debug('Initializing engine with no pool (NullPool)')
            engine = sqlalchemy.create_engine(db_url, connect_args=ssl_connection,
                                              poolclass=sqlalchemy.pool.NullPool)
        return engine.connect()

    def sql_query_execute_request(self, sql_query: str, bind_vars: Any, fetch_limit=0) -> Tuple[Dict, List]:
        """Execute query in DB via engine
        :param bind_vars: in case there are names and values - a bind_var dict, in case there are only values - list
        :param sql_query: the SQL query
        :param fetch_limit: the size of the returned records can be controlled
        :return: results of query, table headers
        """
        if type(bind_vars) is dict:
            sql_query = text(sql_query)

        with self.connection as connection:
            # The isolation level is for stored procedures SQL queries that include INSERT, DELETE etc.
            connection.execution_options(isolation_level="AUTOCOMMIT")
            result = self.connection.execute(sql_query, bind_vars)
            # For avoiding responses with lots of records
            results = result.fetchmany(fetch_limit) if fetch_limit else result.fetchall()

        headers = []
        if results:
            # if the table isn't empty
            headers = list(results[0].keys() if results[0].keys() else '')
        return results, headers


def generate_default_port_by_dialect(dialect: str) -> Optional[str]:
    """
    In case no port was chosen, a default port will be chosen according to the SQL db type. Only return a port for
    Microsoft SQL Server and ODBC Driver 18 for SQL Server where it seems to be required.
    For the other drivers a None port is supported
    :param dialect: sql db type
    :return: default port needed for connection
    """
    if dialect in {'Microsoft SQL Server', 'ODBC Driver 18 for SQL Server'}:
        return "1433"
    return None


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
    In case of Fetch Incidents, there are some validations.
    """
    msg = ''
    params = demisto.params()

    if params.get('isFetch'):

        if not params.get('query'):
            msg += 'Missing parameter Fetch events query. '

        if limit := params.get('max_fetch'):
            limit = arg_to_number(limit)
            if limit < 1 or limit > 50:
                msg += 'Fetch Limit value should be between 1 and 50. '

        if params.get('fetch_parameters') == 'ID and timestamp':
            if not (params.get('column_name') and params.get('id_column')):
                msg += 'Missing Fetch Column or ID Column name (when ID and timestamp are chosen,' \
                       ' fill in both). '

        if params.get('fetch_parameters') in ['Unique ascending', 'Unique timestamp']:
            if not params.get('column_name'):
                msg += 'Missing Fetch Column (when Unique ascending ID or unique timestamp is chosen,' \
                       ' Fetch Column should be filled). '
            if params.get('id_column'):
                msg += 'In case of Unique ascending ID or Unique timestamp, fill only Fetch Column,' \
                       ' ID Column name should be unfilled. '

        if not params.get('first_fetch'):
            msg += 'A starting point for fetching is missing, please enter First fetch timestamp or First fetch ID. '

        # in case of query and not procedure
        if not params.get('query').lower().startswith(('call', 'exec', 'execute')):
            first_condition_key_word, second_condition_key_word = 'where', 'order by'
            query = params.get('query').lower()
            if not (first_condition_key_word in query and second_condition_key_word in query):
                msg += f"Missing at least one of the query's conditions: where {params.get('column_name')}" \
                       f" >:{params.get('column_name')} or order by (asc) {params.get('column_name')}. "

        # The request to the database is pointless if one of the validations failed - so returns informative message
        if msg:
            return msg, {}, []
        # Verify the correctness of the query / procedure
        try:
            params['max_fetch'] = 1
            last_run = initialize_last_run(params.get('fetch_parameters', ''), params.get('first_fetch', ''))
            sql_query = create_sql_query(last_run, params.get('query', ''), params.get('column_name', ''),
                                         params.get('max_fetch', FETCH_DEFAULT_LIMIT))
            bind_variables = generate_bind_variables_for_fetch(params.get('column_name', ''),
                                                               params.get('max_fetch', FETCH_DEFAULT_LIMIT), last_run)
            result, headers = client.sql_query_execute_request(sql_query, bind_variables, 1)
        except Exception as e:
            raise e

        if headers:
            # Verifying the column names are right
            if params.get('column_name') not in headers:
                msg += f'Invalid Fetch Column, *{params.get("column_name")}* does not exist in the table. '

            if params.get('id_column') and params.get('id_column') not in headers:
                msg += f'Invalid ID Column name, *{params.get("id_column")}* does not exist in the table. '

            if params.get('incident_name') and params.get('incident_name') not in headers:
                msg += f'Invalid Incident Name, *{params.get("incident_name")}* does not exist in the table. '

    return msg if msg else 'ok', {}, []


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
            "Result": table,
            "Headers": headers,
            "Query": sql_query,
            "InstanceName": f"{client.dialect}_{client.dbname}",
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


def initialize_last_run(fetch_parameters: str, first_fetch: str):
    """
    This function initializes the last run based on the configuration,
    when the first fetch is initialized either by timestamp or by ID.
    ids field will be initialized to an empty list for the 'ID and timestamp' case, for avoiding duplicates.
    Args:
        fetch_parameters: This is what the fetch is based on (timestamp, ID or both).
        first_fetch: First fetch timestamp or First fetch ID.

    Returns:
            A dictionary which contains the required fields for the last run.
    """

    # Fetch should be by timestamp or id
    if fetch_parameters in ['Unique timestamp', 'ID and timestamp']:
        last_run = {'last_timestamp': first_fetch, 'last_id': False}

    else:  # in case of 'Unique ascending ID'
        last_run = {'last_timestamp': False, 'last_id': first_fetch}

    # for the case when we get timestamp and id - need to maintain an id's list
    last_run['ids'] = list()

    return last_run


def create_sql_query(last_run: dict, query: str, column_name: str, max_fetch: str):
    """
    This function creates the sql query.
    1) In case of runStoreProcedure MSSQL, it wraps the procedure with the limit
    (MSSQL doesn't support limits inside queries, so this is the correct syntax).
    2) In case of runStoreProcedure MySQL, it adds the two parameters (last fetch - id/timestamp and the limit).
    3) In case of queries, returns as it is.
    Args:
        last_run: A dictionary which contains the required fields for the last run.
        query: The query or the procedure given as configuration's parameter.
        column_name: The exact column's name to fetch (id column or timestamp column).
        max_fetch: Fetch Limit given as configuration's parameter.

    Returns:
        Query/procedure ready to run.
    """
    last_timestamp_or_id = last_run.get('last_timestamp') if last_run.get('last_timestamp') else last_run.get(
        'last_id')

    # case of runStoreProcedure MSSQL
    if query.lower().startswith('exec'):
        sql_query = f"SET ROWCOUNT {max_fetch};" \
                    f"{query} @{column_name} = '{last_timestamp_or_id}';" \
                    f"SET ROWCOUNT 0"

    # case of runStoreProcedure MySQL
    elif query.lower().startswith('call'):
        sql_query = f"{query}('{last_timestamp_or_id}', {max_fetch})"

    # case of queries
    else:
        sql_query = query  # type:ignore[assignment]

    return sql_query


def convert_sqlalchemy_to_readable_table(result: dict):
    """

    Args:
        result:

    Returns:

    """
    # converting a sqlalchemy object to a table
    converted_table = [dict(row) for row in result]
    # converting b'' and datetime objects to readable ones
    incidents = [{str(key): str(value) for key, value in dictionary.items()} for dictionary in converted_table]
    return incidents


def update_last_run_after_fetch(table: List[dict], last_run: dict, fetch_parameters: str, column_name: str,
                                id_column: str):
    is_timestamp_and_id = True if fetch_parameters == 'ID and timestamp' else False
    if last_run.get('last_timestamp'):
        last_record_timestamp = table[-1].get(column_name, '')

        # keep the id's for the next fetch cycle for avoiding duplicates
        if is_timestamp_and_id:
            new_ids_list = list()
            for record in table:
                if record.get(column_name) == last_record_timestamp:
                    new_ids_list.append(record.get(id_column))
            last_run['ids'] = new_ids_list

        # allow till 3 digit after the decimal point - due to limits on querying
        before_and_after_decimal_point = last_record_timestamp.split('.')
        if len(before_and_after_decimal_point) == 2:
            last_run['last_timestamp'] = f'{before_and_after_decimal_point[0]}.{before_and_after_decimal_point[1][:3]}'
        elif len(before_and_after_decimal_point) == 1:
            last_run['last_timestamp'] = before_and_after_decimal_point[0]
        else:
            raise Exception(f"Unsupported Format Time! "
                            f"We support one decimal point (not necessary, also possible without) "
                            f"to separate time from milliseconds. {last_record_timestamp=} isn't supported")
    else:
        last_run['last_id'] = table[-1].get(column_name)

    return last_run


def table_to_incidents(table: List[dict], last_run: dict, fetch_parameters: str, column_name: str, id_column: str,
                       incident_name: str) -> List[Dict[str, Any]]:
    incidents = []
    is_timestamp_and_id = True if fetch_parameters == 'ID and timestamp' else False
    for record in table:

        timestamp = record.get(column_name) if last_run.get('last_timestamp') else None
        date_time = dateparser.parse(timestamp) if timestamp else datetime.now()

        # for avoiding duplicate incidents
        if is_timestamp_and_id and record.get(column_name, '').startswith(last_run.get('last_timestamp')):
            if record.get(id_column, '') in last_run.get('ids', []):
                continue

        record['type'] = 'GenericSQL Record'
        incident_context = {
            'name': record.get(incident_name) if record.get(incident_name) else record.get(column_name),
            'occurred': date_time.strftime(DATE_FORMAT),  # type:ignore[union-attr]
            'rawJSON': json.dumps(record),
        }
        incidents.append(incident_context)

    return incidents


def generate_bind_variables_for_fetch(column_name: str, max_fetch: str, last_run: dict):
    """
    This function binds the two variables (last fetch and limit) with their columns.

    Args:
        column_name: The exact column's name to fetch (id column or timestamp column).
        max_fetch: Fetch Limit given as configuration's parameter.
        last_run: A dictionary which contains the required fields for the last run.

    Returns: A dict of the bind variables.

    """

    last_fetch = last_run.get('last_timestamp') if last_run.get('last_timestamp') else last_run.get('last_id')
    bind_variables = {column_name: last_fetch, 'limit': arg_to_number(max_fetch)}
    return bind_variables


def fetch_incidents(client: Client, params: dict):
    last_run = demisto.getLastRun()
    last_run = last_run if last_run else \
        initialize_last_run(params.get('fetch_parameters', ''), params.get('first_fetch', ''))
    demisto.debug("GenericSQL - Start fetching")
    demisto.debug(f"GenericSQL - Last run: {json.dumps(last_run)}")
    sql_query = create_sql_query(last_run, params.get('query', ''), params.get('column_name', ''),
                                 params.get('max_fetch', FETCH_DEFAULT_LIMIT))
    demisto.debug(f"GenericSQL - Query sent to the server: {sql_query}")
    limit_fetch = len(last_run.get('ids', [])) + int(params.get('max_fetch', FETCH_DEFAULT_LIMIT))
    bind_variables = generate_bind_variables_for_fetch(params.get('column_name', ''),
                                                       params.get('max_fetch', FETCH_DEFAULT_LIMIT), last_run)
    result, headers = client.sql_query_execute_request(sql_query, bind_variables, limit_fetch)
    table = convert_sqlalchemy_to_readable_table(result)
    table = table[:limit_fetch]

    incidents: List[Dict[str, Any]] = table_to_incidents(table, last_run, params.get('fetch_parameters', ''),
                                                         params.get('column_name', ''), params.get('id_column', ''),
                                                         params.get('incident_name', ''))

    if table:
        last_run = update_last_run_after_fetch(table, last_run, params.get('fetch_parameters', ''),
                                               params.get('column_name', ''), params.get('id_column', ''))
    demisto.debug(f'GenericSQL - Next run after incidents fetching: {json.dumps(last_run)}')
    demisto.debug(f"GenericSQL - Number of incidents before filtering: {len(result)}")
    demisto.debug(f"GenericSQL - Number of incidents after filtering: {len(incidents)}")
    demisto.debug(f"GenericSQL - Number of incidents skipped: {(len(result) - len(incidents))}")

    demisto.info(f'last record now is: {last_run}, '
                 f'number of incidents fetched is {len(incidents)}')

    return incidents, last_run


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
        verify_certificate: bool = not params.get('insecure', False)
        pool_ttl = int(params.get('pool_ttl') or DEFAULT_POOL_TTL)
        if pool_ttl <= 0:
            pool_ttl = DEFAULT_POOL_TTL
        command = demisto.command()
        client = Client(dialect=dialect, host=host, username=user, password=password,
                        port=port, database=database, connect_parameters=connect_parameters,
                        ssl_connect=ssl_connect, use_pool=use_pool, verify_certificate=verify_certificate,
                        pool_ttl=pool_ttl)
        commands: Dict[str, Callable[[Client, Dict[str, str], str], Tuple[str, Dict[Any, Any], List[Any]]]] = {
            'test-module': test_module,
            'query': sql_query_execute,
            'pgsql-query': sql_query_execute,
            'sql-command': sql_query_execute
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args(), command))
        elif command == 'fetch-incidents':
            incidents, last_run = fetch_incidents(client, params)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f'{command} is not an existing Generic SQL command')
    except Exception as err:
        if 'certificate verify failed' in str(err):
            return_error("Unexpected error: certificate verify failed, unable to get local issuer certificate. "
                         "Try selecting 'Trust any certificate' checkbox in the integration configuration.")
        else:
            return_error(
                f'Unexpected error: {str(err)} \nquery: {demisto.args().get("query")}')
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
