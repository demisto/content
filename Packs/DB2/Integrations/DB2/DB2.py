import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Integration for DB2"""

import re
import traceback
from typing import Any
from collections.abc import Callable
from urllib.parse import parse_qsl

import ibm_db
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

PROTOCOL = "TCPIP"
DRIVER_NAME = "{IBM DB2 ODBC DRIVER}"
CLEAN = re.compile(r"\[.*?\]")
COLON_REGEX = re.compile(r"(?<![:\w\x5c]):(\w+)(?!:)", re.UNICODE)

# ============== DB2 Connection Options ===============

OPTIONS = {
    "ATTR_CASE": ibm_db.ATTR_CASE,
    "SQL_ATTR_AUTOCOMMIT": ibm_db.SQL_ATTR_AUTOCOMMIT,
    "SQL_ATTR_INFO_USERID": ibm_db.SQL_ATTR_INFO_USERID,
    "SQL_ATTR_CURSOR_TYPE": ibm_db.SQL_ATTR_CURSOR_TYPE,
    "SQL_ATTR_INFO_ACCTSTR": ibm_db.SQL_ATTR_INFO_ACCTSTR,
    "SQL_ATTR_INFO_APPLNAME": ibm_db.SQL_ATTR_INFO_APPLNAME,
    "SQL_ATTR_CURRENT_SCHEMA": ibm_db.SQL_ATTR_CURRENT_SCHEMA,
    "SQL_ATTR_INFO_WRKSTNNAME": ibm_db.SQL_ATTR_INFO_WRKSTNNAME,
    "SQL_ATTR_INFO_PROGRAMNAME": ibm_db.SQL_ATTR_INFO_PROGRAMNAME,
    "SQL_ATTR_USE_TRUSTED_CONTEXT": ibm_db.SQL_ATTR_USE_TRUSTED_CONTEXT,
    "SQL_ATTR_TRUSTED_CONTEXT_USERID": ibm_db.SQL_ATTR_TRUSTED_CONTEXT_USERID,
    "SQL_ATTR_TRUSTED_CONTEXT_PASSWORD": ibm_db.SQL_ATTR_TRUSTED_CONTEXT_PASSWORD,
}
VALUES = {
    "SQL_ATTR_AUTOCOMMIT": {
        "SQL_AUTOCOMMIT_ON": ibm_db.SQL_AUTOCOMMIT_ON,
        "SQL_AUTOCOMMIT_OFF": ibm_db.SQL_AUTOCOMMIT_OFF,
    },
    "ATTR_CASE": {
        "CASE_NATURAL": ibm_db.CASE_NATURAL,
        "CASE_LOWER": ibm_db.CASE_LOWER,
        "CASE_UPPER": ibm_db.CASE_UPPER,
    },
    "SQL_ATTR_CURSOR_TYPE": {
        "SQL_CURSOR_FORWARD_ONLY": ibm_db.SQL_CURSOR_FORWARD_ONLY,
        "SQL_CURSOR_KEYSET_DRIVEN": ibm_db.SQL_CURSOR_KEYSET_DRIVEN,
        "SQL_CURSOR_DYNAMIC": ibm_db.SQL_CURSOR_DYNAMIC,
        "SQL_CURSOR_STATIC": ibm_db.SQL_CURSOR_STATIC,
    },
}


""" CLIENT CLASS """


class Client:
    """Client to use in the DB2 databases integration. Overrides BaseClient
    makes the connection to the DB2 DB Server
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: str,
        database: str,
        ssl_connect: bool,
        connect_parameters: str = "",
        use_persistent=False,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.dbname = database
        self.connect_parameters = self._parse_connect_parameters(connect_parameters)
        self.ssl_connect = ssl_connect
        self.use_persistent = use_persistent
        self.connection = self._connect()

    @staticmethod
    def _parse_connect_parameters(connect_parameters: str) -> dict:
        """
        Parses a string of the form key1=value1&key2=value2 etc.
        into a dict with matching keys and values.

        Args:
            connect_parameters: The string with query parameters

        Returns:
            A dict with the keys and values.
        """

        connect_parameters_tuple_list = parse_qsl(connect_parameters, keep_blank_values=True)
        connect_parameters_dict = {}
        for key, value in connect_parameters_tuple_list:
            connect_parameters_dict[key] = value
        return connect_parameters_dict

    @property
    def create_url(self) -> str:
        """
        Create URL for making connection to given host

        Returns:
            string containing all of the required parameters
        """

        conn_string = ("DRIVER={};DATABASE={};HOSTNAME={};PORT={};PROTOCOL={};UID={};PWD={};").format(
            DRIVER_NAME,
            self.dbname,
            self.host,
            self.port,
            PROTOCOL,
            self.username,
            self.password,
        )

        if self.ssl_connect:
            conn_string += "SECURITY=SSL;"

        return conn_string

    def _options(self) -> dict:
        """
        Map connection options with connection parameters
        `ibm_db.OPTION` will be called for every option
        """
        options = {}

        for key, val in self.connect_parameters.items():
            option: str = key.upper()
            value: str = val.upper()

            if option in OPTIONS and option in VALUES and value in VALUES[option]:
                options[option] = VALUES[option][value]
            elif option in OPTIONS and option not in VALUES:
                options[option] = val
            else:
                # skip options which are not valid
                pass

        return options

    def _connect(self) -> ibm_db.IBM_DBConnection:
        """
        Connecting to the host using required parameters and returning the `Connection` object

        Returns:
            a connection object that will be used in order to execute queries
        """

        conn: ibm_db.IBM_DBConnection = None

        try:
            if self.use_persistent:
                demisto.info("Initializing Persistent connection")
                conn = ibm_db.pconnect(self.create_url, "", "", conn_options=self._options())
            else:
                demisto.info("Initializing Non-Persistent connection")
                conn = ibm_db.connect(self.create_url, "", "", conn_options=self._options())

        except Exception:
            demisto.error(f"Connection State:\n{ibm_db.conn_error}")
            demisto.error(f"Connection Error:\n{ibm_db.conn_errormsg()}")
            raise DemistoException(f"DB2 Connection Failed:\n{ibm_db.conn_errormsg()}")

        return conn

    def _prepare_statement(self, query: str, bindvars: Any) -> Any:
        """
        Populate values from bindvars to query and `ibm_db.prepare` statement

        Args:
            query(str): db2 query string
            bindvars(Any): list/dictionay with values to populate query

        Returns:
            ibm_db.prepare
        """

        # Validate bindvars with respect to `?` or `:`
        if len(bindvars):
            if isinstance(bindvars, list) and query.count("?") < len(bindvars):
                raise DemistoException("Insufficient bind values found")
            elif isinstance(bindvars, dict) and query.count(":") < len(bindvars.keys()):
                raise DemistoException("Insufficient bind names & values found")

        demisto.info("Preparing Statement ...")

        if isinstance(bindvars, dict):
            try:

                def repl(x, bindvars=bindvars):
                    return f"'{bindvars[x.group(0).strip(':')]}'"

                query = re.sub(COLON_REGEX, repl=repl, string=query)
            except KeyError as err:
                demisto.error(f"{err.args[0]} key not found in bind names")
                raise DemistoException(f"{err.args[0]} key not found in bind names")

        stmt = ibm_db.prepare(self.connection, query)

        if isinstance(bindvars, list):
            for index, var in enumerate(bindvars, 1):
                ibm_db.bind_param(stmt, index, var)

        return stmt

    def execute_query(self, query: str, bind_vars: Any) -> tuple[list, list]:
        """
        Execute query at DB2 Database via connection

        Args:
            query(str): db2 query string
            bind_vars(Any): in case there are names and values - a bind_vars dict,
                            in case there are only values - list

        Returns:
            Tuple[results(List), headers(List)]
        """
        results = []
        headers = []
        status = False

        stmt = self._prepare_statement(query, bind_vars)

        try:
            demisto.info("Executing ...")
            status = ibm_db.execute(stmt)
            demisto.info("Done !!!")
        except Exception:
            demisto.error(clear(ibm_db.stmt_error()))
            demisto.error(clear(ibm_db.stmt_errormsg()))
            raise DemistoException(clear(ibm_db.stmt_errormsg()))

        demisto.info("Collecting results")
        if status:
            row = ibm_db.fetch_assoc(stmt)
            while row:
                results.append(row)
                row = ibm_db.fetch_assoc(stmt)

        if results:
            headers = [*results[0]]

        return results, headers

    def close(self) -> bool:
        demisto.info("Closing Connection")
        return ibm_db.close(self.connection)


""" HELPER FUNCTIONS """


def clear(message: str):
    """
    Clean data with square brackets from message

    Args:
        message(str): Any message string

    Returns:
        string with clean message
    """

    def repl(x):
        return ""

    return (re.sub(CLEAN, repl=repl, string=message)).strip()


def bind_variables(names: str, values: str) -> Any:
    """
    Binding of column names with their values or return list of values

    Args:
        names(str): column name to bind with values, must be in the length of the values list
        values(str): the values to bind with columns, can be in the length of the names list

    Returns:
        Any: a dict with column and value as a key value pair or list of values
    """
    names_list = argToList(names)
    values_list = argToList(values)

    # assuming the order of values is correct
    if values_list and not names_list:
        return list(values_list)
    elif len(names_list) == len(values_list):
        return dict(zip(names_list, values_list))
    else:
        raise Exception("The bind variables lists are not is the same length")


""" COMMAND FUNCTIONS """


def query_command(client: Client, args: dict, *_) -> CommandResults:
    """
    Executes the db2 query with the connection that was configured in the Client

    Args:
        client(Client): the client object with db connection
        args(demisto.args): arguments for the query-command
    """
    sql_query = str(args.get("query"))
    limit = int(args.get("limit", 50))
    skip = int(args.get("offset", 0))
    bind_variable_name = args.get("bind_variables_name", "")
    bind_variable_values = args.get("bind_variables_values", "")

    try:
        variables = bind_variables(bind_variable_name, bind_variable_values)
        result, headers = client.execute_query(sql_query, variables)

        converted_table = [dict(row) for row in result]
        table = [{str(key): str(value) for key, value in dictionary.items()} for dictionary in converted_table]
        table = table[skip: skip + limit]

        human_readable = tableToMarkdown(name="Query result:", t=table, headers=headers, removeNull=True)

        context = {"Result": table, "Query": sql_query, "DbName": f"{client.dbname}"}
        client.close()

        return CommandResults(
            outputs_prefix="DB2",
            outputs_key_field="Query",
            outputs=context,
            raw_response=result,
            readable_output=human_readable,
        )
    except Exception as err:
        client.close()
        demisto.error(f"error:\n {err}")
        if str(err).lower() == "column information cannot be retrieved: ":
            human_readable = f"{sql_query} Command Executed Successfully"
            return CommandResults(readable_output=human_readable)
        raise DemistoException(err)


def test_module(client: Client, *_) -> str:
    """
    If the connection in the client was successful the test will return OK
    if it wasn't an exception will be raised
    """
    return "ok"


def main():  # pragma: no cover
    """main function, parses params and runs command functions"""

    params = demisto.params()

    # Fetch required parameters
    host = params.get("host")
    uid = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    database = params.get("dbname")
    port = params.get("port", 50000)
    ssl_connect = params.get("ssl_connect")
    connect_params = params.get("connect_parameters")
    use_persistent = params.get("use_persistent")

    command = demisto.command()
    demisto.debug(f"command being called is {command}")

    try:
        client = Client(
            host=host,
            username=uid,
            password=password,
            port=port,
            database=database,
            ssl_connect=ssl_connect,
            connect_parameters=connect_params,
            use_persistent=use_persistent,
        )

        commands: dict[str, Callable] = {
            "test-module": test_module,
            "db2-query": query_command,
        }
        if command in commands:
            return_results(*commands[command](client, demisto.args(), command))
        else:
            raise NotImplementedError(f"{command} is not an existing DB2 command")
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"failed to execute {command} command.\nerror:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
