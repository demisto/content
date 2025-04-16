import demistomock as demisto  # pylint: disable=W9005
from CommonServerPython import *  # pylint: disable=W9011

from CommonServerUserPython import *

"""IMPORTS"""

from datetime import date, datetime, timedelta
from datetime import time as dttime
from decimal import Decimal

import snowflake.connector  # pylint: disable=E0401,E0611
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

"""GLOBAL VARS"""

PARAMS = demisto.params()  # pylint: disable=W9016
CREDENTIALS = PARAMS.get("credentials")
USER = CREDENTIALS.get("identifier")
PASSWORD = CREDENTIALS.get("password")
CERTIFICATE = CREDENTIALS.get("credentials", {}).get("sshkey").encode()
CERT_PASSWORD = CREDENTIALS.get("credentials", {}).get("password")
CERT_PASSWORD = CERT_PASSWORD.encode() if CERT_PASSWORD else None
ACCOUNT = PARAMS.get("account")
AUTHENTICATOR = PARAMS.get("authenticator")
REGION = PARAMS.get("region")
WAREHOUSE = PARAMS.get("warehouse")
DATABASE = PARAMS.get("database")
SCHEMA = PARAMS.get("schema")
ROLE = PARAMS.get("role")
INSECURE = PARAMS.get("insecure", False)
# How much time before the first fetch to retrieve incidents
IS_FETCH = PARAMS.get("isFetch")
FETCH_TIME = PARAMS.get("fetch_time")
FETCH_QUERY = PARAMS.get("fetch_query")
DATETIME_COLUMN = PARAMS.get("datetime_column")
INCIDENT_NAME_COLUMN = PARAMS.get("incident_name_column")
MAX_ROWS = int(PARAMS.get("limit")) if PARAMS.get("limit") else 10000

TYPE_CODE_TO_DATATYPE = {
    0: "number/int",
    1: "real",
    2: "varchar/string",
    3: "date",
    4: "timestamp",
    5: "variant",
    6: "timestamp_ltz",
    7: "timestamp_tz",
    8: "timestamp_tz",
    9: "object",
    10: "array",
    11: "binary",
    12: "time",
    13: "boolean",
}
DT_NEEDS_CHECKING = {"date", "timestamp", "timestamp_ltz", "timestamp_tz", "time"}


"""SETUP"""

if IS_FETCH and not (FETCH_QUERY and DATETIME_COLUMN):
    err_msg = "When fetching is enabled there are two additional parameters that are required;"
    err_msg += " The fetch query that determines what data to fetch and the name of the column"
    err_msg += " in the fetched data that contains a datetime object or timestamp."
    raise Exception(err_msg)


"""HELPER FUNCTIONS"""


def convert_datetime_to_string(v):  # pylint: disable=W9014
    """
    Parses date, time, timedelta, or datetime object into string

    parameter: (datetime/date/time/timedelta) v
        The datetime/date/time/timedelta object to convert

    returns:
        Formatted string of the object
    """
    demisto.info(f"[test] in convert_datetime_to_string didn't got {v=}.")
    if isinstance(v, datetime):
        demisto.info(f"[test] in convert_datetime_to_string in first condition {v=}.")
        return v.strftime("%Y-%m-%d %H:%M:%S.%f %z").strip()
    elif isinstance(v, date):
        demisto.info(f"[test] in convert_datetime_to_string in second condition {v=}.")
        return v.strftime("%Y-%m-%d").strip()
    elif isinstance(v, dttime):
        demisto.info(f"[test] in convert_datetime_to_string in third condition {v=}.")
        return v.strftime("%H:%M:%S.%f").strip()
    demisto.info(f"[test] in convert_datetime_to_string in no condition {v=}.")
    return v


def error_message_from_snowflake_error(e):  # pylint: disable=W9014
    """
    Return formatted error message from contents of a Snowflake error

    parameter: (snowflake.connector.errors.Error) e
        The Snowflake error object

    returns:
        Formatted error message
    """
    err_msg = f"Snowflake DB error code: {e.errno}\n"
    err_msg += f"ANSI-compliant SQL State code: {e.sqlstate}\n"
    err_msg += f"Snowflake query ID: {e.sfqid}\n"
    err_msg += "Error message: {}"
    if e.errno == 606:
        first_sentence = e.raw_msg[: e.raw_msg.find(".") + 1]
        err_msg = err_msg.format(first_sentence)
        err_msg += " Specify an active warehouse in the command "
        err_msg += "arguments or in the integration parameters."
    elif e.errno == 2003:
        err_msg = err_msg.format(e.raw_msg)
        err_msg += " A possible explanation is that the values you entered"
        err_msg += " for the 'warehouse' and 'database' were incorrect."
    else:
        err_msg = err_msg.format(e.raw_msg)
    return err_msg


def set_provided(params, key, val1, val2=None):  # pylint: disable=W9014
    """
    If value is provided, set it in the dict
    """
    if val1:
        params[key] = val1
    elif val2:
        params[key] = val2


def process_table_row(row, checks):  # pylint: disable=W9014
    """
    Check row data and reformat if necessary

    The 'checks' parameter contains the names of fields that have the potential to cause
    issues when they will be json decoded. This function checks the values of the fields
    flagged in the 'checks' parameter and formats the contents to a json friendly type if
    necessary.

    parameter: (dict) row
        The data (table row) that needs to be processed

    parameter: (dict[str, list]) checks
        Dictionary where the key is a string indicative of the type (or bucket of types) that needs
        reformatting and the values are a list of column names whose data is of that type

    returns:
        Reformatted Row
    """
    demisto.info(f"[test] in process_table_row got {row=}, {checks=}.")
    for column_name, val in row.items():
        if column_name in checks.get("isDecimal", []):
            demisto.info(f"[test] in process_table_row got isDecimal for {column_name=}, {val=}.")
            # Then check the value and reformat it if necessary
            if isinstance(val, Decimal):
                row[column_name] = str(val)
        elif column_name in checks.get("isDT", []):
            demisto.info(f"[test] in process_table_row got isDT for {column_name=}, {val=}.")
            # Then reformat it if necessary
            row[column_name] = convert_datetime_to_string(val)
    demisto.info(f"[test] in process_table_row return {row=}.")
    return row


def format_to_json_serializable(column_descriptions, results):  # pylint: disable=W9014
    """
    Screen and reformat any data in 'results' argument that is
    not json serializable, and return 'results'. 'results' can
    be a table of data (a list of rows) or a single row.

    parameter: (list) column_descriptions
        The metadata that describes data for each column in the 'results' parameter

    parameter: (list/dict) results
        What was returned by the cursor object's execute or fetch operation

    returns:
        Reformatted 'results'
    """
    name = 0
    type_code = 1

    checks: dict = {}
    # Screen by type_code
    for col in column_descriptions:
        # if col[type_code] == 0:
        if TYPE_CODE_TO_DATATYPE.get(col[type_code]) == "number/int":
            # Then need to check that column's data to see if its data type is Decimal
            checks.setdefault("isDecimal", []).append(col[name])
        # elif col[type_code] in {3, 4, 6, 7, 8, 12}:
        elif TYPE_CODE_TO_DATATYPE.get(col[type_code]) in DT_NEEDS_CHECKING:
            # Then need to check that column's data to see if its data type is date, time, timedelta or datetime
            checks.setdefault("isDT", []).append(col[name])

    # if 'results' is a list then it is a data table (list of rows) and need to process each row
    # in the table, otherwise if 'results' is a dict then it a single table row
    # Check candidates and reformat if necessary
    if isinstance(results, dict):
        demisto.info(f"[test] in format_to_json_serializable got dict {results=}.")
        results = process_table_row(results, checks)
    else:
        demisto.info(f"[test] in format_to_json_serializable got list {results=}.")
        # if 'results' isn't a dict, assume it's a list
        for i, row in enumerate(results):
            results[i] = process_table_row(row, checks)
    demisto.info(f"[test] in format_to_json_serializable {results=}.")
    return results


def get_connection_params(args):  # pylint: disable=W9014
    """
    Construct and return the connection parameters

    parameter: (dict) args
        The command arguments of the command function calling this helper function

    returns:
        Snowflake connection params
    """
    params: dict = {}
    set_provided(params, "user", USER)
    set_provided(params, "password", PASSWORD)
    set_provided(params, "account", ACCOUNT)
    set_provided(params, "authenticator", AUTHENTICATOR)
    set_provided(params, "region", REGION)
    set_provided(params, "insecure_mode", INSECURE)
    set_provided(params, "warehouse", args.get("warehouse"), WAREHOUSE)
    set_provided(params, "database", args.get("database"), DATABASE)
    set_provided(params, "schema", args.get("schema"), SCHEMA)
    set_provided(params, "role", args.get("role"), ROLE)
    if CERTIFICATE:
        p_key = serialization.load_pem_private_key(CERTIFICATE, password=CERT_PASSWORD, backend=default_backend())
        pkb = p_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        params["private_key"] = pkb
    return params


def row_to_incident(column_descriptions, row):  # pylint: disable=W9014
    """
    Create incident from data returned by queried database in fetch_incidents

    parameter: (list) column_descriptions
        The metadata that describes the values for each column in the 'data' parameter

    parameter: (dict) row
        The row of data where each cell's key in the row is the name of the column
        to which it belongs

    returns:
        Incident Object
    """
    incident = {}
    occurred = row.get(DATETIME_COLUMN)
    timestamp = None
    if occurred:
        demisto.info(f"[test] in row_to_incident got {occurred=}")
        if isinstance(occurred, dttime | timedelta):
            err_msg = "The datetime field specified in the integration parameters must "
            err_msg += 'contain values of type "datetime" or "date".'
            raise Exception(err_msg)
        timestamp = occurred.timestamp() * 1000
    else:
        demisto.info(f"[test] in row_to_incident didn't get occur.")
        err_msg = "Nothing found when trying to fetch the datetime field specified in"
        err_msg += " the integration parameters. Please check that the name was correct."
        err_msg += " If the field name was correct, verify that the returned value for"
        err_msg += " the specified field is not NULL for ALL of the rows to be fetched."
        raise Exception(err_msg)
    # Incident Title
    if INCIDENT_NAME_COLUMN:
        demisto.info(f"[test] in row_to_incident didn't got {INCIDENT_NAME_COLUMN=}.")
        name = row.get(INCIDENT_NAME_COLUMN)
        demisto.info(f"[test] in row_to_incident didn't got {name=}.")
    else:
        name = "Snowflake Incident -- "
        demisto.info(f"[test] in row_to_incident didn't got {occurred=}.")
        name += convert_datetime_to_string(occurred) + "- " + str(datetime.now().timestamp())
        demisto.info(f"[test] in row_to_incident didn't got {name=}.")
    incident["name"] = name
    incident["occurred"] = occurred.isoformat()
    # Incident occurrence time as timestamp - the datetime field specified in the integration parameters
    incident["timestamp"] = timestamp
    # The raw response for the row (reformatted to be json serializable) returned by the db query
    demisto.info(f"[test] in row_to_incident so far got {incident=}.")
    reformatted_row = format_to_json_serializable(column_descriptions, row)
    incident["rawJSON"] = json.dumps(reformatted_row)
    demisto.info(f"[test] in row_to_incident return {incident=}.")
    return incident


"""MAIN FUNCTIONS / API CALLS"""


def test_module():
    """
    Test the validity of the integration instance parameters by trying to create a connection

    returns:
        An 'ok' message if valid, otherwise an error message
    """
    params = get_connection_params({})
    with snowflake.connector.connect(**params):  # pylint: disable=E1101
        demisto.results("ok")  # pylint: disable=W9008


def fetch_incidents():
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # # demisto.getLastRun() will returns an obj with the previous run in it.
    # last_run = demisto.getLastRun()
    # # Get the last fetch time and data if it exists
    # last_fetch = last_run.get("last_fetched_data_timestamp")
    # last_fetched_data = last_run.get("last_fetched_data")
    # # Handle first time fetch, fetch incidents retroactively
    # if not last_fetch:
    #     last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)
    # args = {"rows": MAX_ROWS, "query": FETCH_QUERY}
    # demisto.info(f'[test] going to get incidents with {args=}')
    # column_descriptions, data = snowflake_query(args)
    # demisto.info(f'[test] got events with {column_descriptions=} and {data=}')
    # data.sort(key=lambda k: k[DATETIME_COLUMN])
    # # convert the data/events to demisto incidents
    # incidents = []
    # for row in data:
    #     incident = row_to_incident(column_descriptions, row)
    #     incident_timestamp = incident.get("timestamp")

    #     # Update last run and add incident if the incident is newer than last fetch
    #     if incident_timestamp and incident_timestamp >= last_fetch:
    #         last_fetch = incident_timestamp
    #         if incident.get("rawJSON") != last_fetched_data:
    #             last_fetched_data = incident.get("rawJSON")
    #             del incident["timestamp"]
    #             incidents.append(incident)

    # this_run = {"last_fetched_data": last_fetched_data, "last_fetched_data_timestamp": last_fetch}
    # demisto.setLastRun(this_run)
    incident = {"name": "2792150219529", "occurred": "2024-04-25T17:17:00", "rawJSON": {"TICKET_PAYMENT_EVENT_ID": "a71e5d608b686bf62732d63498d4d09f", "TICKET_PAYMENT_ID": "71e605332aa0aa5d10d8501fb2c6bc38", "TICKET_TRANSACTION_ID": "42f45a0f1d6e5b0048674ece9da3bf39", "TICKET_ID": "8d3ad8d699d0bb02739d45c6b24f72c6", "TICKET_INCREMENTAL_ID": "2f6fdbd1ce8cad1dbc0855e3e2c6f7ae", "PNR_ID": "f7f4e68ac0c38d4ad7eee05f72ac62a5", "RECORD_INDICATOR": "22", "TICKET_NUMBER": "2792150219529", "TICKET_CREATE_DATE": "2024-04-04", "TRANSACTION_DATETIME": "2024-04-25 17:17:00.000000", "PNR_LOCATOR": "JQBKFG", "PNR_CREATE_DATE": "2024-04-04", "PAYMENT_SEQUENCE_NUMBER": 1, "FORM_OF_PAYMENT_CODE": "CC", "FORM_OF_PAYMENT_CODE_DESC": "CREDIT CARD", "PAYMENT_AMOUNT": "581.1900", "PAYMENT_VENDOR_CODE": "VI", "ACCOUNT_NUMBER": "4030P1XXXXXX0394", "PAYMENT_CURRENCY_CODE": "USD", "PAYMENT_REMARKS": "VI4030P1XXXXXX0394", "PAYMENT_APPROVAL_CODE": "004288", "PAYMENT_APPROVAL_TYPE_CODE": None, "PAYMENT_APPROVAL_TYPE_CODE_DESC": None, "SABRE_FILE_CREATION_TIMESTAMP": "2024-04-26 03:00:00.000000", "METADATA_FILENAME": "processed/tkt-payment/2024/04/TktPayment_20240426_A.dat.gz", "METADATA_ROW_NUMBER": 449206, "METADATA_INSERT_TIMESTAMP": "2024-04-26 07:35:36.003000", "ROW_INSERT_TIMESTAMP": "2024-08-14 22:43:09.851000"}}
    incident["rawJSON"] = json.dumps(incident["rawJSON"])
    demisto.incidents([incident])


def snowflake_query(args):  # pylint: disable=W9014
    params = get_connection_params(args)
    query = args.get("query")
    limit = args.get("limit", "100")
    try:
        limit = int(limit)
    except ValueError:
        raise ValueError("The value for limit must be an integer.")
    if limit > MAX_ROWS:
        limit = MAX_ROWS
    with snowflake.connector.connect(**params) as connection, connection.cursor(snowflake.connector.DictCursor) as cur:  # pylint: disable=E1101
        cur.execute(query)
        results = cur.fetchmany(limit)
        if results:
            return cur.description, results
        else:
            return [], []


def snowflake_query_command():
    args = demisto.args()  # pylint: disable=W9017
    query = args.get("query")
    db = args.get("database") if args.get("database") else DATABASE
    schema = args.get("schema") if args.get("schema") else SCHEMA
    demisto.info(f'[test] snowflake_query_command {args=}')
    col_descriptions, results = snowflake_query(args)
    demisto.info(f'[test] snowflake_query_command {col_descriptions=} {results=}')
    if not results:
        demisto.results("No data found matching the query")  # pylint: disable=W9008
    else:
        results = format_to_json_serializable(col_descriptions, results)

        entry_context = {"Database": db, "Schema": schema, "Query": query, "Result": results}
        columns = argToList(args.get("columns"))
        human_readable = tableToMarkdown(query, results, columns, removeNull=True)
        demisto_transform = "Snowflake(val.Query && val.Query === obj.Query"
        demisto_transform += " && val.Database && val.Database === obj.Database"
        demisto_transform += " && val.Schema && val.Schema === obj.Schema)"
        outputs = {demisto_transform: entry_context}

        return_outputs(outputs=outputs, readable_output=human_readable, raw_response=results)  # pylint: disable=W9009


def snowflake_update_command():
    args = demisto.args()  # pylint: disable=W9017
    db_operation = args.get("db_operation")
    params = get_connection_params(args)
    with snowflake.connector.connect(**params) as connection, connection.cursor() as cursor:  # pylint: disable=E1101
        cursor.execute(db_operation)
        demisto.results("Operation executed successfully.")  # pylint: disable=W9008


"""COMMAND SWITCHBOARD"""

commands = {
    "test-module": test_module,
    "fetch-incidents": fetch_incidents,
    "snowflake-query": snowflake_query_command,
    "snowflake-update": snowflake_update_command,
}


"""EXECUTION"""


def main() -> None:
    error = ""
    try:
        handle_proxy()
        if demisto.command() in commands:
            commands[demisto.command()]()
    except snowflake.connector.errors.Error as e:  # pylint: disable=E1101
        error = error_message_from_snowflake_error(e)
    except Exception as e:
        if IS_FETCH:
            raise e
        else:
            if isinstance(e, snowflake.connector.errors.Error):  # pylint: disable=E1101
                error = error_message_from_snowflake_error(e)
            else:
                error = str(e)
    finally:
        if error:
            return_error(error)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
