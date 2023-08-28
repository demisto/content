import os

import pytest
import sqlalchemy
import pyodbc
import cx_Oracle

from test_data import input_data
from GenericSQL import Client, sql_query_execute, generate_default_port_by_dialect


class ResultMock:
    def __init__(self):
        pass

    def fetchall(self):
        return []


class ConnectionMock:
    def __enter__(self):
        return ConnectionMock()

    def __exit__(self, exc, value, tb):
        pass

    def execute(self, sql_query, bind_vars):
        return ResultMock()

    def execution_options(self, isolation_level):
        pass


ARGS1 = {
    'query': "select Name from city",
    'limit': 5,
    'skip': 0
}

ARGS2 = {
    'query': "select * from mysql.user",
    'limit': 1,
    'skip': 0
}

ARGS3 = {
    'query': "select Name from city where 1=2",
    'limit': 5,
    'skip': 0
}


RAW1 = [{'Name': 'Kabul'}, {'Name': 'Qandahar'}, {'Name': 'Herat'}, {'Name': 'Mazar-e-Sharif'}]

RAW2 = [{'Host': '%',
         'User': 'admin',
         'Select_priv': 'Y',
         'Insert_priv': 'Y',
         'Update_priv': 'Y',
         'Delete_priv': 'Y',
         'Create_priv': 'Y',
         'Drop_priv': 'Y',
         'Reload_priv': 'Y',
         'Shutdown_priv': 'N',
         'Process_priv': 'Y',
         'File_priv': 'N',
         'Grant_priv': 'Y',
         'References_priv': 'Y',
         'Index_priv': 'Y',
         'Alter_priv': 'Y',
         'Show_db_priv': 'Y',
         'Super_priv': 'N',
         'Create_tmp_table_priv': 'Y',
         'Lock_tables_priv': 'Y',
         'Execute_priv': 'Y',
         'Repl_slave_priv': 'Y',
         'Repl_client_priv': 'Y',
         'Create_view_priv': 'Y',
         'Show_view_priv': 'Y',
         'Create_routine_priv': 'Y',
         'Alter_routine_priv': 'Y',
         'Create_user_priv': 'Y',
         'Event_priv': 'Y',
         'Trigger_priv': 'Y',
         'Create_tablespace_priv': 'N',
         'ssl_type': '',
         'ssl_cipher': b'',
         'x509_issuer': b'',
         'x509_subject': b'',
         'max_questions': 0,
         'max_updates': 0,
         'max_connections': 0,
         'max_user_connections': 0,
         'plugin': 'mysql_native_password',
         'authentication_string': 'test',
         'password_expired': 'N',
         'password_last_changed': '2020-02-17 08:49:45',
         'password_lifetime': None,
         'account_locked': 'N',
         'Create_role_priv': 'N',
         'Drop_role_priv': 'N',
         'Password_reuse_history': None,
         'Password_reuse_time': None,
         'Password_require_current': None,
         'User_attributes': None}]

HEADER1 = ['Name']

HEADER2 = ['Host', 'User', 'Select_priv', 'Insert_priv', 'Update_priv', 'Delete_priv', 'Create_priv', 'Drop_priv',
           'Reload_priv', 'Shutdown_priv', 'Process_priv', 'File_priv', 'Grant_priv', 'References_priv', 'Index_priv',
           'Alter_priv', 'Show_db_priv', 'Super_priv', 'Create_tmp_table_priv', 'Lock_tables_priv', 'Execute_priv',
           'Repl_slave_priv', 'Repl_client_priv', 'Create_view_priv', 'Show_view_priv', 'Create_routine_priv',
           'Alter_routine_priv', 'Create_user_priv', 'Event_priv', 'Trigger_priv', 'Create_tablespace_priv', 'ssl_type',
           'ssl_cipher', 'x509_issuer', 'x509_subject', 'max_questions', 'max_updates', 'max_connections',
           'max_user_connections', 'plugin', 'authentication_string', 'password_expired', 'password_last_changed',
           'password_lifetime', 'account_locked', 'Create_role_priv', 'Drop_role_priv', 'Password_reuse_history',
           'Password_reuse_time', 'Password_require_current', 'User_attributes']

EXPECTED_OUTPUT1 = {
    'GenericSQL(val.Query && val.Query === obj.Query)':
        {'GenericSQL': {'Result': [{'Name': 'Kabul'},
                                   {'Name': 'Qandahar'},
                                   {'Name': 'Herat'},
                                   {'Name': 'Mazar-e-Sharif'}],
                        'Headers': HEADER1,
                        'Query': 'select Name from city',
                        'InstanceName': 'sql_dialect_database'}}
}

EXPECTED_OUTPUT2 = \
    {'GenericSQL(val.Query && val.Query === obj.Query)': {'GenericSQL': {'Result': [{
        'Host': '%',
        'User': 'admin',
        'Select_priv': 'Y',
        'Insert_priv': 'Y',
        'Update_priv': 'Y',
        'Delete_priv': 'Y',
        'Create_priv': 'Y',
        'Drop_priv': 'Y',
        'Reload_priv': 'Y',
        'Shutdown_priv': 'N',
        'Process_priv': 'Y',
        'File_priv': 'N',
        'Grant_priv': 'Y',
        'References_priv': 'Y',
        'Index_priv': 'Y',
        'Alter_priv': 'Y',
        'Show_db_priv': 'Y',
        'Super_priv': 'N',
        'Create_tmp_table_priv': 'Y',
        'Lock_tables_priv': 'Y',
        'Execute_priv': 'Y',
        'Repl_slave_priv': 'Y',
        'Repl_client_priv': 'Y',
        'Create_view_priv': 'Y',
        'Show_view_priv': 'Y',
        'Create_routine_priv': 'Y',
        'Alter_routine_priv': 'Y',
        'Create_user_priv': 'Y',
        'Event_priv': 'Y',
        'Trigger_priv': 'Y',
        'Create_tablespace_priv': 'N',
        'ssl_type': '',
        'ssl_cipher': "b''",
        'x509_issuer': "b''",
        'x509_subject': "b''",
        'max_questions': '0',
        'max_updates': '0',
        'max_connections': '0',
        'max_user_connections': '0',
        'plugin': 'mysql_native_password',
        'authentication_string': 'test',
        'password_expired': 'N',
        'password_last_changed': '2020-02-17 08:49:45',
        'password_lifetime': 'None',
        'account_locked': 'N',
        'Create_role_priv': 'N',
        'Drop_role_priv': 'N',
        'Password_reuse_history': 'None',
        'Password_reuse_time': 'None',
        'Password_require_current': 'None',
        'User_attributes': 'None',
    }], 'Headers': HEADER2,
        'Query': 'select * from mysql.user',
        'InstanceName': 'sql_dialect_database'}}}

EMPTY_OUTPUT = {
    'GenericSQL(val.Query && val.Query === obj.Query)': {
        'GenericSQL':
            {
                'Result': [],
                'Headers': [],
                'Query': 'select Name from city where 1=2',
                'InstanceName': 'sql_dialect_database'
            }
    }
}


@pytest.mark.parametrize('command, args, response, expected_result, header', [
    # Classic sql query, showing a table from database and convert it to readable data
    (sql_query_execute, ARGS1, RAW1, EXPECTED_OUTPUT1, HEADER1),
    # Simulates an mysql default tables such as "user",
    # in previous bug the value- b'' couldn't be converted to a readable value and the query failed
    (sql_query_execute, ARGS2, RAW2, EXPECTED_OUTPUT2, HEADER2),
])
def test_sql_queries(command, args, response, expected_result, header, mocker):
    """Unit test
    Given
    - select query
    - raw response of the database
    When
    - mock the database result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    # needed in order not to make a connection in tests
    mocker.patch.object(Client, '_create_engine_and_connect', return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response, header))
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


def test_sql_queries_with_empty_table(mocker):
    """Unit test
    Given
    - query that return an empty table
    - raw response of the database
    When
    - mock the database result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_create_engine_and_connect', return_value=ConnectionMock())
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    result = sql_query_execute(client, ARGS3)
    assert EMPTY_OUTPUT == result[1]  # entry context is found in the 2nd place in the result of the command


def test_mysql_integration():
    """Test actual connection to mysql. Will be skipped unless MYSQL_HOST is set.
    Can be used to do local debuging of connecting to MySQL by set env var MYSQL_HOST or changing the code below.

    Test assumes mysql credentials: root/password

    You can setup mysql locally by running:
    docker run --name mysql-80 -e MYSQL_ROOT_PASSWORD=password -d mysql:8.0

    And then set env var: MYSQL_HOST=localhost
    """
    host = os.getenv('MYSQL_HOST', '')
    if not host:
        pytest.skip('Skipping mysql integration test as MYSQL_HOST is not set')
    dialect = 'MySQL'
    client = Client(dialect, host, 'root', 'password', generate_default_port_by_dialect(dialect), 'mysql', "", False, True)
    res = client.sql_query_execute_request('show processlist', {})
    assert len(res) >= 1


@pytest.mark.parametrize('connect_parameters, dialect, expected_response', [
    ('arg1=value1&arg2=value2', 'MySQL', {'arg1': 'value1', 'arg2': 'value2'}),
    ('arg1=value1&arg2=value2', 'Microsoft SQL Server', {'arg1': 'value1', 'arg2': 'value2', 'driver': 'FreeTDS'}),
    ('arg1=value1&arg2=value2', 'Microsoft SQL Server - MS ODBC Driver',
     {'arg1': 'value1', 'arg2': 'value2', 'driver': 'ODBC Driver 18 for SQL Server', 'TrustServerCertificate': 'yes'})])
def test_parse_connect_parameters(connect_parameters, dialect, expected_response):
    assert Client.parse_connect_parameters(connect_parameters, dialect, False) == expected_response


def test_loading_relevant_drivers():
    assert 'FreeTDS' in pyodbc.drivers()
    assert 'ODBC Driver 18 for SQL Server' in pyodbc.drivers(), pyodbc.drivers()

    try:
        # make sure oracle manages to load tns client libraries.
        # Will fail, but we want to be sure we don't fail on loading the driver
        cx_Oracle.connect()
    except Exception as ex:
        assert 'ORA-12162' in str(ex)

    # freetds test
    engine = sqlalchemy.create_engine('mssql+pyodbc:///testuser:testpass@127.0.0.1:1433/TEST?driver=FreeTDS')
    try:
        engine.execute('select 1 as [Result]')
    except Exception as ex:
        assert "Can't open lib" not in str(ex), "Failed because of missing lib: " + str(ex)


# case of fetch by simple query based on id -- checking last_run update and incidents
@pytest.mark.parametrize('table, params, response, headers, expected_incidents, expected_last_run', [
    (input_data.TABLE_1, input_data.PARAMS_1, input_data.RESPONSE_1, input_data.HEADERS_1,
     input_data.EXPECTED_INCIDENTS_1, input_data.EXPECTED_LAST_RUN_1)])
def test_fetch_incident_by_id_simple_query(table, params, response, headers, expected_incidents, expected_last_run,
                                           mocker):
    """
    Given
    - raw response of the database - 3 records from the database
    - configuration parameters:
         - 'fetch_parameters': 'Unique ascending ID'
         - 'query': 'select * from incidents where incident_id >:incident_id order by incident_id'
         - 'first_fetch': '-1'
         - 'max_fetch': '3'
    - last_run: {} (first fetch cycle)
    When
    - running one fetch cycle
    Then
    - validate the last_run - 'last_id' should be updated to '1002' as the last record.
    - validate the number of incidents - As the max_fetch parameter, the number of incidents should be 3.
    """
    from GenericSQL import fetch_incidents
    mocker.patch('GenericSQL.demisto.getLastRun', return_value={})
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    # check last run is updated as expected
    assert expected_last_run == last_run
    # check the limit
    assert len(incidents) == len(expected_incidents)


# case of fetch by simple query based on id where first id is bigger than the last one in the DB --
# checking last_run update - it should be the same when there are no incidents
@pytest.mark.parametrize('table, params, response, headers, last_run_before_fetch', [
    (input_data.TABLE_2, input_data.PARAMS_2, input_data.RESPONSE_2, input_data.HEADERS_2,
     input_data.LAST_RUN_BEFORE_FETCH_2)])
def test_fetch_incident_without_incidents(table, params, response, headers, last_run_before_fetch, mocker):
    """
    Given
    - raw response of the database - an empty response list
    - configuration parameters:
        - 'fetch_parameters': 'Unique ascending ID'
        - 'query': 'select * from incidents where incident_id >:incident_id order by incident_id'
        - 'first_fetch': '1012'
        - 'max_fetch': '3'
    - last_run: {'last_timestamp': False, 'last_id': '1012', 'ids': []}
    When
    - running one fetch cycle
    Then
    - validate the last_run:
        should be the same as given before fetch {'last_timestamp': False, 'last_id': '1012', 'ids': []} - no incidents
    """
    from GenericSQL import fetch_incidents
    mocker.patch('GenericSQL.demisto.getLastRun', return_value=last_run_before_fetch)
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    # check last run is not updated, should be the same - We don't have any new incidents
    assert last_run_before_fetch == last_run


# case of fetch by procedure based on timestamp and id -- Verifying there aren't any duplicates
@pytest.mark.parametrize('table, params, response, headers, last_run_before_second_fetch, expected_incidents', [
    (input_data.TABLE_3, input_data.PARAMS_3, input_data.RESPONSE_3, input_data.HEADERS_3,
     input_data.LAST_RUN_BEFORE_SECOND_FETCH_3, input_data.EXPECTED_INCIDENTS_3)])
def test_fetch_incident_avoiding_duplicates(table, params, response, headers, last_run_before_second_fetch,
                                            expected_incidents, mocker):
    """
    Given
    - raw response of the database - 2 records from the database
    - configuration parameters:
        - 'fetch_parameters': 'ID and timestamp'
        - 'query': 'call Test_MySQL_6'
            [CREATE PROCEDURE Test_MySQL_6(IN ts DATETIME, IN l INT)
            BEGIN
                SELECT *
                FROM incidents
                WHERE timestamp >= ts order by timestamp asc limit l;
            END]
        - 'first_fetch': '2022-11-24 13:09:56'
        - 'max_fetch': '2'
    - last_run: {'last_timestamp': '2022-11-24 13:09:56', 'last_id': False, 'ids': ['1000']}
    When
    - running one fetch cycle
    Then
    - validate the incidents - should contain only one incident at the end, after omitting the duplicate incident
    """
    from GenericSQL import fetch_incidents
    mocker.patch('GenericSQL.demisto.getLastRun', return_value=last_run_before_second_fetch)
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    # check incidents without duplicates
    assert len(expected_incidents) == len(incidents)
    for expected_incident, incident in zip(expected_incidents, incidents):
        assert expected_incident.get('name') == incident.get('name')
        assert expected_incident.get('rawJSON') == incident.get('rawJSON')


# case of two fetch cycles -- checking twice last_run update as expected
@pytest.mark.parametrize('table_first_cycle, table_second_cycle, params, response_first_cycle, response_second_cycle, '
                         'headers, expected_last_run_4_1, expected_last_run_4_2',
                         [(input_data.TABLE_4_1, input_data.TABLE_4_2, input_data.PARAMS_4, input_data.RESPONSE_4_1,
                           input_data.RESPONSE_4_2, input_data.HEADERS_4, input_data.EXPECTED_LAST_RUN_4_1,
                           input_data.EXPECTED_LAST_RUN_4_2)])
def test_fetch_incident_update_last_run(table_first_cycle, table_second_cycle, params, response_first_cycle,
                                        response_second_cycle, headers, expected_last_run_4_1, expected_last_run_4_2,
                                        mocker):
    """
    Given
    - raw responses of the database:
        2 records from the database for the first cycle and then another 2 records for the second.
    - configuration parameters:
        - 'fetch_parameters': 'Unique timestamp'
        - 'query': 'call Test_MySQL_3'
            [CREATE PROCEDURE Test_MySQL_3(IN ts VARCHAR(255), IN l INT)
            BEGIN
                SELECT *
                FROM incidents
                WHERE timestamp > ts limit l;
            END]
        - 'first_fetch': '2020-01-01 01:01:01'
        - 'max_fetch': '2'
    - first last_run: {}
    When
    - running two fetch cycles
    Then
    - Validate the last run's update during two cycles of fetch:
        after first fetch should be {'last_timestamp': '2022-11-24 13:10:12', 'last_id': False, 'ids': []}, as the
        timestamp in the last (second record).
        after second fetch should be {'ids': [], 'last_id': False, 'last_timestamp': '2022-11-24 13:10:43'}, as the
        timestamp in the last (second record).
    """

    from GenericSQL import fetch_incidents
    # first fetch cycle
    mocker.patch('GenericSQL.demisto.getLastRun', return_value={})
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response_first_cycle, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table_first_cycle)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    assert expected_last_run_4_1 == last_run

    # second fetch cycle
    mocker.patch('GenericSQL.demisto.getLastRun', return_value=last_run)
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response_second_cycle, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table_second_cycle)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    assert expected_last_run_4_2 == last_run


# case of several records with the same timestamp - when the number is greater than the limit
# check the de-duplication mechanism
@pytest.mark.parametrize('table_first_cycle, table_second_cycle, table_third_cycle, params, response_first_cycle, '
                         'response_second_cycle, response_third_cycle, headers, expected_last_run_5_1, '
                         'expected_last_run_5_2, expected_last_run_5_3',
                         [(input_data.TABLE_5_1, input_data.TABLE_5_2, input_data.TABLE_5_3, input_data.PARAMS_5,
                           input_data.RESPONSE_5_1, input_data.RESPONSE_5_2, input_data.RESPONSE_5_3,
                           input_data.HEADERS_5, input_data.EXPECTED_LAST_RUN_5_1, input_data.EXPECTED_LAST_RUN_5_2,
                           input_data.EXPECTED_LAST_RUN_5_3)])
def test_fetch_incidents_de_duplication(table_first_cycle, table_second_cycle, table_third_cycle, params,
                                        response_first_cycle, response_second_cycle, response_third_cycle, headers,
                                        expected_last_run_5_1, expected_last_run_5_2, expected_last_run_5_3,
                                        mocker):
    """
    Given
    - raw responses of the database:
        1 record from the database for the first cycle and then another 2 records for the second,
        then 3 records for the third.
    - configuration parameters:
        - 'fetch_parameters': 'ID and timestamp'
        - 'query': 'call Test_MySQL_6'
            [CREATE PROCEDURE Test_MySQL_6(IN ts DATETIME, IN l INT)
            BEGIN
                SELECT *
                FROM incidents
                WHERE timestamp >= ts order by timestamp asc limit l;
            END]
        - 'first_fetch': '2020-01-01 01:01:01'
        - 'max_fetch': '1'
    - first last_run: {}
    When
    - running three fetch cycles
    Then
    - Validate the update of the last run during three fetch cycles, focusing on the IDs.
        Since they have the same timestamp, the last_run should accumulate the ids every cycle,
         and the 'last_timestamp' field should remain unchanged.
    - Validate the number of incidents, which should be just one per cycle.
    """

    from GenericSQL import fetch_incidents
    # first fetch cycle
    mocker.patch('GenericSQL.demisto.getLastRun', return_value={})
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response_first_cycle, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table_first_cycle)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    assert expected_last_run_5_1 == last_run
    assert len(incidents) == 1

    # second fetch cycle
    mocker.patch('GenericSQL.demisto.getLastRun', return_value=last_run)
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response_second_cycle, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table_second_cycle)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    assert expected_last_run_5_2 == last_run
    assert len(incidents) == 1

    # third fetch cycle
    mocker.patch('GenericSQL.demisto.getLastRun', return_value=last_run)
    mocker.patch.object(Client, '_create_engine_and_connect',
                        return_value=mocker.Mock(spec=sqlalchemy.engine.base.Connection))
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response_third_cycle, headers))
    mocker.patch('GenericSQL.convert_sqlalchemy_to_readable_table', return_value=table_third_cycle)
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "", False)
    incidents, last_run = fetch_incidents(client, params)
    assert expected_last_run_5_3 == last_run
    assert len(incidents) == 1
