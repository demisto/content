from GenericSQL import Client, sql_query_execute
import pytest

args1 = {
    'query': "select Name from city",
    'limit': 5,
    'skip': 0
}

args2 = {
    'query': "select * from mysql.user",
    'limit': 1,
    'skip': 0
}

raw1 = [{'Name': 'Kabul'}, {'Name': 'Qandahar'}, {'Name': 'Herat'}, {'Name': 'Mazar-e-Sharif'}]

raw2 = [{'Host': '%',
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

expected_output1 = {
    'GenericSQL(val.Query && val.Query === obj.Query)':
        {'GenericSQL': {'Result': [{'Name': 'Kabul'},
                                   {'Name': 'Qandahar'},
                                   {'Name': 'Herat'},
                                   {'Name': 'Mazar-e-Sharif'}],
                        'Query': 'select Name from city',
                        'InstanceName': 'sql_dialect_database'}}
}

expected_output2 = \
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
    }], 'Query': 'select * from mysql.user',
        'InstanceName': 'sql_dialect_database'}}}

header1 = ['Name']

header2 = ['Host', 'User', 'Select_priv', 'Insert_priv', 'Update_priv', 'Delete_priv', 'Create_priv', 'Drop_priv',
           'Reload_priv', 'Shutdown_priv', 'Process_priv', 'File_priv', 'Grant_priv', 'References_priv', 'Index_priv',
           'Alter_priv', 'Show_db_priv', 'Super_priv', 'Create_tmp_table_priv', 'Lock_tables_priv', 'Execute_priv',
           'Repl_slave_priv', 'Repl_client_priv', 'Create_view_priv', 'Show_view_priv', 'Create_routine_priv',
           'Alter_routine_priv', 'Create_user_priv', 'Event_priv', 'Trigger_priv', 'Create_tablespace_priv', 'ssl_type',
           'ssl_cipher', 'x509_issuer', 'x509_subject', 'max_questions', 'max_updates', 'max_connections',
           'max_user_connections', 'plugin', 'authentication_string', 'password_expired', 'password_last_changed',
           'password_lifetime', 'account_locked', 'Create_role_priv', 'Drop_role_priv', 'Password_reuse_history',
           'Password_reuse_time', 'Password_require_current', 'User_attributes']


@pytest.mark.parametrize('command, args, response, expected_result, header', [
    # Classic sql query, showing a table from database and convert it to readable data
    (sql_query_execute, args1, raw1, expected_output1, header1),
    # Simulates an mysql default tables such as "user",
    # in previous bug the value- b'' couldn't be converted to a readable value and the query failed
    (sql_query_execute, args2, raw2, expected_output2, header2),
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
    validate the expected_result and the created context
    """
    mocker.patch.object(Client, '_create_engine_and_connect')  # needed in order not to make a connection in tests
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(response, header))
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "")
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
