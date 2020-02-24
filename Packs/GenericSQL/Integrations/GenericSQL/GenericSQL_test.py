from GenericSQL.GenericSQL import Client, sql_query_execute, sql_command_execute
import pytest

args1 = {
        'query': "select Name from city",
        'limit': 5,
        'skip': 0
}

raw1 = [{'Name': 'Kabul'}, {'Name': 'Qandahar'}, {'Name': 'Herat'}, {'Name': 'Mazar-e-Sharif'}]

expected_output = {
    'GenericSQL.sql_dialect.database(val.city && val.city === obj.city)':
        [
            {'Name': 'Kabul'},
            {'Name': 'Qandahar'},
            {'Name': 'Herat'},
            {'Name': 'Mazar-e-Sharif'}
        ]
}


db_name = "new_schema"
sql_insert_args = {
        'query': "INSERT into People (ID, FirstName, LastName) values (11511, 'noticeme', 'hereiam')"
        }
human_readable_insert = "Insert command executed to new_schema db into People table"

sql_delete_args = {
        'query': "Delete FROM People WHERE ID=11511"
        }
human_readable_delete = "Delete command executed from new_schema db from People table"

sql_update_args = {
        'query': "Update People Set FirstName='updated' Where ID=11511;"
        }
human_readable_update = "Update command executed in new_schema db in People table"


@pytest.mark.parametrize('command, args, response, expected_result', [
    (sql_query_execute, args1, raw1, expected_output),
])
def test_sql_queries(command, args, response, expected_result, mocker):
    """Unit test // complete
    """
    """TODO
    Given
    - valid zip file - no password required
    - empty folder _dir
    When
    - run extract on that zip file and export the internal files to _dir
    Then
    - ensure zip file content have be saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    mocker.patch.object(Client, '_create_engine_and_connect')  # needed in order not to make a connection in tests
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(raw1, ['Name']))
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database')
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


# there is an issue with the name
# no raw data
@pytest.mark.parametrize('command, command_type, args, expected_result', [
    (sql_command_execute, 'sql-insert', sql_insert_args, human_readable_insert),
    (sql_command_execute, 'sql-delete', sql_delete_args, human_readable_delete),
    (sql_command_execute, 'sql-update', sql_update_args, human_readable_update),

])
def test_sql_commands(command, command_type, args, expected_result, mocker):
    """Unit test // complete
    """
    """TODO
    Given
    - valid zip file - no password required
    - empty folder _dir
    When
    - run extract on that zip file and export the internal files to _dir
    Then
    - ensure zip file content have be saved at _dir directory with the original filename
    - ensure that the saved file has expected content
    """
    mocker.patch.object(Client, '_create_engine_and_connect')  # needed in order not to make a connection in tests
    mocker.patch.object(Client, 'sql_query_execute_request')
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', db_name)
    result = command(client, args, command_type)
    assert expected_result == result[0]  # human readable is found in the 2nd place in the result of the command

