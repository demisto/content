from GenericSQL import Client, sql_query_execute
import pytest

args1 = {
    'query': "select Name from city",
    'limit': 5,
    'skip': 0
}

raw1 = [{'Name': 'Kabul'}, {'Name': 'Qandahar'}, {'Name': 'Herat'}, {'Name': 'Mazar-e-Sharif'}]

expected_output = {
    'GenericSQL(val.Query && val.Query === obj.Query)':
        {'GenericSQL': {'Result': [{'Name': 'Kabul'},
                                   {'Name': 'Qandahar'},
                                   {'Name': 'Herat'},
                                   {'Name': 'Mazar-e-Sharif'}],
                        'Query': 'select Name from city',
                        'InstanceName': 'sql_dialect_database'}}
}


@pytest.mark.parametrize('command, args, response, expected_result', [
    (sql_query_execute, args1, raw1, expected_output),
])
def test_sql_queries(command, args, response, expected_result, mocker):
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
    mocker.patch.object(Client, 'sql_query_execute_request', return_value=(raw1, ['Name']))
    client = Client('sql_dialect', 'server_url', 'username', 'password', 'port', 'database', "")
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command
