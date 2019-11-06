import demistomock as demisto
from Vertica import connect_db

RETURN_ERROR_TARGET = 'Vertica.return_error'


def test_connect_db_fail(mocker):
    bad_connection_params = {
        "credentials": {
            "identifier": "stam",
            "password": "stam"
        },
        "database": "bad",
        "url": "127.0.0.1"
    }
    mocker.patch.object(demisto, 'params',
                        return_value=bad_connection_params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('url') == '127.0.0.1'
    connect_db()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 150
    assert 'Could not connect to DB' in err_msg
