import demistomock as demisto
from Active_Directory_Query import main

BASE_TEST_PARAMS = {
    'server_ip': '127.0.0.1',
    'secure_connection': 'None',
    'page_size': '500',
    'credentials': {'identifier': 'bad', 'password': 'bad'}
}

RETURN_ERROR_TARGET = 'Active_Directory_Query.return_error'


def test_bad_host_no_ssl(mocker):
    mocker.patch.object(demisto, 'params',
                        return_value=BASE_TEST_PARAMS)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('server_ip') == '127.0.0.1'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg


def test_bad_ssl(mocker):
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '185.199.108.153'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['port'] = 443
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg
    assert 'SSL error' in err_msg
