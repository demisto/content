import demistomock as demisto
from Active_Directory_Query import main
import socket
import ssl
from threading import Thread
import time
import os
import pytest

BASE_TEST_PARAMS = {
    'server_ip': '127.0.0.1',
    'secure_connection': 'None',
    'page_size': '500',
    'credentials': {'identifier': 'bad', 'password': 'bad'}
}

RETURN_ERROR_TARGET = 'Active_Directory_Query1.return_error'


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
    demisto_info_mock = mocker.patch.object(demisto, "info")
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg
    assert 'SSL error' in err_msg
    # call_args_list holds all calls (we need the first) with a tuple of args list and kwargs
    info_msg = demisto_info_mock.call_args_list[0][0][0]
    # ip is not in the certificate. so it should fail on host match
    assert "doesn't match any name" in info_msg


def ssl_bad_socket_server(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # cert and keyfile generated with
    # openssl req -x509 -nodes -days 3000 -newkey rsa:2048 -keyout key.pem -out cert.pem
    try:
        context.load_cert_chain('cert.pem', 'key.pem')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', port))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                try:
                    conn, addr = ssock.accept()
                except ssl.SSLError as err:
                    if 'TLSV1_ALERT_UNKNOWN_CA' in str(err):
                        # all is ok. client refused our cert
                        return
                    raise
                conn.recv(32)
                msg = b'THIS IS A TEST SERVER WHICH IGNORES PROTOCOL\n\n'
                for x in range(10):
                    msg += msg
                conn.send(msg)
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
    except Exception as ex:
        pytest.fail("Failed starting ssl_bad_socket_server: {}".format(ex))
        raise


def test_faulty_server(mocker):
    port = 9638
    t = Thread(target=ssl_bad_socket_server, args=(port,))
    t.start()
    time.sleep(1)  # wait for socket server to startup
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '127.0.0.1'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['unsecure'] = True
    params['port'] = port
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    t.join(5)
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg


def test_ssl_custom_cert(mocker, request):
    ENV_KEY = 'SSL_CERT_FILE'
    os.environ[ENV_KEY] = 'cert.pem'

    def cleanup():
        os.environ.pop(ENV_KEY)

    request.addfinalizer(cleanup)
    port = 9637
    t = Thread(target=ssl_bad_socket_server, args=(port,))
    t.start()
    time.sleep(1)  # wait for socket server to startup
    params = BASE_TEST_PARAMS.copy()
    params['server_ip'] = '127.0.0.1'  # disable-secrets-detection
    params['secure_connection'] = 'SSL'
    params['port'] = port
    mocker.patch.object(demisto, 'params',
                        return_value=params)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    # validate our mock of params
    assert demisto.params().get('secure_connection') == 'SSL'
    main()
    t.join(5)
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert len(err_msg) < 100
    assert 'Failed to access' in err_msg
    assert 'SSL error' not in err_msg


def test_endpoint_entry():
    """
    Given:
         Custom attributes to filter the computer object entry.
    When:
        The function filters the computer object according to the custom attributes.
    Then:
        The function will return all the computer object entry because custom attributes contain '*'.

    """
    from Active_Directory_Query import endpoint_entry
    custom_attributes_with_asterisk = endpoint_entry({'dn': 'dn', 'name': 'name', 'memberOf': 'memberOf'}, ['*'])
    assert custom_attributes_with_asterisk == {'Groups': 'memberOf', 'Hostname': 'name', 'ID': 'dn', 'Type': 'AD'}
