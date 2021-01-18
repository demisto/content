def test_jarm_fingerprint(mocker):
    from JARM import Client, jarm_fingerprint_command

    MOCK_HOST = 'google.com'
    MOCK_IP = '172.217.23.110'
    MOCK_PORT = '443'
    MOCK_FINGERPRINT = '27d27d27d29d27d1dc27d27d27d27d6c727b989c06cb37f7678fa2982d9377'

    mocker.patch('Scanner.scan', return_value=(MOCK_FINGERPRINT, MOCK_IP, int(MOCK_PORT)))
    client = Client()
    args = {
        'host': MOCK_HOST,
        'port': MOCK_PORT
    }
    response = jarm_fingerprint_command(client, args)

    mock_response = {
        "Host": MOCK_HOST,
        "Port": MOCK_PORT,
        "Fingerprint": MOCK_FINGERPRINT
    }

    assert response.outputs == mock_response
