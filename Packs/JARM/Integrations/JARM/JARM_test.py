def test_parse_fqdn_implicit_port(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = 'google.com'
    MOCK_PORT = 443

    hostname = f'{MOCK_HOSTNAME}:{str(MOCK_PORT)}'
    port = None

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'fqdn',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_fqdn_noport(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = 'google.com'
    MOCK_PORT = 443

    hostname = f'{MOCK_HOSTNAME}'
    port = None

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'fqdn',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_fqdn_explicit_port(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = 'google.com'
    MOCK_PORT = 443

    hostname = f'{MOCK_HOSTNAME}'
    port = MOCK_PORT

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'fqdn',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_fqdn_explicit_port_wins_over_implicit(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = 'google.com'
    MOCK_PORT = 443

    hostname = f'{MOCK_HOSTNAME}:999'
    port = MOCK_PORT

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'fqdn',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_ipv4_implicit_port(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = '1.2.3.4'
    MOCK_PORT = 443

    hostname = f'{MOCK_HOSTNAME}:{MOCK_PORT}'
    port = None

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'ip',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_ipv4_explicit_port(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = '1.2.3.4'
    MOCK_PORT = 443

    hostname = f'{MOCK_HOSTNAME}'
    port = MOCK_PORT

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'ip',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_url_with_fqdn_and_port(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = 'google.com'
    MOCK_PORT = 443

    hostname = f'https://{MOCK_HOSTNAME}:{MOCK_PORT}'
    port = None

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'fqdn',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_parse_url_with_ip_and_port(mocker):
    from JARM import parse_hostname

    MOCK_HOSTNAME = '1.2.3.4'
    MOCK_PORT = 443

    hostname = f'https://{MOCK_HOSTNAME}:{MOCK_PORT}'
    port = None

    assert parse_hostname(hostname=hostname, port=port) == {
        'target_type': 'ip',
        'target_host': MOCK_HOSTNAME,
        'port': MOCK_PORT
    }


def test_jarm_fingerprint(mocker):
    from JARM import Client, jarm_fingerprint_command

    MOCK_HOST = 'google.com'
    MOCK_PORT = '443'
    MOCK_FINGERPRINT = '27d27d27d29d27d1dc27d27d27d27d6c727b989c06cb37f7678fa2982d9377'

    mocker.patch('jarm.scanner.scanner.Scanner.scan', return_value=(MOCK_FINGERPRINT, MOCK_HOST, int(MOCK_PORT)))
    client = Client()
    args = {
        'host': MOCK_HOST,
        'port': MOCK_PORT
    }
    response = jarm_fingerprint_command(client, args)

    mock_response = {
        "FQDN": MOCK_HOST,
        "Port": int(MOCK_PORT),
        "Fingerprint": MOCK_FINGERPRINT
    }

    assert response[0].outputs == mock_response
