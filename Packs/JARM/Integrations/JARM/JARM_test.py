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
    MOCK_FINGERPRINT = '27d40d40d29d40d1dc42d43d00041d132f09251ceeb363bb0349f742bf0947'

    mocker.patch('jarm.scanner.scanner.Scanner.scan_async', return_value=(MOCK_FINGERPRINT, MOCK_HOST, int(MOCK_PORT)))
    client = Client()
    args = {
        'host': MOCK_HOST,
        'port': MOCK_PORT
    }
    response = jarm_fingerprint_command(client, args)

    mock_response = {
        "FQDN": MOCK_HOST,
        "Port": int(MOCK_PORT),
        "Fingerprint": MOCK_FINGERPRINT,
        "Target": f'{MOCK_HOST}:{int(MOCK_PORT)}'
    }

    assert response.outputs == mock_response
