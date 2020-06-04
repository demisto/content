from JsonWhoIs import whois


def test_whois_error(requests_mock, mocker):
    return_error_mock = mocker.patch('JsonWhoIs.return_error')
    return_value = {'error': 'an error'}
    requests_mock.get('https://jsonwhois.com/api/v1/whois?domain=domain', json=return_value)
    whois('domain')
    assert 1 == return_error_mock.call_count
