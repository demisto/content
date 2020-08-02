import pytest

from JsonWhoIs import whois, DemistoException


def test_whois_error(requests_mock):
    return_value = {'error': 'an error'}
    requests_mock.get('https://jsonwhois.com/api/v1/whois?domain=domain', json=return_value)
    with pytest.raises(DemistoException, match='an error'):
        whois('domain')
