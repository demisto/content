from FeedMicrosoftIntune import Client

URL = 'https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints'


def test_build_iterator(requests_mock):
    with open('test_data/Microsoft_endpoint_mock.html', 'r') as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_domain = 'login.microsoftonline.com'
    expected_domain_glob = '*.manage.microsoft.com'
    expected_ip = '52.175.12.209'
    expected_cidr = '40.82.248.224/28'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    domain_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'Domain'}
    domain_glob_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'DomainGlob'}
    ip_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'IP'}
    cidr_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'CIDR'}
    assert expected_domain in domain_indicators
    assert expected_domain_glob in domain_glob_indicators
    assert expected_ip in ip_indicators
    assert expected_cidr in cidr_indicators
