from AzureADConnectHealthFeed import Client


URL = 'https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-agent-install#outbound-connectivity-to-the-azure-service-endpoints' # noqa


def test_build_iterator(requests_mock):
    with open('test_data/Microsoft_endpoint_mock.html', 'r') as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_url = 'https://login.microsoftonline.com'
    expected_domain_glob = '*.blob.core.windows.net'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    url_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'URL'}
    domain_glob_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'DomainGlob'}
    assert expected_url in url_indicators
    assert expected_domain_glob in domain_glob_indicators
