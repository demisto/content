from FeedZoom import Client


URL = "https://support.zoom.us/hc/en-us/articles/201362683-Network-Firewall-or-Proxy-Server-Settings-for-Zoom"


def test_build_iterator(requests_mock):
    with open('test_data/zoom_endpoint_mock.html', 'r') as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_cidr = '3.7.35.0/25'
    expected_ipv6 = '2620:123:2000::/40'
    expected_glob = '*.zoom.us'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    cidr_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'CIDR'}
    ipv6_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'IPv6CIDR'}
    domain_glob_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'DomainGlob'}
    assert expected_cidr in cidr_indicators
    assert expected_ipv6 in ipv6_indicators
    assert expected_glob in domain_glob_indicators
