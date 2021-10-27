from unittest import mock

from FeedZoom import Client


URL = "https://assets.zoom.us/docs/ipranges"


@mock.patch('subprocess.check_output')
def test_build_iterator(requests_mock):
    with open('test_data/zoom_endpoint.txt', 'r') as file:
        response = file.read()
    requests_mock.return_value = response

    expected_cidr = '3.7.35.0/25'
    expected_glob = '*.zoom.us'
    expected_ipv4 = '1.2.3.4'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    cidr_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'CIDR'}
    ip_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'IP'}
    domain_glob_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'DomainGlob'}
    assert expected_cidr in cidr_indicators
    assert expected_ipv4 in ip_indicators
    assert expected_glob in domain_glob_indicators
