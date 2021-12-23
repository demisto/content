from FeedZoom import Client
import demistomock as demisto


URL = "https://assets.zoom.us/docs/ipranges"


def test_build_iterator(mocker):
    with open('test_data/zoom_endpoint.txt', 'r') as file:
        response = file.read()
    mocker.patch.object(Client, '_http_request', return_value=response)
    mocker.patch.object(demisto, 'params',
                        return_value={'zoom_clients_certificate_validation': 'crl3.digicert.com,crl4.digicert.com',
                                      'zoom_clients_user_browser': '*.zoom.us'})

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
