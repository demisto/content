from FeedZoom import Client


URL = "https://support.zoom.us/hc/en-us/articles/201362683-Network-Firewall-or-Proxy-Server-Settings-for-Zoom"


def test_build_iterator():
    expected_cidr = '3.7.35.0/25'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    cidr_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'CIDR'}
    assert expected_cidr in cidr_indicators
