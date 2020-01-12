import pytest
from azureFeed import Client  # , get_indicators_command, fetch_indicators


@pytest.mark.parametrize('regions_list, services_list', [(['All'], ['All'])])
def test_download_link_fetching(regions_list, services_list):
    client = Client(regions_list, services_list)
    assert client.get_azure_download_link()


BUILD_IP_PACK = [
    (['All'], ['All'], '19.117.63.126', 'global', 'some service', {
        'value': '19.117.63.126',
        'type': 'IPv4',
        'region': 'global',
        'service': 'some service'
    }),
    (['All'], ['All'], 'FE80::0202:B3FF:FE1E:8329', 'global', 'some service', {
        'value': 'FE80::0202:B3FF:FE1E:8329',
        'type': 'IPv6',
        'region': 'global',
        'service': 'some service'
    }),
    (['All'], ['All'], '8.8.8.8/10', 'global', 'some service', {})
]


@pytest.mark.parametrize('regions_list, services_list, ip, region, service, expected_result', BUILD_IP_PACK)
def test_build_ip(regions_list, services_list, ip, region, service, expected_result):
    client = Client(regions_list, services_list)
    assert client.build_ip_indicator(ip, region=region, service=service) == expected_result
