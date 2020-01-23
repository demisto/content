import pytest
from CommonServerPython import *
from FeedAzure import Client, main


@pytest.mark.parametrize('regions_list, services_list', [(['All'], ['All'])])
def test_download_link_fetching(regions_list, services_list):
    client = Client(regions_list, services_list)
    assert client.get_azure_download_link()


BUILD_IP_PACK = [
    (
        ['All'],
        ['All'],
        '19.117.63.126',
        'global',
        'some service',
        {
            'value': '19.117.63.126',
            'type': 'IP',
            'region': 'global',
            'service': 'some service',
        },
    ),
    (
        ['All'],
        ['All'],
        'FE80::0202:B3FF:FE1E:8329',
        'global',
        'some service',
        {
            'value': 'FE80::0202:B3FF:FE1E:8329',
            'type': 'IPv6',
            'region': 'global',
            'service': 'some service',
        },
    ),
    (['All'], ['All'], '8.8.8/10', 'global', 'some service', {}),
]


@pytest.mark.parametrize('regions_list, services_list, ip, region, service, expected_result', BUILD_IP_PACK)
def test_build_ip(regions_list, services_list, ip, region, service, expected_result):
    client = Client(regions_list, services_list)
    assert (client.build_ip_indicator(ip, region=region, service=service) == expected_result)


EXTRACT_METADATA_PACK = [
    (
        ['All'],
        ['All'],
        {
            'name': 'test-name',
            'id': 'test-id',
            'properties': {
                'changeNumber': 0,
                'region': '',
                'platform': 'Azure',
                'systemService': 'AzureAD',
                'addressPrefixes': ['9.9.9.9'],
            },
        },
        {
            'id': 'test-id',
            'name': 'test-name',
            'region': '',
            'platform': 'Azure',
            'system_service': 'AzureAD',
            'address_prefixes': ['9.9.9.9'],
        },
    ),
    (['All'], ['All'], {'name': 'test-name-2', 'id': 'test-id-2', 'region': 'ME'}, {}),
    (['All'], ['All'], {'name': 'test-name', 'id': 'test-id', 'properties': {}}, {}),
]


@pytest.mark.parametrize('regions_list, services_list, values_group_section, expected_result', EXTRACT_METADATA_PACK)
def test_extract_metadata(regions_list, services_list, values_group_section, expected_result):
    client = Client(regions_list, services_list)
    assert (client.extract_metadata_of_indicators_group(values_group_section) == expected_result)


EXTRACT_INDICATORS_PACK = [
    (
        ['All'],
        ['All'],
        [
            {
                'name': 'test-name',
                'id': 'test-id',
                'properties': {
                    'changeNumber': 0,
                    'region': '',
                    'platform': 'Azure',
                    'systemService': 'AzureAD',
                    'addressPrefixes': ['9.9.9.9', '5.5.5.5'],
                },
            }
        ],
        [
            {
                'value': '9.9.9.9',
                'type': 'IP',
                'azure_id': 'test-id',
                'azure_name': 'test-name',
                'azure_region': '',
                'azure_platform': 'Azure',
                'azure_system_service': 'AzureAD',
            },
            {
                'value': '5.5.5.5',
                'type': 'IP',
                'azure_id': 'test-id',
                'azure_name': 'test-name',
                'azure_region': '',
                'azure_platform': 'Azure',
                'azure_system_service': 'AzureAD',
            },
        ],
    ),
    (
        [],
        ['All'],
        [
            {
                'name': 'test-name',
                'id': 'test-id',
                'properties': {
                    'changeNumber': 0,
                    'region': '',
                    'platform': 'Azure',
                    'systemService': 'AzureAD',
                    'addressPrefixes': ['9.9.9.9', '5.5.5.5'],
                },
            }
        ],
        [],
    ),
    (
        ['All'],
        [],
        [
            {
                'name': 'test-name',
                'id': 'test-id',
                'properties': {
                    'changeNumber': 0,
                    'region': '',
                    'platform': 'Azure',
                    'systemService': 'AzureAD',
                    'addressPrefixes': ['9.9.9.9', '5.5.5.5'],
                },
            }
        ],
        [],
    ),
    (
        ['NW'],
        ['AD'],
        [
            {
                'name': 'test-name',
                'id': 'test-id',
                'properties': {
                    'changeNumber': 0,
                    'region': '',
                    'platform': 'Azure',
                    'systemService': 'AzureAD',
                    'addressPrefixes': ['9.9.9.9', '5.5.5.5'],
                },
            }
        ],
        [],
    ),
    (
        ['All'],
        ['All'],
        [],
        [],
    ),
    (
        ['All'],
        ['All'],
        None,
        [],
    ),
]


@pytest.mark.parametrize('regions_list, services_list, values_group_section, expected_result', EXTRACT_INDICATORS_PACK)
def test_extract_indicators(regions_list, services_list, values_group_section, expected_result):
    client = Client(regions_list, services_list)
    assert (client.extract_indicators_from_values_dict(values_group_section) == expected_result)


def test_get_indicators(mocker):
    mocker.patch.object(demisto, 'args', return_value={
        'regions': 'norwaye, westus',
        'services': 'AzureBackup, AzureAppService',
    })
    mocker.patch.object(demisto, 'command', return_value='azure-get-indicators')
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_args[0][0]['Contents']
