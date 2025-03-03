"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import pytest
import os
import requests
import demistomock as demisto

import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
def init_tests(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'host': 'foo.bar',
        'broker': False,
        'credentials': {'identifier': 'foo', 'password': 'bar'},
        'verify_ssl': False,
        'timeout': '100',
        'first_run_time_range': '2',
        'fetch_limit': '250',
        'proxy': False
    })

    mocker.patch.dict(os.environ, {
        'HTTP_PROXY': '',
        'HTTPS_PROXY': '',
        'http_proxy': '',
        'https_proxy': ''
    })


def test_find_covs(mocker):
    '''
    Making sure correct Cov ids are returned when provided with an org name
    '''
    text = '''<html>
    <head><title>Select Covalence</title></head><body><h1>Select Covalence</h1><p>
    <a href="/index/2016-001-AA">Capsule Corp</a><p>
    <a href="/index/2016-001-AB">Acme Inc.</a><p>
    <a href="/index/2016-001-AC">Acme Inc.</a><p>
    </body><html>'''
    r = requests.Response()
    r.status_code = 200
    type(r).text = mocker.PropertyMock(return_value=text)
    mocker.patch.object(requests, 'get', return_value=r)

    from CovalenceForSecurityProviders import find_covs
    assert find_covs('Capsule Corp') == ['2016-001-AA']
    assert find_covs('Acme Inc.') == ['2016-001-AB', '2016-001-AC']


def test_build_host():
    '''
    Making sure the Covalence url is correctly built
    '''
    from CovalenceForSecurityProviders import build_host

    host = build_host('foo.bar')
    assert host == 'https://foo.bar/CovalenceWebUI/services'


def test_send_request_direct_dict(mocker):
    '''
    Making sure dict is returned for dict responses
    Direct mode
    '''
    import CovalenceForSecurityProviders
    # direct mode, no need to find cov from org_name
    mocker.patch.object(CovalenceForSecurityProviders, 'login', return_value=requests.Session())

    mock_get_sensor = util_load_json('test_data/get_sensor.json')
    r = requests.Response()
    r.status_code = 200
    r._content = json.dumps(mock_get_sensor).encode('utf-8')
    mocker.patch.object(requests.Session, 'send', return_value=r)

    resp = CovalenceForSecurityProviders.send_request('GET', '/rest/v1/sensors/sensor_id', target_org=None)
    assert resp == [mock_get_sensor]


def test_send_request_direct_list(mocker):
    '''
    Making sure list is returned for list responses
    Direct mode
    '''
    import CovalenceForSecurityProviders
    # direct mode, no need to find cov from org_name
    mocker.patch.object(CovalenceForSecurityProviders, 'login', return_value=requests.Session())

    mock_list_sensor = util_load_json('test_data/list_sensor.json')
    r = requests.Response()
    r.status_code = 200
    r._content = json.dumps(mock_list_sensor).encode('utf-8')
    mocker.patch.object(requests.Session, 'send', return_value=r)

    resp = CovalenceForSecurityProviders.send_request('GET', '/rest/v1/sensors', target_org=None)
    assert resp == mock_list_sensor


def test_send_request_broker_dict(mocker):
    '''
    Broker mode, the org has 2 covalences
    Making sure the request is sent to both covalences
    Making sure that both responses (dict) get merged in a list and returned
    '''
    mocker.patch.object(demisto, 'params', return_value={'broker': True})

    import CovalenceForSecurityProviders
    mocker.patch.object(CovalenceForSecurityProviders, 'find_covs', return_value=['2016-001-AB', '2016-001-AC'])
    mocker.patch.object(CovalenceForSecurityProviders, 'login', return_value=requests.Session())

    mock_get_sensor = util_load_json('test_data/get_sensor.json')
    r = requests.Response()
    r.status_code = 200
    r._content = json.dumps(mock_get_sensor).encode('utf-8')
    mocker.patch.object(requests.Session, 'send', return_value=r)
    sensor_list = []
    sensor_list.append(mock_get_sensor)
    sensor_list.append(mock_get_sensor)

    resp = CovalenceForSecurityProviders.send_request('GET', '/rest/v1/sensors/sensor_id', target_org='Acme Inc.')
    assert resp == sensor_list


def test_send_request_broker_list(mocker):
    '''
    Broker mode, the org has 2 covalences
    Making sure the request is sent to both covalences
    Making sure that both responses (list) get merged in a list and returned
    '''
    mocker.patch.object(demisto, 'params', return_value={'broker': True})

    import CovalenceForSecurityProviders
    mocker.patch.object(CovalenceForSecurityProviders, 'find_covs', return_value=['2016-001-AB', '2016-001-AC'])
    mocker.patch.object(CovalenceForSecurityProviders, 'login', return_value=requests.Session())

    mock_list_sensor = util_load_json('test_data/list_sensor.json')
    r = requests.Response()
    r.status_code = 200
    r._content = json.dumps(mock_list_sensor).encode('utf-8')
    mocker.patch.object(requests.Session, 'send', return_value=r)
    sensor_list = []
    sensor_list = sensor_list + mock_list_sensor
    sensor_list = sensor_list + mock_list_sensor

    resp = CovalenceForSecurityProviders.send_request('GET', '/rest/v1/sensors/sensor_id', target_org='Acme Inc.')
    assert resp == sensor_list


def test_list_alerts(mocker):
    mock_list_alerts = util_load_json('test_data/list_alerts.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_alerts)

    r = CovalenceForSecurityProviders.list_alerts()

    assert len(r[0].keys()) == 8
    assert 'acknowledgedStatus' in r[0]
    assert 'analystDescription' in r[0]
    assert 'destIp' in r[0]
    assert 'sourceIp' in r[0]
    assert 'subType' in r[0]
    assert 'title' in r[0]
    assert 'type' in r[0]


def test_list_alerts_details(mocker):
    mock_list_alerts = util_load_json('test_data/list_alerts.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_alerts)

    r = CovalenceForSecurityProviders.list_alerts()

    assert len(r[0].keys()) == 48
    assert 'id' in r[0]
    assert 'sensorId' in r[0]
    assert 'type' in r[0]
    assert 'organizationId' in r[0]
    assert 'subType' in r[0]
    assert 'severity' in r[0]
    assert 'facility' in r[0]
    assert 'priority' in r[0]
    assert 'createdTime' in r[0]
    assert 'lastAlertedTime' in r[0]
    assert 'title' in r[0]
    assert 'notes' in r[0]
    assert 'alertHash' in r[0]
    assert 'assignee' in r[0]
    assert 'analystTitle' in r[0]
    assert 'analystDescription' in r[0]
    assert 'endpointAgentUuid' in r[0]
    assert 'pcapResourceUuid' in r[0]
    assert 'sourceCityName' in r[0]
    assert 'sourceCountryName' in r[0]
    assert 'destCityName' in r[0]
    assert 'destCountryName' in r[0]
    assert 'destIp' in r[0]
    assert 'destPort' in r[0]
    assert 'protocol' in r[0]
    assert 'destDomainName' in r[0]
    assert 'destCiscoUmbrellaRanking' in r[0]
    assert 'destMajesticMillionRanking' in r[0]
    assert 'destCiscoUmbrellaTopLevelDomainRanking' in r[0]
    assert 'destMajesticMillionTopLevelDomainRanking' in r[0]
    assert 'sourceIp' in r[0]
    assert 'sourcePort' in r[0]
    assert 'sourceDomainName' in r[0]
    assert 'sourceCiscoUmbrellaRanking' in r[0]
    assert 'sourceMajesticMillionRanking' in r[0]
    assert 'sourceCiscoUmbrellaTopLevelDomainRanking' in r[0]
    assert 'sourceMajesticMillionTopLevelDomainRanking' in r[0]
    assert 'sourceGeoX' in r[0]
    assert 'sourceGeoY' in r[0]
    assert 'destGeoX' in r[0]
    assert 'destGeoY' in r[0]
    assert 'isFavorite' in r[0]
    assert 'alertCount' in r[0]
    assert 'acknowledgedStatus' in r[0]
    assert 'blacklistDetails' in r[0]
    assert 'sigEvalDetails' in r[0]
    assert 'sourceIpAttributes' in r[0]
    assert 'destIpAttributes' in r[0]


def test_list_sensors(mocker):
    mock_list_sensor = util_load_json('test_data/list_sensor.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_sensor)

    r = CovalenceForSecurityProviders.list_sensors()

    assert len(r[0].keys()) == 3
    assert 'isAuthorized' in r[0]
    assert 'isNetflowGenerator' in r[0]
    assert 'name' in r[0]


def test_list_sensors_details(mocker):
    mock_list_sensor = util_load_json('test_data/list_sensor.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_sensor)

    r = CovalenceForSecurityProviders.list_sensors()

    assert len(r[0].keys()) == 7
    assert 'id' in r[0]
    assert 'name' in r[0]
    assert 'isAuthorized' in r[0]
    assert 'listeningInterfaces' in r[0]
    assert 'isNetflowGenerator' in r[0]
    assert 'bytesIn' in r[0]
    assert 'bytesOut' in r[0]
    assert 'lastActive' not in r[0]


def test_get_sensor(mocker):
    mock_get_sensor = [util_load_json('test_data/get_sensor.json')]

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'sensor_id': 'id'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_get_sensor)

    r = CovalenceForSecurityProviders.get_sensor()

    assert isinstance(r, list)
    assert len(r[0].keys()) == 7
    assert 'id' in r[0]
    assert 'name' in r[0]
    assert 'isAuthorized' in r[0]
    assert 'listeningInterfaces' in r[0]
    assert 'isNetflowGenerator' in r[0]
    assert 'bytesIn' in r[0]
    assert 'bytesOut' in r[0]
    assert 'lastActive' not in r[0]


def test_connections_summary_by_ip(mocker):
    mock_connections_summary_by_ip = util_load_json('test_data/connections_summary_by_ip.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_connections_summary_by_ip)

    r = CovalenceForSecurityProviders.connections_summary_by_ip()

    assert len(r[0].keys()) == 9
    assert 'averageDuration' in r[0]
    assert 'bytesIn' in r[0]
    assert 'clientServerRelationship' in r[0]
    assert 'destinationIpAddress' in r[0]
    assert 'dstDomainName' in r[0]
    assert 'serverPorts' in r[0]
    assert 'sourceDomainName' in r[0]
    assert 'sourceIpAddress' in r[0]


def test_connections_summary_by_ip_details(mocker):
    mock_connections_summary_by_ip = util_load_json('test_data/connections_summary_by_ip.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_connections_summary_by_ip)

    r = CovalenceForSecurityProviders.connections_summary_by_ip()

    assert len(r[0].keys()) == 24
    assert 'id' in r[0]
    assert 'sourceId' in r[0]
    assert 'sourceIpAddress' in r[0]
    assert 'sourceMacAddress' in r[0]
    assert 'destinationId' in r[0]
    assert 'destinationIpAddress' in r[0]
    assert 'destinationMacAddress' in r[0]
    assert 'serverPortCount' in r[0]
    assert 'serverPorts' in r[0]
    assert 'bytesIn' in r[0]
    assert 'bytesOut' in r[0]
    assert 'packetsIn' in r[0]
    assert 'packetsOut' in r[0]
    assert 'continuingConnectionCount' in r[0]
    assert 'terminatedConnectionCount' in r[0]
    assert 'totalDuration' in r[0]
    assert 'averageDuration' in r[0]
    assert 'sourceCity' in r[0]
    assert 'sourceCountry' in r[0]
    assert 'destinationCity' in r[0]
    assert 'destinationCountry' in r[0]
    assert 'sourceDomainName' in r[0]
    assert 'dstDomainName' in r[0]
    assert 'clientServerRelationship' in r[0]


def test_connections_summary_by_port(mocker):
    mock_connections_summary_by_port = util_load_json('test_data/connections_summary_by_port.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_connections_summary_by_port)

    r = CovalenceForSecurityProviders.connections_summary_by_port()

    assert len(r[0].keys()) == 8
    assert 'averageDuration' in r[0]
    assert 'bytesIn' in r[0]
    assert 'bytesOut' in r[0]
    assert 'destinationIpAddress' in r[0]
    assert 'dstDomainName' in r[0]
    assert 'serverPort' in r[0]
    assert 'sourceDomainName' in r[0]
    assert 'sourceIpAddress' in r[0]


def test_connections_summary_by_port_details(mocker):
    mock_connections_summary_by_port = util_load_json('test_data/connections_summary_by_port.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_connections_summary_by_port)

    r = CovalenceForSecurityProviders.connections_summary_by_port()

    assert len(r[0].keys()) == 25
    assert 'id' in r[0]
    assert 'sourceId' in r[0]
    assert 'sourceIpAddress' in r[0]
    assert 'sourceMacAddress' in r[0]
    assert 'destinationId' in r[0]
    assert 'destinationIpAddress' in r[0]
    assert 'destinationMacAddress' in r[0]
    assert 'serverPort' in r[0]
    assert 'protocol' in r[0]
    assert 'continuingConnectionCount' in r[0]
    assert 'terminatedConnectionCount' in r[0]
    assert 'bytesIn' in r[0]
    assert 'bytesOut' in r[0]
    assert 'packetsIn' in r[0]
    assert 'packetsOut' in r[0]
    assert 'totalDuration' in r[0]
    assert 'averageDuration' in r[0]
    assert 'sourceCity' in r[0]
    assert 'sourceCountry' in r[0]
    assert 'destinationCity' in r[0]
    assert 'destinationCountry' in r[0]
    assert 'sourceDomainName' in r[0]
    assert 'dstDomainName' in r[0]
    assert 'startTime' in r[0]
    assert 'endTime' in r[0]


def test_list_dns_resolutions(mocker):
    mock_list_dns_resolutions = util_load_json('test_data/list_dns_resolutions.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_dns_resolutions)

    r = CovalenceForSecurityProviders.list_dns_resolutions()

    assert len(r[0].keys()) == 4
    assert 'domainName' in r[0]
    assert 'requestOriginIp' in r[0]
    assert 'requestTime' in r[0]
    assert 'resolvedIp' in r[0]


def test_list_dns_resolutions_details(mocker):
    mock_list_dns_resolutions = util_load_json('test_data/list_dns_resolutions.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_dns_resolutions)

    r = CovalenceForSecurityProviders.list_dns_resolutions()

    assert len(r[0].keys()) == 9
    assert 'id' in r[0]
    assert 'domainName' in r[0]
    assert 'resolvedIp' in r[0]
    assert 'requestOriginIp' in r[0]
    assert 'nameserverIp' in r[0]
    assert 'nodeLabel' in r[0]
    assert 'requestTime' in r[0]
    assert 'byteCount' in r[0]
    assert 'pktCount' in r[0]


def test_list_internal_networks(mocker):
    mock_list_internal_networks = util_load_json('test_data/list_internal_networks.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_internal_networks)

    r = CovalenceForSecurityProviders.list_internal_networks()

    assert len(r[0].keys()) == 2
    assert 'notes' in r[0]
    assert 'cidr' in r[0]


def test_list_endpoint_agents(mocker):
    mock_list_endpoint_agents = util_load_json('test_data/list_endpoint_agents.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_endpoint_agents)

    r = CovalenceForSecurityProviders.list_endpoint_agents()

    assert len(r[0].keys()) == 7
    assert 'hardwareVendor' in r[0]
    assert 'hostName' in r[0]
    assert 'ipAddress' in r[0]
    assert 'isConnected' in r[0]
    assert 'lastSessionUser' in r[0]
    assert 'operatingSystem' in r[0]
    assert 'serialNumber' in r[0]


def test_list_endpoint_agents_details(mocker):
    mock_list_endpoint_agents = util_load_json('test_data/list_endpoint_agents.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_list_endpoint_agents)

    r = CovalenceForSecurityProviders.list_endpoint_agents()

    assert len(r[0].keys()) == 25
    assert 'agentUuid' in r[0]
    assert 'agentVersion' in r[0]
    assert 'firstSeenTime' in r[0]
    assert 'lastSeenTime' in r[0]
    assert 'lastSessionUser' in r[0]
    assert 'isMobile' in r[0]
    assert 'isConnected' in r[0]
    assert 'coreVersion' in r[0]
    assert 'coreArchitecture' in r[0]
    assert 'coreOs' in r[0]
    assert 'operatingSystem' in r[0]
    assert 'hostName' in r[0]
    assert 'hardwareVendor' in r[0]
    assert 'hardwareModel' in r[0]
    assert 'arch' in r[0]
    assert 'osDistro' in r[0]
    assert 'osVersion' in r[0]
    assert 'kernelVersion' in r[0]
    assert 'operatingSystemReleaseId' in r[0]
    assert 'ipAddress' in r[0]
    assert 'secondaryIpAddress' in r[0]
    assert 'ipAddresses' in r[0]
    assert 'serialNumber' in r[0]
    assert 'deviceIdentifier' in r[0]
    assert 'cpuArchitectureEnum' in r[0]


def test_search_endpoint_process(mocker):
    mock_search_endpoint_process = util_load_json('test_data/search_endpoint_process.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_search_endpoint_process)

    r = CovalenceForSecurityProviders.search_endpoint_process()

    assert len(r[0].keys()) == 5
    assert 'commandLine' in r[0]
    assert 'firstSeenTime' in r[0]
    assert 'lastSeenTime' in r[0]
    assert 'processPath' in r[0]
    assert 'username' in r[0]


def test_search_endpoint_process_details(mocker):
    mock_search_endpoint_process = util_load_json('test_data/search_endpoint_process.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_search_endpoint_process)

    r = CovalenceForSecurityProviders.search_endpoint_process()

    assert len(r[0].keys()) == 13
    assert 'id' in r[0]
    assert 'agentUuid' in r[0]
    assert 'processName' in r[0]
    assert 'processPath' in r[0]
    assert 'parentProcessName' in r[0]
    assert 'parentProcessPath' in r[0]
    assert 'commandLine' in r[0]
    assert 'username' in r[0]
    assert 'firstSeenTime' in r[0]
    assert 'lastSeenTime' in r[0]
    assert 'lastEndTime' in r[0]
    assert 'seenCount' in r[0]
    assert 'activeCount' in r[0]


def test_search_endpoint_installed_software(mocker):
    mock_search_endpoint_installed_software = util_load_json('test_data/search_endpoint_installed_software.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'false'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_search_endpoint_installed_software)

    r = CovalenceForSecurityProviders.search_endpoint_installed_software()

    assert len(r[0].keys()) == 5
    assert 'installTimestamp' in r[0]
    assert 'name' in r[0]
    assert 'uninstallTimestamp' in r[0]
    assert 'vendor' in r[0]
    assert 'version' in r[0]


def test_search_endpoint_installed_software_details(mocker):
    mock_search_endpoint_installed_software = util_load_json('test_data/search_endpoint_installed_software.json')

    import CovalenceForSecurityProviders
    mocker.patch.object(demisto, 'args', return_value={
        'target_org': None,
        'details': 'true'
    })
    mocker.patch.object(CovalenceForSecurityProviders, 'send_request', return_value=mock_search_endpoint_installed_software)

    r = CovalenceForSecurityProviders.search_endpoint_installed_software()

    assert len(r[0].keys()) == 16
    assert 'arch' in r[0]
    assert 'type' in r[0]
    assert 'packageManager' in r[0]
    assert 'installTimestamp' in r[0]
    assert 'uninstallTimestamp' in r[0]
    assert 'name' in r[0]
    assert 'version' in r[0]
    assert 'vendor' in r[0]
    assert 'installPath' in r[0]
    assert 'appDataPath' in r[0]
    assert 'sharedDataPath' in r[0]
    assert 'installedForUser' in r[0]
    assert 'installSource' in r[0]
    assert 'id' in r[0]
    assert 'agentUuid' in r[0]
    assert 'softwareNotifyAction' in r[0]


def test_list_org(mocker):
    mocker.patch.object(demisto, 'params', return_value={'broker': True})
    text = '''<html>
    <head><title>Select Covalence</title></head><body><h1>Select Covalence</h1><p>
    <a href="/index/2016-001-AA">Capsule Corp</a><p>
    <a href="/index/2016-001-AB">Acme Inc.</a><p>
    <a href="/index/2016-001-AC">Acme Inc.</a><p>
    </body><html>'''
    r = requests.Response()
    r.status_code = 200
    type(r).text = mocker.PropertyMock(return_value=text)
    mocker.patch.object(requests, 'get', return_value=r)

    import CovalenceForSecurityProviders
    org_names = CovalenceForSecurityProviders.list_org()

    assert len(org_names) == 2
    assert {'org_name': 'Capsule Corp'} in org_names
    assert {'org_name': 'Acme Inc.'} in org_names
