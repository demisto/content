import demistomock as demisto
import pytest
from pytest import raises
from BMCDiscovery import Client, \
    discovery_process_status_command, \
    discovery_scan_status_list_command, \
    discovery_search_command, \
    discovery_search_custom_command, \
    discovery_scan_create_command, \
    discovery_scan_stop_command,\
    discovery_scan_summary_command, \
    discovery_scan_results_list_command
import os
import sys
import io
import json
from CommonServerPython import *
p = os.path.abspath('.')
sys.path.insert(1, p)

INTEGRATION_NAME = 'BMCDiscovery'
VALID_TOKEN = 'NDpYU09BUjo6OnRMbmxsZXVGMkVIcjh6THJPMlRvZnMwZ3RTcVg1c21YZ0dFQjJjMHNEM2xYYVk0QS9aUjVJZzowLTcyNDgwYTNkZGNhYmY1YWYzZjQxZGQxZjkwMjg0NmQwNmU4ZDZjZGFhZjE1MWNkODc5YWIyMTc0OGIwZTY2YjM='  # noqa: E501
INVALID_TOKEN = '95884261de2415f969ab47a06e486f7374'
URL = "http://fake-bmc-api.com"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationName': 'BMC Discovery'}})


def mock_client(mocker, http_request_result=None):
    client = Client(
        url=URL,
        verify=False,
        proxy=False,
        api_token=VALID_TOKEN
    )
    if http_request_result:
        mocker.patch.object(client, '_http_request', return_value=http_request_result)
    return client


client = mock_client(Client)


def test_discovery_process_status_command(mocker):
    mocker.patch.object(client, 'discovery_process_status', return_value=util_load_json('test_data/discovery_process_resp.json'))
    results = discovery_process_status_command(client)
    assert results.raw_response.get('status') == 'running'


def test_discovery_search_custom_command(mocker):
    mocker.patch.object(client, 'discovery_search_custom',
                        return_value=util_load_json('test_data/discovery_search_custom_resp.json'))
    query = \
        "SEARCH FLAGS(no_segment) DeviceInfo WHERE #DiscoveryResult:DiscoveryAccessResult:DiscoveryAccess:DiscoveryAccess._last_marker TRAVERSE Primary:Inference:InferredElement: SHOW kind(#), name, #InferredElement:Inference:Associate:DiscoveryAccess.endpoint"  # noqa: E501
    results = discovery_search_custom_command(client, query=query)
    assert results.outputs.get('data')[0].get('count') == 326


def test_discovery_scan_status_list_command_by_id(mocker):
    mocker.patch.object(client, 'discovery_scan_status_list',
                        return_value=util_load_json('test_data/discovery_scan_status_list_id_resp.json'))
    run_id = 'f5ac176243062b2b14c1a75a6e446973636f7665727952756e'
    results = discovery_scan_status_list_command(client, run_id=run_id)
    assert results.outputs[0].get('label') == "Sample_run_16"


def test_discovery_scan_status_list_command_single(mocker):
    mocker.patch.object(client, 'discovery_scan_status_list',
                        return_value=util_load_json('test_data/discovery_scan_status_list_single_resp.json'))
    results = discovery_scan_status_list_command(client)
    assert results.outputs[0].get('valid_ranges') == '192.168.0.0/16'


def test_discovery_scan_status_list_command_multiple(mocker):
    mocker.patch.object(client, 'discovery_scan_status_list',
                        return_value=util_load_json('test_data/discovery_scan_status_list_multi_resp.json'))
    results = discovery_scan_status_list_command(client)
    assert len(results.outputs) == 2


def test_discovery_scan_create_command(mocker):
    mocker.patch.object(client, 'discovery_scan_create',
                        return_value=util_load_json('test_data/discovery_scan_create_resp.json'))
    label = 'Sample_XSOAR_scan'
    ranges = '10.11.6.0/24'
    results = discovery_scan_create_command(client, label=label, ranges=ranges)
    assert results.outputs.get('uuid') == '7e1c02625b07bf307ca81c796e446973636f7665727952756e'


def test_discovery_scan_stop_command(mocker):
    mocker.patch.object(client, 'discovery_scan_stop', return_value='true')
    run_id = 'f5ac176243062b2b14c1a75a6e446973636f7665727952756e'
    results = discovery_scan_stop_command(client, run_id=run_id)
    assert results.outputs == 'true'


def test_discovery_scan_summary_command_single(mocker):
    mocker.patch.object(client, 'discovery_scan_summary',
                        return_value=util_load_json('test_data/discovery_scan_summary_single_resp.json'))
    run_id = 'f5ac176243062b2b14c1a75a6e446973636f7665727952756e'
    results = discovery_scan_summary_command(client, run_id=run_id)
    assert results.outputs['Dropped'] == 26879


def test_discovery_scan_summary_command_multiple(mocker):
    mocker.patch.object(client, 'discovery_scan_summary',
                        return_value=util_load_json('test_data/discovery_scan_summary_multi_resp.json'))
    run_id = 'f5ac176243062b2b14c1a7a46e446973636f7665727952756e'
    results = discovery_scan_summary_command(client, run_id=run_id)
    assert results.outputs['Success'] == 13
    assert results.outputs['Dropped'] == 1318643


def test_discovery_scan_results_list_command_success(mocker):
    mocker.patch.object(client, 'discovery_scan_results_list',
                        return_value=util_load_json('test_data/discovery_scan_results_list_success_resp.json'))
    run_id = 'f5ac176243062b2b14c1a75a6e446973636f7665727952756e'
    result_type = 'Success'
    results = discovery_scan_results_list_command(client, run_id=run_id, result_type=result_type)
    assert results.outputs[0].get('kind') == 'DiscoveryAccess'


def test_discovery_scan_results_list_command_noresponse(mocker):
    mocker.patch.object(client, 'discovery_scan_results_list',
                        return_value=util_load_json('test_data/discovery_scan_results_list_empty_resp.json'))
    run_id = 'f5ac176243062b2b14c1a75a6e446973636f7665727952756e'
    result_type = 'NoResponse'
    results = discovery_scan_results_list_command(client, run_id=run_id, result_type=result_type)
    assert results.outputs[0].get('count') == 0


def test_discovery_scan_results_list_command_dropped(mocker):
    mocker.patch.object(client, 'discovery_scan_results_list',
                        return_value=util_load_json('test_data/discovery_scan_results_list_dropped_resp.json'))
    run_id = 'f5ac176243062b2b14c1a75a6e446973636f7665727952756e'
    result_type = 'Dropped'
    limit = 5
    results = discovery_scan_results_list_command(client, run_id=run_id, result_type=result_type, limit=limit)
    assert results.outputs[0].get('next_offset') == 5


def test_discovery_search_command_ip_success(mocker):
    mocker.patch.object(client, 'discovery_search',
                        return_value=util_load_json('test_data/discovery_search_single_success_192.168.11.1_resp.json'))
    kind = 'Host'
    ip = '192.168.11.1'
    results = discovery_search_command(client, kind=kind, ip=ip)
    assert results.outputs.get('data')[0].get('hostname') == 'agent-id-pcfdev-0'


def test_discovery_search_command_ip_fail(mocker):
    mocker.patch.object(client, 'discovery_search',
                        return_value=util_load_json('test_data/discovery_search_fail_192.168.11.1_resp.json'))
    kind = 'SNMPManagedDevice'
    ip = '192.168.11.1'
    results = discovery_search_command(client, kind=kind, ip=ip)
    assert results.outputs.get('count') == 0


def test_discovery_search_command_hostname_multiple(mocker):
    mocker.patch.object(client, 'discovery_search',
                        return_value=util_load_json('test_data/discovery_search_success_multi_ais-blade_resp.json'))
    kind = 'Host'
    hostname = 'ais-blade'
    results = discovery_search_command(client, kind=kind, hostname=hostname)
    assert results.outputs['data'][1]['local_fqdn'] == 'ais-bladedr-02.calbro.com'


def test_discovery_search_custom_command_empty_query_exception():
    with raises(DemistoException, match='Please specify query parameter'):
        discovery_search_custom_command(client)


def test_discovery_search_command_no_ip_exception():
    with raises(DemistoException, match='Please specify ip or hostname parameter'):
        discovery_search_command(client)


def test_discovery_scan_results_list_command_no_id_exception():
    with raises(DemistoException, match='Please specify run_id parameter'):
        discovery_scan_results_list_command(client)


def test_discovery_search_custom_command_no_response(mocker):
    mocker.patch.object(client, 'discovery_search_custom', return_value=None)
    with raises(DemistoException, match='Search command failed'):
        discovery_search_custom_command(client)


def test_discovery_search_command_no_response(mocker):
    mocker.patch.object(client, 'discovery_search', return_value=None)
    with raises(DemistoException, match='Search command failed'):
        discovery_search_command(client)


def test_discovery_process_status_command_no_response(mocker):
    mocker.patch.object(client, 'discovery_process_status', return_value=None)
    with raises(DemistoException, match='Get status failed'):
        discovery_process_status_command(client)


def test_discovery_scan_status_list_command_no_response(mocker):
    mocker.patch.object(client, 'discovery_scan_status_list', return_value=None)
    with raises(DemistoException, match='Get runs failed'):
        discovery_scan_status_list_command(client)


def test_discovery_scan_summary_command_no_response(mocker):
    mocker.patch.object(client, 'discovery_scan_summary', return_value=None)
    with raises(DemistoException, match='Failed to get scan summary'):
        discovery_scan_summary_command(client)


def test_discovery_scan_results_list_command_no_response(mocker):
    mocker.patch.object(client, 'discovery_scan_results_list', return_value=None)
    with raises(DemistoException, match='Failed to get scan results'):
        discovery_scan_results_list_command(client)


def test_discovery_search_command_ip_host_exception():
    with raises(DemistoException, match='ip and hostname are mutually exclusive. Please specify just one parameter'):
        discovery_search_command(client, ip='192.168.1.1', hostname='host.acme.com')


def test_discovery_search_command_invalid_ip_exception():
    with raises(DemistoException, match='Specified ip address doesn\'t look valid'):
        discovery_search_command(client, ip='host.acme.com')


def test_discovery_search_custom_command_invalid_offset_exception():
    with raises(DemistoException, match='"offset" cannot be specified without "results_id"'):
        discovery_search_custom_command(client, query="SEARCH Host show *", offset=100)
