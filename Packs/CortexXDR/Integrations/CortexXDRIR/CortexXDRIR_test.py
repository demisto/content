import copy
import json

import pytest
from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import Common
from CortexXDRIR import XDR_RESOLVED_STATUS_TO_XSOAR

XDR_URL = 'https://api.xdrurl.com'

''' HELPER FUNCTIONS '''


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def get_incident_by_status(incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                           lte_creation_time=None, gte_creation_time=None, starred=None,
                           starred_incidents_fetch_window=None, status=None, sort_by_modification_time=None,
                           sort_by_creation_time=None, page_number=0, limit=100, gte_creation_time_milliseconds=0):
    """
        The function simulate the client.get_incidents method for the test_fetch_incidents_filtered_by_status
        and for the test_get_incident_list_by_status.
        The function got the status as a string, and return from the json file only the incidents
        that are in the given status.
    """
    incidents_list = load_test_data('./test_data/get_incidents_list.json')['reply']['incidents']
    return [incident for incident in incidents_list if incident['status'] == status]


def get_incident_extra_data_by_status(incident_id, alerts_limit):
    """
        The function simulate the client.get_incident_extra_data method for the test_fetch_incidents_filtered_by_status.
        The function got the incident_id, and return the json file by the incident id.
    """
    if incident_id == '1':
        incident_extra_data = load_test_data('./test_data/get_incident_extra_data.json')
    else:
        incident_extra_data = load_test_data('./test_data/get_incident_extra_data_new_status.json')
    return incident_extra_data['reply']


''' TESTS FUNCTIONS '''


def test_get_incident_list(requests_mock):
    from CortexXDRIR import get_incidents_command, Client

    get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incidents/', json=get_incidents_list_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'incident_id_list': '1 day'
    }
    _, outputs, _ = get_incidents_command(client, args)

    expected_output = {
        'PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)':
            get_incidents_list_response.get('reply').get('incidents')
    }
    assert expected_output == outputs


def test_get_incident_list_by_status(mocker):
    from CortexXDRIR import get_incidents_command, Client

    get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'incident_id_list': '1 day',
        'status': 'under_investigation,new'
    }
    mocker.patch.object(client, 'get_incidents', side_effect=get_incident_by_status)

    _, outputs, _ = get_incidents_command(client, args)

    expected_output = {
        'PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)':
            get_incidents_list_response.get('reply').get('incidents')
    }
    assert expected_output == outputs


@freeze_time("1993-06-17 11:00:00 GMT")
def test_fetch_incidents(requests_mock, mocker):
    from CortexXDRIR import fetch_incidents, Client, sort_all_list_incident_fields
    import copy

    get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')
    raw_incident = load_test_data('./test_data/get_incident_extra_data.json')
    modified_raw_incident = raw_incident['reply']['incident'].copy()
    modified_raw_incident['alerts'] = copy.deepcopy(raw_incident['reply'].get('alerts').get('data'))
    modified_raw_incident['file_artifacts'] = raw_incident['reply'].get('file_artifacts').get('data')
    modified_raw_incident['network_artifacts'] = raw_incident['reply'].get('network_artifacts').get('data')
    modified_raw_incident['mirror_direction'] = 'In'
    modified_raw_incident['mirror_instance'] = 'MyInstance'
    modified_raw_incident['last_mirrored_in'] = 740314800000

    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incidents/', json=get_incidents_list_response)
    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/', json=raw_incident)
    mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    modified_raw_incident.get('alerts')[0]['host_ip_list'] = \
        modified_raw_incident.get('alerts')[0].get('host_ip').split(',')

    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance')
    sort_all_list_incident_fields(modified_raw_incident)

    assert len(incidents) == 2
    assert incidents[0]['name'] == "XDR Incident 1 - 'Local Analysis Malware' generated by XDR Agent detected on host" \
                                   " AAAAA involving user Administrator"

    if 'network_artifacts' not in json.loads(incidents[0]['rawJSON']):
        assert False
    assert json.loads(incidents[0]['rawJSON']).pop('last_mirrored_in')
    assert incidents[0]['rawJSON'] == json.dumps(modified_raw_incident)


@freeze_time("1993-06-17 11:00:00 GMT")
def test_fetch_incidents_filtered_by_status(requests_mock, mocker):
    """
    Given:
        - List of fetched incidents
    When
        - Running fetch_incident with a given list of statuses to fetch
    Then
        - Verify the returned result is as we expected
    """
    from CortexXDRIR import fetch_incidents, Client

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    mocker.patch.object(client, 'get_incidents', side_effect=get_incident_by_status)
    mocker.patch.object(client, 'get_incident_extra_data', side_effect=get_incident_extra_data_by_status)

    statuses_to_fetch = ['under_investigation', 'new']

    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', statuses=statuses_to_fetch)

    assert len(incidents) == 2
    assert incidents[0]['name'] == "XDR Incident 1 - 'Local Analysis Malware' generated by XDR Agent detected on host " \
                                   "AAAAA involving user Administrator"
    assert incidents[1]['name'] == "XDR Incident 2 - 'Local Analysis Malware' generated by XDR Agent detected on host " \
                                   "BBBBB involving user Administrator"

    raw_json = json.loads(incidents[0]['rawJSON'])
    assert raw_json['status'] == 'under_investigation'

    raw_json = json.loads(incidents[1]['rawJSON'])
    assert raw_json['status'] == 'new'


def return_extra_data_result(*args):
    if args[1].get('incident_id') == '2':
        raise Exception("Rate limit exceeded")
    else:
        incident_from_extra_data_command = load_test_data('./test_data/incident_example_from_extra_data_command.json')
        return {}, {}, {"incident": incident_from_extra_data_command}


@freeze_time("1993-06-17 11:00:00 GMT")
def test_fetch_incidents_with_rate_limit_error(requests_mock, mocker):
    """
    Given:
        - a Rate limit error occurs in the second call for 'get_extra_data_command'
    When
        - running fetch_incidents command
    Then
        - the first successful incident is being created
        - the second incident is saved for the next run
    """
    from CortexXDRIR import fetch_incidents, Client, sort_all_list_incident_fields
    get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')
    raw_incident = load_test_data('./test_data/get_incident_extra_data.json')
    modified_raw_incident = raw_incident['reply']['incident'].copy()
    modified_raw_incident['alerts'] = raw_incident['reply'].get('alerts').get('data')
    modified_raw_incident['file_artifacts'] = raw_incident['reply'].get('file_artifacts').get('data')
    modified_raw_incident['network_artifacts'] = raw_incident['reply'].get('network_artifacts').get('data')
    modified_raw_incident['mirror_direction'] = 'In'
    modified_raw_incident['mirror_instance'] = 'MyInstance'
    modified_raw_incident['last_mirrored_in'] = 740314800000

    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incidents/', json=get_incidents_list_response)
    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/', json=raw_incident)

    mocker.patch('CortexXDRIR.get_incident_extra_data_command', side_effect=return_extra_data_result)

    mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance')
    sort_all_list_incident_fields(modified_raw_incident)

    assert len(incidents) == 1  # because the second one raised a rate limit error
    assert incidents[0]['name'] == "XDR Incident 1 - 'Local Analysis Malware' generated by XDR Agent detected on host " \
                                   "AAAAA involving user Administrator"
    incidents_from_previous_run = next_run.get('incidents_from_previous_run')
    assert incidents_from_previous_run
    assert len(incidents_from_previous_run) == 1
    assert incidents_from_previous_run[0].get('incident_id') == '2'
    if 'network_artifacts' not in json.loads(incidents[0]['rawJSON']):
        assert False
    assert incidents[0]['rawJSON'] == json.dumps(modified_raw_incident)


def test_get_incident_extra_data(requests_mock):
    from CortexXDRIR import get_incident_extra_data_command, Client

    get_incident_extra_data_response = load_test_data('./test_data/get_incident_extra_data_host_id_array.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/',
                       json=get_incident_extra_data_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'incident_id': '1'
    }
    _, outputs, _ = get_incident_extra_data_command(client, args)

    expected_incident = get_incident_extra_data_response.get('reply').get('incident')
    excepted_alert_modified = get_incident_extra_data_response.get('reply').get('alerts').get('data').copy()

    excepted_alert_modified[0]['host_ip_list'] = excepted_alert_modified[0].get('host_ip').split(',')

    expected_incident.update({
        'alerts': excepted_alert_modified,
        'network_artifacts': get_incident_extra_data_response.get('reply').get('network_artifacts').get('data', []),
        'file_artifacts': get_incident_extra_data_response.get('reply').get('file_artifacts').get('data')
    })

    expected_output = {
        'PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)': expected_incident,
        Common.File.CONTEXT_PATH: [
            {
                'Name': 'wildfire-test-pe-file.exe',
                'SHA256': '8d5aec85593c85ecdc8d5ac601e163a1cc26d877f88c03e9e0e94c9dd4a38fca'
            }
        ],
        'Process(val.Name && val.Name == obj.Name)': [
            {
                'Name': 'wildfire-test-pe-file.exe',
                'CommandLine': '"C:\\Users\\Administrator\\Downloads\\wildfire-test-pe-file.exe"',
                'Hostname': 'AAAAAA'
            }
        ],
        'Endpoint(val.Hostname==obj.Hostname)': [{'Hostname': 'AAAAAA', 'ID': '1234'}]
    }
    assert expected_output == outputs


class TestFetchStarredIncident:

    def test_get_starred_incident_list(self, requests_mock):
        from CortexXDRIR import get_incidents_command, Client

        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')
        requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incidents/', json=get_incidents_list_response)

        client = Client(
            base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
        args = {
            'incident_id_list': '1 day',
            'starred': True,
            'starred_incidents_fetch_window': '3 days'
        }
        _, outputs, _ = get_incidents_command(client, args)

        assert outputs['PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)'][0]['starred'] is True

    def test_get_starred_incident_list_with_limit(self, mocker):
        """
        Given:
            - List of two starred incidents to fetch
        When
            - Running starred fetch_incident with limit of 1
        Then
            - Verify the returned result is as we expected and the fetch incident is getting new incident in each call.
        """
        from CortexXDRIR import get_incidents_command, Client
        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')
        request_side_effect = [{'reply': {'incidents': [get_incidents_list_response['reply']['incidents'][0]]}},
                               {'reply': {'incidents': [get_incidents_list_response['reply']['incidents'][0],
                                                        get_incidents_list_response['reply']['incidents'][1]]}}]
        mocker.patch.object(Client, '_http_request', side_effect=request_side_effect)
        mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
        getLastRun_side_effect = [{'fetched_starred_incidents': {}},
                                  {'fetched_starred_incidents': {'3': True}}]
        mocker.patch.object(demisto, 'getLastRun', side_effect=getLastRun_side_effect)

        client = Client(
            base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
        args = {
            'incident_id_list': '1 day',
            'starred': True,
            'limit': 1,
            'starred_incidents_fetch_window': '3 days'
        }
        _, outputs, _ = get_incidents_command(client, args)
        res = outputs['PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)']
        assert len(res) == 1
        assert res[0]['incident_id'] == '3'

        _, outputs, _ = get_incidents_command(client, args)
        res = outputs['PaloAltoNetworksXDR.Incident(val.incident_id==obj.incident_id)']
        assert len(res) == 1
        assert res[0]['incident_id'] == '4'

    def test_fetch_only_starred_incidents(self, mocker):
        """
        Given:
            - List of fetched incidents
        When
            - Running fetch_incident with "only fetch starred incidents" flag
        Then
            - Verify the returned result is as we expected. First fetch two starred incidents are fetched and on second fetch,
            (same fetch window) incidents are filtered out since they have been fetched already.
        """
        from CortexXDRIR import fetch_incidents, Client

        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')
        last_run_obj = {}
        no_incident_mock_response = {}
        mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})
        mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
        mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
        mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
        mocker.patch('CortexXDRIR.get_incident_extra_data_command', side_effect=return_extra_data_result)

        request_side_effect = [get_incidents_list_response,
                               no_incident_mock_response,
                               no_incident_mock_response,
                               no_incident_mock_response]
        mocker.patch.object(Client, '_http_request', side_effect=request_side_effect)

        client = Client(
            base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
        next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', last_run_obj.get('next_run'),
                                              starred=True,
                                              starred_incidents_fetch_window='3 days')
        assert len(incidents) == 2
        assert incidents[0]['name'] == "XDR Incident 3 - 'Local Analysis Malware' generated by XDR Agent detected on host" \
                                       " AAAAA involving user Administrator"

        last_run_obj = {'next_run': next_run,
                        'fetched_starred_incidents': {'3': True, '4': True}
                        }
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_obj)

        next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', last_run_obj.get('next_run'),
                                              starred=True,
                                              starred_incidents_fetch_window='3 days')

        assert not incidents


def test_get_tenant_info(requests_mock):
    from CortexXDRIR import get_tenant_info_command, Client

    tenant_info_response = load_test_data('./test_data/get_tenant_info.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/system/get_tenant_info/', json=tenant_info_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1/', verify=False, timeout=120, proxy=False)
    expected_output = tenant_info_response.get('reply')
    response = get_tenant_info_command(client)
    assert response.outputs == expected_output


def test_insert_parsed_alert(requests_mock):
    from CortexXDRIR import insert_parsed_alert_command, Client

    insert_alerts_response = load_test_data('./test_data/create_alerts.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/alerts/insert_parsed_alerts/', json=insert_alerts_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        "product": "VPN & Firewall-1",
        "vendor": "Check Point",
        "local_ip": "192.168.1.254",
        "local_port": "35398",
        "remote_ip": "0.0.0.0",
        "remote_port": "0",
        "event_timestamp": "1543270652000",
        "severity": "Low",
        "alert_name": "Alert Name Example",
        "alert_description": "Alert Description"
    }

    readable_output, outputs, _ = insert_parsed_alert_command(client, args)
    assert outputs is None
    assert readable_output == 'Alert inserted successfully'


def test_insert_cef_alerts(requests_mock):
    from CortexXDRIR import insert_cef_alerts_command, Client

    insert_cef_alerts_response = load_test_data('./test_data/insert_cef_alerts.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/alerts/insert_cef_alerts/', json=insert_cef_alerts_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    args = {
        'cef_alerts': [
            'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|microsoft-ds|Unknown|act=AcceptdeviceDirection=0 '
            'rt=1569477512000 spt=56957 dpt=445 cs2Label=Rule Name cs2=ADPrimery '
            'layer_name=FW_Device_blackened Securitylayer_uuid=07693fc7-1a5c-4f31-8afe-77ae96c71b8c match_id=1806 '
            'parent_rule=0rule_action=Accept rule_uid=8e45f36b-d106-4d81-a1f0-9d1ed9a6be5c ifname=bond2logid=0 '
            'loguid={0x5d8c5388,0x61,0x29321fac,0xc0000022} origin=1.1.1.1originsicname=CN=DWdeviceBlackend,'
            'O=Blackend sequencenum=363 version=5dst=1.1.1.1 inzone=External outzone=Internal product=VPN-1 & '
            'FireWall-1 proto=6service_id=microsoft-ds src=1.1.1.1',

            'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|Log|Unknown|act=AcceptdeviceDirection=0 '
            'rt=1569477501000 spt=63088 dpt=5985 cs2Label=Rule Namelayer_name=FW_Device_blackened Securitylayer_'
            'uuid=07693fc7-1a5c-4f31-8afe-77ae96c71b8c match_id=8899 parent_rule=0rule_action=Accept rule_'
            'uid=ae987933-82c0-470f-ab1c-1ad552c82369conn_direction=Internal ifname=bond1.12 '
            'logid=0loguid={0x5d8c537d,0xbb,0x29321fac,0xc0000014} origin=1.1.1.1originsicname=CN=DWdeviceBlackend,'
            'O=Blackend sequencenum=899 version=5dst=1.1.1.1 product=VPN-1 & FireWall-1 proto=6 src=1.1.1.1'
        ]
    }

    readable_output, _, _ = insert_cef_alerts_command(client, args)

    assert readable_output == 'Alerts inserted successfully'


def test_sort_all_list_incident_fields():
    """
    Given:
        -  A raw incident
    When
        - running sort_all_list_incident_fields on it
    Then
        - the list fields (alerts for example) are sorted
    """
    from CortexXDRIR import sort_all_list_incident_fields
    raw_incident = load_test_data('test_data/raw_fetched_incident.json')
    sort_all_list_incident_fields(raw_incident)
    assert raw_incident.get('alerts')[0].get('alertid') == "42"
    assert raw_incident.get('alerts')[1].get('alertid') == "55"
    assert raw_incident.get('alerts')[2].get('alertid') == "60"

    assert raw_incident.get('hosts')[0] == 'HOST1'
    assert raw_incident.get('hosts')[1] == 'HOST2'

    assert raw_incident.get('file_artifacts')[0].get('filename') == 'file.exe'
    assert raw_incident.get('file_artifacts')[1].get('filename') == 'file2.exe'


def test_get_mapping_fields_command():
    """
    Given:
        -  nothing
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping.
    """
    from CortexXDRIR import get_mapping_fields_command
    expected_mapping = {"Cortex XDR Incident": {
        "status": "Current status of the incident: \"new\",\"under_"
                  "investigation\",\"resolved_known_issue\","
                  "\"resolved_duplicate\",\"resolved_false_positive\","
                  "\"resolved_true_positive\",\"resolved_security_testing\",\"resolved_other\"",
        "assigned_user_mail": "Email address of the assigned user.",
        "assigned_user_pretty_name": "Full name of the user assigned to the incident.",
        "resolve_comment": "Comments entered by the user when the incident was resolved.",
        "manual_severity": "Incident severity assigned by the user. This does not "
                           "affect the calculated severity low medium high"
    }}
    res = get_mapping_fields_command()
    assert expected_mapping == res.extract_mapping()


def test_get_remote_data_command_should_update(requests_mock, mocker):
    """
    Given:
        -  an XDR client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - a raw incident (get-extra-data results)
    When
        - running get_remote_data_command
    Then
        - the mirrored_object in the GetRemoteDataResponse is the same as the modified raw incident
        - the entries in the GetRemoteDataResponse in empty
    """
    from CortexXDRIR import get_remote_data_command, Client, sort_all_list_incident_fields
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': 0
    }
    raw_incident = load_test_data('./test_data/get_incident_extra_data.json')
    expected_modified_incident = raw_incident['reply']['incident'].copy()
    expected_modified_incident['alerts'] = copy.deepcopy(raw_incident['reply'].get('alerts').get('data'))
    expected_modified_incident['network_artifacts'] = raw_incident['reply'].get('network_artifacts').get('data')
    expected_modified_incident['file_artifacts'] = raw_incident['reply'].get('file_artifacts').get('data')
    expected_modified_incident['id'] = expected_modified_incident.get('incident_id')
    expected_modified_incident['assigned_user_mail'] = ''
    expected_modified_incident['assigned_user_pretty_name'] = ''
    expected_modified_incident['in_mirror_error'] = ''
    del expected_modified_incident['creation_time']

    expected_modified_incident.get('alerts')[0]['host_ip_list'] = \
        expected_modified_incident.get('alerts')[0].get('host_ip').split(',')

    # make sure get-extra-data is returning an incident
    mocker.patch('CortexXDRIR.get_last_mirrored_in_time', return_value=0)
    mocker.patch('CortexXDRIR.check_if_incident_was_modified_in_xdr', return_value=True)

    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/', json=raw_incident)
    response = get_remote_data_command(client, args)
    sort_all_list_incident_fields(expected_modified_incident)

    assert response.mirrored_object == expected_modified_incident
    assert response.entries == []


def test_get_remote_data_command_with_rate_limit_exception(mocker):
    """
    Given:
        -  an XDR client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - a Rate limit exception is raises from get_extra_data_command method
    When
        - running get_remote_data_command
    Then
        - an "API rate limit" error is thrown so that the server will stop the sync loop and will resume from the last
        incident.
    """
    from CortexXDRIR import get_remote_data_command, Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': 0
    }

    mocker.patch.object(demisto, 'results')
    mocker.patch('CortexXDRIR.get_incident_extra_data_command', side_effect=Exception("Rate limit exceeded"))
    with pytest.raises(SystemExit):
        _ = get_remote_data_command(client, args)

    assert demisto.results.call_args[0][0].get('Contents') == "API rate limit"


def test_get_remote_data_command_should_not_update(requests_mock, mocker):
    """
    Given:
        -  an XDR client
        - arguments (id and lastUpdate time set to a higher than incident modification time)
        - a raw incident (get-extra-data results)
    When
        - running get_remote_data_command
    Then
        - returns an empty dict
    """
    from CortexXDRIR import get_remote_data_command, Client, sort_all_list_incident_fields
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': '2020-07-31T00:00:00Z'
    }
    raw_incident = load_test_data('./test_data/get_incident_extra_data.json')
    expected_modified_incident = {
        'id': 1,
        'in_mirror_error': ''
    }
    sort_all_list_incident_fields(expected_modified_incident)

    # make sure get-extra-data is returning an incident
    mocker.patch('CortexXDRIR.get_last_mirrored_in_time', return_value=0)
    mocker.patch('CortexXDRIR.check_if_incident_was_modified_in_xdr', return_value=False)

    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/', json=raw_incident)

    response = get_remote_data_command(client, args)
    assert response.mirrored_object == expected_modified_incident
    assert response.entries == []


@pytest.mark.parametrize(argnames='incident_status', argvalues=XDR_RESOLVED_STATUS_TO_XSOAR.keys())
def test_get_remote_data_command_should_close_issue(requests_mock, mocker, incident_status):
    """
    Given:
        -  an XDR client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - a raw incident (get-extra-data results) indicating the incident was closed on XDR side
    When
        - running get_remote_data_command
    Then
        - the mirrored_object in the GetRemoteDataResponse is the same as the modified raw incident
        - the entries in the GetRemoteDataResponse holds the closing entry
    """
    import copy
    from CortexXDRIR import get_remote_data_command, Client, sort_all_list_incident_fields
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': 0
    }
    raw_incident = load_test_data('./test_data/get_incident_extra_data.json')
    raw_incident['reply']['incident']['status'] = incident_status
    raw_incident['reply']['incident']['resolve_comment'] = 'Handled'

    close_notes_prefix = 'Known Issue.\n' if incident_status == 'resolved_known_issue' else ''
    close_notes = f'{close_notes_prefix}Handled'

    expected_modified_incident = raw_incident['reply']['incident'].copy()
    expected_modified_incident['alerts'] = copy.deepcopy(raw_incident['reply'].get('alerts').get('data'))
    expected_modified_incident['network_artifacts'] = raw_incident['reply'].get('network_artifacts').get('data')
    expected_modified_incident['file_artifacts'] = raw_incident['reply'].get('file_artifacts').get('data')
    expected_modified_incident['id'] = expected_modified_incident.get('incident_id')
    expected_modified_incident['assigned_user_mail'] = ''
    expected_modified_incident['assigned_user_pretty_name'] = ''
    expected_modified_incident['closeReason'] = XDR_RESOLVED_STATUS_TO_XSOAR[incident_status]
    expected_modified_incident['closeNotes'] = close_notes
    expected_modified_incident['in_mirror_error'] = ''
    del expected_modified_incident['creation_time']
    expected_modified_incident.get('alerts')[0]['host_ip_list'] = \
        expected_modified_incident.get('alerts')[0].get('host_ip').split(',')

    expected_closing_entry = {
        'Type': 1,
        'Contents': {
            'dbotIncidentClose': True,
            'closeReason': XDR_RESOLVED_STATUS_TO_XSOAR[incident_status],
            'closeNotes': close_notes
        },
        'ContentsFormat': 'json'
    }

    # make sure get-extra-data is returning an incident
    mocker.patch('CortexXDRIR.get_last_mirrored_in_time', return_value=0)
    mocker.patch('CortexXDRIR.check_if_incident_was_modified_in_xdr', return_value=True)

    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/', json=raw_incident)

    response = get_remote_data_command(client, args)
    sort_all_list_incident_fields(expected_modified_incident)

    assert response.mirrored_object == expected_modified_incident
    assert expected_closing_entry in response.entries


def test_get_remote_data_command_sync_owners(requests_mock, mocker):
    """
    Given:
        -  an XDR client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - a raw incident (get-extra-data results) with assigned mail moo@demisto.com
    When
        - running get_remote_data_command
    Then
        - the mirrored_object in the GetRemoteDataResponse is the same as the modified raw incident with the equivalent
        owner of the assigned mail
        - the entries in the GetRemoteDataResponse in empty
    """
    from CortexXDRIR import get_remote_data_command, Client, sort_all_list_incident_fields
    import copy
    mocker.patch.object(demisto, 'params', return_value={"sync_owners": True})
    mocker.patch.object(demisto, 'findUser', return_value={"email": "moo@demisto.com", 'username': 'username'})
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': 0
    }
    raw_incident = load_test_data('./test_data/get_incident_extra_data.json')
    raw_incident['reply']['incident']['assigned_user_mail'] = 'moo@demisto.com'

    expected_modified_incident = raw_incident['reply']['incident'].copy()
    expected_modified_incident['alerts'] = copy.deepcopy(raw_incident['reply'].get('alerts').get('data'))
    expected_modified_incident['network_artifacts'] = raw_incident['reply'].get('network_artifacts').get('data')
    expected_modified_incident['file_artifacts'] = raw_incident['reply'].get('file_artifacts').get('data')
    expected_modified_incident['id'] = expected_modified_incident.get('incident_id')
    expected_modified_incident['assigned_user_mail'] = 'moo@demisto.com'
    expected_modified_incident['assigned_user_pretty_name'] = None
    expected_modified_incident['owner'] = 'username'
    expected_modified_incident['in_mirror_error'] = ''
    del expected_modified_incident['creation_time']
    expected_modified_incident.get('alerts')[0]['host_ip_list'] = \
        expected_modified_incident.get('alerts')[0].get('host_ip').split(',')

    # make sure get-extra-data is returning an incident
    mocker.patch('CortexXDRIR.get_last_mirrored_in_time', return_value=0)
    mocker.patch('CortexXDRIR.check_if_incident_was_modified_in_xdr', return_value=True)

    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incident_extra_data/', json=raw_incident)
    response = get_remote_data_command(client, args)
    sort_all_list_incident_fields(expected_modified_incident)

    assert response.mirrored_object == expected_modified_incident
    assert response.entries == []


def test_get_modified_remote_data_command(requests_mock):
    """
    Given:
        - an XDR client
        - arguments - lastUpdate time
        - raw incidents (result of client.get_incidents)
    When
        - running get_modified_remote_data_command
    Then
        - the method is returning a list of incidents IDs that were modified
    """
    from CortexXDRIR import get_modified_remote_data_command, Client

    get_incidents_list_response = load_test_data('./test_data/get_incidents_list.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/get_incidents/', json=get_incidents_list_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'lastUpdate': '2020-11-18T13:16:52.005381+02:00'
    }

    response = get_modified_remote_data_command(client, args)

    assert response.modified_incident_ids == ['1', '2']


def test_get_contributing_event_command(requests_mock):
    from CortexXDRIR import get_contributing_event_command, Client

    contributing_events = load_test_data('./test_data/contributing_events.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/alerts/get_correlation_alert_data/', json=contributing_events)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        "alert_ids": "[1111]",
    }

    response = get_contributing_event_command(client, args)

    assert response.outputs[0].get('alertID') == args.get('alert_ids').strip('[]')
    assert len(response.outputs[0].get('events')) == 1


def test_replace_featured_field_command(requests_mock):
    from CortexXDRIR import replace_featured_field_command, Client

    replace_featured_field = load_test_data('./test_data/replace_featured_field.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/featured_fields/replace_ad_groups', json=replace_featured_field)
    expected_response = {
        'fieldType': 'ad_groups',
        'fields': [
            {'value': 'new value', 'comment': 'this is a comment', 'type': 'ou'},
            {'value': 'one new value', 'comment': '', 'type': ''}
        ]
    }

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        "ad_type": "[\"ou\"]",
        "comments": "[\"this is a comment\"]",
        "field_type": "ad_groups",
        "values": "[\"new value\", \"one new value\"]",
    }

    response = replace_featured_field_command(client, args)

    assert response.outputs == expected_response
    assert len(response.outputs.get('fields')) == 2


def test_failure_to_update_incident():
    from CortexXDRIR import update_incident_command, Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    with pytest.raises(ValueError, match="Can't provide both assignee_email/assignee_name and unassign_user"):
        update_incident_command(client=client, args={'unassign_user': 'true', 'assigned_user_mail': 'user', 'status': 'new'})


def test_update_incident(requests_mock):
    from CortexXDRIR import update_incident_command, Client

    update_incident_response = load_test_data('./test_data/update_incident.json')
    requests_mock.post(f'{XDR_URL}/public_api/v1/incidents/update_incident/', json=update_incident_response)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'incident_id': '1',
        'status': 'new',
        'add_comment': 'new comment',
    }
    readable_output, outputs, _ = update_incident_command(client, args)

    assert outputs is None
    assert readable_output == 'Incident 1 has been updated'


@pytest.mark.parametrize('incident_changed, delta',
                         [(True, {'CortexXDRIRstatus': 'investigating'}),
                          (False, {})])
def test_update_remote_system_command(incident_changed, delta):
    from CortexXDRIR import update_remote_system_command, Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    data = {'CortexXDRIRstatus': 'uninvestigated'}
    expected_remote_id = 'remote_id'
    args = {'remoteId': expected_remote_id, 'data': data, 'entries': [], 'incidentChanged': incident_changed,
            'delta': delta,
            'status': 2,
            }
    actual_remote_id = update_remote_system_command(client, args)
    assert actual_remote_id == expected_remote_id
