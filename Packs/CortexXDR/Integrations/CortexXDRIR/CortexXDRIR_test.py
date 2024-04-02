import copy
import json

import pytest
from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import urljoin, DemistoException
from CoreIRApiModule import XDR_RESOLVED_STATUS_TO_XSOAR
from CortexXDRIR import XSOAR_TO_XDR, XDR_TO_XSOAR
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


@freeze_time("1993-06-17 11:00:00 GMT")
def test_fetch_incidents(requests_mock, mocker):
    from CortexXDRIR import fetch_incidents, Client, sort_all_list_incident_fields

    raw_incident = load_test_data('./test_data/get_multiple_incidents_extra_data.json').get('reply', {}).get('incidents')[0]
    modified_raw_incident = raw_incident['incident']
    modified_raw_incident['alerts'] = raw_incident.get('alerts').get('data')
    modified_raw_incident['file_artifacts'] = raw_incident.get('file_artifacts').get('data')
    modified_raw_incident['network_artifacts'] = raw_incident.get('network_artifacts').get('data')
    modified_raw_incident['mirror_direction'] = 'In'
    modified_raw_incident['mirror_instance'] = 'MyInstance'
    modified_raw_incident['last_mirrored_in'] = 740314800000

    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=[raw_incident])
    mocker.patch.object(demisto, 'params', return_value={"exclude_fields": False, "mirror_direction": "Incoming"})

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    modified_raw_incident.get('alerts')[0]['host_ip_list'] = \
        modified_raw_incident.get('alerts')[0].get('host_ip').split(',')
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance')
    sort_all_list_incident_fields(modified_raw_incident)
    assert len(incidents) == 1
    assert incidents[0]['name'] == "XDR Incident 1 - desc1"
    assert 'network_artifacts' in json.loads(incidents[0]['rawJSON'])
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
    incident_extra_data_under_investigation = load_test_data('./test_data/get_incident_extra_data_host_id_array.json')\
        .get('reply', {}).get('incidents')[0]
    incident_extra_data_new = load_test_data('./test_data/get_incident_extra_data_new_status.json').get('reply')
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', side_effect=[incident_extra_data_under_investigation,
                                                                                  incident_extra_data_new])
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    statuses_to_fetch = ['under_investigation', 'new']

    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', statuses=statuses_to_fetch)

    assert len(incidents) == 2
    assert incidents[0]['name'] == "XDR Incident 1 - 'Local Analysis Malware' generated by XDR Agent detected on host AAAAAA "\
        "involving user Administrator"
    assert incidents[1]['name'] == "XDR Incident 2 - 'Local Analysis Malware' generated by XDR Agent detected on host " \
                                   "BBBBB involving user Administrator"

    raw_json = json.loads(incidents[0]['rawJSON'])
    assert raw_json['status'] == 'under_investigation'

    raw_json = json.loads(incidents[1]['rawJSON'])
    assert raw_json['status'] == 'new'


def return_extra_data_result(*args, **kwargs):
    raise Exception("Rate limit exceeded")


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
    from CortexXDRIR import fetch_incidents, Client
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', side_effect=return_extra_data_result)
    mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    with pytest.raises(Exception) as e:
        next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance')
    assert str(e.value) == 'Rate limit exceeded'


class TestFetchStarredIncident:

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
        mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
        mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
        client = Client(
            base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
        args = {
            'incident_id_list': '1 day',
            'starred': True,
            'limit': 1,
            'starred_incidents_fetch_window': '3 days',
            'integration_context_brand': 'PaloAltoNetworksXDR'
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

        get_incidents_list_response = load_test_data('./test_data/get_starred_incidents_list.json')['reply']['incidents']
        last_run_obj = {}
        mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})
        mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
        mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
        mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
        mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
        mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
        mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=get_incidents_list_response)
        client = Client(
            base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
        next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', last_run_obj.get('next_run'),
                                              starred=True,
                                              starred_incidents_fetch_window='3 days')
        assert len(incidents) == 2
        assert incidents[0]['name'] == "XDR Incident 3 - 'Local Analysis Malware' generated by XDR Agent detected"\
            " on host AAAAA involving user Administrator"

        last_run_obj = {'next_run': next_run,
                        'fetched_starred_incidents': {'3': True, '4': True}
                        }
        mocker.patch.object(demisto, 'getLastRun', return_value=last_run_obj)


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


@pytest.mark.parametrize('dont_format_sublists', [False, True])
def test_format_sublists_param(dont_format_sublists, mocker):
    """
    Given:
        -  A raw incident
    When
        - running sort_all_list_incident_fields on it with dont_format_sublists
    Then
        - if dont_format_sublists is False, should be formatted, so should have underscore
        - if dont_format_sublists is True, should not be formatted, so should not have underscore
        - Underscre value should always be present
    """
    from CortexXDRIR import sort_all_list_incident_fields
    raw_incident = load_test_data('test_data/raw_fetched_incident.json')
    mocker.patch.object(demisto, 'params', return_value={"dont_format_sublists": dont_format_sublists})

    sort_all_list_incident_fields(raw_incident)
    assert bool(raw_incident.get('alerts')[0].get('alertid')) == (not dont_format_sublists)
    assert raw_incident.get('alerts')[0].get('alert_id')


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
    expected_mapping = {"Cortex XDR Incident Schema": {
        "status": "Current status of the incident: \"new\",\"under_"
                  "investigation\",\"resolved_known_issue\","
                  "\"resolved_duplicate\",\"resolved_false_positive\","
                  "\"resolved_true_positive\",\"resolved_security_testing\",\"resolved_other\"",
        "assigned_user_mail": "Email address of the assigned user.",
        "assigned_user_pretty_name": "Full name of the user assigned to the incident.",
        "resolve_comment": "Comments entered by the user when the incident was resolved.",
        "manual_severity": "Incident severity assigned by the user. This does not "
                           "affect the calculated severity low medium high",
        "close_reason": "The close reason of the XSOAR incident"
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
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=raw_incident['reply'])
    response = get_remote_data_command(client, args)
    sort_all_list_incident_fields(expected_modified_incident)

    assert response.mirrored_object == expected_modified_incident
    assert response.entries == []


def test_get_remote_data_command_with_rate_limit_exception(mocker):
    """
    Given:
        - an XDR client
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
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
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
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=raw_incident['reply'])
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
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=raw_incident['reply'])
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


@freeze_time("1997-10-05 15:00:00 GMT")
def test_fetch_incidents_extra_data(requests_mock, mocker):
    """
    Given:
        - List of fetched incidents.
        - List of multiple extra of incidents data response
    When
        - Running fetch_incident
    Then
        - Verify the returned result is as we expected
    """
    from CortexXDRIR import fetch_incidents, Client
    raw_multiple_extra_data = load_test_data('./test_data/get_multiple_incidents_extra_data.json')
    raw_all_alerts_incident_2 = load_test_data('./test_data/get_extra_data_all_alerts.json').get('reply', {}).get('incidents', [])

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
    mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})
    mocker.patch.object(Client, 'get_incident_extra_data', return_value=raw_all_alerts_incident_2)
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=raw_multiple_extra_data.get('reply', {})
                        .get('incidents', []))
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=2)
    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance')
    assert len(incidents) == 2
    assert incidents[0]['name'] == 'XDR Incident 1 - desc1'
    assert json.loads(incidents[0]['rawJSON']).get('incident_id') == '1'
    assert json.loads(incidents[1]['rawJSON']).get('incident_id') == '2'


def test_get_incident_extra_data(mocker):
    """
    Given:
        -  an XDR client
        - arguments (id)
    When
        - Running get_incident_extra_data_command
    Then
        - Verify the returned result is as we expected
    """
    from CortexXDRIR import get_incident_extra_data_command, Client

    get_incident_extra_data_response = load_test_data('./test_data/get_incident_extra_data_host_id_array.json')\
        .get('reply', {}).get('incidents', [])
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=get_incident_extra_data_response)
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=2)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'incident_id': '1'
    }
    _, outputs, raw_incident = get_incident_extra_data_command(client, args)

    expected_output = {
        'Process(val.Name && val.Name == obj.Name)': [
            {
                'Name': 'wildfire-test-pe-file.exe',
                'CommandLine': '"C:\\Users\\Administrator\\Downloads\\wildfire-test-pe-file.exe"',
                'Hostname': 'AAAAAA'
            }
        ],
        'Endpoint(val.Hostname==obj.Hostname)': [{'Hostname': 'AAAAAA', 'ID': '1234'}]
    }
    assert raw_incident == get_incident_extra_data_response[0]
    assert expected_output['Process(val.Name && val.Name == obj.Name)'] == outputs['Process(val.Name && val.Name == obj.Name)']
    assert expected_output['Endpoint(val.Hostname==obj.Hostname)'] == outputs['Endpoint(val.Hostname==obj.Hostname)']


@pytest.mark.parametrize('custom_mapping, expected_resolved_status',
                         [
                             ("Known Issue=Other,Duplicate Incident=Duplicate,False Positive=False Positive,"
                              "True Positive=Resolved,Security Testing=Other,Other=Other",
                              ["Other", "Duplicate", "False Positive", "Resolved", "Other", "Other", "Resolved"]),

                             ("Known Issue=Other,Duplicate Incident=Other,False Positive=False Positive,"
                              "True Positive=Resolved,Security Testing=Other,Other=Other",
                              ["Other", "Other", "False Positive", "Resolved", "Other", "Other", "Resolved"]),

                             ("Duplicate Incident=Other,Security Testing=Other,Other=Other",
                              ["Other", "Other", "False Positive", "Resolved", "Other", "Other", "Resolved"]),

                             # Expecting default mapping to be used when no mapping provided.
                             ("", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             # Expecting default mapping to be used when improper mapping is provided.
                             ("Duplicate=RANDOM1, Other=Random2", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             ("Duplicate Incident=Random3", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             # Expecting default mapping to be used when improper mapping *format* is provided.
                             ("Duplicate Incident=Other False Positive=Other", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             # Expecting default mapping to be used for when improper key-value pair *format* is provided.
                             ("Duplicate Incident=Other, False Positive=Other True Positive=Other",
                              ["Other", "Other", "False Positive", "Resolved", "Security Testing", "Other",
                               "Resolved"]),

                         ],
                         ids=["case-1", "case-2", "case-3", "empty-case", "improper-input-case-1", "improper-input-case-2",
                              "improper-input-case-3", "improper-input-case-4"]
                         )
def test_xdr_to_xsoar_flexible_close_reason_mapping(capfd, mocker, custom_mapping, expected_resolved_status):
    """
    Given:
        - A custom XDR->XSOAR close-reason mapping
        - Expected resolved XSOAR status according to the custom mapping.
    When
        - Handling incoming closing-incident (handle_incoming_closing_incident(...) executed).
    Then
        - The resolved XSOAR statuses match the expected statuses for all possible XDR close-reasons.
    """
    from CortexXDRIR import handle_incoming_closing_incident
    mocker.patch.object(demisto, 'params', return_value={"mirror_direction": "Both",
                                                         "custom_xdr_to_xsoar_close_reason_mapping": custom_mapping})

    all_xdr_close_reasons = XDR_RESOLVED_STATUS_TO_XSOAR.keys()

    for i, xdr_close_reason in enumerate(all_xdr_close_reasons):
        # Mock an xdr incident with "resolved" status.
        incident_data = load_test_data('./test_data/resolved_incident_data.json')
        # Set incident status to be tested close-reason.
        incident_data["status"] = xdr_close_reason

        # Overcoming expected non-empty stderr test failures (Errors are submitted to stderr when improper mapping is provided).
        with capfd.disabled():
            close_entry = handle_incoming_closing_incident(incident_data)
        assert close_entry["Contents"]["closeReason"] == expected_resolved_status[i]


@pytest.mark.parametrize('custom_mapping, direction, should_raise_error',
                         [
                             ("Other=Other,Duplicate=Other,False Positive=False Positive,Resolved=True Positive",
                              XSOAR_TO_XDR, False),

                             ("Known Issue=Other,Duplicate Incident=Duplicate,False Positive=False Positive",
                              XDR_TO_XSOAR, False),

                             ("Duplicate Incident=Random", XSOAR_TO_XDR, True),

                             ("Duplicate=RANDOM1, Other=Random2", XDR_TO_XSOAR, True),
                             # Inverted map provided
                             ("Duplicate=Duplicate Incident", XDR_TO_XSOAR, True),
                             ("Duplicate Incident=Duplicate", XSOAR_TO_XDR, True),
                             # Improper mapping
                             ("Random1, Random2", XDR_TO_XSOAR, True),
                             ("Random1, Random2", XSOAR_TO_XDR, True),

                         ],
                         ids=["case-1", "case-2", "case-3", "case-4", "case-5", "case-6", "case-7", "case-8"]
                         )
def test_test_module(capfd, custom_mapping, direction, should_raise_error):
    """
        Given:
            - mock client with username and api_key (basic auth)
        When:
            - run `test_module` function
        Then:
            - Ensure no error is raised, and return `ok`
        """
    from CortexXDRIR import Client

    # using two different credentials object as they both fields need to be encrypted
    base_url = urljoin("dummy_url", '/public_api/v1')
    proxy = demisto.params().get('proxy')
    verify_cert = not demisto.params().get('insecure', False)

    client = Client(
        base_url=base_url,
        proxy=proxy,
        verify=verify_cert,
        timeout=120,
        params=demisto.params()
    )
    # Overcoming expected non-empty stderr test failures (Errors are submitted to stderr when improper mapping is provided).
    with capfd.disabled():
        if should_raise_error:
            with pytest.raises(DemistoException):
                client.validate_custom_mapping(mapping=custom_mapping, direction=direction)
        else:
            try:
                client.validate_custom_mapping(mapping=custom_mapping, direction=direction)
            except DemistoException as e:
                pytest.fail(f"Unexpected exception raised for input {input}: {e}")


@freeze_time("1997-10-05 15:00:00 GMT")
def test_convert_datetime_to_epoch():
    """
    Given:
      - Datetime object

    When:
      - Calling convert_datetime_to_epoch()

    Then:
      - Returned epoch int matches expected
    """
    from CortexXDRIR import convert_datetime_to_epoch
    from datetime import datetime
    input_datetime = datetime.now()
    assert convert_datetime_to_epoch(input_datetime) == 876063600


@freeze_time("1997-10-05 15:00:00 GMT")
def test_convert_epoch_to_milli():
    """
    Given:
      - Epoch timestamp

    When:
      - Calling convert_epoch_to_milli()

    Then:
      - Returned timestamp matches expected milliseconds
    """
    from CortexXDRIR import convert_epoch_to_milli
    input_epoch = 1577836800
    assert convert_epoch_to_milli(input_epoch) == 1577836800000


@freeze_time("1997-10-05 15:00:00 GMT")
def test_convert_datetime_to_epoch_millis():
    """
    Given:
      - Datetime object

    When:
      - Calling convert_datetime_to_epoch_millis()

    Then:
      - Returned epoch timestamp matches expected milliseconds
    """
    from CortexXDRIR import convert_datetime_to_epoch_millis
    from datetime import datetime
    input_datetime = datetime.now()
    assert convert_datetime_to_epoch_millis(input_datetime) == 876063600


@freeze_time("1997-10-05 15:00:00 GMT")
def test_generate_current_epoch_utc():
    """
    Given: Nothing

    When:
      - Calling generate_current_epoch_utc()

    Then:
      - Returned value is integer epoch timestamp
    """
    from CortexXDRIR import generate_current_epoch_utc
    epoch = generate_current_epoch_utc()
    assert isinstance(epoch, int)
    assert epoch > 876000


def test_generate_key():
    """
    Given: None

    When: Calling generate_key()

    Then: Verify the returned result is as we expected
    """
    from CortexXDRIR import generate_key
    key = generate_key()
    assert len(key) == 128


def test_create_auth():
    """
    Given: Client ID and client secret

    When: Calling create_auth()

    Then: Verify the returned result is as we expected
    """
    from CortexXDRIR import create_auth
    auth = create_auth('client_id')
    assert len(auth) == 3


def test_clear_trailing_whitespace():
    """
    Given:
      - list of dictionary containing a value of String with trailing whitespace

    When:
      - Calling clear_trailing_whitespace()

    Then:
      - Trailing whitespace should be removed
    """
    from CortexXDRIR import clear_trailing_whitespace
    alerts = [{"example": "value  "}]
    actual = clear_trailing_whitespace(alerts)
    assert actual == [{'example': 'value'}]


def test_filter_and_save_unseen_incident_limit_test():
    """
    Given:
      - List of incidents with creation times
      - Last fetch time

    When:
      - Calling filter_and_save_unseen_incident multiple times

    Then:
      - Returns maximum number of incidents per run
    """
    from CortexXDRIR import filter_and_save_unseen_incident
    incident = [{
        "id": "1",
        "creation_time": 1577836800000
    },
        {
        "id": "2",
        "creation_time": 1577836800001
    }]
    assert filter_and_save_unseen_incident(incident, 1, 1) == [{"id": "1", "creation_time": 1577836800000}]


@freeze_time("1997-10-05 15:00:00 GMT")
def test_get_headers(mocker):
    """
    Given:
    - A dictionary of parameters including 'apikey', 'apikey_id', and 'prevent_only'

    When:
    - Calling get_headers with the given parameters

    Then:
    - Returns a dictionary containing the expected headers
    """
    from CortexXDRIR import get_headers
    mocker.patch('secrets.choice', return_value='test')
    # Define the parameters
    params = {
        'apikey': 'test_api_key',
        'apikey_id': 'test_api_key_id',
        'prevent_only': False
    }

    headers = get_headers(params)

    assert len(headers) == 4
    assert headers['x-xdr-nonce'] == 'test' * 64


@freeze_time("1997-10-05 15:00:00 GMT")
def test_get_last_mirrored_in_time_old_incident(mocker):
    """
    Given:
        - An old incident with a lastmirroredintime set

    When:
        - Calling get_last_mirrored_in_time

    Then:
        - Return the timestamp converted from the lastmirroredintime
    """
    from CortexXDRIR import get_last_mirrored_in_time
    demisto_incidents = [{'CustomFields': {'lastmirroredintime': '2020-01-01'}}]
    mocker.patch.object(demisto, 'get_incidents', return_value=demisto_incidents)

    args = {}

    assert get_last_mirrored_in_time(args) == 1577836800000


def test_get_last_mirrored_in_time_new_incident_6_0(mocker):
    """
    Given:
        - A new 6.0 incident with a last_update set

    When:
        - Calling get_last_mirrored_in_time

    Then:
        - Return the timestamp converted from the last_update minus 120 seconds
    """
    from CortexXDRIR import get_last_mirrored_in_time
    mocker.patch.object(demisto, 'get_incidents', return_value=[])
    args = {'last_update': '2020-01-01T00:02:00Z'}

    assert get_last_mirrored_in_time(args) == 1577836800000


def test_incident_modified():
    """
    Given:
        - incident_id
        - last_mirrored_time
        - last_modified_incidents
    When:
        - Calling check_if_incident_was_modified_in_xdr

    Then:
        - Verify the returned result is as we expected
    """
    from CortexXDRIR import check_if_incident_was_modified_in_xdr
    incident_id = "2"
    last_mirrored_time = 1578901000
    last_modified_incidents = {
        "1": 1578900000,
        "2": 1578905000
    }
    assert check_if_incident_was_modified_in_xdr(
        incident_id, last_mirrored_time, last_modified_incidents
    )


def test_create_parsed_alert(mocker):
    """
    Given:
            - product
            - vendor
            - local_ip
            - local_port
            - remote_ip
            - remote_port
            - event_timestamp
            - severity
            - alert_name
            - alert_description
    When:
        - Calling create_parsed_alert().

    Then:
        - Verify the returned result is as we expected
    """
    from CortexXDRIR import create_parsed_alert
    parsed_alert = create_parsed_alert(product='product',
                                       vendor='vendor',
                                       local_ip='1.1.1.1',
                                       local_port='1',
                                       remote_ip='2.2.2.2',
                                       remote_port='2',
                                       event_timestamp="",
                                       severity='high',
                                       alert_name='example',
                                       alert_description='Malicious File')

    assert parsed_alert.get('alert_description') == 'Malicious File'
    assert parsed_alert.get('severity') == 'high'


def test_sync_incoming_incident_owners(mocker):
    """
    Given:
        - incident_data dict with assigned_user_mail

    When:
        - Calling sync_incoming_incident_owners().

    Then:
        - Verify the incident_data result is as we expected.
    """
    from CortexXDRIR import sync_incoming_incident_owners
    incident_data = {'assigned_user_mail': 'www.example@test.com'}
    mocker.patch.object(demisto, 'params', return_value={"sync_owners": True})
    mocker.patch.object(demisto, 'findUser', return_value={"username": "tester"})
    sync_incoming_incident_owners(incident_data)
    assert incident_data.get('owner') == 'tester'


def test_handle_incoming_user_unassignment(mocker):
    """
    Given:
        - incident_data dict with incident_id, owner.

    When:
        - Calling handle_incoming_user_unassignment().

    Then:
        - Verify the returned result is as we expected.
    """
    from CortexXDRIR import handle_incoming_user_unassignment
    incident_data = {'incident_id': '1', 'owner': 'tester'}
    mocker.patch.object(demisto, 'params', return_value={"sync_owners": True})
    handle_incoming_user_unassignment(incident_data)
    assert not incident_data.get('owner')


def test_get_endpoints_by_status_command(mocker):
    """
    Given:
        - incident_data dict with incident_id, owner.

    When:
        - Calling get_endpoints_by_status_command().

    Then:
        - Verify the returned result is as we expected.
    """
    from CortexXDRIR import get_endpoints_by_status_command, Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {'status': ['new', 'in_progress'], 'last_seen_gte': '11', 'last_seen_lte': '1'}
    mocker.patch.object(Client, 'get_endpoints_by_status', return_value=['1', {"endpoint_count": 2}])
    res = get_endpoints_by_status_command(client, args)
    assert res.readable_output == "['new', 'in_progress'] endpoints count: 1"


class TestGetIncidents():

    def test_get_multiple_incidents_extra_data(self, requests_mock, mocker):
        """
        Given: Incidents returned from client.
        When: Running get_multiple_incidents_extra_data.
        Then: Ensure the outputs contain the incidents from the client.
        """
        from CortexXDRIR import Client
        multiple_extra_data = load_test_data('./test_data/get_multiple_incidents_extra_data.json')
        alert_limit = multiple_extra_data['reply']['alerts_limit_per_incident']
        requests_mock.post(f'{XDR_URL}/incidents/get_multiple_incidents_extra_data/', json=multiple_extra_data)
        mocker.patch.object(demisto, 'command', return_value='xdr-get-incident-extra-data')
        mocker.patch.object(Client, '_http_request', return_value=multiple_extra_data)
        client = Client(
            base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
        outputs = Client.get_multiple_incidents_extra_data(client,
                                                           status=['new'],
                                                           starred=True,
                                                           starred_incidents_fetch_window=1575806909185,
                                                           incident_id_list=['1', '2'],
                                                           fields_to_exclude=True)
        assert len(outputs) == len(multiple_extra_data['reply']['incidents'])
        assert outputs[0]['alerts']['total_count'] <= alert_limit
        assert outputs[1]['alerts']['total_count'] <= alert_limit


def test_get_incident_extra_data_incident_not_exist(mocker):
    """
    Given:
        -  an XDR client
        - arguments (id)
    When
        - Running get_incident_extra_data_command
    Then
        - Verify that if the incident id is not found, it returns an error.
    """
    from CortexXDRIR import get_incident_extra_data_command, Client

    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=[])
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=2)

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'incident_id': '1'
    }
    with pytest.raises(DemistoException) as e:
        _, outputs, raw_incident = get_incident_extra_data_command(client, args)
    assert str(e.value) == 'Incident 1 is not found'
