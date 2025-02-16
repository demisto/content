import copy
import json
from unittest.mock import MagicMock, patch

import pytest
from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import CommandResults, urljoin, DemistoException
from CoreIRApiModule import XDR_RESOLVED_STATUS_TO_XSOAR, XSOAR_RESOLVED_STATUS_TO_XDR
from CortexXDRIR import XSOAR_TO_XDR, XDR_TO_XSOAR, get_xsoar_close_reasons, XDR_OPEN_STATUS_TO_XSOAR

XDR_URL = 'https://api.xdrurl.com'

''' HELPER FUNCTIONS '''


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def get_incident_by_status(incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                           lte_creation_time=None, gte_creation_time=None, starred=None,
                           starred_incidents_fetch_window=None, statuses=None, sort_by_modification_time=None,
                           sort_by_creation_time=None, page_number=0, limit=100, gte_creation_time_milliseconds=0):
    """
        The function simulate the client.get_incidents method for the test_fetch_incidents_filtered_by_status
        and for the test_get_incident_list_by_status.
        The function got the status as a string, and return from the json file only the incidents
        that are in the given status.
    """
    incidents_list = load_test_data('./test_data/get_incidents_list.json')['reply']['incidents']
    return [incident for incident in incidents_list if incident['status'] in statuses]


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
    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', exclude_artifacts=False, last_run={})
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
    incident_extra_data_under_investigation = load_test_data(
        './test_data/get_incident_extra_data_host_id_array.json')['reply']['incidents']
    incident_extra_data_new = load_test_data('./test_data/get_incident_extra_data_new_status.json')['reply']['incidents']
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=(
        incident_extra_data_under_investigation + incident_extra_data_new))
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    statuses_to_fetch = ['under_investigation', 'new']

    next_run, incidents = fetch_incidents(
        client, '3 month', 'MyInstance', exclude_artifacts=False, statuses=statuses_to_fetch, last_run={})

    assert len(incidents) == 2
    assert incidents[0]['name'] == "XDR Incident 1 - 'Local Analysis Malware' generated by XDR Agent detected on host AAAAAA " \
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
        next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', exclude_artifacts=False, last_run={})
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
        next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', exclude_artifacts=False,
                                              last_run=last_run_obj.get('next_run', {}),
                                              starred=True,
                                              starred_incidents_fetch_window='3 days')
        assert len(incidents) == 2
        assert incidents[0]['name'] == "XDR Incident 3 - 'Local Analysis Malware' generated by XDR Agent detected" \
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
    assert response.entries[0].get('Contents') == {'dbotIncidentReopen': True}


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
    import sys
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': 0
    }

    mocker.patch('CortexXDRIR.return_error', side_effect=sys.exit)
    mocker.patch('CortexXDRIR.get_incident_extra_data_command', side_effect=Exception("Rate limit exceeded"))
    with pytest.raises(SystemExit):
        _ = get_remote_data_command(client, args)


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


@pytest.mark.parametrize(argnames='incident_status, close_xsoar_incident',
                         argvalues=[(status, close_flag) for status in XDR_RESOLVED_STATUS_TO_XSOAR for close_flag in
                                    [True, False]])
def test_get_remote_data_command_should_close_issue(capfd, requests_mock, mocker, incident_status, close_xsoar_incident):
    """
    Given:
        - an XDR client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - a raw incident (get-extra-data results) indicating the incident was closed on XDR side
    When
        - running get_remote_data_command
    Then
        - If close_xsoar_incident is True, the mirrored_object in the GetRemoteDataResponse holds the closing entry.
        - If close_xsoar_incident is False, the mirrored_object in the GetRemoteDataResponse does not hold the closing entry.
    """
    import copy
    from CortexXDRIR import get_remote_data_command, Client, sort_all_list_incident_fields
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    client._params['close_xsoar_incident'] = close_xsoar_incident
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
    expected_modified_incident['in_mirror_error'] = ''
    del expected_modified_incident['creation_time']
    expected_modified_incident.get('alerts')[0]['host_ip_list'] = \
        expected_modified_incident.get('alerts')[0].get('host_ip').split(',')

    expected_closing_entry = {}
    if close_xsoar_incident:
        expected_modified_incident['closeReason'] = XDR_RESOLVED_STATUS_TO_XSOAR[incident_status]
        expected_modified_incident['closeNotes'] = close_notes

        expected_closing_entry = {
            'Type': 1,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': XDR_RESOLVED_STATUS_TO_XSOAR[incident_status],
                'closeNotes': close_notes
            },
            'ContentsFormat': 'json'
        }

    mocker.patch('CortexXDRIR.get_last_mirrored_in_time', return_value=0)
    mocker.patch('CortexXDRIR.check_if_incident_was_modified_in_xdr', return_value=True)
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=raw_incident['reply'])
    with capfd.disabled():
        response = get_remote_data_command(client, args)
    sort_all_list_incident_fields(expected_modified_incident)

    assert response.mirrored_object == expected_modified_incident

    if close_xsoar_incident:
        assert expected_closing_entry in response.entries
    else:
        assert expected_closing_entry not in response.entries


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
    assert response.entries[0].get('Contents') == {'dbotIncidentReopen': True}


@pytest.mark.parametrize('last_update',
                         ['2020-11-18T13:16:52.005381+02:00',
                          '2024-03-21T17:02:02.000000645Z'])
def test_get_modified_remote_data_command(requests_mock, last_update):
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
        'lastUpdate': last_update
    }

    response, _ = get_modified_remote_data_command(client, args)

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


@pytest.mark.parametrize("data", [
    {'close_reason': 'Resolved', 'status': 'Other'},
    {'CortexXDRIRstatus': 'resolved', 'close_reason': 'Resolved', 'status': 'False Positive'},
    {'status': 'under_investigation'},
    {'status': 'Resolved', 'resolve_comment': 'comment'},
    {'status': 'False Positive', 'resolve_comment': 'comment'}
])
def test_update_remote_system_command_should_not_close_xdr_incident(mocker, data):
    """
    Given:
        - an XDR client with 'close_xdr_incident' set to False.
        - arguments indicating the incident was closed in XSOAR.
    When:
        - running update_remote_system_command with 'close_xdr_incident' set to False.
    Then:
        - the incident in XDR should not be closed.
        - other updates to the incident should still be applied.
    """
    from CortexXDRIR import update_remote_system_command, Client

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False,
        params={'close_xdr_incident': False}
    )

    delta = copy.deepcopy(data)
    expected_remote_id = 'remote_id'

    args = {
        'remoteId': expected_remote_id,
        'data': data,
        'incidentChanged': True,
        'delta': delta,
        'status': 2,
    }

    mock_update_incident_command = mocker.patch("CortexXDRIR.update_incident_command")
    update_remote_system_command(client, args)
    update_args = mock_update_incident_command.call_args[0][1]
    if data.get('status') in XSOAR_RESOLVED_STATUS_TO_XDR:
        assert 'status' not in update_args
        assert 'resolve_comment' not in update_args
    else:
        assert 'status' in update_args
        if data.get('resolve_comment'):
            assert 'resolve_comment' in update_args

    # checks when close_all_alerts is true -> should update only the alerts status
    client._params['close_alerts_in_xdr'] = True
    mock_update_related_alerts = mocker.patch('CortexXDRIR.update_related_alerts')
    update_remote_system_command(client, args)

    if mock_update_related_alerts.called:
        update_args = mock_update_related_alerts.call_args[0][1]
        assert 'status' in update_args


def test_update_remote_system_command_incident_changed_but_no_delta(mocker):
    """
    Given:
        - an XDR client
        - arguments indicating the incident was changed in XSOAR but no delta found
    When:
        - running update_remote_system_command
    Then:
        - no update will happen when incident was changed in XSOAR but no delta found
    """
    from CortexXDRIR import update_remote_system_command, Client

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False,
        params={'close_xdr_incident': False}
    )

    expected_remote_id = 'remote_id'
    args = {
        'remoteId': expected_remote_id,
        'data': {},
        'entries': [],
        'incidentChanged': True,
        'delta': {},
        'status': 2,
    }

    mock_get_update_args = mocker.patch('CoreIRApiModule.get_update_args')
    incident_id = update_remote_system_command(client, args)
    assert mock_get_update_args.call_count == 0
    assert incident_id == expected_remote_id


def test_update_remote_system_command_closing_alerts_and_including_resolve_comment(mocker):
    """
    Given:
        - An XDR client configured with parameters for closing alerts in XDR.
        - Expected remote incident ID and arguments representing a resolved XSOAR incident with a delta
         containing close reason and resolve comment.

    When:
        - Calling update_remote_system_command with the provided client and arguments.

    Then:
        - The get_update_args function should be called once to prepare the update arguments.
        - The update_related_alerts function should be called once to handle the closure of related alerts.
        - The returned incident ID should match the expected remote incident ID.
    """
    from CortexXDRIR import update_remote_system_command, Client

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False,
        params={'close_alerts_in_xdr': True}
    )

    expected_remote_id = 'remote_id'
    args = {
        'remoteId': expected_remote_id,
        'data': {'CortexXDRIRstatus': 'resolved', 'close_reason': 'Resolved', 'status': 'test'},
        'entries': [],
        'incidentChanged': True,
        'delta': {'close_reason': 'resolved', 'resolve_comment': '', 'status': 'resolved_true_positive'},
        'status': 2,
    }

    mocker.patch("CortexXDRIR.update_incident_command")
    mock_get_update_args = mocker.patch('CortexXDRIR.get_update_args', return_value=args.get('delta'))
    mock_update_related_alerts = mocker.patch('CortexXDRIR.update_related_alerts')
    incident_id = update_remote_system_command(client, args)
    assert mock_get_update_args.call_count == 1
    assert mock_update_related_alerts.call_count == 1
    assert incident_id == expected_remote_id


def test_get_update_args_close_incident_without_status_handler(mocker):
    """
    Given:
        - Arguments indicating that the incident was changed in XSOAR but closed without providing a reason.
    When:
        - Running the 'get_update_args.handle_outgoing_issue_closure' function with the provided arguments.
    Then:
        - The 'get_update_args.handle_outgoing_issue_closure' function should append the 'status' field in the delta
  with the value 'resolved_other'.
    """
    from CoreIRApiModule import get_update_args
    from CommonServerPython import UpdateRemoteSystemArgs

    args = {
        'remoteId': 'remote_id',
        'data': {'closeNotes': 'ancd', 'status': 'test'},
        'entries': [],
        'incidentChanged': True,
        'delta': {'runStatus': '1', 'incident_id': 'remote_id'},
        'status': 2,
    }

    parsed_args = UpdateRemoteSystemArgs(args)
    mocker.patch("CoreIRApiModule.handle_outgoing_incident_owner_sync")
    mocker.patch("CoreIRApiModule.handle_user_unassignment")
    parsed_args_delta = get_update_args(parsed_args)
    assert parsed_args_delta.get('status') == 'resolved_other'


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
    raw_all_alerts_incident_2 = load_test_data('./test_data/get_extra_data_all_alerts.json').get('reply', {})

    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
    mocker.patch.object(demisto, 'params', return_value={"extra_data": True, "mirror_direction": "Incoming"})
    mocker.patch.object(Client, 'get_incident_extra_data', return_value=raw_all_alerts_incident_2)
    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=raw_multiple_extra_data.get('reply', {})
                        .get('incidents', []))
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=2)
    next_run, incidents = fetch_incidents(client, '3 month', 'MyInstance', exclude_artifacts=False, last_run={})
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

    get_incident_extra_data_response = load_test_data('./test_data/get_incident_extra_data_host_id_array.json') \
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
                              ["Other", "Duplicate", "Duplicate", "False Positive", "Resolved", "Other", "Other",
                               "Resolved", "Resolved"]),

                             ("Known Issue=Other,Duplicate Incident=Other,False Positive=False Positive,"
                              "True Positive=Resolved,Security Testing=Other,Other=Other",
                              ["Other", "Other", "Duplicate", "False Positive", "Resolved", "Other", "Other",
                               "Resolved", "Resolved"]),

                             ("Duplicate Incident=Other,Security Testing=Other,Other=Other",
                              ["Other", "Other", "Duplicate", "False Positive", "Resolved", "Other", "Other",
                               "Resolved", "Resolved"]),

                             # Expecting default mapping to be used when no mapping provided.
                             ("", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             # Expecting default mapping to be used when improper mapping is provided.
                             ("Duplicate=RANDOM1, Other=Random2", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             ("Duplicate Incident=Random3", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             # Expecting default mapping to be used when improper mapping *format* is provided.
                             ("Duplicate Incident=Other False Positive=Other", list(XDR_RESOLVED_STATUS_TO_XSOAR.values())),

                             # Expecting default mapping to be used for when improper key-value pair *format* is provided.
                             ("Duplicate Incident=Other, False Positive=Other True Positive=Other",
                              ["Other", "Other", "Duplicate", "False Positive", "Resolved", "Security Testing", "Other",
                               "Resolved", "Resolved"]),

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
    from CortexXDRIR import handle_incoming_incident
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
            close_entry = handle_incoming_incident(incident_data)
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
    from CortexXDRIR import Client, validate_custom_close_reasons_mapping

    # using two different credentials object as they both fields need to be encrypted
    base_url = urljoin("dummy_url", '/public_api/v1')
    proxy = demisto.params().get('proxy')
    verify_cert = not demisto.params().get('insecure', False)

    Client(
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
                validate_custom_close_reasons_mapping(mapping=custom_mapping, direction=direction)
        else:
            try:
                validate_custom_close_reasons_mapping(mapping=custom_mapping, direction=direction)
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
        len_incidents = len(multiple_extra_data['reply']['incidents'])
        outputs = Client.get_multiple_incidents_extra_data(client,
                                                           statuses=['new'],
                                                           starred=True,
                                                           starred_incidents_fetch_window=1575806909185,
                                                           incident_id_list=['1', '2'],
                                                           exclude_artifacts=True)
        assert len(outputs) == len_incidents
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


def test_sort_all_incident_data_fields_fetch_case_get_multiple_incidents_extra_data_format(mocker):
    """
    Given:
        -  raw incident in get_incident_extra_data format- alerts and artifacts not in
        incident data information
    When
        - Running sort_all_list_incident_fields
    Then
        - Verify that alerts and artifacts are found.
    """
    from CortexXDRIR import sort_incident_data, sort_all_list_incident_fields
    incident_case_get_multiple_incidents_extra_data = load_test_data('./test_data/get_multiple_incidents_extra_data.json') \
        .get('reply').get('incidents')[0]
    incident_data = sort_incident_data(incident_case_get_multiple_incidents_extra_data)
    sort_all_list_incident_fields(incident_data)
    assert incident_data.get('alerts')
    assert incident_data.get('incident_sources') == ['XDR Agent']
    assert incident_data.get('status') == 'new'
    assert len(incident_data.get('file_artifacts')) == 1


def test_update_alerts_in_xdr_command_expected_result(mocker):
    """
    Given:
        -  an XDR client
        - arguments (incident_id)
    When
        - Running update_alerts_in_xdr_command
    Then
        - Verify update alerts
    """
    from CortexXDRIR import update_alerts_in_xdr_command, Client
    xdrIr_client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
    http_request = mocker.patch.object(xdrIr_client, '_http_request')
    http_request.return_value = {"reply": {"alerts_ids": ['1', '2', '3']}}
    args = {"alert_ids": "1,2,3", "severity": "high", "status": "resolved_threat_handled", "comment": "fixed from test"}
    res = update_alerts_in_xdr_command(xdrIr_client, args)
    assert res.readable_output == "Alerts with IDs 1,2,3 have been updated successfully."


def test_update_alerts_in_xdr_command_fail_to_update(mocker):
    """
    Given:
        -  an XDR client
        - arguments (incident_id)
    When
        - Running update_alerts_in_xdr_command
    Then
        - Did not find alerts to update - raise an error
    """
    from CortexXDRIR import update_alerts_in_xdr_command, Client
    xdrIr_client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
    http_request = mocker.patch.object(xdrIr_client, '_http_request')
    http_request.return_value = {"reply": {"alerts_ids": []}}
    args = {"alert_ids": "1,2,3", "severity": "high", "status": "resolved_threat_handled", "comment": "fixed from test"}
    with pytest.raises(DemistoException) as e:
        update_alerts_in_xdr_command(xdrIr_client, args)
    assert e.value.message == "Could not find alerts to update, please make sure you used valid alert IDs."


def test_update_alerts_in_xdr_command_invalid_response_no_reply(mocker):
    """
    Given:
        -  an XDR client
        - arguments (incident_id)
    When
        - Running update_alerts_in_xdr_command
    Then
        - Verify that if the incident id is not found, it returns an error.
    """
    from CortexXDRIR import update_alerts_in_xdr_command, Client
    xdrIr_client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
    http_request = mocker.patch.object(xdrIr_client, '_http_request')
    http_request.return_value = {"alerts_ids": ['1', '2', '3']}
    args = {"alert_ids": "1,2,3", "severity": "high", "status": "resolved_threat_handled", "comment": "fixed from test"}
    with pytest.raises(DemistoException) as e:
        update_alerts_in_xdr_command(xdrIr_client, args)
    assert e.value.message == ("Parse Error. Response not in format, can't find reply key. "
                               "The response {'alerts_ids': ['1', '2', '3']}.")


def test_update_alerts_in_xdr_command_invalid_response_no_alerts_ids(mocker):
    """
    Given:
        -  an XDR client
        - arguments (incident_id)
    When
        - Running update_alerts_in_xdr_command
    Then
        - Verify that if the incident id is not found, it returns an error.
    """
    from CortexXDRIR import update_alerts_in_xdr_command, Client
    xdrIr_client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=10, proxy=False)
    http_request = mocker.patch.object(xdrIr_client, '_http_request')
    http_request.return_value = {"reply": {'alerts_ids': []}}
    args = {"alert_ids": "1,2,3", "severity": "high", "status": "resolved_threat_handled", "comment": "fixed from test"}
    with pytest.raises(DemistoException) as e:
        update_alerts_in_xdr_command(xdrIr_client, args)
    assert e.value.message == "Could not find alerts to update, please make sure you used valid alert IDs."


@pytest.mark.parametrize('incident_changed, delta',
                         [(True, {'CortexXDRIRstatus': 'resolved', "close_reason": "False Positive"}),
                          (False, {})])
def test_update_remote_system_command_update_alerts(mocker, incident_changed, delta):
    """
    Given:
        - an XDR client
        - arguments (incident fields)
    When
        - update_remote_system_command which triggers Running update_alerts_in_xdr_command
    Then
        - Verify alerts related to incident have been changed when closing the incident
    """
    from CortexXDRIR import update_remote_system_command, Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False, params={'close_alerts_in_xdr': True})
    data = {'CortexXDRIRstatus': 'resolved', 'status': 'test'}
    expected_remote_id = 'remote_id'
    args = {'remoteId': expected_remote_id, 'data': data, 'entries': [], 'incidentChanged': incident_changed,
            'delta': delta,
            'status': 2,
            }
    with patch("CortexXDRIR.update_incident_command") as mock_update_incident_command:
        get_incident_extra_data_mock = mocker.patch.object(client, 'get_incident_extra_data')
        get_incident_extra_data_mock.return_value = {'alerts': {'data': [{'alert_id': '123'}]}}
        mock_update_incident_command.return_value = {}
        http_request_mock = mocker.patch.object(client, 'update_alerts_in_xdr_request')
        http_request_mock.return_value = '1,2,3'
        update_remote_system_command(client, args)


def test_update_alerts_in_xdr_request_called_with():
    """
    Given:
        - an XDR client
        - arguments (incident fields)
    When
        - update_alerts_in_xdr_request is called
    Then
        - the http request is called with the right args
    """
    alerts_ids = '1,2,3'
    severity = 'High'
    status = 'resolved'
    comment = 'i am a test'
    from CortexXDRIR import Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False, params={'close_alerts_in_xdr': True})
    with patch.object(client, '_http_request') as mock_http_request, patch("CortexXDRIR.get_headers") as get_headers_mock:
        mock_http_request.return_value = {
            "reply": {
                "alerts_ids": alerts_ids
            }
        }
        get_headers_mock.return_value = {
            "x-xdr-timestamp": 123,
            "x-xdr-nonce": 456,
            "x-xdr-auth-id": str(678),
            "Authorization": 123,
        }
        client.update_alerts_in_xdr_request(alerts_ids, severity, status, comment)
        mock_http_request.assert_called_once_with(method='POST',
                                                  url_suffix='/alerts/update_alerts',
                                                  json_data={'request_data':
                                                             {'alert_id_list': '1,2,3',
                                                              'update_data':
                                                              {'severity': 'High', 'status': 'resolved',
                                                               'comment': 'i am a test'}
                                                              }
                                                             },
                                                  headers={
                                                      'x-xdr-timestamp': 123,
                                                      'x-xdr-nonce': 456,
                                                      'x-xdr-auth-id': '678',
                                                      'Authorization': 123},
                                                  timeout=120)


def test_update_alerts_in_xdr_request_invalid_response():
    """
    Given:
        - an XDR client
        - arguments (incident fields)
    When
        - update_alerts_in_xdr_request is called
    Then
        - response is not in format-  raise an error
    """
    alerts_ids = '1,2,3'
    severity = 'High'
    status = 'resolved'
    comment = 'i am a test'
    from CortexXDRIR import Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False, params={'close_alerts_in_xdr': True})
    with patch.object(client, '_http_request') as mock_http_request, patch("CortexXDRIR.get_headers") as get_headers_mock, \
            pytest.raises(DemistoException) as e:
        mock_http_request.return_value = {
            "replys": {
                "alerts_ids": alerts_ids
            }
        }
        get_headers_mock.return_value = {
            "x-xdr-timestamp": 123,
            "x-xdr-nonce": 456,
            "x-xdr-auth-id": str(678),
            "Authorization": 123,
        }
        client.update_alerts_in_xdr_request(alerts_ids, severity, status, comment)
    assert e.value.message == ("Parse Error. Response not in format, can't find reply key. "
                               "The response {'replys': {'alerts_ids': '1,2,3'}}.")


def test_update_alerts_in_xdr_command():
    """
    Given:
        - an XDR client
        - arguments (incident fields)
    When
        - test_update_alerts_in_xdr_command is called
    Then
        - raises an error since there is no field to update
    """
    from CortexXDRIR import Client, update_alerts_in_xdr_command
    from CommonServerPython import DemistoException
    args = {'alert_ids': '1'}
    client = Client(
        base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False, params={'close_alerts_in_xdr': True}
    )
    with pytest.raises(DemistoException) as e:
        update_alerts_in_xdr_command(client, args)
    assert e.value.message == "Can not find a field to update for alerts ['1'], please fill in severity/status/comment."


def test_main(mocker):
    """
    Given:
        - Only the required params in the configuration.
    When:
        - Running a command.
    Then:
        - Validate that the code executes gracefully.
    """
    from CortexXDRIR import main
    mocker.patch.object(demisto, 'params', return_value={'url': 'test_url'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mock_client = mocker.patch('CortexXDRIR.Client', autospec=True)
    mock_client.test_module.return_value = 'ok'
    main()


@freeze_time("1993-06-17 11:00:00 GMT")
def test_core_http_request_xpanse_tenant(mocker):
    """
    Unit test to verify behavior in Xpanse tenants on the Xsiam platform with XSOAR Marketplace.

    This test ensures that when working with Xpanse tenants on the Xsiam platform integrated with the
    XSOAR Marketplace, the http_request function from CommonServerPython is used instead of _apiCall,
    as required in Xsiam tenants (CIAC-10878).

    Given:
        - Only the required params in the configuration.
    When:
        - Running a get_incidents to test the http_request function in CoreIRApiModule.
    Then:
        - Should fail since command '_apiCall' is not available via engine.
    """
    from CortexXDRIR import Client
    from CommonServerPython import BaseClient
    base_url = urljoin("dummy_url", '/public_api/v1')
    client = Client(
        base_url=base_url,
        proxy=False,
        verify=False,
        timeout=120,
        params=False
    )
    mocker.patch("CoreIRApiModule.FORWARD_USER_RUN_RBAC", new=False)
    mocker.patch.object(demisto, "_apiCall", return_value=Exception("command '_apiCall' is not available via engine (85)"))
    mocker.patch.object(BaseClient, "_http_request", return_value={'reply': {"incidents": [{"incident": {"incident_id": "1"}}]}})
    res = client.get_incidents(incident_id_list=['1'])
    assert res == [{'incident': {'incident_id': '1'}}]


def test_get_xsoar_close_reasons(mocker):
    mock_response = {
        'body': '{"sysConf":{"incident.closereasons":"CustomReason1, CustomReason 2, Foo","versn":40},"defaultMap":{}}\n',
        'headers': {
            'Content-Length': ['104'],
            'X-Xss-Protection': ['1; mode=block'],
            'X-Content-Type-Options': ['nosniff'],
            'Strict-Transport-Security': ['max-age=10886400000000000; includeSubDomains'],
            'Vary': ['Accept-Encoding'],
            'Server-Timing': ['7'],
            'Date': ['Wed, 03 Jul 2010 09:11:35 GMT'],
            'X-Frame-Options': ['DENY'],
            'Content-Type': ['application/json']
        },
        'status': '200 OK',
        'statusCode': 200
    }
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mock_response)
    assert get_xsoar_close_reasons() == list(XSOAR_RESOLVED_STATUS_TO_XDR.keys()) + ['CustomReason1', 'CustomReason 2', 'Foo']


@freeze_time('1970-01-01 00:00:00.100')
def test_fetch_incidents_dedup():
    """
    Unit test to verify that incidents that occur in the same instant are not not missed or duplicated.

    Given:
        - Two incidents occur in the same instant.
    When:
        - Fetching incidents.
    Then:
        - Assert no incidents are missed or duplicated.
    """
    from CortexXDRIR import fetch_incidents

    last_run = {'time': 0}

    class MockClient:

        _incidents = load_test_data('./test_data/get_incidents_list_dedup.json')

        def save_modified_incidents_to_integration_context(self): ...

        def get_multiple_incidents_extra_data(self, gte_creation_time_milliseconds=0, limit=100, **_):
            return [
                inc for inc in self._incidents
                if inc['creation_time'] >= gte_creation_time_milliseconds
            ][:limit]

    mock_client = MockClient()

    last_run, result_1 = fetch_incidents(
        client=mock_client,
        first_fetch_time='3 days',
        integration_instance={},
        exclude_artifacts=True,
        last_run=last_run,
        max_fetch=2,
    )

    assert len(result_1) == 2
    assert 'XDR Incident 1' in result_1[0]['name']
    assert 'XDR Incident 2' in result_1[1]['name']
    assert last_run['time'] == 100000001
    assert last_run['dedup_incidents'] == ['2']

    last_run, result_2 = fetch_incidents(
        client=mock_client,
        first_fetch_time='3 days',
        integration_instance={},
        exclude_artifacts=True,
        last_run=last_run,
        max_fetch=2,
    )

    assert len(result_2) == 2
    assert 'XDR Incident 3' in result_2[0]['name']
    assert 'XDR Incident 4' in result_2[1]['name']
    assert last_run['time'] == 100000001
    assert last_run['dedup_incidents'] == ['2', '3', '4']

    last_run, result_3 = fetch_incidents(
        client=mock_client,
        first_fetch_time='3 days',
        integration_instance={},
        exclude_artifacts=True,
        last_run=last_run,
        max_fetch=2,
    )

    assert len(result_3) == 2
    assert 'XDR Incident 5' in result_3[0]['name']
    assert 'XDR Incident 6' in result_3[1]['name']
    assert last_run['time'] == 100000002
    assert last_run['dedup_incidents'] == ['6']

    # run empty test and assert last_run stays the same
    old_last_run = last_run.copy()

    last_run, empty_result = fetch_incidents(
        client=mock_client,
        first_fetch_time='3 days',
        integration_instance={},
        exclude_artifacts=True,
        last_run=last_run,
        max_fetch=2,
    )

    assert empty_result == []
    assert last_run == old_last_run


@freeze_time("2020-11-18T13:20:00.00000", tz_offset=0)
def test_get_modified_remote_data_default_xdr_delay(mocker):
    """
    Given:
        - an XDR client
        - arguments - lastUpdate time
        - raw incidents (result of client.get_incidents)
        - xdr_delay = None
    When
        - running get_modified_remote_data_command
    Then
        - the method is returning a list of incidents IDs that were modified after adding xdr_delay
    """
    from CortexXDRIR import get_modified_remote_data_command, Client
    from CommonServerPython import BaseClient

    mocker.patch.object(demisto, 'getIntegrationContext')
    mocker.patch.object(BaseClient, "_http_request", return_value={
        "reply": {"total_count": 0, "result_count": 0, "incidents": [], "restricted_incident_ids": []}
    })
    previous_last_update_time = "2020-11-18T13:15:00.000"
    client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    modified_incidents_empty, new_last_run_time_empty = get_modified_remote_data_command(
        client, {'lastUpdate': previous_last_update_time, }, previous_last_update_time,
    )

    assert not modified_incidents_empty.modified_incident_ids
    assert new_last_run_time_empty == "2020-11-18 13:19:00.001"


@freeze_time("2020-11-18T13:20:00.00000", tz_offset=0)
def test_get_modified_remote_data_two_minutes_xdr_delay(mocker):
    """
    Given:
        - an XDR client
        - arguments - lastUpdate time
        - raw incidents (result of client.get_incidents)
        - xdr_delay = 2 minutes
    When
        - running get_modified_remote_data_command
    Then
        - the method is returning a list of incidents IDs that were modified after adding xdr_delay
    """
    from CortexXDRIR import get_modified_remote_data_command, Client
    from CommonServerPython import BaseClient

    mocker.patch.object(demisto, 'getIntegrationContext')
    mocker.patch.object(BaseClient, "_http_request", return_value=load_test_data('./test_data/get_incidents_list.json'))
    previous_last_update_time = "2020-11-18T13:15:00.000"
    client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)

    incidents_response, new_last_time_stamp = get_modified_remote_data_command(
        client, {'lastUpdate': previous_last_update_time}, previous_last_update_time, xdr_delay=2
    )

    assert new_last_time_stamp == "2020-11-18 13:18:00.001"
    assert incidents_response.modified_incident_ids == ['1', '2']


@freeze_time("2020-11-18T13:20:00.00000", tz_offset=0)
def test_mirror_in_empty_last_update(mocker):
    """
        Given:
            - an XDR client
            - Empty mirror-in args - lastUpdate time = '' (e.g. {'lastUpdate': ''}) may happen the first mirror-in iteration
            - raw incidents (result of client.get_incidents)
        When
            - Running get_modified_remote_data_command function
        Then
            - Make sure we set a default last_update time.
    """
    from CortexXDRIR import get_modified_remote_data_command, Client
    from CommonServerPython import BaseClient

    mocker.patch.object(demisto, 'getIntegrationContext')
    mocker.patch.object(BaseClient, "_http_request", return_value=load_test_data('./test_data/get_incidents_list.json'))
    mock_debug = mocker.patch.object(demisto, 'debug')

    client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    _, _ = get_modified_remote_data_command(
        client, {'lastUpdate': ''}
    )

    expected_log = "Mirror last update is: last_update='' will set it to default_last_update='2020-11-18 13:18:00'"
    assert mock_debug.call_args_list[1].args[0] == expected_log
    assert "last_update='2020-11-18 13:18:00'" in mock_debug.call_args_list[2].args[0]


def test_mirror_in_wrong_last_update(mocker):
    """
        Given:
            - an XDR client
            - Wrong mirror-in args - lastUpdate time = 'abcdefg' (e.g. {'lastUpdate': 'abcdefg'})
            - raw incidents (result of client.get_incidents)
        When
            - Running get_modified_remote_data_command function
        Then
            - Make sure we raise an exception with the expected message.
    """
    from CortexXDRIR import get_modified_remote_data_command, Client
    from CommonServerPython import BaseClient

    mocker.patch.object(demisto, 'getIntegrationContext')
    mocker.patch.object(BaseClient, '_http_request', return_value=load_test_data('./test_data/get_incidents_list.json'))

    client = Client(base_url=f'{XDR_URL}/public_api/v1', verify=False, timeout=120, proxy=False)
    with pytest.raises(DemistoException) as e:
        _, _ = get_modified_remote_data_command(
            client, {'lastUpdate': 'abcdefg'}
        )

    assert e.value.message == "Failed to parse last_update='abcdefg' got last_update_utc=None"


def test_get_distribution_url_command_without_download():
    """
    Given:
        - `download_package` argument set to False.
    When:
        - Calling `get_distribution_url_command` without downloading the package.
    Then:
        - Should return a CommandResults object with the distribution URL and no file download.
    """
    from CoreIRApiModule import get_distribution_url_command
    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")

    args = {
        "distribution_id": "12345",
        "package_type": "x64",
        "download_package": "false",
        "integration_context_brand": "PaloAltoNetworksXDR"
    }

    result = get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "x64")
    assert isinstance(result, CommandResults)
    assert result.outputs == {"id": "12345", "url": "https://example.com/distribution"}
    assert result.outputs_prefix == "PaloAltoNetworksXDR.Distribution"
    assert result.outputs_key_field == "id"
    assert "[Distribution URL](https://example.com/distribution)" in result.readable_output


def test_get_distribution_url_command_with_download(mocker):
    """
    Given:
        - `download_package` set to True.
    When:
        - Calling `get_distribution_url_command` with downloading the package.
    Then:
        - Should return a list with CommandResults for the distribution URL and the downloaded file information.
    """
    from CoreIRApiModule import get_distribution_url_command
    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")
    client._http_request = MagicMock(return_value=b"mock_binary_data")

    args = {
        "distribution_id": "12345",
        "package_type": "x64",
        "download_package": "true",
        "integration_context_brand": "PaloAltoNetworksXDR"
    }
    mocker.patch('CortexXDRIR.fileResult', return_value={
        'Contents': '',
        'ContentsFormat': 'text',
        'Type': 3,
        'File': 'xdr-agent-install-package.msi',
        'FileID': '11111'
    })
    result = get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "x64")
    client._http_request.assert_called_once_with(
        method="GET", full_url="https://example.com/distribution", resp_type="content"
    )
    assert isinstance(result, list)
    assert len(result) == 2
    command_result = result[1]
    assert isinstance(command_result, CommandResults)
    assert command_result.outputs == {"id": "12345", "url": "https://example.com/distribution"}
    assert command_result.outputs_prefix == "PaloAltoNetworksXDR.Distribution"
    assert command_result.outputs_key_field == "id"
    assert "Installation package downloaded successfully." in command_result.readable_output


def test_get_distribution_url_command_without_download_not_supported_type():
    """
    Given:
        - `download_package` argument set to True but package_type is not x64 or x86.
    When:
        - Calling `get_distribution_url_command` without downloading the package.
    Then:
        - Should raise a demisto error.
    """
    from CoreIRApiModule import get_distribution_url_command
    client = MagicMock()
    client.get_distribution_url = MagicMock(return_value="https://example.com/distribution")

    args = {
        "distribution_id": "12345",
        "package_type": "sh",
        "download_package": "true",
        "integration_context_brand": "PaloAltoNetworksXDR"
    }
    with pytest.raises(DemistoException) as e:
        get_distribution_url_command(client, args)
    client.get_distribution_url.assert_called_once_with("12345", "sh")
    assert e.value.message == "`download_package` argument can be used only for package_type 'x64' or 'x86'."


def test_handle_incoming_incident(capfd, mocker):
    """
    Given:
        - incident data of resolved incident
    When
        - Handling incoming closing-incident (handle_incoming_closing_incident(...) executed).
    Then
        - a resolved entry is being added
    """
    from CortexXDRIR import handle_incoming_incident
    from CommonServerPython import EntryType, EntryFormat
    custom_mapping = ("Known Issue=Other,Duplicate Incident=Duplicate,False Positive=False Positive,"
                      "True Positive=Resolved,Security Testing=Other,Other=Other")
    mocker.patch.object(demisto, 'params', return_value={"mirror_direction": "Both",
                                                         "custom_xdr_to_xsoar_close_reason_mapping": custom_mapping})

    for xdr_reopen_reason in XDR_OPEN_STATUS_TO_XSOAR:
        incident_data = load_test_data('./test_data/resolved_incident_data.json')
        # Set incident status to be tested reopen-reason.
        incident_data["status"] = xdr_reopen_reason

        # Overcoming expected non-empty stderr test failures (Errors are submitted to stderr when improper mapping is provided).
        with capfd.disabled():
            reopen_entry = handle_incoming_incident(incident_data)
        assert reopen_entry == {
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentReopen': True
            },
            'ContentsFormat': EntryFormat.JSON
        }


def test_get_remote_data_command_exclude_fields(mocker):
    """
    Given:
        - An XDR client with base URL, headers, and mock HTTP requests
        - Arguments (`id` set to 1 and `lastUpdate` set to 0, which is lower than incident modification time)
    When:
        - Running `get_remote_data_command` with different combinations of `exclude_artifacts`,
        `excluded_alert_fields`, and `remove_nulls_from_alerts` arguments
    Then:
        - The correct `POST` request is made to the `/incidents/get_multiple_incidents_extra_data/`
        endpoint with the appropriate parameters
        - The request data contains correct filters, exclusions, and sorting options based on the provided arguments
    """
    from CortexXDRIR import get_remote_data_command, Client
    client = Client(
        base_url=f'{XDR_URL}/public_api/v2', verify=False, timeout=120, proxy=False)
    args = {
        'id': 1,
        'lastUpdate': 0
    }
    mocker.patch.object(Client, 'headers', return_value={"Authorization": "Bearer test_token"})
    # make sure get-extra-data is returning an incident
    mocker.patch('CortexXDRIR.get_last_mirrored_in_time', return_value=0)
    mocker.patch('CortexXDRIR.check_if_incident_was_modified_in_xdr', return_value=True)
    mocker.patch("CortexXDRIR.ALERTS_LIMIT_PER_INCIDENTS", new=50)
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    client._http_request = MagicMock()

    # Test case 1: no excluded data
    get_remote_data_command(client, args)
    client._http_request.assert_called_with(
        method='POST',
        url_suffix='/incidents/get_multiple_incidents_extra_data/',
        json_data={'request_data':
                   {'search_to': 100, 'sort':
                    {'field': 'creation_time', 'keyword': 'asc'},
                    'filters': [{'field': 'incident_id_list', 'operator': 'in', 'value': ['1']}]}},
        headers=client.headers,
        timeout=120
    )

    # Test case 2: With excluded_alert_fields
    excluded_alert_fields = ["fieldA", "fieldB"]
    get_remote_data_command(client, args, excluded_alert_fields=excluded_alert_fields)
    client._http_request.assert_called_with(
        method='POST',
        url_suffix='/incidents/get_multiple_incidents_extra_data/',
        json_data={'request_data':
                   {'search_to': 100, 'sort':
                    {'field': 'creation_time', 'keyword': 'asc'},
                       'alert_fields_to_exclude': ['fieldA', 'fieldB'],
                       'filters': [{'field': 'incident_id_list', 'operator': 'in', 'value': ['1']}]}},
        headers=client.headers,
        timeout=120
    )

    # Test case 3: With remove_nulls_from_alerts
    get_remote_data_command(client, args, remove_nulls_from_alerts=True)
    client._http_request.assert_called_with(
        method='POST',
        url_suffix='/incidents/get_multiple_incidents_extra_data/',
        json_data={'request_data':
                   {'search_to': 100, 'sort':
                    {'field': 'creation_time', 'keyword': 'asc'},
                       'drop_nulls': True,
                       'filters': [{'field': 'incident_id_list', 'operator': 'in', 'value': ['1']}]}},
        headers=client.headers,
        timeout=120
    )

    # Test case 5: With remove_nulls_from_alerts, excluded_alert_fields
    get_remote_data_command(client, args, remove_nulls_from_alerts=True,
                            excluded_alert_fields=excluded_alert_fields)
    client._http_request.assert_called_with(
        method='POST',
        url_suffix='/incidents/get_multiple_incidents_extra_data/',
        json_data={'request_data':
                   {'search_to': 100, 'sort':
                    {'field': 'creation_time', 'keyword': 'asc'},
                       'alert_fields_to_exclude': ['fieldA', 'fieldB'],
                       'drop_nulls': True,
                       'filters': [{'field': 'incident_id_list', 'operator': 'in', 'value': ['1']}]}},
        headers=client.headers,
        timeout=120
    )


@pytest.fixture
def mock_client():
    from CortexXDRIR import Client
    mock = MagicMock(Client)
    mock.get_multiple_incidents_extra_data = MagicMock()
    return mock


def test_fetch_incidents_multiple_incidents_extra_data_with_excluded_fields(mock_client):
    """
    Given:
        - An XDR client.
        - Parameters for fetching incidents including `exclude_artifacts`, `excluded_alert_fields`,
          and `remove_nulls_from_alerts`.
    When:
        - Running `fetch_incidents` to fetch multiple incidents with provided parameters.
    Then:
        - The correct call is made to `get_multiple_incidents_extra_data` with expected arguments.
        - The call parameters correctly reflect the input values, such as filters, exclusions,
          and sorting options.
    """
    from CortexXDRIR import fetch_incidents
    # Prepare test inputs
    first_fetch_time = "2023-01-01T00:00:00Z"
    integration_instance = "test_integration"
    last_run = {
        'time': 0,
        'incidents_from_previous_run': [],
        'dedup_incidents': []
    }
    statuses = ['open']
    starred = False
    starred_incidents_fetch_window = None
    excluded_alert_fields = ['fieldA', 'fieldB']
    remove_nulls_from_alerts = True
    max_fetch = 10

    fetch_incidents(mock_client, first_fetch_time=first_fetch_time,
                    integration_instance=integration_instance, last_run=last_run,
                    exclude_artifacts=False,
                    max_fetch=max_fetch, statuses=statuses,
                    starred=starred, starred_incidents_fetch_window=starred_incidents_fetch_window,
                    excluded_alert_fields=excluded_alert_fields, remove_nulls_from_alerts=remove_nulls_from_alerts)
    mock_client.get_multiple_incidents_extra_data.assert_called_with(
        gte_creation_time_milliseconds=0,
        statuses=statuses,
        limit=max_fetch + len(last_run['dedup_incidents']),
        starred=starred,
        starred_incidents_fetch_window=None,
        exclude_artifacts=False,
        excluded_alert_fields=excluded_alert_fields,
        remove_nulls_from_alerts=remove_nulls_from_alerts
    )


def test_fetch_incidents_incidents_extra_datat_with_excluded_fields(mocker):
    """
    Given:
        - An XDR client.
        - Parameters for fetching incidents including `exclude_artifacts`, `excluded_alert_fields`,
          and `remove_nulls_from_alerts`.
    When:
        - Running `fetch_incidents` to fetch multiple incidents with provided parameters.
    Then:
        - The correct call is made to `get_multiple_incidents_extra_data` with expected arguments.
        - The call parameters correctly reflect the input values, such as filters, exclusions,
          and sorting options.
    """
    from CortexXDRIR import Client, fetch_incidents
    mocker.patch.object(Client, 'save_modified_incidents_to_integration_context')
    client = Client(base_url=f'{XDR_URL}/public_api/v2', verify=False, timeout=120, proxy=False)
    first_fetch_time = "2023-01-01T00:00:00Z"
    integration_instance = "test_integration"
    last_run = {
        'time': 0,
        'incidents_from_previous_run': [],
        'dedup_incidents': []
    }
    statuses = ['open']
    starred = False
    starred_incidents_fetch_window = None
    excluded_alert_fields = ['fieldA', 'fieldB']
    remove_nulls_from_alerts = True
    max_fetch = 10

    raw_incident = load_test_data('./test_data/get_multiple_incidents_extra_data.json').get('reply', {}).get('incidents')[0]
    raw_incident['incident']['alert_count'] = 10000
    raw_incident['incident']['incident_id'] = 11

    mocker.patch.object(Client, 'get_multiple_incidents_extra_data', return_value=[raw_incident])
    mock_get_incident_extra_data = mocker.patch.object(Client, 'get_incident_extra_data', return_value=raw_incident)
    fetch_incidents(client, first_fetch_time=first_fetch_time,
                    integration_instance=integration_instance, last_run=last_run,
                    exclude_artifacts=False,
                    max_fetch=max_fetch, statuses=statuses,
                    starred=starred, starred_incidents_fetch_window=starred_incidents_fetch_window,
                    excluded_alert_fields=excluded_alert_fields, remove_nulls_from_alerts=remove_nulls_from_alerts)
    # Assume the alert count is above ALERTS_LIMIT_PER_INCIDENTS
    mock_get_incident_extra_data.assert_called_with(
        incident_id=11,
        exclude_artifacts=False,
        excluded_alert_fields=excluded_alert_fields,
        remove_nulls_from_alerts=remove_nulls_from_alerts
    )


def test_handle_excluded_data_param_old_param():
    """
    Given:
        - The `excluded_data_from_alerts` parameter with various combinations of fields to exclude.
    When:
        - Calling the `handle_excluded_data_from_alerts_param` function.
    Then:
        - Ensure that the function correctly separates `null_values` from the rest of the exclusions.
        - Verify that the returned tuple matches the expected exclusions list and boolean value for `null_values`.
    """
    from CortexXDRIR import handle_excluded_data_from_alerts_param
    excluded_data_from_alerts = ['a', 'b']
    assert handle_excluded_data_from_alerts_param(excluded_data_from_alerts) == (['a', 'b'], False)
    excluded_data_from_alerts = ['null_values', 'b']
    assert handle_excluded_data_from_alerts_param(excluded_data_from_alerts) == (['b'], True)
