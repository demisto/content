from datetime import datetime, timedelta
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(requests_mock, mocker):
    from decyfir import Client, fetch_incidents
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    mock_response = util_load_json('test_data/search_alerts.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(Client, 'request_decyfir_api', return_value=mock_response['alerts'])
    last_fetch = (datetime.now() - timedelta(days=80)).strftime(date_format)
    last_run = {
        'last_fetch': last_fetch
    }

    _, new_incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch='90 days',
        decyfir_api_key='api_key',
        incident_type='Attack Surface',
        max_fetch='1'
    )

    assert new_incidents == [{'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Open Ports',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Open Ports'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Open Ports',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Open Ports'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'IP Vulnerability',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'IP Vulnerability'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'IP Vulnerability',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'IP Vulnerability'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Configuration',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Configuration'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Configuration',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Configuration'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Cloud Weakness',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Cloud Weakness'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Cloud Weakness',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Cloud Weakness'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'IP Reputation',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'IP Reputation'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'IP Reputation',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'IP Reputation'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Certificates',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Certificates'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "ip": "103.10.147.138", '
                                         '"alert_created_date": "2023-01-05T04:18:46.001", "uid": '
                                         '"63ac266713b0752aa7865100", "top_domain": "aa.id", "cat": 8, '
                                         '"sub_domain": "ns6.aa.id", "open_ports": [53], "category": '
                                         '"Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'},
                             {'category': 'Attack Surface',
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'decyfircategory': 'Attack Surface',
                              'decyfirsubcategory': 'Certificates',
                              'details': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'labels': [{'type': 'decyfircategory', 'value': 'Attack Surface'},
                                         {'type': 'decyfirsubcategory', 'value': 'Certificates'},
                                         {'type': 'incident_source_from', 'value': 'DeCYFIR'}],
                              'name': 'DOMAIN : ns6.aa.id, aa.id\n IP: 103.10.147.138',
                              'occurred': '2023-01-05T04:18:46Z',
                              'rawJSON': '{"first_seen": "2022-12-28T11:20:07.001", "software": "", '
                                         '"last_seen": "2023-01-05T01:25:55.001", "risk_score": 8, '
                                         '"sub_category": "Open Ports", "web_server": null, "ip": '
                                         '"103.10.147.138", "alert_created_date": '
                                         '"2023-01-05T04:18:46.001", "description": null, '
                                         '"web_server_version": null, "uid": "63ac266713b0752aa7865100", '
                                         '"top_domain": "aa.id", "cat": 8, "sub_domain": "ns6.aa.id", '
                                         '"open_ports": [53], "category": "Attack Surface"}',
                              'severity': 3,
                              'sourceBrand': 'DeCYFIR',
                              'type': 'Attack Surface'}] != [{'alert_created_date': '2023-01-05T04:18:46.001',
                                                              'cat': 8,
                                                              'category': 'Attack Surface',
                                                              'first_seen': '2022-12-28T11:20:07.001',
                                                              'ip': '103.10.147.138',
                                                              'last_seen': '2023-01-05T01:25:55.001',
                                                              'open_ports': [53],
                                                              'severity': 8,
                                                              'software': '',
                                                              'sub_category': 'Open Ports',
                                                              'sub_domain': 'ns6.aa.id',
                                                              'top_domain': 'aa.id',
                                                              'uid': '63ac266713b0752aa7865100'}]
