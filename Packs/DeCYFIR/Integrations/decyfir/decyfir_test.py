from datetime import datetime, timedelta
import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(mocker):
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Open Ports'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Open Ports'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'IP Vulnerability'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'IP Vulnerability'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Configuration'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Configuration'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Cloud Weakness'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Cloud Weakness'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'IP Reputation'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'IP Reputation'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Certificates'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'customFields': {'decyfircategory': 'Attack Surface',
                                               'decyfirdatadetails': [{'fields': 'First seen',
                                                                       'values': '2022-12-28T11:20:07.001'},
                                                                      {'fields': 'Software', 'values': ''},
                                                                      {'fields': 'Last seen',
                                                                       'values': '2023-01-05T01:25:55.001'},
                                                                      {'fields': 'Risk score', 'values': 8},
                                                                      {'fields': 'Sub category',
                                                                       'values': 'Open Ports'},
                                                                      {'fields': 'Ip',
                                                                       'values': '103.10.147.138'},
                                                                      {'fields': 'Alert created date',
                                                                       'values': '2023-01-05T04:18:46.001'},
                                                                      {'fields': 'Top domain',
                                                                       'values': 'aa.id'},
                                                                      {'fields': 'Cat', 'values': 8},
                                                                      {'fields': 'Sub domain',
                                                                       'values': 'ns6.aa.id'},
                                                                      {'fields': 'Open ports',
                                                                       'values': [53]},
                                                                      {'fields': 'Category',
                                                                       'values': 'Attack Surface'}],
                                               'decyfirsubcategory': 'Certificates'},
                              'dbotMirrorId': '63ac266713b0752aa7865100',
                              'labels': [{'type': 'Description', 'value': None}],
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
                              'type': 'Attack Surface'}]
