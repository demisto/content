import demistomock as demisto
import json


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy': True,
                                                         'url': 'https://api.securitycenter.windows.com',
                                                         'tenant_id': '1234',
                                                         'enc_key': 'key',
                                                         'auth_id': '1234567@1234567',
                                                         'fetch_severity': 'Informational,Low,Medium,High',
                                                         'fetch_status': 'New'})
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2018-11-26T16:19:21.840980"})
    mocker.patch.object(demisto, 'incidents')


def atp_mocker(mocker):
    import WindowsDefenderAdvancedThreatProtection as atp
    with open('./test_data/alerts.json', 'r') as f:
        alerts = json.loads(f.read())
    mocker.patch.object(atp, 'list_alerts', return_value=alerts)


def test_fetch(mocker):
    mock_demisto(mocker)
    import WindowsDefenderAdvancedThreatProtection as atp
    atp_mocker(mocker)
    atp.fetch_incidents()
    # Check that all 3 incidents are extracted
    assert 3 == len(demisto.incidents.call_args[0][0])
    assert 'Windows Defender ATP Alert da636983472338927033_-2077013687' == \
           demisto.incidents.call_args[0][0][2].get('name')

    # Check that incident isn't extracted again
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2019-09-01T13:31:08.025286",
                                                             'last_ids': ['da637029414680409372_735564929']})
    atp.fetch_incidents()
    assert [] == demisto.incidents.call_args[0][0]

    # Check that new incident is extracted
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_alert_fetched_time': "2019-09-01T13:29:37.235691",
                                                             'last_ids': ['da637029413772554314_295039533']})
    atp.fetch_incidents()
    assert 'Windows Defender ATP Alert da637029414680409372_735564929' == \
           demisto.incidents.call_args[0][0][0].get('name')


def test_get_file_data(mocker):
    import WindowsDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_file_data_request', return_value=FILE_DATA_API_RESPONSE)
    res = atp.get_file_data("123abc")
    assert res['Sha1'] == "123abc"
    assert res['Size'] == 42


def test_get_alert_related_ips_command(mocker):
    import WindowsDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'id': '123'})
    mocker.patch.object(atp, 'get_alert_related_ips_request', return_value=ALERT_RELATED_IPS_API_RESPONSE)
    _, res, _ = atp.get_alert_related_ips_command()
    assert res['MicrosoftATP.AlertIP(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'IPs': ['1.1.1.1', '2.2.2.2']
    }


def test_get_alert_related_domains_command(mocker):
    import WindowsDefenderAdvancedThreatProtection as atp
    mocker.patch.object(demisto, 'args', return_value={'id': '123'})
    mocker.patch.object(atp, 'get_alert_related_domains_request', return_value=ALERT_RELATED_DOMAINS_API_RESPONSE)
    _, res, _ = atp.get_alert_related_domains_command()
    assert res['MicrosoftATP.AlertDomain(val.AlertID === obj.AlertID)'] == {
        'AlertID': '123',
        'Domains': ['www.example.com', 'www.example2.com']
    }


def test_get_action_data(mocker):
    import WindowsDefenderAdvancedThreatProtection as atp
    mocker.patch.object(atp, 'get_machine_action_by_id_request', return_value=ACTION_DATA_API_RESPONSE)
    res = atp.get_action_data("123456")
    assert res['ID'] == "123456"
    assert res['Status'] == "Succeeded"


""" API RAW RESULTS """

FILE_DATA_API_RESPONSE = {
    "sha1": "123abc",
    "sha256": "456abc",
    "md5": "789abc",
    "globalPrevalence": 123,
    "globalFirstObserved": "2016-07-16T17:16:55.530433Z",
    "globalLastObserved": "2020-02-26T14:35:12.6778604Z",
    "size": 42,
    "fileType": None,
    "isPeFile": True,
    "filePublisher": None,
    "fileProductName": None,
    "signer": "Microsoft Windows",
    "issuer": "Microsoft issuer",
    "signerHash": "147abc",
    "isValidCertificate": True,
    "determinationType": "Unknown",
    "determinationValue": ""
}

ALERT_RELATED_IPS_API_RESPONSE = {
        "value": [
            {
                "id": "1.1.1.1"
            },
            {
                "id": "2.2.2.2"
            }
        ]
    }


ALERT_RELATED_DOMAINS_API_RESPONSE = {
    "value": [
        {
            "host": "www.example.com"
        },
        {
            "host": "www.example2.com"
        }

    ]
}

ACTION_DATA_API_RESPONSE = {
    "id": "123456",
    "type": "Unisolate",
    "requestor": "147258",
    "requestorComment": "Test",
    "status": "Succeeded",
    "machineId": "987abc",
    "computerDnsName": "desktop-test",
    "creationDateTimeUtc": "2020-02-26T09:23:12.5820502Z",
    "lastUpdateDateTimeUtc": "2020-02-26T09:23:37.3018521Z",
    "cancellationRequestor": None,
    "cancellationComment": None,
    "cancellationDateTimeUtc": None,
    "errorHResult": 0,
    "scope": None,
    "relatedFileInfo": None
}
