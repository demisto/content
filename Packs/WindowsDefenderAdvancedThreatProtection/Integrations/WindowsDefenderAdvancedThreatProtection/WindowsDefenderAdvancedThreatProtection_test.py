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
    assert 'Windows Defender ATP Alert da637029414680409372_735564929' ==\
           demisto.incidents.call_args[0][0][0].get('name')
