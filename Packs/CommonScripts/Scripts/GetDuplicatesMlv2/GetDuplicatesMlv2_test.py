import demistomock as demisto
from GetDuplicatesMlv2 import main, Utils
from CommonServerPython import entryTypes


def test_main(mocker):
    def executeCommand(name, args=None):
        if name == 'findIndicators':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': [{
                        "investigationIDs": ["1", "2"],
                        "value": "test@test.com",
                        "indicator_type": "Email",
                    }]
                }
            ]
        elif name == 'getIncidents':
            return demisto.exampleIncidents  # use original mock
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={
        "compareIndicators": "Email, IP, Domain, File SHA256, File MD5, URL",
        "compareEmailLabels": "Email/headers/From, Email/headers/Subject, Email/text, Email/html, Email/attachments",
        "UseLocalEnvDuplicatesInLastDays": "30"
    })
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    # validate our mocks are good
    assert 'URL' in demisto.args()['compareIndicators']
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0][0]
    assert results.startswith('Did not find any')


def test_extract_domain_from_url(mocker):
    import requests

    class MySession(requests.Session):
        def merge_environment_settings(self, *args, **kwargs):
            config = super(MySession, self).merge_environment_settings(*args, **kwargs)
            config['verify'] = False
            return config

    mocker.patch('requests.Session', MySession)

    res = Utils.extract_domain_from_url("https://www.google.com")  # disable-secrets-detection
    assert res == 'google.com'
    res = Utils.extract_domain_from_url("https://www.google.co.il")  # disable-secrets-detection
    assert res == 'google.co.il'
