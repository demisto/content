import demistomock as demisto
import OnboardingIntegration


def test_frequency(mocker):
    mocker.patch.object(demisto, 'params',
                        return_value={'frequency': '1'})
    mocker.patch.object(demisto, 'command',
                        return_value='fetch-incidents')
    mocker.patch.object(demisto, 'incidents')
    OnboardingIntegration.main()
    assert demisto.incidents.call_count == 1


def test_no_settings(mocker):
    mocker.patch.object(demisto, 'params',
                        return_value={})
    mocker.patch.object(demisto, 'command',
                        return_value='fetch-incidents')
    mocker.patch.object(demisto, 'incidents')
    OnboardingIntegration.main()
    assert demisto.incidents.call_count == 1
