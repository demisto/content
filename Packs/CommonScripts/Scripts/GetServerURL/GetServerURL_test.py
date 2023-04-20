import demistomock as demisto
from CommonServerPython import *
import GetServerURL


def test_get_url(mocker):
    # Set
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})
    mocker.patch.object(demisto, 'results')

    # Arrange
    GetServerURL.main()
    output = demisto.results.call_args[0][0]

    # Assert
    assert output == {
        'Type': entryTypes['note'],
        'HumanReadable': 'https://www.eizelulz.com:8443',
        'ContentsFormat': formats['text'],
        'Contents': 'https://www.eizelulz.com:8443',
        'EntryContext': {'ServerURL': {
            'Scheme': 'https',
            'Host': 'www.eizelulz.com',
            'Port': 8443,
            'URL': 'https://www.eizelulz.com:8443'
        }},
        'IgnoreAutoExtract': False,
        'IndicatorTimeline': None
    }
