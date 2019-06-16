import demistomock as demisto
from CommonServerPython import entryTypes
import main from Ping


RETURN_ERROR_TARGET = 'Ping.return_error'


def test_ping(mocker):
    mocker.patch.object(demisto, 'args', return_value={'address': 'google.com'})
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['address'] == 'google.com'
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert 'google.com' in results[0]["EntryContext"]["Ping"]['destination']
