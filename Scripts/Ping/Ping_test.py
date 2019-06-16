import demistomock as demisto
from CommonServerPython import entryTypes
from Ping import main
import re

# To run the tests in an editor see: test_data/ping

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
    assert re.match(r'\d+\.\d+\.\d+.\d+', results[0]["EntryContext"]["Ping"]['destination_ip']) is not None
    assert results[0]["EntryContext"]["Ping"]['mdev_rtt']


def test_fail_ping(mocker):
    mocker.patch.object(demisto, 'args', return_value={'address': 'nonExistingDomain45343.com'})  # disable-secrets-detection
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    main()
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert 'Name does not resolve' in err_msg
