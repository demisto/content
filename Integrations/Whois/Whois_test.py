import Whois
import demistomock as demisto


def test_test_command(mocker):
    mocker.patch.object(demisto, 'results')
    Whois.test_command()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'ok'
