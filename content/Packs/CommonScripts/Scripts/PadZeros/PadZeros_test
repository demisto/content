from PadZeros import main
import demistomock as demisto
from CommonServerPython import entryTypes


def test_pad_zeros(mocker):
    mocker.patch.object(demisto, 'args', return_value={'value': 'somanyzeros', 'length': 15})
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['Contents'] == '0000somanyzeros'
